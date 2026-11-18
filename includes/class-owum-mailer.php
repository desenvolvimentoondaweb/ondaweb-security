<?php
defined( 'ABSPATH' ) || exit;

/**
 * Report email. Runs inside the daily event, on the configured frequency:
 * - monthly: on the chosen day (or the first day after it on which cron runs), report of the previous month;
 * - weekly: on Mondays, report of the previous Monday to Sunday;
 * - biweekly: on the 15th and the 30th (last day in February), report since the previous send.
 */
class OWUM_Mailer {

	public static function init() {
		add_action( 'owum_daily', array( __CLASS__, 'maybe_send' ), 20 );
	}

	/** Report frequency: weekly, biweekly or monthly. */
	public static function freq() {
		$s = owum_settings();
		return in_array( $s['freq'], array( 'weekly', 'biweekly', 'monthly' ), true ) ? $s['freq'] : 'monthly';
	}

	private static function day( $ts ) {
		return gmdate( 'Y-m-d', $ts );
	}

	/** 15th and 30th of a month (the 30th becomes the last day in February). */
	private static function biweekly_days( $y, $m ) {
		$last = (int) gmdate( 't', gmmktime( 12, 0, 0, $m, 1, $y ) );
		return array( 15, min( 30, $last ) );
	}

	/**
	 * Most recent scheduled send on or before $today for weekly/biweekly frequencies.
	 *
	 * @return array ['send' => Y-m-d, 'period' => 'Y-m-d_Y-m-d']
	 */
	public static function last_point( $freq, $today ) {
		$t = strtotime( $today . ' 12:00:00 UTC' );
		if ( 'weekly' === $freq ) {
			$send = $t - ( ( (int) gmdate( 'N', $t ) - 1 ) * DAY_IN_SECONDS ); // Monday of this week
			return array( 'send' => self::day( $send ), 'period' => self::day( $send - 7 * DAY_IN_SECONDS ) . '_' . self::day( $send - DAY_IN_SECONDS ) );
		}
		$y = (int) gmdate( 'Y', $t );
		$m = (int) gmdate( 'n', $t );
		$d = (int) gmdate( 'j', $t );
		$pt   = gmmktime( 12, 0, 0, $m - 1, 1, $y ); // previous month
		$pd   = self::biweekly_days( (int) gmdate( 'Y', $pt ), (int) gmdate( 'n', $pt ) );
		$cd   = self::biweekly_days( $y, $m );
		if ( $d >= $cd[1] ) {
			$send = gmmktime( 12, 0, 0, $m, $cd[1], $y );
			$from = gmmktime( 12, 0, 0, $m, 15, $y );
		} elseif ( $d >= 15 ) {
			$send = gmmktime( 12, 0, 0, $m, 15, $y );
			$from = gmmktime( 12, 0, 0, $m - 1, $pd[1], $y );
		} else {
			$send = gmmktime( 12, 0, 0, $m - 1, $pd[1], $y );
			$from = gmmktime( 12, 0, 0, $m - 1, 15, $y );
		}
		return array( 'send' => self::day( $send ), 'period' => self::day( $from ) . '_' . self::day( $send - DAY_IN_SECONDS ) );
	}

	/** Period of the last complete report (used by "Send now"). */
	public static function last_period() {
		$f = self::freq();
		return 'monthly' === $f ? self::previous_month() : self::last_point( $f, current_time( 'Y-m-d' ) )['period'];
	}

	/** Period from the last scheduled send until today (partial report). */
	public static function current_period() {
		$f = self::freq();
		if ( 'monthly' === $f ) {
			return current_time( 'Y-m' );
		}
		return self::last_point( $f, current_time( 'Y-m-d' ) )['send'] . '_' . current_time( 'Y-m-d' );
	}

	/** Date (Y-m-d) of the next automatic send. */
	public static function next_send() {
		$s     = owum_settings();
		$f     = self::freq();
		$today = current_time( 'Y-m-d' );
		$t     = strtotime( $today . ' 12:00:00 UTC' );
		$last  = get_site_option( 'owum_last_sent' );
		if ( 'monthly' === $f ) {
			$day = (int) $s['day'];
			if ( (int) gmdate( 'j', $t ) < $day ) {
				return gmdate( 'Y-m-', $t ) . sprintf( '%02d', $day );
			}
			if ( $last !== gmdate( 'Y-m', $t ) ) {
				return $today;
			}
			return self::day( gmmktime( 12, 0, 0, (int) gmdate( 'n', $t ) + 1, $day, (int) gmdate( 'Y', $t ) ) );
		}
		$p = self::last_point( $f, $today );
		$late = ( strtotime( $today ) - strtotime( $p['send'] ) ) / DAY_IN_SECONDS;
		if ( $late <= 3 && $last !== $p['send'] ) {
			return $today; // due: goes out on the next run of the daily routine
		}
		if ( 'weekly' === $f ) {
			return self::day( strtotime( $p['send'] . ' 12:00:00 UTC' ) + 7 * DAY_IN_SECONDS );
		}
		$y  = (int) gmdate( 'Y', $t );
		$m  = (int) gmdate( 'n', $t );
		$d  = (int) gmdate( 'j', $t );
		$cd = self::biweekly_days( $y, $m );
		if ( $d < 15 ) {
			return self::day( gmmktime( 12, 0, 0, $m, 15, $y ) );
		}
		if ( $d < $cd[1] ) {
			return self::day( gmmktime( 12, 0, 0, $m, $cd[1], $y ) );
		}
		return self::day( gmmktime( 12, 0, 0, $m + 1, 15, $y ) );
	}

	public static function maybe_send() {
		$s = owum_settings();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		$f = self::freq();
		if ( 'monthly' !== $f ) {
			$today = current_time( 'Y-m-d' );
			$p     = self::last_point( $f, $today );
			$late  = ( strtotime( $today ) - strtotime( $p['send'] ) ) / DAY_IN_SECONDS;
			// Up to 3 days late (WP-Cron depends on visits); older sends are skipped, not piled up.
			if ( $late > 3 || get_site_option( 'owum_last_sent' ) === $p['send'] ) {
				return;
			}
			OWUM_Collector::force_check();
			if ( self::send( $p['period'] ) ) {
				update_site_option( 'owum_last_sent', $p['send'] );
			}
			return;
		}
		$month = current_time( 'Y-m' );
		if ( (int) current_time( 'j' ) < (int) $s['day'] || get_site_option( 'owum_last_sent' ) === $month ) {
			return;
		}
		OWUM_Collector::force_check();
		if ( self::send( self::previous_month() ) ) {
			update_site_option( 'owum_last_sent', $month );
		}
	}

	public static function previous_month() {
		$first = strtotime( current_time( 'Y-m-01' ) . ' 12:00:00' );
		return gmdate( 'Y-m', strtotime( '-1 month', $first ) );
	}

	public static function recipients() {
		$s    = owum_settings();
		$list = array_filter( array_map( 'trim', explode( ',', (string) $s['emails'] ) ), 'is_email' );
		return array_values( $list );
	}

	/**
	 * @param string $ym Period: month (Y-m) or range of days (Y-m-d_Y-m-d).
	 */
	public static function send( $ym ) {
		$to = self::recipients();
		if ( ! $to ) {
			return false;
		}
		$sent  = false;
		$error = '';
		try {
			$s       = owum_settings();
			/* translators: 1: client / site name, 2: period (month and year, or dates) */
			$subject = sprintf( __( '[%1$s] Updates and security report – %2$s', 'ondaweb-security' ), $s['client_name'], OWUM_Report::period_label( $ym ) );
			// Logos by URL (work with any email/SMTP plugin).
			$body = '<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#ffffff;">' . OWUM_Report::html( $ym, 'email' ) . '</body></html>';

			$embed = array( __CLASS__, 'embed_logos' );
			add_action( 'phpmailer_init', $embed );
			$fail = function ( $e ) use ( &$error ) {
				$error = is_wp_error( $e ) ? $e->get_error_message() : '';
			};
			add_action( 'wp_mail_failed', $fail );
			$sent = wp_mail( $to, $subject, $body, array( 'Content-Type: text/html; charset=UTF-8' ) );
			remove_action( 'phpmailer_init', $embed );
			remove_action( 'wp_mail_failed', $fail );
		} catch ( \Throwable $e ) {
			$sent  = false;
			$error = $e->getMessage() . ' (' . basename( $e->getFile() ) . ':' . $e->getLine() . ')';
			OWUM_ErrorLog::add( 'error', __( 'Report email', 'ondaweb-security' ) . ': ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString(), 'source' => 'self' ) );
		}
		update_site_option(
			'owum_last_mail',
			array(
				'when'  => current_time( 'mysql' ),
				'month' => $ym,
				'ok'    => (bool) $sent,
				'to'    => implode( ', ', $to ),
				'error' => $error,
			)
		);
		return (bool) $sent;
	}

	/**
	 * When the email goes through WordPress' PHPMailer, embeds the logos in the message
	 * (they show even when external images are blocked). With other mail plugins,
	 * logos keep loading from the image URL.
	 */
	public static function embed_logos( $phpmailer ) {
		if ( ! is_object( $phpmailer ) || ! method_exists( $phpmailer, 'addEmbeddedImage' ) || ! property_exists( $phpmailer, 'Body' ) ) {
			return;
		}
		foreach ( array( 'client', 'ondaweb' ) as $which ) {
			try {
				$l = owum_logo( $which );
				if ( ! $l || empty( $l['path'] ) || ! is_readable( $l['path'] ) ) {
					continue;
				}
				$cid = 'owum-logo-' . $which;
				if ( $phpmailer->addEmbeddedImage( $l['path'], $cid, basename( $l['path'] ), 'base64', $l['mime'] ) ) {
					$phpmailer->Body = str_replace( 'src="' . esc_attr( $l['url'] ) . '"', 'src="cid:' . $cid . '"', $phpmailer->Body );
				}
			} catch ( \Throwable $e ) {
				OWUM_ErrorLog::add( 'warning', __( 'Could not embed the logo in the email', 'ondaweb-security' ) . ': ' . $e->getMessage(), array( 'source' => 'self' ), false );
			}
		}
	}
}
