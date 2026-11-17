<?php
defined( 'ABSPATH' ) || exit;

/**
 * Monthly report email. Runs inside the daily event: on the configured day
 * (or the first day after it on which cron runs) it sends the previous month's report.
 */
class OWUM_Mailer {

	public static function init() {
		add_action( 'owum_daily', array( __CLASS__, 'maybe_send' ), 20 );
	}

	public static function maybe_send() {
		$s = owum_settings();
		if ( empty( $s['enabled'] ) ) {
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
	 * @param string $ym History month (Y-m).
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
			/* translators: 1: client / site name, 2: month and year */
			$subject = sprintf( __( '[%1$s] Updates and security report – %2$s', 'ondaweb-security' ), $s['client_name'], OWUM_Report::month_label( $ym ) );
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
