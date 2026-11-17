<?php
defined( 'ABSPATH' ) || exit;

/**
 * Client report (updates + security) with the Ondaweb layout.
 *
 * Built with tables and inline styles so the same HTML works in email clients and,
 * with print_css(), as an A4 PDF (browser "Save as PDF") with header, footer and page numbers.
 */
class OWUM_Report {

	const C_TEXT   = '#1b1d1f';
	const C_BODY   = '#2c3033';
	const C_MUTED  = '#5f666a';
	const C_LINE   = '#e3e5e7';
	const C_SOFT   = '#f6f6f3';
	const C_ORANGE = '#f58634';
	const C_RED    = '#ef4057';
	const C_TEAL   = '#0cbbc8';
	const C_TEAL_D = '#0a9aa5';
	const C_NAVY   = '#2c2e49';
	const C_OK     = '#0a9aa5';
	const C_OK_BG  = '#e3f7f9';
	const C_FREE   = '#2c2e49';
	const C_FREEBG = '#ebebf1';
	const C_PAID   = '#c2600f';
	const C_PAIDBG = '#fff1e6';
	const FONT     = "'Segoe UI',Selawik,'Helvetica Neue',Arial,sans-serif";
	const MONO     = "'DejaVu Sans Mono',Menlo,Consolas,monospace";

	/** [start, end] of a month given as Y-m. */
	public static function month_range( $ym ) {
		$ts    = strtotime( $ym . '-01 00:00:00' );
		$start = gmdate( 'Y-m-01 00:00:00', $ts );
		$end   = gmdate( 'Y-m-t 23:59:59', $ts );
		return array( $start, $end );
	}

	/** "October 2026" / "Outubro de 2026" — month names come from the WordPress translation of the site. */
	public static function month_label( $ym ) {
		global $wp_locale;
		list( $y, $m ) = array_map( 'intval', explode( '-', $ym ) );
		$name = ( $wp_locale && $m >= 1 && $m <= 12 ) ? $wp_locale->get_month( $m ) : (string) $m;
		$name = function_exists( 'mb_strtoupper' ) ? mb_strtoupper( mb_substr( $name, 0, 1 ) ) . mb_substr( $name, 1 ) : ucfirst( $name );
		/* translators: 1: month name, 2: year */
		return sprintf( _x( '%1$s %2$s', 'month name and year', 'ondaweb-security' ), $name, $y );
	}

	/** Site address without the scheme (www.example.com). */
	public static function site_host() {
		return untrailingslashit( preg_replace( '#^https?://#', '', network_home_url( '/' ) ) );
	}

	/* ------------------------------------------------------------------ */
	/* Small building blocks                                               */
	/* ------------------------------------------------------------------ */

	private static function upper( $s ) {
		return function_exists( 'mb_strtoupper' ) ? mb_strtoupper( $s ) : strtoupper( $s );
	}

	/** Translated text that may contain <code>/<strong>: keeps only those tags and styles them. */
	private static function rich( $text ) {
		$t = wp_kses( $text, array( 'code' => array(), 'strong' => array() ) );
		return str_replace( '<code>', '<code style="font-family:' . self::MONO . ';font-size:.9em;background:#eceeef;border-radius:3px;padding:1px 4px;">', $t );
	}

	private static function eyebrow( $text, $color ) {
		return '<div style="font-size:9.5px;font-weight:700;letter-spacing:.16em;color:' . $color . ';margin:0 0 6px;">' . esc_html( self::upper( $text ) ) . '</div>';
	}

	private static function h2( $text, $sub = '' ) {
		$o  = '<table role="presentation" class="owum-h2" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:34px 0 12px;"><tr>';
		$o .= '<td style="width:12px;padding:0 12px 0 0;vertical-align:middle;"><div style="width:12px;height:12px;background:' . self::C_ORANGE . ';border-radius:2px;font-size:0;line-height:0;">&nbsp;</div></td>';
		$o .= '<td style="vertical-align:middle;font-size:19px;font-weight:700;color:' . self::C_TEXT . ';">' . esc_html( $text ) . '</td></tr></table>';
		if ( $sub ) {
			$o .= '<p style="margin:-4px 0 14px;font-size:13px;line-height:1.6;color:' . self::C_BODY . ';">' . $sub . '</p>';
		}
		return $o;
	}

	private static function p( $html, $extra = '' ) {
		return '<p style="margin:0 0 12px;font-size:13.5px;line-height:1.7;color:' . self::C_BODY . ';' . $extra . '">' . $html . '</p>';
	}

	/** Teal circle with a check mark (or orange dot when pending). */
	private static function tick( $ok = true ) {
		$bg = $ok ? self::C_TEAL : self::C_ORANGE;
		$ch = $ok ? '&#10003;' : '!';
		return '<span style="display:inline-block;width:16px;height:16px;line-height:16px;border-radius:50%;background:' . $bg . ';color:#fff;font-size:10px;font-weight:700;text-align:center;vertical-align:middle;">' . $ch . '</span>';
	}

	private static function pill( $ok ) {
		$fg   = $ok ? self::C_TEAL_D : self::C_PAID;
		$bg   = $ok ? self::C_OK_BG : self::C_PAIDBG;
		$text = $ok ? __( 'Verified', 'ondaweb-security' ) : __( 'Being handled', 'ondaweb-security' );
		return '<span style="display:inline-block;white-space:nowrap;padding:5px 12px;border-radius:14px;background:' . $bg . ';color:' . $fg . ';font-size:9.5px;font-weight:700;letter-spacing:.14em;">&#9679;&nbsp; ' . esc_html( self::upper( $text ) ) . '</span>';
	}

	/** Line icon of an area (inline SVG; email clients that drop SVG just show the empty tile). */
	private static function icon( $name, $mode ) {
		$paths = array(
			'cross' => '<path d="M5 5l14 14M19 5L5 19"/><circle cx="12" cy="12" r="2.4"/><circle cx="5" cy="5" r="1.4"/><circle cx="19" cy="19" r="1.4"/><circle cx="19" cy="5" r="1.4"/><circle cx="5" cy="19" r="1.4"/>',
			'chip'  => '<circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1.6"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
			'bars'  => '<path d="M8 3v18M16 3v18"/><path d="M5.5 8h5M13.5 15h5"/>',
			'plug'  => '<path d="M12 3v18"/><path d="M8 7h8M7 11h10M9 15h6"/>',
		);
		if ( 'email' === $mode ) {
			return ''; // most email clients drop inline SVG
		}
		$svg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="' . self::C_TEAL . '" stroke-width="1.5" stroke-linecap="round" style="display:block;margin:7px auto;">' . ( isset( $paths[ $name ] ) ? $paths[ $name ] : $paths['cross'] ) . '</svg>';
		return '<div style="width:32px;height:32px;border-radius:7px;background:' . self::C_SOFT . ';">' . $svg . '</div>';
	}

	/** Stat cards in a row: [value, label, top color]. */
	private static function stat_cards( $cards ) {
		$w  = floor( 100 / count( $cards ) );
		$o  = '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:10px 0;margin:6px -10px 4px;table-layout:fixed;"><tr>';
		foreach ( $cards as $c ) {
			$o .= '<td style="width:' . $w . '%;background:' . self::C_SOFT . ';border-top:3px solid ' . $c[2] . ';border-radius:8px;padding:16px 16px 18px;vertical-align:top;">';
			$o .= '<div style="font-size:24px;font-weight:700;color:' . self::C_TEXT . ';line-height:1.15;">' . $c[0] . '</div>';
			$o .= '<div style="font-size:11px;line-height:1.4;color:' . self::C_MUTED . ';margin-top:6px;">' . esc_html( $c[1] ) . '</div></td>';
		}
		return $o . '</tr></table>';
	}

	/** Table with a black header row. $cols = [[label, width%], ...]. */
	private static function table_open( $cols ) {
		$o = '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:4px 0 6px;"><tr>';
		foreach ( $cols as $c ) {
			$o .= '<th style="background:#000;color:#fff;text-align:left;padding:9px 12px;font-size:9.5px;font-weight:700;letter-spacing:.14em;' . ( ! empty( $c[1] ) ? 'width:' . $c[1] . '%;' : '' ) . '">' . esc_html( self::upper( $c[0] ) ) . '</th>';
		}
		return $o . '</tr>';
	}

	private static function td( $html, $extra = '' ) {
		return '<td style="padding:9px 12px;font-size:12.5px;line-height:1.5;color:' . self::C_TEXT . ';border-bottom:1px solid ' . self::C_LINE . ';vertical-align:top;' . $extra . '">' . $html . '</td>';
	}

	private static function empty_row( $cols, $text ) {
		return '<tr><td colspan="' . (int) $cols . '" style="padding:12px;font-size:12.5px;color:' . self::C_MUTED . ';border-bottom:1px solid ' . self::C_LINE . ';">' . esc_html( $text ) . '</td></tr>';
	}

	private static function small( $text ) {
		return '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( $text ) . '</span>';
	}

	public static function badge( $status ) {
		$map   = array(
			'ok'   => array( self::C_OK, self::C_OK_BG ),
			'free' => array( self::C_FREE, self::C_FREEBG ),
			'paid' => array( self::C_PAID, self::C_PAIDBG ),
		);
		$c     = isset( $map[ $status ] ) ? $map[ $status ] : $map['ok'];
		$label = OWUM_Collector::status_label( $status );
		return '<span style="display:inline-block;padding:2px 9px;border-radius:10px;font-size:10.5px;font-weight:700;white-space:nowrap;color:' . $c[0] . ';background:' . $c[1] . ';">' . esc_html( $label ) . '</span>';
	}

	/** "Security fix" tag for items with a known vulnerability. */
	private static function sec_tag( $key ) {
		if ( ! OWSU_Vulns::for_key( $key ) ) {
			return '';
		}
		return ' <span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#fff;background:' . self::C_RED . ';white-space:nowrap;">' . esc_html__( 'Security fix', 'ondaweb-security' ) . '</span>';
	}

	/* ------------------------------------------------------------------ */
	/* Security areas                                                      */
	/* ------------------------------------------------------------------ */

	/** Text of an implemented action (some depend on values found by the check). */
	private static function action_text( $check, $label, $text, $r ) {
		$d = isset( $r['data'] ) ? (array) $r['data'] : array();
		if ( 'ssl_expiry' === $check && ! empty( $d['until'] ) ) {
			$text = ! empty( $d['issuer'] )
				/* translators: 1: certificate issuer (e.g. Let's Encrypt), 2: date */
				? sprintf( __( '%1$s certificate, valid until %2$s, which keeps the connection between the visitor and the site encrypted.', 'ondaweb-security' ), $d['issuer'], owum_date_ts( $d['until'] ) )
				/* translators: %s: date */
				: sprintf( __( 'certificate valid until %s, which keeps the connection between the visitor and the site encrypted.', 'ondaweb-security' ), owum_date_ts( $d['until'] ) );
		} elseif ( 'ssl_expiry' === $check ) {
			$text = __( 'the certificate in use is valid and keeps the connection between the visitor and the site encrypted.', 'ondaweb-security' );
		}
		if ( 'php_version' === $check && ! empty( $d['php'] ) ) {
			$label = 'PHP ' . $d['php'];
			$text  = ! empty( $d['until'] )
				/* translators: %s: date */
				? sprintf( __( 'version with security support until %s, so it keeps receiving fixes.', 'ondaweb-security' ), owum_date_ts( $d['until'] ) )
				: __( 'version with security support, so it keeps receiving fixes.', 'ondaweb-security' );
		} elseif ( 'php_version' === $check ) {
			$text = __( 'version with security support, so it keeps receiving fixes.', 'ondaweb-security' );
		}
		return array( $label, $text );
	}

	/**
	 * Status of each area from the last scan.
	 *
	 * @return array id => [area, done[[label,text]], pend[label], ok(bool), proof]
	 */
	public static function areas( $scan ) {
		$res = isset( $scan['results'] ) ? (array) $scan['results'] : array();
		$out = array();
		foreach ( OWSU_Areas::all() as $id => $a ) {
			$done = array();
			$pend = array();
			$okid = array();
			foreach ( $a['actions'] as $act ) {
				list( $check, $label, $text ) = $act;
				$r = isset( $res[ $check ] ) ? $res[ $check ] : null;
				if ( ! $r || ! in_array( $r['status'], array( 'ok', 'crit', 'warn' ), true ) ) {
					continue; // not applicable / not verified
				}
				if ( 'ok' === $r['status'] ) {
					$done[]         = self::action_text( $check, $label, $text, $r );
					$okid[ $check ] = $r;
				} else {
					$pend[] = $label;
				}
			}
			if ( ! $done && ! $pend ) {
				continue;
			}
			$out[ $id ] = array(
				'area'  => $a,
				'done'  => $done,
				'pend'  => $pend,
				'ok'    => ! $pend,
				'proof' => self::proof( $id, $okid, count( $done ), count( $done ) + count( $pend ) ),
			);
		}
		return $out;
	}

	/** "Verified result" sentence of an area. */
	private static function proof( $id, $ok, $n_ok, $n_all ) {
		if ( 0 === $n_ok ) {
			/* translators: %s: brand (Ondaweb) */
			return sprintf( __( 'Being handled by the %s team.', 'ondaweb-security' ), owum_brand() );
		}
		if ( $n_ok < $n_all ) {
			/* translators: 1: measures confirmed, 2: total measures, 3: brand (Ondaweb) */
			return sprintf( __( '%1$d of %2$d measures confirmed; the others are being handled by the %3$s team.', 'ondaweb-security' ), $n_ok, $n_all, owum_brand() );
		}
		$data = function ( $check, $key ) use ( $ok ) {
			return isset( $ok[ $check ]['data'][ $key ] ) ? $ok[ $check ]['data'][ $key ] : null;
		};
		switch ( $id ) {
			case 'headers':
				return __( 'Present in the site\'s responses.', 'ondaweb-security' );
			case 'admin':
				$parts = array();
				if ( isset( $ok['login_url'] ) && $data( 'login_url', 'http' ) ) {
					/* translators: %d: HTTP status code */
					$parts[] = sprintf( __( '<code>/wp-login.php</code> returns %d', 'ondaweb-security' ), $data( 'login_url', 'http' ) );
				}
				if ( isset( $ok['login_captcha'] ) ) {
					$parts[] = __( 'reCAPTCHA active on login', 'ondaweb-security' );
				}
				return $parts ? implode( '; ', $parts ) . '.' : __( 'Confirmed in the automatic check.', 'ondaweb-security' );
			case 'enum':
				return __( 'Listing blocked for visitors; authors sitemap removed.', 'ondaweb-security' );
			case 'xmlrpc':
				/* translators: %d: HTTP status code */
				return $data( 'xmlrpc', 'http' ) ? sprintf( __( 'Returns %d.', 'ondaweb-security' ), $data( 'xmlrpc', 'http' ) ) : __( 'Blocked.', 'ondaweb-security' );
			case 'exposure':
				return __( 'No version exposed on the home page.', 'ondaweb-security' );
			case 'files':
				return null !== $data( 'up_php_files', 'files' )
					/* translators: %s: number of files */
					? sprintf( __( 'Sensitive files blocked; no PHP file in uploads (%s files checked).', 'ondaweb-security' ), number_format_i18n( (int) $data( 'up_php_files', 'files' ) ) )
					: __( 'Confirmed in the automatic check.', 'ondaweb-security' );
			case 'wp':
				return __( 'Confirmed in the automatic check.', 'ondaweb-security' );
		}
		return __( 'Confirmed.', 'ondaweb-security' );
	}

	private static function action_count( $n ) {
		/* translators: %d: number of actions */
		return sprintf( _n( '%d action', '%d actions', $n, 'ondaweb-security' ), $n );
	}

	private static function areas_grid( $areas, $mode ) {
		$o    = '';
		$rows = array_chunk( $areas, 3, true );
		foreach ( $rows as $row ) {
			$o .= '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:10px 10px;margin:-4px -10px 0;table-layout:fixed;"><tr>';
			foreach ( $row as $st ) {
				$a      = $st['area'];
				$o     .= '<td style="width:33%;border:1px solid ' . self::C_LINE . ';border-top:3px solid ' . self::C_ORANGE . ';border-radius:10px;padding:16px;vertical-align:top;">';
				$o     .= self::icon( $a['icon'], $mode );
				$o     .= '<div style="font-size:14px;font-weight:700;color:' . self::C_TEXT . ';margin:' . ( 'email' === $mode ? '0' : '12px' ) . ' 0 6px;line-height:1.3;">' . esc_html( $a['title'] ) . '</div>';
				$o     .= '<div style="font-size:11.5px;line-height:1.55;color:' . self::C_BODY . ';min-height:72px;">' . esc_html( $a['scope'] ) . '</div>';
				$status = $st['ok'] ? '<span style="color:' . self::C_TEAL_D . ';">' . esc_html__( 'Verified', 'ondaweb-security' ) . '</span>' : '<span style="color:' . self::C_PAID . ';">' . esc_html( sprintf( /* translators: %d: number of items */ __( '%d being handled', 'ondaweb-security' ), count( $st['pend'] ) ) ) . '</span>';
				$o     .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-top:12px;border-top:1px solid ' . self::C_LINE . ';"><tr><td style="padding-top:9px;font-size:11px;font-weight:700;color:' . self::C_TEXT . ';">' . esc_html( self::action_count( count( $st['done'] ) + count( $st['pend'] ) ) ) . '</td><td style="padding-top:9px;font-size:10.5px;text-align:right;">' . $status . '</td></tr></table>';
				$o     .= '</td>';
			}
			for ( $i = count( $row ); $i < 3; $i++ ) {
				$o .= '<td style="width:33%;"></td>';
			}
			$o .= '</tr></table>';
		}
		return $o;
	}

	private static function measure_card( $st, $mode ) {
		$a  = $st['area'];
		$o  = '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:0;border:1px solid ' . self::C_LINE . ';border-left:4px solid ' . self::C_ORANGE . ';border-radius:12px;margin:0 0 16px;">';
		$o .= '<tr><td colspan="2" style="padding:14px 20px;border-bottom:1px solid ' . self::C_LINE . ';"><table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;"><tr>';
		$ic = self::icon( $a['icon'], $mode );
		$o .= $ic ? '<td style="width:32px;padding-right:14px;vertical-align:middle;">' . $ic . '</td>' : '';
		$o .= '<td style="vertical-align:middle;font-size:16px;font-weight:700;color:' . self::C_TEXT . ';">' . esc_html( $a['title'] ) . '</td>';
		$o .= '<td style="vertical-align:middle;text-align:right;">' . self::pill( $st['ok'] ) . '</td></tr></table></td></tr>';

		$o .= '<tr><td style="padding:18px 20px 16px;vertical-align:top;">';
		$o .= '<p style="margin:0 0 14px;font-size:13px;line-height:1.65;color:' . self::C_BODY . ';">' . esc_html( $a['intro'] ) . '</p>';
		if ( $st['done'] ) {
			$o .= self::eyebrow( __( 'Implemented actions', 'ondaweb-security' ), self::C_ORANGE );
			foreach ( $st['done'] as $d ) {
				$o .= self::bullet( '<strong style="color:' . self::C_TEXT . ';">' . self::rich( $d[0] ) . ':</strong> ' . self::rich( $d[1] ), self::C_ORANGE );
			}
		}
		if ( $st['pend'] ) {
			$o .= '<div style="height:8px;font-size:0;line-height:0;">&nbsp;</div>' . self::eyebrow( __( 'Being handled', 'ondaweb-security' ), self::C_PAID );
			foreach ( $st['pend'] as $label ) {
				/* translators: %s: brand (Ondaweb) */
				$o .= self::bullet( '<strong style="color:' . self::C_TEXT . ';">' . self::rich( $label ) . ':</strong> ' . esc_html( sprintf( __( 'being handled by the %s team.', 'ondaweb-security' ), owum_brand() ) ), self::C_RED );
			}
		}
		$o .= '</td>';
		$o .= '<td style="width:30%;background:' . self::C_SOFT . ';padding:18px 18px 16px;vertical-align:top;border-radius:0 0 12px 0;">';
		$o .= self::eyebrow( __( 'Risk reduced', 'ondaweb-security' ), self::C_ORANGE );
		$o .= '<p style="margin:0 0 16px;font-size:12px;line-height:1.6;color:' . self::C_BODY . ';">' . esc_html( $a['risk'] ) . '</p>';
		$o .= self::eyebrow( __( 'Verified result', 'ondaweb-security' ), self::C_TEAL_D );
		$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;"><tr><td style="vertical-align:top;padding:1px 8px 0 0;">' . self::tick( $st['ok'] ) . '</td><td style="font-size:12px;line-height:1.5;font-weight:700;color:' . self::C_TEXT . ';">' . self::rich( $st['proof'] ) . '</td></tr></table>';
		$o .= '</td></tr></table>';
		return $o;
	}

	private static function bullet( $html, $color ) {
		return '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 7px;"><tr><td style="vertical-align:top;padding:6px 10px 0 0;"><div style="width:7px;height:7px;background:' . $color . ';border-radius:1px;font-size:0;line-height:0;">&nbsp;</div></td><td style="font-size:12.5px;line-height:1.6;color:' . self::C_BODY . ';">' . $html . '</td></tr></table>';
	}

	/* ------------------------------------------------------------------ */
	/* Report                                                              */
	/* ------------------------------------------------------------------ */

	/**
	 * Builds the report.
	 *
	 * @param string $ym   History month (Y-m).
	 * @param string $mode 'print' (browser / PDF) or 'email'.
	 */
	public static function html( $ym, $mode = 'print' ) {
		$settings      = owum_settings();
		$brand         = owum_brand();
		$inv           = OWUM_Collector::inventory();
		list( $s, $e ) = self::month_range( $ym );
		$log           = array_values(
			array_filter(
				OWUM_Logger::get( $s, $e ),
				function ( $r ) {
					return 'inicio' !== $r['action'];
				}
			)
		);
		$sec_log       = array_values( array_filter( $log, function ( $r ) { return 'security' === $r['item_type']; } ) );
		$log           = array_values( array_filter( $log, function ( $r ) { return 'security' !== $r['item_type']; } ) );
		$items         = array_merge( $inv['plugins'], $inv['themes'] );
		$paid          = array_filter( $items, function ( $r ) { return 'paid' === $r['status']; } );
		$free          = array_filter( $items, function ( $r ) { return 'free' === $r['status']; } );
		$core          = $inv['core'];
		$updated_count = count( array_filter( $log, function ( $r ) { return 'atualizado' === $r['action']; } ) );
		$today         = owum_date();
		$host          = self::site_host();
		$client        = $settings['client_name'] ? $settings['client_name'] : $host;

		$scan  = OWSU_Security::last_scan();
		$sc    = $scan ? $scan['score'] : null;
		$areas = $scan ? self::areas( $scan ) : array();
		$pend  = $sc ? $sc['count']['crit'] + $sc['count']['warn'] : 0;
		$sdate = $scan ? owum_date( $scan['time'] ) : '';
		$n_act = 0;
		$n_ver = 0;
		foreach ( $areas as $st ) {
			$n_act += count( $st['done'] );
			$n_ver += $st['ok'] ? 1 : 0;
		}

		// Fixes applied this month that are still in place.
		$latest = array();
		foreach ( $sec_log as $r ) { // newest first
			if ( ! isset( $latest[ $r['item_key'] ] ) ) {
				$latest[ $r['item_key'] ] = $r;
			}
		}
		$applied = count(
			array_filter(
				$latest,
				function ( $r ) {
					return 'correcao' === $r['action'] && OWSU_Security::is_on( substr( $r['item_key'], 4 ) );
				}
			)
		);

		$o = '<div class="owum-report" style="font-family:' . self::FONT . ';color:' . self::C_TEXT . ';max-width:860px;margin:0 auto;">';

		// Top bar (on screen and in the email; in the PDF it repeats on every page through print_css()).
		$logo = owum_logo( 'ondaweb' );
		$o   .= '<table role="presentation" class="owum-screen" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:0 0 22px;"><tr>';
		$o   .= '<td style="vertical-align:middle;"><img src="' . esc_url( $logo['url'] ) . '" alt="' . esc_attr( $brand ) . '" height="26" style="height:26px;width:auto;display:block;border:0;"></td>';
		$o   .= '<td style="vertical-align:middle;text-align:right;font-size:9.5px;font-weight:700;letter-spacing:.16em;color:' . self::C_MUTED . ';">' . esc_html( self::upper( __( 'WordPress updates and security', 'ondaweb-security' ) ) ) . ' <span style="color:' . self::C_ORANGE . ';">·</span> ' . esc_html( self::upper( $client ) ) . '</td>';
		$o   .= '</tr></table>';

		// Cover.
		$o .= '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:0;background:#000;border-radius:14px;">';
		$o .= '<tr><td style="padding:34px 36px 0;vertical-align:middle;">';
		$cl = owum_logo( 'client' );
		if ( $cl ) {
			$o .= '<div style="display:inline-block;background:#fff;border-radius:8px;padding:8px 12px;margin:0 0 18px;"><img src="' . esc_url( $cl['url'] ) . '" alt="' . esc_attr( $client ) . '" height="34" style="height:34px;width:auto;max-width:200px;display:block;border:0;"></div>';
		}
		/* translators: %s: client name */
		$o .= self::eyebrow( sprintf( __( 'Client %s', 'ondaweb-security' ), $client ), self::C_ORANGE );
		$o .= '<div style="font-size:30px;line-height:1.15;font-weight:700;color:#fff;margin:8px 0 14px;">' . esc_html__( 'Updates and security report', 'ondaweb-security' ) . '</div>';
		$o .= '<div style="font-size:14px;color:#d4d6d8;">' . esc_html( $host ) . '</div>';
		$o .= '</td><td style="padding:34px 36px 0 0;width:150px;vertical-align:middle;text-align:right;">';
		if ( $sc ) {
			$o .= '<div style="display:inline-block;width:124px;height:124px;border:7px solid ' . self::C_ORANGE . ';border-radius:50%;text-align:center;">';
			$o .= '<div style="padding-top:36px;color:#fff;font-size:30px;font-weight:700;line-height:1;">' . (int) $sc['score'] . '<span style="font-size:12px;font-weight:400;color:#aeb2b5;">/100</span></div>';
			/* translators: %s: grade (A-E) */
			$o .= '<div style="margin-top:8px;font-size:9px;font-weight:700;letter-spacing:.16em;color:' . self::C_ORANGE . ';">' . esc_html( self::upper( sprintf( __( 'Grade %s', 'ondaweb-security' ), $sc['grade'] ) ) ) . '</div></div>';
		}
		$o .= '</td></tr>';
		$meta = array(
			array( __( 'Date', 'ondaweb-security' ), $today ),
			array( __( 'Period', 'ondaweb-security' ), self::month_label( $ym ) ),
			array( __( 'Prepared by', 'ondaweb-security' ), $brand ),
			array( __( 'Scope', 'ondaweb-security' ), __( 'WordPress and published site', 'ondaweb-security' ) ),
		);
		$o .= '<tr><td colspan="2" style="padding:26px 36px 26px;"><table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;border-top:1px solid #2b2e30;"><tr>';
		foreach ( $meta as $m ) {
			$o .= '<td style="padding:18px 18px 0 0;vertical-align:top;"><div style="font-size:8.5px;font-weight:700;letter-spacing:.16em;color:#8a8f93;">' . esc_html( self::upper( $m[0] ) ) . '</div><div style="font-size:12.5px;color:#fff;margin-top:5px;">' . esc_html( $m[1] ) . '</div></td>';
		}
		$o .= '</tr></table></td></tr>';
		$o .= '<tr><td colspan="2" style="padding:0;font-size:0;line-height:0;"><table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;"><tr><td style="width:60%;height:6px;background:' . self::C_ORANGE . ';border-radius:0 0 0 14px;"></td><td style="width:20%;height:6px;background:' . self::C_RED . ';"></td><td style="width:20%;height:6px;background:' . self::C_TEAL . ';border-radius:0 0 14px 0;"></td></tr></table></td></tr>';
		$o .= '</table>';

		// Summary.
		$o .= self::h2( __( 'Summary', 'ondaweb-security' ) );
		$sum = array();
		if ( $sc ) {
			$sum[] = sprintf(
				/* translators: 1: number of tests, 2: score, 3: grade */
				esc_html__( 'The automatic security check (%1$d tests) resulted in %2$s', 'ondaweb-security' ),
				(int) $sc['total'],
				'<strong style="color:' . self::C_TEXT . ';">' . esc_html( sprintf( /* translators: 1: score, 2: grade */ __( 'grade %1$d/100 (%2$s)', 'ondaweb-security' ), $sc['score'], $sc['grade'] ) ) . '</strong>'
			) . ', ' . ( $pend
				/* translators: %d: number of items */
				? sprintf( esc_html__( 'with %s being handled by the team.', 'ondaweb-security' ), '<strong style="color:' . self::C_TEXT . ';">' . esc_html( sprintf( _n( '%d item', '%d items', $pend, 'ondaweb-security' ), $pend ) ) . '</strong>' )
				: '<strong style="color:' . self::C_TEXT . ';">' . esc_html__( 'with no critical or warning items.', 'ondaweb-security' ) . '</strong>' );
			/* translators: %s: date */
			$sum[] = esc_html( sprintf( __( 'The tests, run on %s directly against the published site, confirmed the protections described in this report.', 'ondaweb-security' ), $sdate ) );
			if ( $applied ) {
				/* translators: 1: number of improvements, 2: month and year */
				$sum[] = esc_html( sprintf( _n( '%1$d security improvement was applied in %2$s.', '%1$d security improvements were applied in %2$s.', $applied, 'ondaweb-security' ), $applied, self::month_label( $ym ) ) );
			}
		}
		/* translators: 1: month and year, 2: number of updates */
		$sum[] = esc_html( sprintf( _n( 'In %1$s, %2$d update was recorded.', 'In %1$s, %2$d updates were recorded.', $updated_count, 'ondaweb-security' ), self::month_label( $ym ), $updated_count ) );
		$o    .= self::p( implode( ' ', $sum ) );

		if ( $sc ) {
			$o .= self::stat_cards(
				array(
					array( (int) $sc['score'] . '/100', sprintf( /* translators: %s: grade */ __( 'Grade %s in the automatic check', 'ondaweb-security' ), $sc['grade'] ), self::C_ORANGE ),
					array( (string) (int) $sc['total'], __( 'Automatic tests run', 'ondaweb-security' ), self::C_TEAL ),
					array( (string) $pend, __( 'Critical or warning items', 'ondaweb-security' ), self::C_RED ),
					array( (string) $n_ver, __( 'Areas with measures implemented and verified', 'ondaweb-security' ), self::C_NAVY ),
				)
			);
		}

		// Vulnerabilities (only when found).
		$vulns = array();
		foreach ( (array) OWSU_Vulns::get()['items'] as $it ) {
			$vulns[ $it['key'] ] = $it['name'];
		}
		if ( OWSU_Vulns::key() && $vulns ) {
			$tag = '<span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#fff;background:' . self::C_RED . ';">' . esc_html__( 'Security fix', 'ondaweb-security' ) . '</span>';
			$o  .= '<div style="margin:16px 0 0;padding:14px 18px;background:#fdecee;border-left:3px solid ' . self::C_RED . ';border-radius:8px;font-size:12.5px;line-height:1.6;">' . sprintf(
				/* translators: 1: number of components (in bold), 2: "Security fix" tag */
				_n( 'Known security flaws were found in %1$s installed component. The updates that fix them are marked with %2$s in the tables below and should be prioritized.', 'Known security flaws were found in %1$s installed components. The updates that fix them are marked with %2$s in the tables below and should be prioritized.', count( $vulns ), 'ondaweb-security' ),
				'<strong>' . count( $vulns ) . '</strong>',
				$tag
			) . '</div>';
		}

		if ( $areas ) {
			// How the check was done.
			$o  .= self::h2( __( 'How the check was done', 'ondaweb-security' ) );
			$how = array(
				array( 'chip', __( 'Automatic check', 'ondaweb-security' ), sprintf( /* translators: 1: number of tests, 2: score, 3: grade */ __( '%1$d configuration tests run on the site\'s WordPress, with a final grade of %2$d/100 (%3$s).', 'ondaweb-security' ), $sc['total'], $sc['score'], $sc['grade'] ) ),
				array( 'cross', __( 'Tests on the published site', 'ondaweb-security' ), sprintf( /* translators: %s: date */ __( 'Requests made on %s directly to the published site, the way a visitor or a bot would access it.', 'ondaweb-security' ), $sdate ) ),
			);
			$o  .= '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:10px 0;margin:0 -10px;table-layout:fixed;"><tr>';
			foreach ( $how as $h ) {
				$o .= '<td style="width:50%;border:1px solid ' . self::C_LINE . ';border-radius:10px;padding:18px;vertical-align:top;"><table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;"><tr>' . ( 'email' === $mode ? '' : '<td style="vertical-align:top;padding-right:14px;">' . self::icon( $h[0], $mode ) . '</td>' ) . '<td style="vertical-align:top;"><div style="font-size:13px;font-weight:700;color:' . self::C_TEXT . ';margin-bottom:4px;">' . esc_html( $h[1] ) . '</div><div style="font-size:11.5px;line-height:1.55;color:' . self::C_BODY . ';">' . esc_html( $h[2] ) . '</div></td></tr></table></td>';
			}
			$o .= '</tr></table>';

			// Areas covered.
			$o .= '<div class="owum-break"></div>';
			$o .= self::h2(
				__( 'Areas covered', 'ondaweb-security' ),
				esc_html(
					sprintf(
						/* translators: 1: number of areas, 2: number of actions */
						__( 'The work was organized in %1$d areas, adding up to %2$d implemented actions. The table below shows what each area covers; the actions, the risk reduced and the verified result are detailed in the next section.', 'ondaweb-security' ),
						count( $areas ),
						$n_act
					)
				)
			);
			$o .= self::areas_grid( $areas, $mode );
			/* translators: %s: date */
			$o .= self::p( esc_html( sprintf( __( 'The scope is limited to the WordPress configuration and the behavior of the published site on %s.', 'ondaweb-security' ), $sdate ) ), 'font-size:11.5px;color:' . self::C_MUTED . ';margin-top:12px;' );

			// Measures.
			$o .= '<div class="owum-break"></div>';
			$o .= self::h2( __( 'Measures implemented and verified', 'ondaweb-security' ) );
			foreach ( $areas as $st ) {
				$o .= self::measure_card( $st, $mode );
			}

			// Overview.
			$o .= self::h2( __( 'Overview of results', 'ondaweb-security' ) );
			$o .= self::table_open( array( array( __( 'Area', 'ondaweb-security' ), 34 ), array( __( 'Verified result', 'ondaweb-security' ) ) ) );
			foreach ( $areas as $st ) {
				$o .= '<tr>' . self::td( '<strong>' . esc_html( $st['area']['title'] ) . '</strong>' ) . self::td( '<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;"><tr><td style="vertical-align:top;padding-right:8px;">' . self::tick( $st['ok'] ) . '</td><td style="font-size:12.5px;line-height:1.5;">' . self::rich( $st['proof'] ) . '</td></tr></table>' ) . '</tr>';
			}
			$o .= '</table>';
		}

		// Updates.
		$o .= '<div class="owum-break"></div>';
		$o .= self::h2( __( 'Updates', 'ondaweb-security' ) );
		$o .= self::stat_cards(
			array(
				array( esc_html( $core['installed'] ), $core['available'] ? sprintf( /* translators: %s: version number */ __( 'WordPress — %s available', 'ondaweb-security' ), $core['available'] ) : __( 'WordPress — latest version', 'ondaweb-security' ), self::C_NAVY ),
				array( (string) $updated_count, __( 'Updates recorded in the period', 'ondaweb-security' ), self::C_TEAL ),
				array( (string) ( count( $free ) + ( $core['available'] ? 1 : 0 ) ), sprintf( /* translators: %s: brand (Ondaweb) */ __( 'Pending, to be applied by %s', 'ondaweb-security' ), $brand ), self::C_ORANGE ),
				array( (string) count( $paid ), __( 'Pending, need the client\'s approval', 'ondaweb-security' ), self::C_RED ),
			)
		);

		$t_item  = __( 'Item', 'ondaweb-security' );
		$t_inst  = __( 'Installed', 'ondaweb-security' );
		$t_avail = __( 'Available', 'ondaweb-security' );
		$t_usage = __( 'Usage', 'ondaweb-security' );

		// Paid updates.
		$o .= '<div style="font-size:14.5px;font-weight:700;margin:26px 0 4px;">' . esc_html__( 'Updates that need the client\'s approval', 'ondaweb-security' ) . '</div>';
		$o .= self::p( esc_html__( 'Paid plugins/themes with a new version. Updating depends on an active license or a purchase/renewal.', 'ondaweb-security' ), 'font-size:12px;' );
		$o .= self::table_open( array( array( $t_item, 30 ), array( $t_inst, 12 ), array( $t_avail, 14 ), array( $t_usage, 16 ), array( __( 'Notes / license', 'ondaweb-security' ) ) ) );
		if ( ! $paid ) {
			$o .= self::empty_row( 5, __( 'No paid updates pending.', 'ondaweb-security' ) );
		}
		foreach ( $paid as $r ) {
			$avail = esc_html( $r['available'] ) . ( 'manual' === $r['available_src'] ? self::small( __( 'entered manually', 'ondaweb-security' ) ) : '' );
			$o    .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . self::small( OWUM_Logger::type_label( $r['type'] ) ) ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_PAID . ';">' . $avail . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( esc_html( $r['obs'] ) ) . '</tr>';
		}
		$o .= '</table>';

		// Updates applied by Ondaweb.
		/* translators: %s: brand (Ondaweb) */
		$o .= '<div style="font-size:14.5px;font-weight:700;margin:26px 0 4px;">' . esc_html( sprintf( __( 'Available updates – applied by %s', 'ondaweb-security' ), $brand ) ) . '</div>';
		/* translators: %s: brand (Ondaweb) */
		$o .= self::p( esc_html( sprintf( __( 'Free plugins and plugins licensed by %s. No action needed from the client.', 'ondaweb-security' ), $brand ) ), 'font-size:12px;' );
		$o .= self::table_open( array( array( $t_item, 40 ), array( $t_inst, 18 ), array( $t_avail, 18 ), array( $t_usage ) ) );
		if ( $core['available'] ) {
			$o .= '<tr>' . self::td( '<strong>WordPress (core)</strong>' . self::sec_tag( 'core' ) ) . self::td( esc_html( $core['installed'] ) ) . self::td( '<strong style="color:' . self::C_ORANGE . ';">' . esc_html( $core['available'] ) . '</strong>' ) . self::td( is_multisite() ? esc_html__( 'Network (all sites)', 'ondaweb-security' ) : esc_html__( 'Site', 'ondaweb-security' ) ) . '</tr>';
		}
		if ( ! $free && ! $core['available'] ) {
			$o .= self::empty_row( 4, __( 'Everything is up to date.', 'ondaweb-security' ) );
		}
		foreach ( $free as $r ) {
			$o .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . self::small( OWUM_Logger::type_label( $r['type'] ) . ' · ' . OWUM_Collector::tipo_label( $r['tipo'] ) ) ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_ORANGE . ';">' . esc_html( $r['available'] ) . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . '</tr>';
		}
		$o .= '</table>';

		// History of the month.
		/* translators: %s: month and year */
		$o .= '<div style="font-size:14.5px;font-weight:700;margin:26px 0 10px;">' . esc_html( sprintf( __( 'Updates made in %s', 'ondaweb-security' ), self::month_label( $ym ) ) ) . '</div>';
		$o .= self::table_open( array( array( __( 'Date', 'ondaweb-security' ), 18 ), array( $t_item, 32 ), array( __( 'Action', 'ondaweb-security' ), 14 ), array( __( 'Version', 'ondaweb-security' ), 18 ), array( __( 'Source', 'ondaweb-security' ) ) ) );
		if ( ! $log ) {
			$o .= self::empty_row( 5, __( 'No changes recorded in this period.', 'ondaweb-security' ) );
		}
		foreach ( $log as $r ) {
			$ver = $r['old_version'] && $r['new_version'] ? esc_html( $r['old_version'] ) . ' → <strong>' . esc_html( $r['new_version'] ) . '</strong>' : esc_html( $r['new_version'] ? $r['new_version'] : $r['old_version'] );
			$o  .= '<tr>' . self::td( esc_html( owum_date( $r['logged_at'], true ) ), 'white-space:nowrap;' ) . self::td( '<strong>' . esc_html( OWUM_Logger::item_label( $r ) ) . '</strong>' . self::small( OWUM_Logger::type_label( $r['item_type'] ) ) ) . self::td( esc_html( OWUM_Logger::action_label( $r['action'] ) ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( OWUM_Logger::source_label( $r['source'] ) ) . ( $r['user_login'] && '—' !== $r['user_login'] ? self::small( $r['user_login'] ) : '' ) ) . '</tr>';
		}
		$o .= '</table>';

		// Inventory.
		foreach ( array( 'plugins' => __( 'Plugin inventory', 'ondaweb-security' ), 'themes' => __( 'Theme inventory', 'ondaweb-security' ) ) as $k => $title ) {
			$c  = count( $inv[ $k ] );
			$o .= '<div style="font-size:14.5px;font-weight:700;margin:26px 0 4px;">' . esc_html( $title ) . '</div>';
			$o .= self::p(
				esc_html(
					is_multisite()
						/* translators: %d: number of items */
						? sprintf( _n( '%d installed in the network.', '%d installed in the network.', $c, 'ondaweb-security' ), $c )
						/* translators: %d: number of items */
						: sprintf( _n( '%d installed.', '%d installed.', $c, 'ondaweb-security' ), $c )
				),
				'font-size:12px;'
			);
			$o .= self::table_open( array( array( __( 'Name', 'ondaweb-security' ), 34 ), array( __( 'Version', 'ondaweb-security' ), 18 ), array( __( 'Type', 'ondaweb-security' ), 16 ), array( $t_usage, 16 ), array( __( 'Status', 'ondaweb-security' ) ) ) );
			foreach ( $inv[ $k ] as $r ) {
				$ver = esc_html( $r['installed'] ) . ( $r['available'] ? ' <span style="color:' . self::C_MUTED . ';">→ ' . esc_html( $r['available'] ) . '</span>' : '' );
				$o  .= '<tr>' . self::td( esc_html( $r['name'] ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( OWUM_Collector::tipo_label( $r['tipo'] ) ) ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( self::badge( $r['status'] ) ) . '</tr>';
			}
			$o .= '</table>';
		}

		// Reference dates.
		$dates = array();
		if ( $scan ) {
			$res = $scan['results'];
			if ( ! empty( $res['ssl_expiry']['data']['until'] ) ) {
				$d       = $res['ssl_expiry']['data'];
				$dates[] = array(
					owum_date_ts( $d['until'] ),
					__( 'HTTPS certificate', 'ondaweb-security' ),
					! empty( $d['issuer'] )
						/* translators: %s: certificate issuer */
						? sprintf( __( 'Validity of the %s certificate in use on the site.', 'ondaweb-security' ), $d['issuer'] )
						: __( 'Validity of the certificate in use on the site.', 'ondaweb-security' ),
				);
			}
			if ( ! empty( $res['php_version']['data']['until'] ) ) {
				$d       = $res['php_version']['data'];
				$dates[] = array( owum_date_ts( $d['until'] ), 'PHP ' . $d['php'], __( 'End of security support for the version in use on the server.', 'ondaweb-security' ) );
			}
		}
		if ( $dates ) {
			$o .= self::h2( __( 'Reference dates', 'ondaweb-security' ) );
			$o .= '<table role="presentation" class="owum-avoid" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:10px 0;margin:0 -10px;table-layout:fixed;"><tr>';
			foreach ( $dates as $d ) {
				$o .= '<td style="width:50%;border:1px solid ' . self::C_LINE . ';border-radius:10px;padding:14px;vertical-align:middle;"><table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:collapse;"><tr>';
				$o .= '<td style="vertical-align:middle;padding-right:14px;"><div style="background:#000;border-radius:7px;padding:7px 12px;text-align:center;white-space:nowrap;"><div style="font-size:8px;font-weight:700;letter-spacing:.16em;color:' . self::C_ORANGE . ';">' . esc_html( self::upper( __( 'until', 'ondaweb-security' ) ) ) . '</div><div style="font-size:15px;font-weight:700;color:#fff;margin-top:2px;">' . esc_html( $d[0] ) . '</div></div></td>';
				$o .= '<td style="vertical-align:middle;"><div style="font-size:13px;font-weight:700;">' . esc_html( $d[1] ) . '</div><div style="font-size:11.5px;line-height:1.5;color:' . self::C_MUTED . ';margin-top:3px;">' . esc_html( $d[2] ) . '</div></td>';
				$o .= '</tr></table></td>';
			}
			if ( 1 === count( $dates ) ) {
				$o .= '<td style="width:50%;"></td>';
			}
			$o .= '</tr></table>';
		}

		// Note.
		$o .= '<div class="owum-avoid" style="margin:26px 0 0;padding:16px 20px;background:' . self::C_SOFT . ';border-left:3px solid ' . self::C_ORANGE . ';border-radius:8px;font-size:12px;line-height:1.6;color:' . self::C_BODY . ';"><strong style="color:' . self::C_TEXT . ';">' . esc_html__( 'Note:', 'ondaweb-security' ) . '</strong> ';
		$o .= $scan
			/* translators: %s: date */
			? esc_html( sprintf( __( 'this report describes the state verified on %s. The tests are configuration tests run against the published site; they do not replace a full penetration test.', 'ondaweb-security' ), $sdate ) )
			/* translators: %s: date */
			: esc_html( sprintf( __( 'this report describes the state on %s.', 'ondaweb-security' ), $today ) );
		$o .= '</div>';

		/* translators: 1: report name, 2: site address, 3: date, 4: brand */
		$o .= '<p class="owum-screen" style="margin:28px 0 0;padding-top:12px;border-top:1px solid ' . self::C_LINE . ';font-size:10.5px;color:' . self::C_MUTED . ';">' . esc_html( sprintf( __( '%1$s · %2$s · %3$s · %4$s', 'ondaweb-security' ), __( 'Updates and security report', 'ondaweb-security' ), $host, $today, $brand ) ) . '</p>';
		$o .= '</div>';
		return $o;
	}

	/**
	 * Print rules for the PDF: A4, Ondaweb header and footer with page numbers on every page.
	 * Chrome/Edge 131+ draw them with @page margin boxes; other browsers simply print without them.
	 */
	public static function print_css() {
		$s      = owum_settings();
		$host   = self::site_host();
		$client = $s['client_name'] ? $s['client_name'] : $host;
		$logo   = owum_logo( 'ondaweb' );
		$css    = function ( $t ) {
			return '"' . str_replace( array( '\\', '"', "\n" ), array( '\\\\', '\\"', ' ' ), $t ) . '"';
		};
		/* translators: 1: current page number, 2: total pages — keep the %1$s and %2$s */
		$page = explode( '%%', str_replace( array( '%1$s', '%2$s' ), array( '%%P%%', '%%T%%' ), __( 'Page %1$s of %2$s', 'ondaweb-security' ) ) );
		$pg   = '';
		foreach ( $page as $part ) {
			if ( 'P' === $part ) {
				$pg .= ' counter(page)';
			} elseif ( 'T' === $part ) {
				$pg .= ' counter(pages)';
			} elseif ( '' !== $part ) {
				$pg .= ' ' . $css( $part );
			}
		}
		$foot = __( 'Updates and security report', 'ondaweb-security' ) . ' · ' . $host . ' · ' . owum_date();
		$head = self::upper( __( 'WordPress updates and security', 'ondaweb-security' ) ) . '  ·  ' . self::upper( $client );
		$font = "font-family:'Segoe UI',Selawik,'Helvetica Neue',Arial,sans-serif;";
		return '@media print{'
			. '@page{size:A4;margin:24mm 15mm 18mm;'
			. '@top-left{content:image-set(url(' . $css( $logo['url'] ) . ') 5x);vertical-align:bottom;padding-bottom:6mm;}'
			. '@top-right{content:' . $css( $head ) . ';' . $font . 'font-size:7pt;font-weight:700;letter-spacing:.16em;color:#5f666a;vertical-align:bottom;padding-bottom:8.6mm;}'
			. '@bottom-left{content:image-set(url(' . $css( $logo['url'] ) . ') 10x) "\\00a0\\00a0\\00a0" ' . $css( $foot ) . ';' . $font . 'font-size:6.5pt;color:#5f666a;vertical-align:top;padding-top:5mm;border-top:.5pt solid #e3e5e7;}'
			. '@bottom-right{content:' . trim( $pg ) . ';' . $font . 'font-size:6.5pt;color:#5f666a;vertical-align:top;padding-top:5mm;border-top:.5pt solid #e3e5e7;}'
			. '}'
			. '.owum-screen{display:none!important;}'
			. '.owum-avoid,.owum-avoid tr,.owum-report tr{break-inside:avoid;page-break-inside:avoid;}'
			. '.owum-h2{break-after:avoid;page-break-after:avoid;}'
			. '.owum-break{break-before:page;page-break-before:always;}'
			. '*{-webkit-print-color-adjust:exact;print-color-adjust:exact;}'
			. '}';
	}
}
