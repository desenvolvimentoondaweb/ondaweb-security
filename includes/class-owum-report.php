<?php
defined( 'ABSPATH' ) || exit;

/**
 * HTML report with inline styles (works in email clients and when printed / saved as PDF).
 */
class OWUM_Report {

	const C_TEXT   = '#1f2937';
	const C_MUTED  = '#6b7280';
	const C_LINE   = '#e5e7eb';
	const C_HEAD   = '#0b3b5c';
	const C_OK     = '#166534';
	const C_OK_BG  = '#dcfce7';
	const C_FREE   = '#1e40af';
	const C_FREEBG = '#dbeafe';
	const C_PAID   = '#9a3412';
	const C_PAIDBG = '#ffedd5';

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

	/** Texts that mention the agency / support provider (or a neutral wording when none is set). */
	private static function by_support() {
		$b = owum_brand();
		/* translators: %s: agency / support provider name */
		return $b ? sprintf( __( 'applied by %s', 'ondaweb-security' ), $b ) : __( 'applied by the support team', 'ondaweb-security' );
	}

	public static function badge( $status ) {
		$map   = array(
			'ok'   => array( self::C_OK, self::C_OK_BG ),
			'free' => array( self::C_FREE, self::C_FREEBG ),
			'paid' => array( self::C_PAID, self::C_PAIDBG ),
		);
		$c     = isset( $map[ $status ] ) ? $map[ $status ] : $map['ok'];
		$label = OWUM_Collector::status_label( $status );
		return '<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap;color:' . $c[0] . ';background:' . $c[1] . ';">' . esc_html( $label ) . '</span>';
	}

	private static function th( $label, $align = 'left' ) {
		return '<th style="text-align:' . $align . ';padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:' . self::C_MUTED . ';border-bottom:2px solid ' . self::C_LINE . ';">' . esc_html( $label ) . '</th>';
	}

	private static function td( $html, $extra = '' ) {
		return '<td style="padding:8px 10px;font-size:13px;color:' . self::C_TEXT . ';border-bottom:1px solid ' . self::C_LINE . ';vertical-align:top;' . $extra . '">' . $html . '</td>';
	}

	private static function h2( $text, $sub = '' ) {
		$out = '<h2 style="font-size:16px;color:' . self::C_HEAD . ';margin:28px 0 4px;">' . esc_html( $text ) . '</h2>';
		if ( $sub ) {
			$out .= '<p style="margin:0 0 10px;font-size:12px;color:' . self::C_MUTED . ';">' . esc_html( $sub ) . '</p>';
		}
		return $out;
	}

	private static function table_open() {
		return '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:6px 0 4px;">';
	}

	private static function empty_row( $cols, $text ) {
		return '<tr><td colspan="' . (int) $cols . '" style="padding:12px 10px;font-size:13px;color:' . self::C_MUTED . ';border-bottom:1px solid ' . self::C_LINE . ';">' . esc_html( $text ) . '</td></tr>';
	}

	/** "Security fix" tag for items with a known vulnerability. */
	private static function sec_tag( $key ) {
		if ( ! OWSU_Vulns::for_key( $key ) ) {
			return '';
		}
		return ' <span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#991b1b;background:#fee2e2;white-space:nowrap;">' . esc_html__( 'Security fix', 'ondaweb-security' ) . '</span>';
	}

	/** Security summary for the client — no technical details. */
	private static function security_section( $ym, $sec_log ) {
		$scan = OWSU_Security::last_scan();
		if ( ! $scan ) {
			return '';
		}
		$sc    = $scan['score'];
		$pend  = $sc['count']['crit'] + $sc['count']['warn'];
		$vulns = array();
		foreach ( (array) OWSU_Vulns::get()['items'] as $it ) {
			$vulns[ $it['key'] ] = $it['name'];
		}
		$color = OWSU_Security::grade_color( $sc['grade'] );

		$brand = owum_brand();
		$o     = self::h2(
			__( 'Security', 'ondaweb-security' ),
			/* translators: %s: date of the last security check */
			sprintf( __( 'Status as of the check on %s.', 'ondaweb-security' ), owum_date( $scan['time'] ) ) . ' ' .
			/* translators: %s: agency / support provider name */
			( $brand ? sprintf( __( 'Technical details are kept by the %s team.', 'ondaweb-security' ), $brand ) : __( 'Technical details are kept by the support team.', 'ondaweb-security' ) )
		);
		$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:8px 0;margin:0 -8px;"><tr>';
		$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;text-align:center;vertical-align:middle;"><div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">' . esc_html__( 'Security grade', 'ondaweb-security' ) . '</div><div style="font-size:34px;font-weight:700;color:' . $color . ';line-height:1.2;">' . esc_html( $sc['grade'] ) . '</div><div style="font-size:12px;color:' . self::C_MUTED . ';">' . esc_html( sprintf( /* translators: %d: score from 0 to 100 */ __( '%d out of 100', 'ondaweb-security' ), (int) $sc['score'] ) ) . '</div></td>';
		$cards = array(
			array( __( 'Points checked', 'ondaweb-security' ), (string) $sc['total'], __( 'in this analysis', 'ondaweb-security' ), self::C_HEAD ),
			array( __( 'Compliant', 'ondaweb-security' ), (string) $sc['count']['ok'], __( 'no action needed', 'ondaweb-security' ), self::C_OK ),
			array( __( 'Being handled', 'ondaweb-security' ), (string) $pend, __( 'followed up by the team', 'ondaweb-security' ), $pend ? self::C_PAID : self::C_OK ),
		);
		foreach ( $cards as $c ) {
			$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;vertical-align:top;"><div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">' . esc_html( $c[0] ) . '</div><div style="font-size:24px;font-weight:700;color:' . $c[3] . ';margin:4px 0;">' . esc_html( $c[1] ) . '</div><div style="font-size:12px;color:' . self::C_MUTED . ';">' . esc_html( $c[2] ) . '</div></td>';
		}
		$o .= '</tr></table>';

		if ( OWSU_Vulns::key() ) {
			if ( $vulns ) {
				$tag = '<span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#991b1b;background:#fee2e2;">' . esc_html__( 'Security fix', 'ondaweb-security' ) . '</span>';
				$o  .= '<p style="font-size:13px;margin:12px 0 0;">' . sprintf(
					/* translators: 1: number of components (in bold), 2: "Security fix" tag */
					_n( 'Known security flaws were found in %1$s installed component. The updates that fix them are marked with %2$s in the tables below and should be prioritized.', 'Known security flaws were found in %1$s installed components. The updates that fix them are marked with %2$s in the tables below and should be prioritized.', count( $vulns ), 'ondaweb-security' ),
					'<strong>' . count( $vulns ) . '</strong>',
					$tag
				) . '</p>';
			} else {
				$o .= '<p style="font-size:13px;margin:12px 0 0;color:' . self::C_OK . ';">' . esc_html__( 'No known security flaws in the installed versions.', 'ondaweb-security' ) . '</p>';
			}
		}

		// Only fixes still in place (the item's last action this month was "apply" and it is still on).
		$latest = array();
		foreach ( $sec_log as $r ) { // already newest first
			if ( ! isset( $latest[ $r['item_key'] ] ) ) {
				$latest[ $r['item_key'] ] = $r;
			}
		}
		$applied = array_filter(
			$latest,
			function ( $r ) {
				return 'correcao' === $r['action'] && OWSU_Security::is_on( substr( $r['item_key'], 4 ) );
			}
		);
		if ( $applied ) {
			/* translators: %s: month and year */
			$o .= '<p style="font-size:13px;margin:14px 0 4px;"><strong>' . esc_html( sprintf( __( 'Security improvements applied in %s:', 'ondaweb-security' ), self::month_label( $ym ) ) ) . '</strong></p><ul style="margin:0 0 0 18px;padding:0;font-size:13px;">';
			foreach ( array_reverse( $applied ) as $r ) {
				$o .= '<li style="margin:2px 0;">' . esc_html( OWUM_Logger::item_label( $r ) ) . ' <span style="color:' . self::C_MUTED . ';font-size:11px;">(' . esc_html( owum_date( $r['logged_at'] ) ) . ')</span></li>';
			}
			$o .= '</ul>';
		}
		return $o;
	}

	/**
	 * Builds the report.
	 *
	 * @param string $ym   History month (Y-m).
	 * @param string $mode 'print' (logos by URL) or 'email' (logos embedded by CID).
	 */
	public static function html( $ym, $mode = 'print' ) {
		$settings        = owum_settings();
		$inv             = OWUM_Collector::inventory();
		list( $s, $e )   = self::month_range( $ym );
		$log             = OWUM_Logger::get( $s, $e );
		$log             = array_values(
			array_filter(
				$log,
				function ( $r ) {
					return 'inicio' !== $r['action'];
				}
			)
		);
		$sec_log         = array_values( array_filter( $log, function ( $r ) { return 'security' === $r['item_type']; } ) );
		$log             = array_values( array_filter( $log, function ( $r ) { return 'security' !== $r['item_type']; } ) );
		$items           = array_merge( $inv['plugins'], $inv['themes'] );
		$paid            = array_filter( $items, function ( $r ) { return 'paid' === $r['status']; } );
		$free            = array_filter( $items, function ( $r ) { return 'free' === $r['status']; } );
		$core            = $inv['core'];
		$updated_count   = count( array_filter( $log, function ( $r ) { return 'atualizado' === $r['action']; } ) );

		$o  = '<div style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Arial,sans-serif;color:' . self::C_TEXT . ';max-width:900px;margin:0 auto;">';

		// Logos.
		$brand = owum_brand();
		$logo_html = function ( $which, $align ) use ( $mode ) {
			$l = owum_logo( $which );
			if ( ! $l ) {
				return '';
			}
			$src = ( 'email' === $mode && $l['path'] && file_exists( $l['path'] ) ) ? 'cid:owum-logo-' . $which : $l['url'];
			$alt = 'client' === $which ? __( 'Client logo', 'ondaweb-security' ) : ( owum_brand() ? owum_brand() : __( 'Technical support', 'ondaweb-security' ) );
			return '<img src="' . esc_attr( $src ) . '" alt="' . esc_attr( $alt ) . '" height="56" style="height:56px;max-height:56px;width:auto;max-width:220px;display:inline-block;border:0;">';
		};
		$lc = $logo_html( 'client', 'left' );
		$lo = $logo_html( 'ondaweb', 'right' );
		if ( $lc || $lo ) {
			$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:14px;"><tr>';
			$o .= '<td style="text-align:left;vertical-align:middle;">' . $lc . '</td>';
			$o .= '<td style="text-align:right;vertical-align:middle;">' . ( $lo ? '<div style="font-size:10px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;">' . esc_html__( 'Technical support', 'ondaweb-security' ) . '</div>' . $lo : '' ) . '</td>';
			$o .= '</tr></table>';
		}

		// Header.
		$o .= '<div style="border-bottom:3px solid ' . self::C_HEAD . ';padding-bottom:12px;margin-bottom:16px;">';
		$o .= '<div style="font-size:12px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.06em;">' . esc_html__( 'Updates and security report', 'ondaweb-security' ) . '</div>';
		$o .= '<h1 style="font-size:22px;margin:4px 0;color:' . self::C_HEAD . ';">' . esc_html( $settings['client_name'] ) . '</h1>';
		$n  = count( $inv['sites'] );
		$o .= '<div style="font-size:13px;color:' . self::C_MUTED . ';">'
			/* translators: %s: month and year (in bold) */
			. sprintf( esc_html__( 'Period: %s', 'ondaweb-security' ), '<strong style="color:' . self::C_TEXT . ';">' . esc_html( self::month_label( $ym ) ) . '</strong>' )
			/* translators: %s: date and time */
			. ' · ' . esc_html( sprintf( __( 'Versions as of %s', 'ondaweb-security' ), owum_date( '', true ) ) )
			/* translators: %d: number of sites in the network */
			. ( is_multisite() ? ' · ' . esc_html( sprintf( _n( '%d site in the network', '%d sites in the network', $n, 'ondaweb-security' ), $n ) ) : '' ) . '</div>';
		$o .= '</div>';

		// Summary.
		$cards = array(
			/* translators: %s: version number */
			array( 'WordPress', esc_html( $core['installed'] ), $core['available'] ? esc_html( sprintf( __( 'Available: %s', 'ondaweb-security' ), $core['available'] ) ) : esc_html__( 'Latest version', 'ondaweb-security' ), $core['available'] ? self::C_FREE : self::C_OK ),
			array( __( 'Updates this period', 'ondaweb-security' ), (string) $updated_count, esc_html__( 'recorded in the history', 'ondaweb-security' ), self::C_HEAD ),
			array( __( 'Pending (team)', 'ondaweb-security' ), (string) count( $free ), esc_html( self::by_support() ), self::C_FREE ),
			array( __( 'Pending (paid)', 'ondaweb-security' ), (string) count( $paid ), esc_html__( 'need approval', 'ondaweb-security' ), self::C_PAID ),
		);
		$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:8px 0;margin:0 -8px;"><tr>';
		foreach ( $cards as $c ) {
			$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;vertical-align:top;">';
			$o .= '<div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">' . esc_html( $c[0] ) . '</div>';
			$o .= '<div style="font-size:24px;font-weight:700;color:' . $c[3] . ';margin:4px 0;">' . $c[1] . '</div>';
			$o .= '<div style="font-size:12px;color:' . self::C_MUTED . ';">' . $c[2] . '</div>';
			$o .= '</td>';
		}
		$o .= '</tr></table>';

		$o .= self::security_section( $ym, $sec_log );

		$t_item  = __( 'Item', 'ondaweb-security' );
		$t_inst  = __( 'Installed', 'ondaweb-security' );
		$t_avail = __( 'Available', 'ondaweb-security' );
		$t_usage = __( 'Usage', 'ondaweb-security' );

		// Paid updates.
		$o .= self::h2( __( 'Updates that need the client\'s approval', 'ondaweb-security' ), __( 'Paid plugins/themes with a new version. Updating depends on an active license or a purchase/renewal.', 'ondaweb-security' ) );
		$o .= self::table_open() . '<tr>' . self::th( $t_item ) . self::th( $t_inst ) . self::th( $t_avail ) . self::th( $t_usage ) . self::th( __( 'Notes / license', 'ondaweb-security' ) ) . '</tr>';
		if ( ! $paid ) {
			$o .= self::empty_row( 5, __( 'No paid updates pending.', 'ondaweb-security' ) );
		}
		foreach ( $paid as $r ) {
			$avail = esc_html( $r['available'] ) . ( 'manual' === $r['available_src'] ? ' <span style="color:' . self::C_MUTED . ';font-size:11px;">(' . esc_html__( 'entered manually', 'ondaweb-security' ) . ')</span>' : '' );
			$o    .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['type'] ) ) . '</span>' ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_PAID . ';">' . $avail . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( esc_html( $r['obs'] ) ) . '</tr>';
		}
		$o .= '</table>';

		// Updates applied by the team.
		$o .= self::h2(
			/* translators: %s: agency / support provider name */
			$brand ? sprintf( __( 'Available updates – applied by %s', 'ondaweb-security' ), $brand ) : __( 'Available updates – applied by the support team', 'ondaweb-security' ),
			/* translators: %s: agency / support provider name */
			$brand ? sprintf( __( 'Free plugins and plugins licensed by %s. No action needed from the client.', 'ondaweb-security' ), $brand ) : __( 'Free plugins and plugins licensed by the support team. No action needed from the client.', 'ondaweb-security' )
		);
		$o .= self::table_open() . '<tr>' . self::th( $t_item ) . self::th( $t_inst ) . self::th( $t_avail ) . self::th( $t_usage ) . '</tr>';
		if ( $core['available'] ) {
			$o .= '<tr>' . self::td( '<strong>WordPress (core)</strong>' . self::sec_tag( 'core' ) ) . self::td( esc_html( $core['installed'] ) ) . self::td( '<strong style="color:' . self::C_FREE . ';">' . esc_html( $core['available'] ) . '</strong>' ) . self::td( is_multisite() ? esc_html__( 'Network (all sites)', 'ondaweb-security' ) : esc_html__( 'Site', 'ondaweb-security' ) ) . '</tr>';
		}
		if ( ! $free && ! $core['available'] ) {
			$o .= self::empty_row( 4, __( 'Everything is up to date.', 'ondaweb-security' ) );
		}
		foreach ( $free as $r ) {
			$o .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['type'] ) . ' · ' . OWUM_Collector::tipo_label( $r['tipo'] ) ) . '</span>' ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_FREE . ';">' . esc_html( $r['available'] ) . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . '</tr>';
		}
		$o .= '</table>';

		// History of the month.
		/* translators: %s: month and year */
		$o .= self::h2( sprintf( __( 'Updates made in %s', 'ondaweb-security' ), self::month_label( $ym ) ) );
		$o .= self::table_open() . '<tr>' . self::th( __( 'Date', 'ondaweb-security' ) ) . self::th( $t_item ) . self::th( __( 'Action', 'ondaweb-security' ) ) . self::th( __( 'Version', 'ondaweb-security' ) ) . self::th( __( 'Source', 'ondaweb-security' ) ) . '</tr>';
		if ( ! $log ) {
			$o .= self::empty_row( 5, __( 'No changes recorded in this period.', 'ondaweb-security' ) );
		}
		foreach ( $log as $r ) {
			$ver = $r['old_version'] && $r['new_version'] ? esc_html( $r['old_version'] ) . ' → <strong>' . esc_html( $r['new_version'] ) . '</strong>' : esc_html( $r['new_version'] ? $r['new_version'] : $r['old_version'] );
			$o  .= '<tr>' . self::td( esc_html( owum_date( $r['logged_at'], true ) ), 'white-space:nowrap;' ) . self::td( '<strong>' . esc_html( OWUM_Logger::item_label( $r ) ) . '</strong><br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['item_type'] ) ) . '</span>' ) . self::td( esc_html( OWUM_Logger::action_label( $r['action'] ) ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( OWUM_Logger::source_label( $r['source'] ) ) . ( $r['user_login'] && '—' !== $r['user_login'] ? '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( $r['user_login'] ) . '</span>' : '' ) ) . '</tr>';
		}
		$o .= '</table>';

		// Inventory.
		foreach ( array( 'plugins' => __( 'Plugin inventory', 'ondaweb-security' ), 'themes' => __( 'Theme inventory', 'ondaweb-security' ) ) as $k => $title ) {
			$c  = count( $inv[ $k ] );
			$o .= self::h2(
				$title,
				is_multisite()
					/* translators: %d: number of items */
					? sprintf( _n( '%d installed in the network.', '%d installed in the network.', $c, 'ondaweb-security' ), $c )
					/* translators: %d: number of items */
					: sprintf( _n( '%d installed.', '%d installed.', $c, 'ondaweb-security' ), $c )
			);
			$o .= self::table_open() . '<tr>' . self::th( __( 'Name', 'ondaweb-security' ) ) . self::th( __( 'Version', 'ondaweb-security' ) ) . self::th( __( 'Type', 'ondaweb-security' ) ) . self::th( $t_usage ) . self::th( __( 'Status', 'ondaweb-security' ) ) . '</tr>';
			foreach ( $inv[ $k ] as $r ) {
				$ver = esc_html( $r['installed'] ) . ( $r['available'] ? ' <span style="color:' . self::C_MUTED . ';">→ ' . esc_html( $r['available'] ) . '</span>' : '' );
				$o  .= '<tr>' . self::td( esc_html( $r['name'] ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( OWUM_Collector::tipo_label( $r['tipo'] ) ) ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( self::badge( $r['status'] ) ) . '</tr>';
			}
			$o .= '</table>';
		}

		$o .= '<p style="margin-top:28px;font-size:11px;color:' . self::C_MUTED . ';border-top:1px solid ' . self::C_LINE . ';padding-top:10px;">' . esc_html( sprintf( /* translators: 1: plugin name, 2: site address */ __( 'Report generated automatically by %1$s · %2$s', 'ondaweb-security' ), OWUM_PRODUCT, network_home_url( '/' ) ) ) . '</p>';
		$o .= '</div>';

		return $o;
	}
}
