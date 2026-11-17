<?php
defined( 'ABSPATH' ) || exit;

/**
 * "Security" page and internal technical report.
 */
class OWSU_Admin {

	public static function init() {
		foreach ( array( 'owsu_scan', 'owsu_vuln_update', 'owsu_apply', 'owsu_undo', 'owsu_tech_report' ) as $a ) {
			add_action( 'admin_post_' . $a, array( __CLASS__, $a ) );
		}
		add_action( 'wp_ajax_owsu_scan_step', array( __CLASS__, 'ajax_step' ) );
	}

	private static function url( $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => 'owum-security' ), $args ), $base );
	}

	private static function guard( $action ) {
		if ( ! current_user_can( owum_cap() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'ondaweb-security' ), 403 );
		}
		check_admin_referer( $action );
	}

	private static function back( $msg, $extra = array(), $is_error = false ) {
		$args = array_merge( array( 'owsu_msg' => rawurlencode( $msg ) ), $extra );
		if ( $is_error ) {
			$args['owsu_err'] = 1;
		}
		wp_safe_redirect( self::url( $args ) );
		exit;
	}

	/* Handlers ------------------------------------------------------------ */

	public static function owsu_scan() {
		self::guard( 'owsu_scan' );
		OWSU_Security::run_all();
		self::back( __( 'Check finished.', 'ondaweb-security' ) );
	}

	public static function owsu_vuln_update() {
		self::guard( 'owsu_vuln_update' );
		$r = OWSU_Vulns::update();
		OWSU_Security::run_all();
		if ( is_wp_error( $r ) ) {
			self::back( __( 'Error:', 'ondaweb-security' ) . ' ' . $r->get_error_message(), array(), true );
		}
		self::back( __( 'Vulnerability database updated and check finished.', 'ondaweb-security' ) );
	}

	public static function owsu_apply() {
		self::guard( 'owsu_apply' );
		$id = isset( $_POST['check'] ) ? sanitize_key( wp_unslash( $_POST['check'] ) ) : ''; // phpcs:ignore
		if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
			self::back( __( 'Unknown check.', 'ondaweb-security' ), array(), true );
		}
		@set_time_limit( 180 ); // phpcs:ignore
		$title = OWSU_Security::definitions()[ $id ]['title'];
		/* translators: %s: name of the security check */
		$what  = sprintf( __( 'Apply fix "%s"', 'ondaweb-security' ), $title );
		try {
			$r = OWSU_Security::apply( $id );
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'error', $what . ': ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ) );
			self::back( __( 'Unexpected error while applying the fix. The details were saved in the Error log.', 'ondaweb-security' ), array( 'focus' => $id ), true );
		}
		if ( is_wp_error( $r ) ) {
			OWUM_ErrorLog::op( $what, $r->get_error_message() );
			self::back( __( 'Error:', 'ondaweb-security' ) . ' ' . $r->get_error_message(), array( 'focus' => $id ), true );
		}
		// The new check runs over HTTP to reflect the fix just applied.
		self::safe_run_one( $id );
		$scan = OWSU_Security::last_scan();
		$res  = isset( $scan['results'][ $id ] ) ? $scan['results'][ $id ] : array( 'status' => 'info' );
		/* translators: %s: name of the security check */
		$msg  = sprintf( __( 'Fix applied: %s.', 'ondaweb-security' ), $title );
		if ( in_array( $res['status'], array( 'crit', 'warn' ), true ) ) {
			$msg .= ' ' . __( 'The check still reports a problem — see the item details.', 'ondaweb-security' );
		}
		self::back( $msg, array( 'focus' => $id ) );
	}

	public static function owsu_undo() {
		self::guard( 'owsu_undo' );
		$id = isset( $_POST['check'] ) ? sanitize_key( wp_unslash( $_POST['check'] ) ) : ''; // phpcs:ignore
		if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
			self::back( __( 'Unknown check.', 'ondaweb-security' ), array(), true );
		}
		@set_time_limit( 180 ); // phpcs:ignore
		try {
			OWSU_Security::undo( $id );
		} catch ( \Throwable $e ) {
			/* translators: %s: name of the security check */
			OWUM_ErrorLog::add( 'error', sprintf( __( 'Undo fix "%s"', 'ondaweb-security' ), OWSU_Security::definitions()[ $id ]['title'] ) . ': ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ) );
			self::back( __( 'Unexpected error while undoing. The details were saved in the Error log.', 'ondaweb-security' ), array( 'focus' => $id ), true );
		}
		self::safe_run_one( $id );
		/* translators: %s: name of the security check */
		self::back( sprintf( __( 'Fix undone: %s.', 'ondaweb-security' ), OWSU_Security::definitions()[ $id ]['title'] ), array( 'focus' => $id ) );
	}

	/* Step-by-step check (progress bar) ------------------------------------- */

	private static function tmp_key() {
		return 'owsu_scan_tmp_' . get_current_user_id();
	}

	public static function ajax_step() {
		if ( ! current_user_can( owum_cap() ) || ! check_ajax_referer( 'owsu_scan_step', 'nonce', false ) ) {
			wp_send_json_error( array( 'msg' => __( 'Session expired. Reload the page.', 'ondaweb-security' ) ), 403 );
		}
		@set_time_limit( 120 ); // phpcs:ignore
		$op = isset( $_POST['op'] ) ? sanitize_key( $_POST['op'] ) : ''; // phpcs:ignore

		if ( 'start' === $op ) {
			$steps = array();
			if ( ! empty( $_POST['vuln'] ) && OWSU_Vulns::key() ) { // phpcs:ignore
				$steps[] = array( 'id' => '__vuln', 'label' => __( 'Downloading the Wordfence vulnerability database', 'ondaweb-security' ), 'group' => __( 'May take up to 1 minute', 'ondaweb-security' ), 'slow' => 1 );
			}
			$groups = OWSU_Security::groups();
			foreach ( OWSU_Security::definitions() as $id => $d ) {
				$steps[] = array( 'id' => $id, 'label' => $d['title'], 'group' => $groups[ $d['group'] ] );
			}
			set_site_transient( self::tmp_key(), array( 'started' => current_time( 'mysql' ), 'results' => array(), 'notes' => array() ), HOUR_IN_SECONDS );
			wp_send_json_success( array( 'steps' => $steps ) );
		}

		$tmp = get_site_transient( self::tmp_key() );
		if ( ! is_array( $tmp ) ) {
			wp_send_json_error( array( 'msg' => __( 'The check expired. Start again.', 'ondaweb-security' ) ), 409 );
		}

		if ( 'step' === $op ) {
			$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : ''; // phpcs:ignore
			if ( '__vuln' === $id ) {
				$r = OWSU_Vulns::update();
				$v = OWSU_Vulns::get();
				if ( is_wp_error( $r ) ) {
					$tmp['notes'][] = __( 'Vulnerability database', 'ondaweb-security' ) . ': ' . $r->get_error_message();
					set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
					wp_send_json_success( array( 'status' => 'warn', 'label' => __( 'Failed', 'ondaweb-security' ), 'detail' => $r->get_error_message() ) );
				}
				/* translators: %s: number of records */
				wp_send_json_success( array( 'status' => 'ok', 'label' => 'OK', 'detail' => sprintf( __( '%s records analyzed', 'ondaweb-security' ), number_format_i18n( (int) $v['records'] ) ) ) );
			}
			if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
				wp_send_json_error( array( 'msg' => __( 'Unknown check.', 'ondaweb-security' ) ), 400 );
			}
			OWSU_Security::reset_http();
			$res                    = OWSU_Security::run_check( $id );
			$tmp['results'][ $id ]  = $res;
			set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
			wp_send_json_success( array( 'status' => $res['status'], 'label' => OWSU_Security::status_label( $res['status'] ), 'detail' => $res['detail'] ) );
		}

		if ( 'fail' === $op ) {
			// The browser got no answer for a step (error 500, timeout, etc.).
			$id   = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : ''; // phpcs:ignore
			$why  = isset( $_POST['why'] ) ? sanitize_text_field( wp_unslash( $_POST['why'] ) ) : ''; // phpcs:ignore
			$defs = OWSU_Security::definitions();
			/* translators: 1: name of the security check, 2: reason */
			OWUM_ErrorLog::add( 'error', sprintf( __( 'Check "%1$s" did not answer: %2$s', 'ondaweb-security' ), ( isset( $defs[ $id ] ) ? $defs[ $id ]['title'] : $id ), $why ), array( 'source' => 'self', 'extra' => __( 'Step of the check with progress bar.', 'ondaweb-security' ) ) );
			if ( isset( $defs[ $id ] ) ) {
				/* translators: %s: reason */
				$tmp['results'][ $id ] = array( 'status' => 'info', 'detail' => sprintf( __( 'Could not check (%s). Details in the Error log.', 'ondaweb-security' ), $why ), 'items' => array() );
				set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
			}
			wp_send_json_success();
		}

		if ( 'finish' === $op ) {
			$results = array();
			foreach ( OWSU_Security::definitions() as $id => $d ) {
				$results[ $id ] = isset( $tmp['results'][ $id ] ) ? $tmp['results'][ $id ] : array( 'status' => 'info', 'detail' => __( 'Not checked.', 'ondaweb-security' ), 'items' => array() );
			}
			$scan = array(
				'time'    => current_time( 'mysql' ),
				'results' => $results,
				'score'   => OWSU_Security::score( $results ),
			);
			update_site_option( 'owsu_scan', $scan );
			delete_site_transient( self::tmp_key() );
			/* translators: 1: grade (A-E), 2: score 0-100 */
			$msg  = sprintf( __( 'Check finished: grade %1$s (%2$d/100).', 'ondaweb-security' ), $scan['score']['grade'], $scan['score']['score'] );
			$args = array( 'owsu_msg' => rawurlencode( $msg ) );
			if ( $tmp['notes'] ) {
				$args['owsu_msg'] = rawurlencode( __( 'Error:', 'ondaweb-security' ) . ' ' . implode( ' ', $tmp['notes'] ) . ' — ' . $msg );
				$args['owsu_err'] = 1;
			}
			wp_send_json_success( array( 'redirect' => self::url( $args ) ) );
		}
		wp_send_json_error( array( 'msg' => __( 'Invalid operation.', 'ondaweb-security' ) ), 400 );
	}

	private static function safe_run_one( $id ) {
		try {
			OWSU_Security::run_one( $id );
		} catch ( \Throwable $e ) {
			/* translators: %s: check id */
			OWUM_ErrorLog::add( 'warning', sprintf( __( 'Re-check of "%s" failed', 'ondaweb-security' ), $id ) . ': ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine() ), false );
		}
	}

	/* Page ------------------------------------------------------------------ */

	private static function badge( $status ) {
		return '<span class="owsu-badge ' . esc_attr( $status ) . '">' . esc_html( OWSU_Security::status_label( $status ) ) . '</span>';
	}

	private static function action_form( $action, $id, $label, $class, $confirm ) {
		$busy = 'owsu_undo' === $action ? __( 'Undoing the fix and testing the site…', 'ondaweb-security' ) : __( 'Applying the fix and testing the site…', 'ondaweb-security' );
		return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline" data-owum-confirm="' . esc_attr( $confirm ) . '" data-owum-busy="' . esc_attr( $busy ) . '">'
			. '<input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="check" value="' . esc_attr( $id ) . '">'
			. wp_nonce_field( $action, '_wpnonce', true, false )
			. '<button type="submit" class="button ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	private static function link( $action, $label, $class = 'page-title-action', $target = '' ) {
		$url = wp_nonce_url( add_query_arg( 'action', $action, admin_url( 'admin-post.php' ) ), $action );
		return '<a class="' . esc_attr( $class ) . '" href="' . esc_url( $url ) . '"' . ( $target ? ' target="' . esc_attr( $target ) . '"' : '' ) . '>' . esc_html( $label ) . '</a>';
	}

	public static function page() {
		$scan  = OWSU_Security::last_scan();
		$defs  = OWSU_Security::definitions();
		$fixes = OWSU_Security::fixes();
		$vul   = OWSU_Vulns::get();
		?>
		<style>
			.owsu-head{display:grid;grid-template-columns:200px 1fr;gap:16px;margin:16px 0}
			@media (max-width:782px){.owsu-head{grid-template-columns:1fr}}
			.owsu-grade{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:16px;text-align:center}
			.owsu-grade .g{font-size:56px;font-weight:700;line-height:1}
			.owsu-grade .s{color:#646970;margin-top:4px}
			.owsu-counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
			.owsu-counts>div{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:12px 14px}
			.owsu-counts .n{font-size:26px;font-weight:600}
			.owsu-counts .l{font-size:11px;text-transform:uppercase;color:#646970;letter-spacing:.04em}
			.owsu-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
			.owsu-badge.crit{background:#fee2e2;color:#991b1b}.owsu-badge.warn{background:#ffedd5;color:#9a3412}
			.owsu-badge.ok{background:#dcfce7;color:#166534}.owsu-badge.info{background:#e0e7ff;color:#3730a3}
			.owsu-table td{vertical-align:top}
			.owsu-table .why{color:#646970;font-size:12px;margin:2px 0 6px}
			.owsu-table .det{margin:0}
			.owsu-table ul.items{margin:6px 0 0 18px;list-style:disc;font-size:12px}
			.owsu-table details.howto summary{cursor:pointer;color:#2271b1;margin-top:6px}
			.owsu-table details.howto>div{margin-top:6px;padding:8px 12px;background:#fff;border-left:3px solid #2271b1}
			.owsu-table .applied{font-size:11px;color:#166534;display:block;margin-bottom:4px}
			.owsu-table tr.owsu-focus{outline:2px solid #2271b1}
			.owsu-filter{margin:6px 0 10px}
			.owsu-filter a{margin-right:10px;text-decoration:none}.owsu-filter a.current{font-weight:600;color:#000}
			tr.owsu-hide,h2.owsu-hide,table.owsu-hide{display:none}
			.owsu-vt td{font-size:12px}
		</style>
		<div class="wrap owum-ui"><?php OWUM_Admin::brand_bar(); ?>
			<h1 class="wp-heading-inline"><?php esc_html_e( 'Security', 'ondaweb-security' ); ?></h1>
			<?php
			echo str_replace( '<a ', '<a data-owsu-scan="0" ', self::link( 'owsu_scan', __( 'Run check', 'ondaweb-security' ) ) ); // phpcs:ignore
			if ( OWSU_Vulns::key() ) {
				echo str_replace( '<a ', '<a data-owsu-scan="1" ', self::link( 'owsu_vuln_update', __( 'Update vulnerability database', 'ondaweb-security' ) ) ); // phpcs:ignore
			}
			if ( $scan ) {
				echo self::link( 'owsu_tech_report', __( 'Technical report (internal)', 'ondaweb-security' ), 'page-title-action', '_blank' ); // phpcs:ignore
			}
			?>
			<hr class="wp-header-end">
			<?php
			if ( ! empty( $_GET['owsu_msg'] ) ) { // phpcs:ignore
				$m   = sanitize_text_field( wp_unslash( rawurldecode( $_GET['owsu_msg'] ) ) ); // phpcs:ignore
				$cls = ! empty( $_GET['owsu_err'] ) ? 'notice-error' : 'notice-success'; // phpcs:ignore
				echo '<div class="notice ' . esc_attr( $cls ) . ' is-dismissible"><p>' . esc_html( $m ) . '</p></div>';
			}
			if ( ! OWSU_Vulns::key() ) {
				/* translators: %s: link to the Settings screen */
				echo '<div class="notice notice-info"><p>' . sprintf( esc_html__( 'To check for known vulnerabilities, enter the Wordfence Intelligence API key in %s.', 'ondaweb-security' ), '<a href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) ) . '">' . esc_html__( 'Settings', 'ondaweb-security' ) . '</a>' ) . '</p></div>';
			}
			if ( ! $scan ) {
				/* translators: %s: "Run check" button label */
				echo '<p>' . sprintf( esc_html__( 'No check has been run yet. Click %s (takes a few seconds).', 'ondaweb-security' ), '<strong>' . esc_html__( 'Run check', 'ondaweb-security' ) . '</strong>' ) . '</p></div>';
				return;
			}
			$sc = $scan['score'];
			?>
			<div class="owsu-head">
				<div class="owsu-grade">
					<div class="g"><?php echo esc_html( $sc['grade'] ); ?></div>
					<div class="s"><?php echo esc_html( sprintf( /* translators: %d: score 0-100 */ __( 'Score %d/100', 'ondaweb-security' ), $sc['score'] ) ); ?></div>
				</div>
				<div>
					<div class="owsu-counts">
						<div><div class="l"><?php esc_html_e( 'Critical', 'ondaweb-security' ); ?></div><div class="n"><?php echo (int) $sc['count']['crit']; ?></div></div>
						<div><div class="l"><?php esc_html_e( 'Warning', 'ondaweb-security' ); ?></div><div class="n"><?php echo (int) $sc['count']['warn']; ?></div></div>
						<div><div class="l">OK</div><div class="n"><?php echo (int) $sc['count']['ok']; ?></div></div>
						<div><div class="l"><?php esc_html_e( 'Informational', 'ondaweb-security' ); ?></div><div class="n"><?php echo (int) $sc['count']['info']; ?></div></div>
					</div>
					<p class="description"><?php
						/* translators: %s: date and time */
						echo esc_html( sprintf( __( 'Last check: %s.', 'ondaweb-security' ), owum_date( $scan['time'], true ) ) . ' ' . __( 'The check also runs automatically once a day.', 'ondaweb-security' ) );
						if ( OWSU_Vulns::key() ) {
							/* translators: %s: date and time, or "not downloaded" */
							echo ' ' . esc_html( sprintf( __( 'Vulnerability database: %s.', 'ondaweb-security' ), ! empty( $vul['time'] ) ? owum_date( $vul['time'], true ) : __( 'not downloaded', 'ondaweb-security' ) ) );
						}
					?></p>
				</div>
			</div>

			<div class="owsu-filter">
				<a href="#" class="current" data-f="all"><?php esc_html_e( 'All', 'ondaweb-security' ); ?></a>
				<a href="#" data-f="pend"><?php echo esc_html( sprintf( /* translators: %d: count */ __( 'Pending only (%d)', 'ondaweb-security' ), $sc['count']['crit'] + $sc['count']['warn'] ) ); ?></a>
			</div>

			<?php
			$focus = isset( $_GET['focus'] ) ? sanitize_key( $_GET['focus'] ) : ''; // phpcs:ignore
			foreach ( OWSU_Security::groups() as $gid => $gname ) :
				$ids = array_keys( wp_list_filter( $defs, array( 'group' => $gid ) ) );
				if ( ! $ids ) {
					continue;
				}
				?>
				<h2><?php echo esc_html( $gname ); ?></h2>
				<table class="widefat owsu-table">
					<tbody>
					<?php foreach ( $ids as $id ) :
						$d = $defs[ $id ];
						$r = isset( $scan['results'][ $id ] ) ? $scan['results'][ $id ] : array( 'status' => 'info', 'detail' => __( 'Not checked yet.', 'ondaweb-security' ), 'items' => array() );
						$applied = OWSU_Security::is_on( $id );
						?>
						<tr id="owsu-<?php echo esc_attr( $id ); ?>" data-status="<?php echo esc_attr( $r['status'] ); ?>" class="<?php echo $focus === $id ? 'owsu-focus' : ''; ?>">
							<td style="width:90px"><?php echo self::badge( $r['status'] ); // phpcs:ignore ?></td>
							<td>
								<strong><?php echo esc_html( $d['title'] ); ?></strong>
								<p class="why"><?php echo esc_html( $d['why'] ); ?></p>
								<p class="det"><?php echo esc_html( $r['detail'] ); ?></p>
								<?php
								if ( $r['items'] && 'vulns' !== $id ) {
									$shown = array_slice( $r['items'], 0, 8 );
									$rest  = array_slice( $r['items'], 8 );
									echo '<ul class="items">';
									foreach ( $shown as $it ) {
										echo '<li>' . esc_html( $it ) . '</li>';
									}
									echo '</ul>';
									if ( $rest ) {
										echo '<details><summary style="cursor:pointer;color:#2271b1;font-size:12px;margin-left:18px">' . esc_html( sprintf( /* translators: %d: count */ __( '%d more', 'ondaweb-security' ), count( $rest ) ) ) . '</summary><ul class="items">';
										foreach ( $rest as $it ) {
											echo '<li>' . esc_html( $it ) . '</li>';
										}
										echo '</ul></details>';
									}
								}
								?>
								<?php if ( 'vulns' === $id ) { self::vuln_table(); } ?>
								<details class="howto"><summary><?php esc_html_e( 'How to fix', 'ondaweb-security' ); ?></summary><div><?php echo wp_kses_post( $d['howto'] ); ?></div></details>
							</td>
							<td style="width:170px;text-align:right">
								<?php
								if ( $applied ) {
									/* translators: %s: date */
									echo '<span class="applied">✓ ' . ( ! empty( $fixes[ $id ]['when'] ) ? esc_html( sprintf( __( 'Applied on %s', 'ondaweb-security' ), owum_date( $fixes[ $id ]['when'] ) ) ) : esc_html__( 'Active', 'ondaweb-security' ) ) . '</span>';
									if ( ! empty( $d['config'] ) ) {
										echo '<a class="button" href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) . '#owum-login' ) . '">' . esc_html__( 'Configure', 'ondaweb-security' ) . '</a> ';
									}
									echo self::action_form( 'owsu_undo', $id, __( 'Undo', 'ondaweb-security' ), '', 'login_url' === $id ? __( 'Move the login back to /wp-login.php?', 'ondaweb-security' ) : __( 'Undo this fix?', 'ondaweb-security' ) ); // phpcs:ignore
								} elseif ( ! empty( $d['config'] ) && in_array( $r['status'], array( 'crit', 'warn' ), true ) ) {
									echo '<a class="button button-primary" href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) . '#owum-login' ) . '">' . esc_html__( 'Configure', 'ondaweb-security' ) . '</a>';
								} elseif ( $d['fix'] && in_array( $r['status'], array( 'crit', 'warn' ), true ) ) {
									/* translators: %s: name of the security check */
									echo self::action_form( 'owsu_apply', $id, __( 'Apply fix', 'ondaweb-security' ), 'button-primary', sprintf( __( 'Apply the fix "%s"?', 'ondaweb-security' ), $d['title'] ) . "\n\n" . __( 'It can be undone at any time from this panel.', 'ondaweb-security' ) ); // phpcs:ignore
								}
								?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endforeach; ?>
			<p class="description" style="margin-top:16px"><?php esc_html_e( 'Vulnerability data: Wordfence Intelligence (Defiant, Inc.). Applied fixes are recorded in the History.', 'ondaweb-security' ); ?></p>
		</div>
		<script>
		(function(){
			var f=document.querySelector('.owsu-filter');
			f.addEventListener('click',function(e){
				var a=e.target.closest('a');if(!a)return;e.preventDefault();
				f.querySelectorAll('a').forEach(function(x){x.classList.remove('current')});a.classList.add('current');
				var pend=a.dataset.f==='pend';
				document.querySelectorAll('.owsu-table').forEach(function(t){
					var vis=0;
					t.querySelectorAll(':scope>tbody>tr').forEach(function(tr){
						var hide=pend&&!(tr.dataset.status==='crit'||tr.dataset.status==='warn');
						tr.classList.toggle('owsu-hide',hide);if(!hide)vis++;
					});
					t.classList.toggle('owsu-hide',!vis);t.previousElementSibling.classList.toggle('owsu-hide',!vis);
				});
			});
			var el=document.querySelector('tr.owsu-focus');if(el)el.scrollIntoView({block:'center'});
		})();
		</script>
		<?php
	}

	private static function vuln_table() {
		$items = (array) OWSU_Vulns::get()['items'];
		if ( ! $items ) {
			return;
		}
		echo '<table class="widefat striped owsu-vt" style="margin-top:8px"><thead><tr><th>' . esc_html__( 'Item', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Installed', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Vulnerability', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Severity', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Fixed in', 'ondaweb-security' ) . '</th></tr></thead><tbody>';
		foreach ( $items as $it ) {
			$title = esc_html( $it['title'] ) . ( $it['cve'] ? ' <span class="description">(' . esc_html( $it['cve'] ) . ')</span>' : '' );
			if ( $it['ref'] ) {
				$title = '<a href="' . esc_url( $it['ref'] ) . '" target="_blank" rel="noopener">' . $title . '</a>';
			}
			$sev = $it['rating'] ? esc_html( $it['rating'] . ( $it['score'] ? ' (' . $it['score'] . ')' : '' ) ) : '—';
			echo '<tr><td><strong>' . esc_html( $it['name'] ) . '</strong></td><td>' . esc_html( $it['version'] ) . '</td><td>' . $title . '</td><td>' . $sev . '</td><td>' . ( $it['patched'] ? '<strong>' . esc_html( $it['patched'] ) . '</strong>' : '<span style="color:#991b1b">' . esc_html__( 'no fix', 'ondaweb-security' ) . '</span>' ) . '</td></tr>'; // phpcs:ignore
		}
		echo '</tbody></table>';
	}

	/* Technical report (internal) ------------------------------------------ */

	public static function owsu_tech_report() {
		self::guard( 'owsu_tech_report' );
		$scan  = OWSU_Security::last_scan();
		$defs  = OWSU_Security::definitions();
		$fixes = OWSU_Security::fixes();
		$s     = owum_settings();
		if ( ! $scan ) {
			wp_die( esc_html__( 'Run a check first.', 'ondaweb-security' ) );
		}
		$sc    = $scan['score'];
		$colors = array( 'crit' => array( '#991b1b', '#fee2e2' ), 'warn' => array( '#9a3412', '#ffedd5' ), 'ok' => array( '#166534', '#dcfce7' ), 'info' => array( '#3730a3', '#e0e7ff' ) );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
<!doctype html>
<html <?php language_attributes(); ?>><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( sanitize_title( __( 'Technical security report', 'ondaweb-security' ) ) . '-' . sanitize_title( $s['client_name'] ) . '-' . current_time( 'Y-m-d' ) ); ?></title>
<style>
	body{margin:0;background:#f3f4f6;font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#1f2937}
	.bar{position:sticky;top:0;background:#7f1d1d;color:#fff;padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
	.bar button{font:inherit;padding:6px 12px;border:0;border-radius:4px;background:#fff;color:#7f1d1d;font-weight:600;cursor:pointer}
	.page{background:#fff;max-width:960px;margin:24px auto;padding:36px 40px}
	h1{font-size:20px;margin:0 0 4px;color:#7f1d1d} h2{font-size:15px;margin:24px 0 6px;color:#0b3b5c;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
	.conf{display:inline-block;background:#fee2e2;color:#991b1b;font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px;letter-spacing:.05em}
	.item{padding:8px 0;border-bottom:1px solid #f1f1f1;page-break-inside:avoid}
	.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:6px}
	.det{color:#374151;margin:2px 0}.muted{color:#6b7280;font-size:12px}
	ul{margin:4px 0 0 18px;font-size:12px}
	table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:5px 6px;border-bottom:1px solid #e5e7eb;vertical-align:top}
	@media print{body{background:#fff}.bar{display:none}.page{margin:0;padding:0;max-width:none}@page{size:A4;margin:14mm 12mm}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body>
<div class="bar"><button onclick="window.print()"><?php esc_html_e( 'Save as PDF / Print', 'ondaweb-security' ); ?></button><span><?php esc_html_e( 'Internal document — do not forward to the client.', 'ondaweb-security' ); ?></span></div>
<div class="page">
	<span class="conf"><?php esc_html_e( 'CONFIDENTIAL – INTERNAL USE', 'ondaweb-security' ); ?></span>
	<h1><?php echo esc_html( sprintf( /* translators: %s: client name */ __( 'Technical security report — %s', 'ondaweb-security' ), $s['client_name'] ) ); ?></h1>
	<div class="muted"><?php
		echo esc_html(
			sprintf(
				/* translators: 1: date and time, 2: site address, 3: score, 4: grade, 5: critical count, 6: warning count, 7: OK count */
				__( 'Check of %1$s · %2$s · Score %3$d/100 (%4$s) · %5$d critical, %6$d warning, %7$d OK', 'ondaweb-security' ),
				owum_date( $scan['time'], true ),
				OWSU_Security::home(),
				$sc['score'],
				$sc['grade'],
				$sc['count']['crit'],
				$sc['count']['warn'],
				$sc['count']['ok']
			)
		);
	?></div>
	<?php
	foreach ( OWSU_Security::groups() as $gid => $gname ) {
		$ids = array_keys( wp_list_filter( $defs, array( 'group' => $gid ) ) );
		usort(
			$ids,
			function ( $a, $b ) use ( $scan ) {
				$rank = array( 'crit' => 0, 'warn' => 1, 'info' => 2, 'ok' => 3 );
				return $rank[ $scan['results'][ $a ]['status'] ] <=> $rank[ $scan['results'][ $b ]['status'] ];
			}
		);
		echo '<h2>' . esc_html( $gname ) . '</h2>';
		foreach ( $ids as $id ) {
			$r = $scan['results'][ $id ];
			$c = $colors[ $r['status'] ];
			echo '<div class="item"><span class="b" style="color:' . esc_attr( $c[0] ) . ';background:' . esc_attr( $c[1] ) . '">' . esc_html( OWSU_Security::status_label( $r['status'] ) ) . '</span><strong>' . esc_html( $defs[ $id ]['title'] ) . '</strong>';
			if ( ! empty( $fixes[ $id ]['on'] ) ) {
				/* translators: %s: date */
				echo ' <span class="muted">· ' . esc_html( sprintf( __( 'fix applied on %s', 'ondaweb-security' ), owum_date( $fixes[ $id ]['when'] ) ) ) . '</span>';
			}
			echo '<div class="det">' . esc_html( $r['detail'] ) . '</div>';
			if ( $r['items'] ) {
				echo '<ul>';
				foreach ( $r['items'] as $it ) {
					echo '<li>' . esc_html( $it ) . '</li>';
				}
				echo '</ul>';
			}
			echo '</div>';
		}
	}
	$vi = (array) OWSU_Vulns::get()['items'];
	if ( $vi ) {
		echo '<h2>' . esc_html__( 'Vulnerability details', 'ondaweb-security' ) . '</h2><table><tr><th>' . esc_html__( 'Item', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Version', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Vulnerability', 'ondaweb-security' ) . '</th><th>CVSS</th><th>' . esc_html__( 'Fixed in', 'ondaweb-security' ) . '</th><th>' . esc_html__( 'Recommendation', 'ondaweb-security' ) . '</th></tr>';
		foreach ( $vi as $it ) {
			echo '<tr><td>' . esc_html( $it['name'] ) . '</td><td>' . esc_html( $it['version'] ) . '</td><td>' . esc_html( $it['title'] ) . ( $it['cve'] ? '<br><span class="muted">' . esc_html( $it['cve'] ) . '</span>' : '' ) . '</td><td>' . esc_html( $it['rating'] . ' ' . ( $it['score'] ? $it['score'] : '' ) ) . '</td><td>' . esc_html( $it['patched'] ? $it['patched'] : __( 'no fix', 'ondaweb-security' ) ) . '</td><td>' . esc_html( $it['remediation'] ) . '</td></tr>';
		}
		echo '</table><p class="muted">' . esc_html__( 'Source: Wordfence Intelligence (Defiant, Inc.).', 'ondaweb-security' ) . '</p>';
	}
	?>
</div></body></html>
		<?php
		exit;
	}
}
