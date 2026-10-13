<?php
// Remove tabela e opções ao EXCLUIR o plugin (desativar não apaga nada).
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->base_prefix}owum_log" ); // phpcs:ignore

foreach ( array( 'owum_snapshot', 'owum_meta', 'owum_settings', 'owum_db_version', 'owum_last_sent', 'owum_last_mail', 'owum_last_check', 'owsu_fixes', 'owsu_scan', 'owsu_vulns', 'owsu_tracking_since', 'owum_mig_child_themes', 'owsu_rc_error', 'owum_gh_check', 'owum_errors', 'owum_errors_seen' ) as $opt ) {
	delete_site_option( $opt );
}
delete_site_transient( 'owum_detect_lock' );
delete_site_transient( 'owum_gh_release' );
delete_site_transient( 'owum_err_mails' );
delete_site_transient( 'owsu_scan_tmp' );
