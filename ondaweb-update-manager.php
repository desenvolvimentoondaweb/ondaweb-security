<?php
/**
 * Plugin Name:       Ondaweb Security Updater
 * Description:       Version inventory (WordPress, plugins and themes), automatic update history, security checks and one-click fixes, known vulnerabilities (Wordfence Intelligence), login protection and a monthly client report by email and PDF. Works on single sites and multisite networks.
 * Version:           1.5.0
 * Plugin URI:        https://github.com/desenvolvimentoondaweb/ondaweb-security
 * Update URI:        https://github.com/desenvolvimentoondaweb/ondaweb-security
 * Author:            Ondaweb
 * Author URI:        https://ondaweb.com.br
 * Network:           true
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ondaweb-security
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

define( 'OWUM_VERSION', '1.5.0' );
define( 'OWUM_FILE', __FILE__ );
define( 'OWUM_DIR', plugin_dir_path( __FILE__ ) );
define( 'OWUM_PRODUCT', 'Ondaweb Security Updater' );

require_once OWUM_DIR . 'includes/class-owum-errorlog.php';
OWUM_ErrorLog::boot();
require_once OWUM_DIR . 'includes/class-owum-installer.php';
require_once OWUM_DIR . 'includes/class-owum-collector.php';
require_once OWUM_DIR . 'includes/class-owum-logger.php';
require_once OWUM_DIR . 'includes/class-owum-report.php';
require_once OWUM_DIR . 'includes/class-owum-mailer.php';
require_once OWUM_DIR . 'includes/class-owum-admin.php';
require_once OWUM_DIR . 'includes/class-owum-updater.php';
require_once OWUM_DIR . 'includes/security/class-owsu-security.php';
require_once OWUM_DIR . 'includes/security/class-owsu-hardening.php';
require_once OWUM_DIR . 'includes/security/class-owsu-vulns.php';
require_once OWUM_DIR . 'includes/security/class-owsu-admin.php';
require_once OWUM_DIR . 'includes/security/class-owsu-login.php';
require_once OWUM_DIR . 'includes/security/class-owsu-captcha.php';

register_activation_hook( __FILE__, array( 'OWUM_Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'OWUM_Installer', 'deactivate' ) );

// Translations (bundled in /languages; a site translation in wp-content/languages/plugins takes precedence).
add_action(
	'init',
	function () {
		load_plugin_textdomain( 'ondaweb-security', false, dirname( plugin_basename( OWUM_FILE ) ) . '/languages' );
	},
	1
);

add_action(
	'plugins_loaded',
	function () {
		OWUM_Installer::maybe_upgrade();
		OWUM_Updater::init();
		OWSU_Login::init();
		OWSU_Captcha::init();
		OWSU_Hardening::init();
		OWUM_Logger::init();
		OWUM_Mailer::init();
		// Daily routine: refresh the vulnerability database and run the checks before the monthly email.
		add_action(
			'owum_daily',
			function () {
				if ( OWSU_Vulns::key() ) {
					OWSU_Vulns::update();
				}
			},
			8
		);
		add_action( 'owum_daily', array( 'OWSU_Security', 'run_all' ), 10 );
		if ( is_admin() ) {
			OWUM_Admin::init();
			OWSU_Admin::init();
		}
	}
);

/**
 * Plugin settings with defaults.
 *
 * New installs start neutral (no agency branding, emails go to the site admin).
 * Installs that existed before white-labelling keep the Ondaweb branding (see OWUM_Installer::migrate_brand()).
 */
function owum_settings() {
	$admin    = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
	$defaults = array(
		'emails'       => $admin,
		'enabled'      => 1,
		'day'          => 1,
		'client_name'  => is_multisite() ? get_site_option( 'site_name' ) : get_bloginfo( 'name' ),
		'logo_client'  => 0,
		'logo_ondaweb' => 0,  // agency (support) logo — key kept for compatibility
		'brand_name'   => '', // agency / support provider shown in reports
		'brand_url'    => '',
		'brand_logo_default' => 0, // 1 = use the Ondaweb logo bundled with the plugin (legacy installs)
		'agency_licensed'    => array(), // items classified as "agency license" by default
		'wf_key'       => '',
		'login_slug'   => '',
		'rc_version'   => '',
		'rc_site'      => '',
		'rc_secret'    => '',
		'rc_score'     => 0.5,
		'rc_verified'  => '',
		'err_email'    => $admin,
		'err_mail'     => 1,
		'err_site'     => 1,
	);
	return wp_parse_args( (array) get_site_option( 'owum_settings', array() ), $defaults );
}

/** Agency / support provider name ('' when not configured). */
function owum_brand() {
	$s = owum_settings();
	return trim( (string) $s['brand_name'] );
}

/**
 * Logo data (image from the main site's media library).
 *
 * @param string $which 'client' or 'ondaweb' (agency).
 * @return array|null [url, path, mime]
 */
function owum_logo( $which ) {
	$s  = owum_settings();
	$id = (int) ( isset( $s[ 'logo_' . $which ] ) ? $s[ 'logo_' . $which ] : 0 );
	if ( ! $id ) {
		return ( 'ondaweb' === $which && ! empty( $s['brand_logo_default'] ) ) ? owum_default_logo() : null;
	}
	$switched = false;
	if ( is_multisite() && ! is_main_site() ) {
		switch_to_blog( get_main_site_id() );
		$switched = true;
	}
	$url  = wp_get_attachment_url( $id );
	$path = get_attached_file( $id );
	$mime = get_post_mime_type( $id );
	if ( $switched ) {
		restore_current_blog();
	}
	return $url ? array( 'url' => $url, 'path' => $path, 'mime' => $mime ) : null;
}

/** Ondaweb logo bundled with the plugin (used by installs branded as Ondaweb). */
function owum_default_logo() {
	return array(
		'url'     => plugins_url( 'assets/logo-ondaweb.png', OWUM_FILE ),
		'path'    => OWUM_DIR . 'assets/logo-ondaweb.png',
		'mime'    => 'image/png',
		'default' => true,
	);
}

/**
 * Formats a local MySQL datetime for display, following the language of the site
 * (e.g. 10/31/2026 in English, 31/10/2026 in Portuguese).
 *
 * @param string $mysql Y-m-d H:i:s (local time). Empty = now.
 * @param bool   $time  Include the time.
 */
function owum_date( $mysql = '', $time = false ) {
	$mysql = $mysql ? $mysql : current_time( 'mysql' );
	$fmt   = $time
		/* translators: PHP date format: short date with time (see https://www.php.net/manual/datetime.format.php) */
		? _x( 'm/d/Y g:i a', 'short date with time', 'ondaweb-security' )
		/* translators: PHP date format: short date (see https://www.php.net/manual/datetime.format.php) */
		: _x( 'm/d/Y', 'short date', 'ondaweb-security' );
	return mysql2date( $fmt, $mysql );
}

/** Same as owum_date() for a Unix timestamp. */
function owum_date_ts( $ts, $time = false ) {
	return owum_date( get_date_from_gmt( gmdate( 'Y-m-d H:i:s', (int) $ts ) ), $time );
}

/**
 * Capability required to see and manage the plugin.
 */
function owum_cap() {
	return is_multisite() ? 'manage_network_plugins' : 'update_plugins';
}
