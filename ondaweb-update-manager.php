<?php
/**
 * Plugin Name:       Ondaweb Security Updater
 * Description:       Inventário de versões (WordPress, plugins e temas) da rede multisite, histórico automático de atualizações, verificações e correções de segurança, vulnerabilidades conhecidas (Wordfence Intelligence) e relatório mensal por e-mail e PDF.
 * Version:           1.4.0
 * Plugin URI:        https://github.com/desenvolvimentoondaweb/ondaweb-security
 * Update URI:        https://github.com/desenvolvimentoondaweb/ondaweb-security
 * Author:            Ondaweb
 * Author URI:        https://ondaweb.com.br
 * Network:           true
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Text Domain:       owum
 */

defined( 'ABSPATH' ) || exit;

define( 'OWUM_VERSION', '1.4.0' );
define( 'OWUM_FILE', __FILE__ );
define( 'OWUM_DIR', plugin_dir_path( __FILE__ ) );

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
		// Rotina diária: atualiza a base de vulnerabilidades e roda as verificações antes do e-mail mensal.
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
 * Configurações do plugin, com valores padrão.
 */
function owum_settings() {
	$defaults = array(
		'emails'      => 'suporte@ondaweb.com.br',
		'enabled'     => 1,
		'day'         => 1,
		'client_name' => is_multisite() ? get_site_option( 'site_name' ) : get_bloginfo( 'name' ),
		'logo_client' => 0,
		'logo_ondaweb'=> 0,
		'wf_key'      => '',
		'login_slug'  => '',
		'rc_version'  => '',
		'rc_site'     => '',
		'rc_secret'   => '',
		'rc_score'    => 0.5,
		'rc_verified' => '',
		'err_email'   => 'desenvolvimento.ondaweb@gmail.com',
		'err_mail'    => 1,
		'err_site'    => 1,
	);
	return wp_parse_args( (array) get_site_option( 'owum_settings', array() ), $defaults );
}

/**
 * Dados de um logo (imagem da biblioteca de mídia do site principal).
 *
 * @param string $which 'client' ou 'ondaweb'.
 * @return array|null [url, path, mime]
 */
function owum_logo( $which ) {
	$s  = owum_settings();
	$id = (int) ( isset( $s[ 'logo_' . $which ] ) ? $s[ 'logo_' . $which ] : 0 );
	if ( ! $id ) {
		// Logo da Ondaweb já vem incluído no plugin.
		return 'ondaweb' === $which ? owum_default_logo() : null;
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

/** Logo padrão da Ondaweb, incluído no plugin. */
function owum_default_logo() {
	return array(
		'url'     => plugins_url( 'assets/logo-ondaweb.png', OWUM_FILE ),
		'path'    => OWUM_DIR . 'assets/logo-ondaweb.png',
		'mime'    => 'image/png',
		'default' => true,
	);
}

/**
 * Capacidade exigida para ver e gerenciar o plugin.
 */
function owum_cap() {
	return is_multisite() ? 'manage_network_plugins' : 'update_plugins';
}
