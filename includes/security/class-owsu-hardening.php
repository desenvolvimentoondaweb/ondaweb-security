<?php
defined( 'ABSPATH' ) || exit;

/**
 * Aplica, a cada requisição, as proteções ativadas no painel de segurança.
 * Tudo aqui é reversível: basta desligar a correção no painel.
 */
class OWSU_Hardening {

	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'track_login' ), 10, 2 );

		$fixes = OWSU_Security::fixes();
		$on    = function ( $id ) use ( $fixes ) {
			return ! empty( $fixes[ $id ]['on'] );
		};

		if ( $on( 'debug_display' ) ) {
			@ini_set( 'display_errors', '0' ); // phpcs:ignore
		}
		if ( $on( 'force_ssl_admin' ) && function_exists( 'force_ssl_admin' ) ) {
			force_ssl_admin( true );
		}
		if ( $on( 'file_edit' ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'deny_file_edit' ), 10, 2 );
		}
		if ( $on( 'xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_filter( 'wp_headers', array( __CLASS__, 'no_pingback' ) );
			remove_action( 'wp_head', 'rsd_link' );
			add_action( 'init', array( __CLASS__, 'block_xmlrpc' ), 0 );
		}
		if ( $on( 'user_enum' ) ) {
			add_filter( 'rest_endpoints', array( __CLASS__, 'rest_users' ) );
			add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ), 0 );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'no_user_sitemap' ), 10, 2 );
		}
		if ( $on( 'generator' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( self::headers() || $on( 'hdr_powered' ) ) {
			foreach ( array( 'send_headers', 'admin_init', 'login_init' ) as $hook ) {
				add_action( $hook, array( __CLASS__, 'send' ), 1 );
			}
		}
	}

	/** Cabeçalhos ativados. */
	public static function headers() {
		$fixes = OWSU_Security::fixes();
		$out   = array();
		$https = 0 === strpos( OWSU_Security::home(), 'https://' );
		$map   = array(
			'hdr_hsts'        => $https ? 'Strict-Transport-Security: max-age=31536000' : '',
			'hdr_nosniff'     => 'X-Content-Type-Options: nosniff',
			'hdr_frame'       => 'X-Frame-Options: SAMEORIGIN',
			'hdr_referrer'    => 'Referrer-Policy: strict-origin-when-cross-origin',
			'hdr_permissions' => 'Permissions-Policy: camera=(), microphone=(), payment=(), usb=(), geolocation=(self)',
			'hdr_csp'         => 'Content-Security-Policy: ' . ( $https ? 'upgrade-insecure-requests; ' : '' ) . "frame-ancestors 'self'",
		);
		foreach ( $map as $id => $header ) {
			if ( $header && ! empty( $fixes[ $id ]['on'] ) ) {
				$out[] = $header;
			}
		}
		return $out;
	}

	public static function send() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( self::headers() as $h ) {
			header( $h, true );
		}
		if ( OWSU_Security::is_on( 'hdr_powered' ) ) {
			header_remove( 'X-Powered-By' );
		}
	}

	public static function deny_file_edit( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	public static function no_pingback( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public static function block_xmlrpc() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			exit( 'XML-RPC desativado.' );
		}
	}

	public static function rest_users( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}

	public static function block_author_scan() {
		if ( ! is_user_logged_in() && isset( $_GET['author'] ) ) { // phpcs:ignore
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	public static function no_user_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	public static function track_login( $login, $user ) {
		if ( $user instanceof WP_User ) {
			update_user_meta( $user->ID, 'owsu_last_login', time() );
		}
		if ( ! get_site_option( 'owsu_tracking_since' ) ) {
			update_site_option( 'owsu_tracking_since', time() );
		}
	}
}
