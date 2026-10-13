<?php
defined( 'ABSPATH' ) || exit;

/**
 * Endereço de login personalizado (substitui o plugin WPS Hide Login).
 *
 * - O login passa a funcionar em /<slug> (em cada site da rede, no próprio caminho).
 * - /wp-login.php e /wp-admin (para visitantes não logados) passam a responder "página não encontrada".
 * - Todos os links gerados pelo WordPress (login, sair, senha perdida, e-mails) usam o novo endereço.
 *
 * Recuperação de acesso: adicione no wp-config.php
 *     define( 'OWSU_LOGIN_SLUG_OFF', true );
 * ou renomeie a pasta do plugin por FTP.
 */
class OWSU_Login {

	private static $is_login = false;
	private static $block    = false;

	/* Configuração --------------------------------------------------------- */

	public static function slug() {
		if ( defined( 'OWSU_LOGIN_SLUG_OFF' ) && OWSU_LOGIN_SLUG_OFF ) {
			return '';
		}
		if ( self::wps_active() ) {
			return '';
		}
		return self::saved_slug();
	}

	public static function saved_slug() {
		$s = owum_settings();
		return isset( $s['login_slug'] ) ? (string) $s['login_slug'] : '';
	}

	/** O plugin WPS Hide Login está ativo? (nesse caso este recurso fica em espera para não conflitar) */
	public static function wps_active() {
		$file = 'wps-hide-login/wps-hide-login.php';
		if ( in_array( $file, (array) get_option( 'active_plugins', array() ), true ) ) {
			return true;
		}
		return is_multisite() && array_key_exists( $file, (array) get_site_option( 'active_sitewide_plugins', array() ) );
	}

	/** Endereço configurado no WPS Hide Login (para migrar). */
	public static function wps_slug() {
		$v = get_site_option( 'whl_page' );
		if ( ! $v ) {
			$v = is_multisite() ? get_blog_option( get_main_site_id(), 'whl_page' ) : get_option( 'whl_page' );
		}
		return $v ? sanitize_title( $v ) : '';
	}

	public static function reserved() {
		return array( 'wp-admin', 'admin', 'login', 'wp-login', 'wp-login-php', 'dashboard', 'wp-content', 'wp-includes', 'wp-json', 'feed', 'xmlrpc', 'index', 'wp-signup', 'wp-activate', 'wp-cron', 'page', 'comments', 'search', 'author', 'category', 'tag', 'embed', 'sitemap', 'wp-sitemap', 'robots', '404' );
	}

	/**
	 * Valida o endereço digitado.
	 *
	 * @return string|WP_Error Slug limpo ('' = desativar).
	 */
	public static function validate( $raw ) {
		$slug = sanitize_title( (string) $raw );
		if ( '' === $slug ) {
			return '';
		}
		if ( strlen( $slug ) < 4 ) {
			return new WP_Error( 'owsu', 'O endereço de login precisa ter pelo menos 4 caracteres.' );
		}
		if ( in_array( $slug, self::reserved(), true ) ) {
			return new WP_Error( 'owsu', 'O endereço "' . $slug . '" é reservado pelo WordPress ou fácil de adivinhar. Escolha outro.' );
		}
		if ( is_multisite() ) {
			foreach ( get_sites( array( 'number' => 0, 'fields' => 'ids' ) ) as $id ) {
				$d = get_site( $id );
				if ( $d && preg_match( '#/' . preg_quote( $slug, '#' ) . '/$#', $d->path ) ) {
					return new WP_Error( 'owsu', 'Já existe um site da rede com o endereço "' . $slug . '". Escolha outro.' );
				}
			}
			switch_to_blog( get_main_site_id() );
		}
		$page = get_page_by_path( $slug, OBJECT, array( 'page', 'post' ) );
		if ( is_multisite() ) {
			restore_current_blog();
		}
		if ( $page ) {
			return new WP_Error( 'owsu', 'Já existe uma página ou post com o endereço "' . $slug . '". Escolha outro.' );
		}
		return $slug;
	}

	/** URL de login de um site. */
	public static function url( $blog_id = null, $scheme = null, $slug = null ) {
		$slug  = null === $slug ? self::slug() : $slug;
		$home  = $blog_id ? get_home_url( $blog_id, '/', $scheme ) : home_url( '/', $scheme );
		$perma = $blog_id && is_multisite() ? get_blog_option( $blog_id, 'permalink_structure' ) : get_option( 'permalink_structure' );
		if ( $perma ) {
			return $home . ( '/' === substr( $perma, -1 ) ? trailingslashit( $slug ) : $slug );
		}
		return $home . '?' . $slug;
	}

	/* Execução ------------------------------------------------------------- */

	public static function init() {
		if ( '' === self::slug() ) {
			return;
		}
		add_filter( 'site_url', array( __CLASS__, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_network_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( __CLASS__, 'filter_redirect' ), 10, 2 );
		add_filter( 'update_welcome_email', array( __CLASS__, 'filter_text' ) );
		add_filter( 'update_welcome_user_email', array( __CLASS__, 'filter_text' ) );
		// Impede que /login, /admin e /dashboard redirecionem para o login e revelem o endereço.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		self::parse();
		add_action( 'wp_loaded', array( __CLASS__, 'route' ), 1 );
	}

	private static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore
		$path = wp_parse_url( rawurldecode( $uri ), PHP_URL_PATH );
		return untrailingslashit( (string) $path );
	}

	private static function base_paths() {
		return array_unique(
			array(
				untrailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ),
				untrailingslashit( (string) wp_parse_url( site_url( '/' ), PHP_URL_PATH ) ),
			)
		);
	}

	private static function parse() {
		global $pagenow;
		$slug  = self::slug();
		$path  = self::request_path();
		$bases = self::base_paths();

		foreach ( $bases as $b ) {
			if ( $path === $b . '/' . $slug || ( ! get_option( 'permalink_structure' ) && isset( $_GET[ $slug ] ) && in_array( $path, array( $b, $b . '/index.php' ), true ) ) ) { // phpcs:ignore
				self::$is_login = true;
				$pagenow        = 'wp-login.php'; // phpcs:ignore
				return;
			}
		}

		$file = basename( $path );
		if ( in_array( $file, array( 'wp-login.php', 'wp-register.php' ), true ) || in_array( $path, array_map( function ( $b ) { return $b . '/wp-login'; }, $bases ), true ) ) {
			// Formulário de posts protegidos por senha continua funcionando.
			if ( isset( $_GET['action'] ) && 'postpass' === $_GET['action'] ) { // phpcs:ignore
				return;
			}
			self::$block = true;
			$pagenow     = 'index.php'; // phpcs:ignore
		}
	}

	public static function route() {
		global $pagenow;
		if ( self::$block ) {
			self::not_found();
		}
		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() && ! in_array( $pagenow, array( 'admin-post.php', 'admin-ajax.php' ), true ) ) {
			wp_safe_redirect( home_url( '/404/' ) );
			exit;
		}
		if ( self::$is_login ) {
			self::load_login();
		}
	}

	private static function load_login() {
		global $error, $interim_login, $action, $user_login;
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/** Responde com a página 404 do tema. */
	private static function not_found() {
		global $pagenow, $wp_query;
		$pagenow = 'index.php'; // phpcs:ignore
		if ( ! defined( 'WP_USE_THEMES' ) ) {
			define( 'WP_USE_THEMES', true );
		}
		wp();
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
		require_once ABSPATH . WPINC . '/template-loader.php';
		exit;
	}

	/* Filtros de URL -------------------------------------------------------- */

	public static function filter_site_url( $url, $path = '', $scheme = null, $blog_id = null ) {
		return self::rewrite( $url, $blog_id, $scheme );
	}

	public static function filter_network_site_url( $url, $path = '', $scheme = null ) {
		return self::rewrite( $url, is_multisite() ? get_main_site_id() : null, $scheme );
	}

	public static function filter_redirect( $location, $status = 302 ) {
		return self::rewrite( $location, null, null );
	}

	public static function filter_text( $text ) {
		return str_replace( 'wp-login.php', self::slug(), $text );
	}

	private static function rewrite( $url, $blog_id, $scheme ) {
		if ( ! is_string( $url ) || false === strpos( $url, 'wp-login.php' ) || false !== strpos( $url, 'action=postpass' ) ) {
			return $url;
		}
		$parts = explode( '?', $url, 2 );
		$new   = self::url( $blog_id, in_array( $scheme, array( 'http', 'https', 'relative' ), true ) ? $scheme : null );
		if ( isset( $parts[1] ) && '' !== $parts[1] ) {
			$new .= ( false === strpos( $new, '?' ) ? '?' : '&' ) . $parts[1];
		}
		return $new;
	}

	/* Aviso por e-mail ------------------------------------------------------ */

	public static function notify( $slug ) {
		$to = OWUM_Mailer::recipients();
		if ( ! $to ) {
			return;
		}
		$s     = owum_settings();
		$lines = array();
		if ( '' === $slug ) {
			$lines[] = 'O endereço de login personalizado foi DESATIVADO.';
			$lines[] = 'O login voltou ao endereço padrão: ' . trailingslashit( OWSU_Security::site_url() ) . 'wp-login.php';
		} else {
			$main    = self::url( is_multisite() ? get_main_site_id() : null, null, $slug );
			$lines[] = 'O endereço de login foi alterado para:';
			$lines[] = '';
			$lines[] = '    ' . $main;
			if ( is_multisite() ) {
				$lines[] = '';
				$lines[] = 'Cada site da rede usa o mesmo endereço no próprio caminho (ex.: https://dominio/nome-do-site/' . $slug . ').';
			}
			$lines[] = '';
			$lines[] = '/wp-login.php e /wp-admin passam a responder "página não encontrada" para quem não está logado.';
			$lines[] = 'Recuperação de acesso: adicione define( \'OWSU_LOGIN_SLUG_OFF\', true ); no wp-config.php.';
		}
		$user    = wp_get_current_user();
		$lines[] = '';
		$lines[] = 'Alterado por: ' . ( $user && $user->exists() ? $user->user_login : 'sistema' ) . ' em ' . current_time( 'd/m/Y H:i' ) . '.';
		wp_mail( $to, sprintf( '[%s] Endereço de login %s', $s['client_name'], '' === $slug ? 'desativado' : 'alterado' ), implode( "\n", $lines ) );
	}
}
