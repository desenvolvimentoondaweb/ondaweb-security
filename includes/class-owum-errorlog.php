<?php
defined( 'ABSPATH' ) || exit;

/**
 * Error log.
 *
 * Captures:
 *  - fatal errors of the whole site (from any plugin, theme or WordPress itself);
 *  - PHP warnings raised by this plugin's own files;
 *  - failures of the plugin's operations (applying fixes, downloading the vulnerability
 *    database, sending emails, checks that could not finish, etc.).
 *
 * Repeated errors are grouped (counter). Fatal errors and plugin failures can be emailed
 * to the developer, rate-limited so the inbox is not flooded.
 *
 * The origin is stored as a code and translated on display: a fatal error can happen
 * before WordPress loads translations, and translating at that moment raises a notice.
 */
class OWUM_ErrorLog {

	const OPTION   = 'owum_errors';
	const MAX      = 300;
	const MAX_MAIL = 10; // emails per hour, at most

	private static $seen_request = array();
	private static $mailing      = false;
	private static $prev_handler = null;

	/* Capture ----------------------------------------------------------------- */

	/** Called as soon as the plugin loads (before plugins_loaded). */
	public static function boot() {
		// Fatal errors: WordPress calls this filter before showing the "critical error" screen.
		add_filter( 'wp_should_handle_php_error', array( __CLASS__, 'on_wp_fatal' ), 1, 2 );
		// Fallback, in case the WordPress fatal error handler is disabled.
		register_shutdown_function( array( __CLASS__, 'on_shutdown' ) );
		// PHP warnings coming from this plugin's files.
		self::$prev_handler = set_error_handler( array( __CLASS__, 'on_php_error' ) ); // phpcs:ignore
		// Email sending failures (from any origin).
		add_action( 'wp_mail_failed', array( __CLASS__, 'on_mail_failed' ) );
	}

	private static function is_fatal( $e ) {
		return is_array( $e ) && isset( $e['type'] ) && in_array( (int) $e['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR ), true );
	}

	public static function on_wp_fatal( $should_handle, $error ) {
		// WordPress also passes ordinary warnings through this filter; only fatal errors are recorded.
		if ( self::is_fatal( $error ) ) {
			self::record_php( $error );
		}
		return $should_handle;
	}

	public static function on_shutdown() {
		$e = error_get_last();
		if ( self::is_fatal( $e ) ) {
			self::record_php( $e );
		}
	}

	public static function on_php_error( $errno, $errstr, $errfile = '', $errline = 0 ) {
		if ( $errfile && 0 === strpos( wp_normalize_path( $errfile ), wp_normalize_path( OWUM_DIR ) ) && ( error_reporting() & $errno ) ) {
			$level = in_array( $errno, array( E_WARNING, E_USER_WARNING, E_CORE_WARNING, E_COMPILE_WARNING ), true ) ? 'warning' : 'notice';
			if ( in_array( $errno, array( E_DEPRECATED, E_USER_DEPRECATED ), true ) ) {
				$level = 'notice';
			}
			self::add( $level, $errstr, array( 'file' => $errfile, 'line' => $errline, 'php' => self::php_type( $errno ) ) );
		}
		if ( self::$prev_handler ) {
			return call_user_func( self::$prev_handler, $errno, $errstr, $errfile, $errline );
		}
		return false; // continue with PHP's standard handler
	}

	public static function on_mail_failed( $error ) {
		if ( self::$mailing || ! is_wp_error( $error ) ) {
			return;
		}
		$data = $error->get_error_data();
		$to   = is_array( $data ) && ! empty( $data['to'] ) ? implode( ', ', (array) $data['to'] ) : '';
		$early = ! did_action( 'after_setup_theme' );
		self::add(
			'error',
			( $early ? 'Email could not be sent' : __( 'Email could not be sent', 'ondaweb-security' ) ) . ': ' . $error->get_error_message(),
			array(
				'source' => 'mail',
				'extra'  => $to ? ( $early ? 'Recipient' : __( 'Recipient', 'ondaweb-security' ) ) . ': ' . $to : '',
			),
			false
		);
	}

	private static function record_php( $e ) {
		$msg  = isset( $e['message'] ) ? (string) $e['message'] : '';
		$file = isset( $e['file'] ) ? (string) $e['file'] : '';
		$line = isset( $e['line'] ) ? (int) $e['line'] : 0;
		$key  = md5( $msg . $file . $line );
		if ( isset( self::$seen_request[ $key ] ) ) {
			return; // already recorded in this request (WP filter + fallback)
		}
		self::$seen_request[ $key ] = 1;
		$ours = $file && 0 === strpos( wp_normalize_path( $file ), wp_normalize_path( OWUM_DIR ) );
		$s    = owum_settings();
		if ( ! $ours && empty( $s['err_site'] ) ) {
			return;
		}
		// PHP's fatal error message already carries the "Stack trace"; split it for display.
		$trace = '';
		if ( false !== strpos( $msg, 'Stack trace:' ) ) {
			list( $msg, $trace ) = array_map( 'trim', explode( 'Stack trace:', $msg, 2 ) );
		}
		self::add( 'fatal', $msg, array( 'file' => $file, 'line' => $line, 'trace' => $trace, 'php' => self::php_type( isset( $e['type'] ) ? $e['type'] : E_ERROR ) ) );
	}

	/* Recording --------------------------------------------------------------- */

	/**
	 * Records an occurrence.
	 *
	 * @param string $level   fatal | error | warning | notice
	 * @param string $message Message.
	 * @param array  $ctx     file, line, trace, source (code), extra, php
	 * @param bool   $mail    May send an email alert.
	 */
	public static function add( $level, $message, $ctx = array(), $mail = true ) {
		try {
			$message = wp_strip_all_tags( (string) $message );
			$file    = isset( $ctx['file'] ) ? wp_normalize_path( (string) $ctx['file'] ) : '';
			$line    = isset( $ctx['line'] ) ? (int) $ctx['line'] : 0;
			$source  = ! empty( $ctx['source'] ) ? (string) $ctx['source'] : self::origin( $file );
			$hash    = md5( $level . '|' . $message . '|' . $file . '|' . $line );
			$now     = current_time( 'mysql' );
			$user    = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;

			$log = self::all();
			if ( isset( $log[ $hash ] ) ) {
				$log[ $hash ]['count']++;
				$log[ $hash ]['last'] = $now;
				$log[ $hash ]['url']  = self::request_url();
				if ( $user && $user->exists() ) {
					$log[ $hash ]['user'] = $user->user_login;
				}
				$entry = $log[ $hash ];
				unset( $log[ $hash ] );
			} else {
				$entry = array(
					'hash'    => $hash,
					'level'   => $level,
					'message' => self::cut( $message, 2000 ),
					'file'    => self::short_path( $file ),
					'line'    => $line,
					'source'  => $source,
					'php'     => isset( $ctx['php'] ) ? (string) $ctx['php'] : '',
					'trace'   => isset( $ctx['trace'] ) ? self::cut( (string) $ctx['trace'], 4000 ) : '',
					'extra'   => isset( $ctx['extra'] ) ? self::cut( (string) $ctx['extra'], 1000 ) : '',
					'url'     => self::request_url(),
					'user'    => $user && $user->exists() ? $user->user_login : '',
					'first'   => $now,
					'last'    => $now,
					'count'   => 1,
					'mailed'  => '',
				);
			}
			$log = array( $hash => $entry ) + $log; // newest first
			if ( count( $log ) > self::MAX ) {
				$log = array_slice( $log, 0, self::MAX, true );
			}
			update_site_option( self::OPTION, $log );

			if ( $mail && in_array( $level, array( 'fatal', 'error' ), true ) ) {
				self::maybe_mail( $hash );
			}
		} catch ( \Throwable $t ) {
			// Never let the error log raise another error.
			return;
		}
	}

	/** Failure of one of the plugin's operations (shortcut). */
	public static function op( $what, $message, $extra = '' ) {
		self::add( 'error', $what . ': ' . $message, array( 'source' => 'self', 'extra' => $extra ) );
	}

	public static function all() {
		$log = get_site_option( self::OPTION, array() );
		return is_array( $log ) ? $log : array();
	}

	public static function clear() {
		update_site_option( self::OPTION, array() );
	}

	/** Serious errors not yet seen in the dashboard. */
	public static function unseen() {
		$seen = (string) get_site_option( 'owum_errors_seen', '' );
		$n    = 0;
		foreach ( self::all() as $e ) {
			if ( in_array( $e['level'], array( 'fatal', 'error' ), true ) && $e['last'] > $seen ) {
				$n++;
			}
		}
		return $n;
	}

	public static function mark_seen() {
		update_site_option( 'owum_errors_seen', current_time( 'mysql' ) );
	}

	/* E-mail ----------------------------------------------------------------- */

	private static function maybe_mail( $hash ) {
		$s = owum_settings();
		if ( empty( $s['err_mail'] ) || self::$mailing ) {
			return;
		}
		$to = array_values( array_filter( array_map( 'trim', explode( ',', (string) $s['err_email'] ) ), 'is_email' ) );
		if ( ! $to ) {
			return;
		}
		$log = self::all();
		if ( ! isset( $log[ $hash ] ) ) {
			return;
		}
		$e = $log[ $hash ];
		// Same error: at most one email every 6 hours.
		if ( $e['mailed'] && strtotime( $e['mailed'] ) > strtotime( current_time( 'mysql' ) ) - 6 * HOUR_IN_SECONDS ) {
			return;
		}
		// At most 10 emails per hour overall.
		$sent = array_filter( (array) get_site_transient( 'owum_err_mails' ), function ( $t ) { return $t > time() - HOUR_IN_SECONDS; } );
		if ( count( $sent ) >= self::MAX_MAIL ) {
			return;
		}

		self::$mailing = true;
		$site          = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
		$subject       = sprintf( '[%s] %s: %s', $site, self::level_label( $e['level'] ), self::cut( $e['message'], 90 ) );
		$ok            = wp_mail( $to, $subject, self::mail_body( $e ) );
		self::$mailing = false;

		if ( $ok ) {
			$sent[] = time();
			set_site_transient( 'owum_err_mails', array_values( $sent ), HOUR_IN_SECONDS );
			$log                    = self::all();
			$log[ $hash ]['mailed'] = current_time( 'mysql' );
			update_site_option( self::OPTION, $log );
		}
	}

	/** Mail labels; English when called before WordPress can load translations. */
	private static function labels() {
		if ( ! did_action( 'after_setup_theme' ) ) {
			return array(
				'level'   => 'Level',
				'origin'  => 'Origin',
				'message' => 'Message',
				'file'    => 'File',
				'details' => 'Details',
				'url'     => 'Address',
				'user'    => 'User',
				'guest'   => '(visitor / system)',
				'when'    => 'When',
				'times'   => '%1$d occurrences since %2$s',
				'env'     => 'Environment',
				'site'    => 'Site',
				'trace'   => 'Stack trace',
				'full'    => 'Full log',
				'limit'   => 'Identical errors send at most one email every 6 hours.',
			);
		}
		return array(
			'level'   => __( 'Level', 'ondaweb-security' ),
			'origin'  => __( 'Origin', 'ondaweb-security' ),
			'message' => __( 'Message', 'ondaweb-security' ),
			'file'    => __( 'File', 'ondaweb-security' ),
			'details' => __( 'Details', 'ondaweb-security' ),
			'url'     => __( 'Address', 'ondaweb-security' ),
			'user'    => __( 'User', 'ondaweb-security' ),
			'guest'   => __( '(visitor / system)', 'ondaweb-security' ),
			'when'    => __( 'When', 'ondaweb-security' ),
			/* translators: 1: number of occurrences, 2: date and time of the first one */
			'times'   => __( '%1$d occurrences since %2$s', 'ondaweb-security' ),
			'env'     => __( 'Environment', 'ondaweb-security' ),
			'site'    => __( 'Site', 'ondaweb-security' ),
			'trace'   => __( 'Stack trace', 'ondaweb-security' ),
			'full'    => __( 'Full log', 'ondaweb-security' ),
			'limit'   => __( 'Identical errors send at most one email every 6 hours.', 'ondaweb-security' ),
		);
	}

	public static function mail_body( $e ) {
		global $wp_version;
		$l   = self::labels();
		$row = function ( $label, $value ) {
			return str_pad( $label . ':', 13 ) . $value;
		};
		$early = ! did_action( 'after_setup_theme' );
		$fmt   = function ( $mysql ) use ( $early ) {
			return $early ? mysql2date( 'Y-m-d H:i:s', $mysql ) : owum_date( $mysql, true );
		};
		$lines = array(
			$row( $l['level'], self::level_label( $e['level'] ) . ( $e['php'] ? ' (' . $e['php'] . ')' : '' ) ),
			$row( $l['origin'], self::source_label( $e['source'] ) ),
			$row( $l['message'], $e['message'] ),
		);
		if ( $e['file'] ) {
			$lines[] = $row( $l['file'], $e['file'] . ( $e['line'] ? ':' . $e['line'] : '' ) );
		}
		if ( $e['extra'] ) {
			$lines[] = $row( $l['details'], $e['extra'] );
		}
		$lines[] = $row( $l['url'], $e['url'] );
		$lines[] = $row( $l['user'], $e['user'] ? $e['user'] : $l['guest'] );
		$lines[] = $row( $l['when'], $fmt( $e['last'] ) . ( $e['count'] > 1 ? ' (' . sprintf( $l['times'], $e['count'], $fmt( $e['first'] ) ) . ')' : '' ) );
		$lines[] = $row( $l['env'], 'WordPress ' . $wp_version . ' · PHP ' . PHP_VERSION . ' · ' . OWUM_PRODUCT . ' ' . OWUM_VERSION . ( is_multisite() ? ' · multisite' : '' ) );
		$lines[] = $row( $l['site'], network_home_url( '/' ) );
		if ( $e['trace'] ) {
			$lines[] = '';
			$lines[] = $l['trace'] . ':';
			$lines[] = $e['trace'];
		}
		$lines[] = '';
		$lines[] = $l['full'] . ': ' . self::page_url();
		$lines[] = $l['limit'];
		return implode( "\n", $lines );
	}

	public static function page_url() {
		return add_query_arg( 'page', 'owum-errors', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) );
	}

	/* Helpers ------------------------------------------------------------------ */

	public static function level_label( $l ) {
		if ( ! did_action( 'after_setup_theme' ) ) {
			$m = array( 'fatal' => 'Fatal error', 'error' => 'Error', 'warning' => 'Warning', 'notice' => 'Notice' );
		} else {
			$m = array(
				'fatal'   => __( 'Fatal error', 'ondaweb-security' ),
				'error'   => __( 'Error', 'ondaweb-security' ),
				'warning' => __( 'Warning', 'ondaweb-security' ),
				'notice'  => __( 'Notice', 'ondaweb-security' ),
			);
		}
		return isset( $m[ $l ] ) ? $m[ $l ] : $l;
	}

	/**
	 * Display text of an origin code ("plugin|Name", "theme|slug", "core"...).
	 * Entries recorded before 1.5 hold Portuguese text, shown as stored.
	 */
	public static function source_label( $code ) {
		$early = ! did_action( 'after_setup_theme' );
		$parts = explode( '|', (string) $code, 2 );
		$arg   = isset( $parts[1] ) ? $parts[1] : '';
		switch ( $parts[0] ) {
			case 'self':
				return OWUM_PRODUCT;
			case 'mail':
				return $early ? 'Email' : __( 'Email', 'ondaweb-security' );
			case 'core':
				return $early ? 'WordPress (core)' : __( 'WordPress (core)', 'ondaweb-security' );
			case 'other':
				return $early ? 'Other' : __( 'Other', 'ondaweb-security' );
			case 'unknown':
				return $early ? 'Unknown' : __( 'Unknown', 'ondaweb-security' );
			case 'plugin':
				/* translators: %s: plugin name */
				return sprintf( $early ? 'Plugin: %s' : __( 'Plugin: %s', 'ondaweb-security' ), $arg );
			case 'mu':
				/* translators: %s: file name in wp-content/mu-plugins */
				return sprintf( $early ? 'Must-use plugin (mu-plugins): %s' : __( 'Must-use plugin (mu-plugins): %s', 'ondaweb-security' ), $arg );
			case 'theme':
				/* translators: %s: theme folder */
				return sprintf( $early ? 'Theme: %s' : __( 'Theme: %s', 'ondaweb-security' ), $arg );
		}
		return 'Ondaweb Security Updater' === $code ? OWUM_PRODUCT : (string) $code;
	}

	private static function php_type( $t ) {
		$m = array(
			E_ERROR             => 'E_ERROR',
			E_PARSE             => 'E_PARSE',
			E_CORE_ERROR        => 'E_CORE_ERROR',
			E_COMPILE_ERROR     => 'E_COMPILE_ERROR',
			E_USER_ERROR        => 'E_USER_ERROR',
			E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
			E_WARNING           => 'E_WARNING',
			E_USER_WARNING      => 'E_USER_WARNING',
			E_NOTICE            => 'E_NOTICE',
			E_USER_NOTICE       => 'E_USER_NOTICE',
			E_DEPRECATED        => 'E_DEPRECATED',
			E_USER_DEPRECATED   => 'E_USER_DEPRECATED',
		);
		return isset( $m[ $t ] ) ? $m[ $t ] : (string) $t;
	}

	/** Who caused the error, from the file path (returns an origin code). */
	public static function origin( $file ) {
		$f = wp_normalize_path( (string) $file );
		if ( '' === $f ) {
			return 'unknown';
		}
		if ( 0 === strpos( $f, wp_normalize_path( OWUM_DIR ) ) ) {
			return 'self';
		}
		$plugins = wp_normalize_path( WP_PLUGIN_DIR ) . '/';
		if ( 0 === strpos( $f, $plugins ) ) {
			$slug = strtok( substr( $f, strlen( $plugins ) ), '/' );
			return 'plugin|' . self::plugin_name( $slug );
		}
		$mu = wp_normalize_path( WPMU_PLUGIN_DIR ) . '/';
		if ( 0 === strpos( $f, $mu ) ) {
			return 'mu|' . strtok( substr( $f, strlen( $mu ) ), '/' );
		}
		$themes = wp_normalize_path( get_theme_root() ) . '/';
		if ( 0 === strpos( $f, $themes ) ) {
			return 'theme|' . strtok( substr( $f, strlen( $themes ) ), '/' );
		}
		if ( false !== strpos( $f, '/wp-includes/' ) || false !== strpos( $f, '/wp-admin/' ) ) {
			return 'core';
		}
		return 'other';
	}

	private static function plugin_name( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			return $slug;
		}
		foreach ( get_plugins() as $file => $data ) {
			if ( 0 === strpos( $file, $slug . '/' ) || $file === $slug ) {
				return $data['Name'];
			}
		}
		return $slug;
	}

	private static function short_path( $f ) {
		$root = wp_normalize_path( ABSPATH );
		return 0 === strpos( $f, $root ) ? substr( $f, strlen( $root ) ) : $f;
	}

	private static function request_url() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'WP-CLI';
		}
		if ( wp_doing_cron() ) {
			return 'WP-Cron';
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore
		// Never store passwords, keys or tokens that come in the address.
		$uri    = preg_replace( '/([?&](?:pwd|pass|password|key|token|secret|nonce|_wpnonce|g-recaptcha-response|rp_key)=)[^&]*/i', '$1***', $uri );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( $_SERVER['REQUEST_METHOD'] ) : 'get'; // phpcs:ignore
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : ''; // phpcs:ignore
		return strtoupper( $method ) . ' ' . ( $host ? ( is_ssl() ? 'https://' : 'http://' ) . $host : '' ) . self::cut( $uri, 300 );
	}

	private static function cut( $s, $n ) {
		return function_exists( 'mb_substr' ) ? ( mb_strlen( $s ) > $n ? mb_substr( $s, 0, $n ) . '…' : $s ) : substr( $s, 0, $n );
	}
}
