<?php
defined( 'ABSPATH' ) || exit;

/**
 * Registro de erros.
 *
 * Captura:
 *  - erros fatais do site inteiro (de qualquer plugin, tema ou do WordPress);
 *  - avisos do PHP gerados pelos arquivos deste plugin;
 *  - falhas das operações do plugin (aplicar correções, baixar base de vulnerabilidades,
 *    enviar e-mails, verificações que não puderam ser concluídas etc.).
 *
 * Erros repetidos são agrupados (contador). Erros fatais e falhas do plugin podem ser
 * enviados por e-mail ao desenvolvedor, com limite para não lotar a caixa de entrada.
 */
class OWUM_ErrorLog {

	const OPTION   = 'owum_errors';
	const MAX      = 300;
	const MAX_MAIL = 10; // e-mails por hora, no máximo

	private static $seen_request = array();
	private static $mailing      = false;
	private static $prev_handler = null;

	/* Captura ---------------------------------------------------------------- */

	/** Chamado assim que o plugin carrega (antes de plugins_loaded). */
	public static function boot() {
		// Erros fatais: o WordPress chama este filtro antes de mostrar a tela "Houve um erro crítico".
		add_filter( 'wp_should_handle_php_error', array( __CLASS__, 'on_wp_fatal' ), 1, 2 );
		// Plano B, se o gerenciador de erros do WordPress estiver desativado.
		register_shutdown_function( array( __CLASS__, 'on_shutdown' ) );
		// Avisos do PHP vindos dos arquivos deste plugin.
		self::$prev_handler = set_error_handler( array( __CLASS__, 'on_php_error' ) ); // phpcs:ignore
		// Falhas de envio de e-mail (de qualquer origem).
		add_action( 'wp_mail_failed', array( __CLASS__, 'on_mail_failed' ) );
	}

	private static function is_fatal( $e ) {
		return is_array( $e ) && isset( $e['type'] ) && in_array( (int) $e['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR ), true );
	}

	public static function on_wp_fatal( $should_handle, $error ) {
		// O WordPress também passa avisos comuns por este filtro; registra só erros fatais.
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
		return false; // segue para o tratamento padrão do PHP
	}

	public static function on_mail_failed( $error ) {
		if ( self::$mailing || ! is_wp_error( $error ) ) {
			return;
		}
		$data = $error->get_error_data();
		$to   = is_array( $data ) && ! empty( $data['to'] ) ? implode( ', ', (array) $data['to'] ) : '';
		self::add( 'error', 'Falha ao enviar e-mail: ' . $error->get_error_message(), array( 'source' => 'E-mail', 'extra' => $to ? 'Destinatário: ' . $to : '' ), false );
	}

	private static function record_php( $e ) {
		$msg  = isset( $e['message'] ) ? (string) $e['message'] : '';
		$file = isset( $e['file'] ) ? (string) $e['file'] : '';
		$line = isset( $e['line'] ) ? (int) $e['line'] : 0;
		$key  = md5( $msg . $file . $line );
		if ( isset( self::$seen_request[ $key ] ) ) {
			return; // já registrado nesta requisição (filtro do WP + plano B)
		}
		self::$seen_request[ $key ] = 1;
		$ours = $file && 0 === strpos( wp_normalize_path( $file ), wp_normalize_path( OWUM_DIR ) );
		$s    = owum_settings();
		if ( ! $ours && empty( $s['err_site'] ) ) {
			return;
		}
		// A mensagem de erro fatal do PHP já traz o "Stack trace"; separa para exibir melhor.
		$trace = '';
		if ( false !== strpos( $msg, 'Stack trace:' ) ) {
			list( $msg, $trace ) = array_map( 'trim', explode( 'Stack trace:', $msg, 2 ) );
		}
		self::add( 'fatal', $msg, array( 'file' => $file, 'line' => $line, 'trace' => $trace, 'php' => self::php_type( isset( $e['type'] ) ? $e['type'] : E_ERROR ) ) );
	}

	/* Registro --------------------------------------------------------------- */

	/**
	 * Registra uma ocorrência.
	 *
	 * @param string $level   fatal | error | warning | notice
	 * @param string $message Mensagem.
	 * @param array  $ctx     file, line, trace, source, extra, php
	 * @param bool   $mail    Pode gerar alerta por e-mail.
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
			$log = array( $hash => $entry ) + $log; // mais recentes primeiro
			if ( count( $log ) > self::MAX ) {
				$log = array_slice( $log, 0, self::MAX, true );
			}
			update_site_option( self::OPTION, $log );

			if ( $mail && in_array( $level, array( 'fatal', 'error' ), true ) ) {
				self::maybe_mail( $hash );
			}
		} catch ( \Throwable $t ) {
			// Nunca deixar o registro de erros gerar outro erro.
			return;
		}
	}

	/** Falha de uma operação do plugin (atalho). */
	public static function op( $what, $message, $extra = '' ) {
		self::add( 'error', $what . ': ' . $message, array( 'source' => 'Ondaweb Security Updater', 'extra' => $extra ) );
	}

	public static function all() {
		$log = get_site_option( self::OPTION, array() );
		return is_array( $log ) ? $log : array();
	}

	public static function clear() {
		update_site_option( self::OPTION, array() );
	}

	/** Erros graves ainda não vistos no painel. */
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
		// Mesmo erro: no máximo um e-mail a cada 6 horas.
		if ( $e['mailed'] && strtotime( $e['mailed'] ) > strtotime( current_time( 'mysql' ) ) - 6 * HOUR_IN_SECONDS ) {
			return;
		}
		// No máximo 10 e-mails por hora no total.
		$sent = array_filter( (array) get_site_transient( 'owum_err_mails' ), function ( $t ) { return $t > time() - HOUR_IN_SECONDS; } );
		if ( count( $sent ) >= self::MAX_MAIL ) {
			return;
		}

		self::$mailing = true;
		$site          = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
		$subject       = sprintf( '[%s] %s: %s', $site, 'fatal' === $e['level'] ? 'Erro fatal' : 'Erro', self::cut( $e['message'], 90 ) );
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

	public static function mail_body( $e ) {
		global $wp_version;
		$lines = array(
			'Nível:       ' . self::level_label( $e['level'] ) . ( $e['php'] ? ' (' . $e['php'] . ')' : '' ),
			'Origem:      ' . $e['source'],
			'Mensagem:    ' . $e['message'],
		);
		if ( $e['file'] ) {
			$lines[] = 'Arquivo:     ' . $e['file'] . ( $e['line'] ? ':' . $e['line'] : '' );
		}
		if ( $e['extra'] ) {
			$lines[] = 'Detalhes:    ' . $e['extra'];
		}
		$lines[] = 'Endereço:    ' . $e['url'];
		$lines[] = 'Usuário:     ' . ( $e['user'] ? $e['user'] : '(visitante / sistema)' );
		$lines[] = 'Quando:      ' . mysql2date( 'd/m/Y H:i:s', $e['last'] ) . ( $e['count'] > 1 ? ' (' . $e['count'] . ' ocorrências desde ' . mysql2date( 'd/m/Y H:i', $e['first'] ) . ')' : '' );
		$lines[] = 'Ambiente:    WordPress ' . $wp_version . ' · PHP ' . PHP_VERSION . ' · Plugin ' . OWUM_VERSION . ( is_multisite() ? ' · multisite' : '' );
		$lines[] = 'Site:        ' . network_home_url( '/' );
		if ( $e['trace'] ) {
			$lines[] = '';
			$lines[] = 'Rastreamento:';
			$lines[] = $e['trace'];
		}
		$lines[] = '';
		$lines[] = 'Registro completo: ' . self::page_url();
		$lines[] = 'Erros iguais geram no máximo um e-mail a cada 6 horas.';
		return implode( "\n", $lines );
	}

	public static function page_url() {
		return add_query_arg( 'page', 'owum-errors', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) );
	}

	/* Auxiliares -------------------------------------------------------------- */

	public static function level_label( $l ) {
		$m = array(
			'fatal'   => 'Erro fatal',
			'error'   => 'Erro',
			'warning' => 'Aviso',
			'notice'  => 'Observação',
		);
		return isset( $m[ $l ] ) ? $m[ $l ] : $l;
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

	/** Quem causou o erro, pelo caminho do arquivo. */
	public static function origin( $file ) {
		$f = wp_normalize_path( (string) $file );
		if ( '' === $f ) {
			return 'Desconhecida';
		}
		if ( 0 === strpos( $f, wp_normalize_path( OWUM_DIR ) ) ) {
			return 'Ondaweb Security Updater';
		}
		$plugins = wp_normalize_path( WP_PLUGIN_DIR ) . '/';
		if ( 0 === strpos( $f, $plugins ) ) {
			$slug = strtok( substr( $f, strlen( $plugins ) ), '/' );
			return 'Plugin: ' . self::plugin_name( $slug );
		}
		$mu = wp_normalize_path( WPMU_PLUGIN_DIR ) . '/';
		if ( 0 === strpos( $f, $mu ) ) {
			return 'Plugin obrigatório (mu-plugins): ' . strtok( substr( $f, strlen( $mu ) ), '/' );
		}
		$themes = wp_normalize_path( get_theme_root() ) . '/';
		if ( 0 === strpos( $f, $themes ) ) {
			return 'Tema: ' . strtok( substr( $f, strlen( $themes ) ), '/' );
		}
		if ( false !== strpos( $f, '/wp-includes/' ) || false !== strpos( $f, '/wp-admin/' ) ) {
			return 'WordPress (núcleo)';
		}
		return 'Outro';
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
		// Nunca guarda senhas, chaves ou tokens que venham no endereço.
		$uri    = preg_replace( '/([?&](?:pwd|pass|password|key|token|secret|nonce|_wpnonce|g-recaptcha-response|rp_key)=)[^&]*/i', '$1***', $uri );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( $_SERVER['REQUEST_METHOD'] ) : 'get'; // phpcs:ignore
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : ''; // phpcs:ignore
		return strtoupper( $method ) . ' ' . ( $host ? ( is_ssl() ? 'https://' : 'http://' ) . $host : '' ) . self::cut( $uri, 300 );
	}

	private static function cut( $s, $n ) {
		return function_exists( 'mb_substr' ) ? ( mb_strlen( $s ) > $n ? mb_substr( $s, 0, $n ) . '…' : $s ) : substr( $s, 0, $n );
	}
}
