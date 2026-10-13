<?php
defined( 'ABSPATH' ) || exit;

/**
 * Google reCAPTCHA v2 (caixa "Não sou um robô") ou v3 (invisível) no login,
 * senha perdida e cadastro.
 *
 * Só passa a valer depois de um teste bem-sucedido na tela de Configurações,
 * para que chaves erradas nunca bloqueiem o acesso ao painel.
 *
 * Recuperação de acesso: adicione no wp-config.php
 *     define( 'OWSU_RECAPTCHA_OFF', true );
 */
class OWSU_Captcha {

	const VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
	const ADMIN_URL  = 'https://www.google.com/recaptcha/admin/create';

	public static function cfg() {
		$s = owum_settings();
		return array(
			'v'        => in_array( $s['rc_version'], array( 'v2', 'v3' ), true ) ? $s['rc_version'] : '',
			'site'     => trim( (string) $s['rc_site'] ),
			'secret'   => trim( (string) $s['rc_secret'] ),
			'score'    => min( 0.9, max( 0.1, (float) $s['rc_score'] ) ),
			'verified' => (string) $s['rc_verified'],
		);
	}

	public static function hash( $c ) {
		return md5( $c['v'] . '|' . $c['site'] . '|' . $c['secret'] );
	}

	public static function configured() {
		$c = self::cfg();
		return '' !== $c['v'] && '' !== $c['site'] && '' !== $c['secret'];
	}

	public static function verified() {
		$c = self::cfg();
		return self::configured() && hash_equals( self::hash( $c ), $c['verified'] );
	}

	public static function active() {
		if ( defined( 'OWSU_RECAPTCHA_OFF' ) && OWSU_RECAPTCHA_OFF ) {
			return false;
		}
		return self::verified();
	}

	public static function label() {
		$c = self::cfg();
		return 'v3' === $c['v'] ? 'reCAPTCHA v3 (invisível)' : 'reCAPTCHA v2 (caixa "Não sou um robô")';
	}

	/* Login ----------------------------------------------------------------- */

	public static function init() {
		if ( ! self::active() ) {
			return;
		}
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'login_form', array( __CLASS__, 'field' ) );
		add_action( 'lostpassword_form', array( __CLASS__, 'field' ) );
		add_action( 'register_form', array( __CLASS__, 'field' ) );
		add_filter( 'authenticate', array( __CLASS__, 'check_login' ), 30, 3 );
		add_action( 'lostpassword_post', array( __CLASS__, 'check_lost' ), 10, 1 );
		add_filter( 'registration_errors', array( __CLASS__, 'check_register' ), 10, 3 );
	}

	public static function enqueue() {
		$c = self::cfg();
		if ( 'v3' === $c['v'] ) {
			wp_enqueue_script( 'owsu-recaptcha', 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $c['site'] ), array(), null, true ); // phpcs:ignore
			wp_add_inline_script( 'owsu-recaptcha', self::v3_js( $c['site'] ) );
		} else {
			wp_enqueue_script( 'owsu-recaptcha', 'https://www.google.com/recaptcha/api.js?hl=pt-BR', array(), null, true ); // phpcs:ignore
		}
	}

	/** Script v3: obtém o token no momento do envio (tokens expiram em 2 minutos). */
	public static function v3_js( $site ) {
		return "(function(){var K=" . wp_json_encode( $site ) . ";var A={loginform:'login',lostpasswordform:'lostpassword',registerform:'register',owsurctest:'settings_test'};"
			. "document.addEventListener('submit',function(e){var f=e.target,i=f.querySelector('.owsu-rc3');if(!i||f.getAttribute('data-owsu-ok'))return;e.preventDefault();"
			. "var go=function(t){i.value=t||'';f.setAttribute('data-owsu-ok','1');HTMLFormElement.prototype.submit.call(f);};"
			. "if(!window.grecaptcha){go('');return;}grecaptcha.ready(function(){grecaptcha.execute(K,{action:A[f.id]||'login'}).then(go,function(){go('');});});},true);})();";
	}

	public static function field() {
		$c = self::cfg();
		if ( 'v3' === $c['v'] ) {
			echo '<input type="hidden" name="g-recaptcha-response" class="owsu-rc3" value="">';
			return;
		}
		// O formulário de login tem 272px úteis; a caixa do Google tem 304px.
		echo '<div class="g-recaptcha" data-sitekey="' . esc_attr( $c['site'] ) . '" style="transform:scale(.89);transform-origin:0 0;margin:0 0 4px;"></div>';
	}

	private static function is_form_post() {
		return 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) && ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ); // phpcs:ignore
	}

	private static function token() {
		return isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : ''; // phpcs:ignore
	}

	public static function check_login( $user, $username = '', $password = '' ) {
		global $pagenow;
		if ( ! self::is_form_post() || ! isset( $_POST['log'] ) || 'wp-login.php' !== $pagenow ) { // phpcs:ignore
			return $user;
		}
		$r = self::verify( self::token(), 'login' );
		return is_wp_error( $r ) ? $r : $user;
	}

	public static function check_lost( $errors ) {
		if ( ! self::is_form_post() ) {
			return;
		}
		$r = self::verify( self::token(), 'lostpassword' );
		if ( is_wp_error( $r ) && $errors instanceof WP_Error ) {
			$errors->add( 'owsu_captcha', $r->get_error_message() );
		}
	}

	public static function check_register( $errors, $login = '', $email = '' ) {
		$r = self::verify( self::token(), 'register' );
		if ( is_wp_error( $r ) ) {
			$errors->add( 'owsu_captcha', $r->get_error_message() );
		}
		return $errors;
	}

	/* Verificação no Google ------------------------------------------------- */

	/**
	 * @param string $token  Resposta enviada pelo formulário.
	 * @param string $action Ação esperada (v3).
	 * @param bool   $strict true = falha se o Google não responder (usado no teste); false = libera o login.
	 * @return true|WP_Error
	 */
	public static function verify( $token, $action = 'login', $strict = false, $cfg = null ) {
		$c = $cfg ? $cfg : self::cfg();
		if ( '' === $token ) {
			return new WP_Error( 'owsu_captcha', '<strong>Erro:</strong> confirme que você não é um robô e tente novamente.' );
		}
		$res = wp_remote_post(
			self::VERIFY_URL,
			array(
				'timeout' => 10,
				'body'    => array(
					'secret'   => $c['secret'],
					'response' => $token,
					'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '', // phpcs:ignore
				),
			)
		);
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			$msg = is_wp_error( $res ) ? $res->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code( $res );
			update_site_option( 'owsu_rc_error', array( 'time' => current_time( 'mysql' ), 'msg' => $msg ) );
			if ( $strict ) {
				return new WP_Error( 'owsu_captcha', 'Não foi possível contatar o Google para validar (' . $msg . ').' );
			}
			// Google fora do ar ou bloqueado pelo servidor: não tranca o acesso.
			return true;
		}
		$d = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( empty( $d['success'] ) ) {
			$codes = ! empty( $d['error-codes'] ) ? implode( ', ', (array) $d['error-codes'] ) : '';
			if ( $strict ) {
				return new WP_Error( 'owsu_captcha', 'O Google recusou a verificação' . ( $codes ? ' (' . $codes . ')' : '' ) . '. Confira se as chaves são da versão escolhida e se o domínio está cadastrado.' );
			}
			return new WP_Error( 'owsu_captcha', '<strong>Erro:</strong> a verificação anti-robô falhou. Tente novamente.' );
		}
		if ( 'v3' === $c['v'] ) {
			if ( isset( $d['action'] ) && $d['action'] !== $action ) {
				return new WP_Error( 'owsu_captcha', '<strong>Erro:</strong> a verificação anti-robô falhou. Tente novamente.' );
			}
			if ( ! $strict && isset( $d['score'] ) && (float) $d['score'] < $c['score'] ) {
				return new WP_Error( 'owsu_captcha', '<strong>Erro:</strong> o acesso foi bloqueado pela proteção anti-robô. Tente novamente em alguns minutos.' );
			}
		}
		return true;
	}

	/**
	 * Confere se a chave secreta existe (sem precisar de um token válido).
	 *
	 * @return true|WP_Error|null null = não foi possível consultar o Google.
	 */
	public static function check_secret( $secret ) {
		$res = wp_remote_post( self::VERIFY_URL, array( 'timeout' => 10, 'body' => array( 'secret' => $secret, 'response' => 'owsu-test' ) ) );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
			return null;
		}
		$d = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( ! empty( $d['error-codes'] ) && in_array( 'invalid-input-secret', (array) $d['error-codes'], true ) ) {
			return new WP_Error( 'owsu', 'A chave secreta do reCAPTCHA é inválida.' );
		}
		return true;
	}
}
