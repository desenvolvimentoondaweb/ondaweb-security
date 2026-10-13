<?php
defined( 'ABSPATH' ) || exit;

/**
 * Envio mensal do relatório. Roda dentro do evento diário: no dia configurado
 * (ou no primeiro dia seguinte em que o cron rodar) envia o relatório do mês anterior.
 */
class OWUM_Mailer {

	public static function init() {
		add_action( 'owum_daily', array( __CLASS__, 'maybe_send' ), 20 );
	}

	public static function maybe_send() {
		$s = owum_settings();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		$month = current_time( 'Y-m' );
		if ( (int) current_time( 'j' ) < (int) $s['day'] || get_site_option( 'owum_last_sent' ) === $month ) {
			return;
		}
		OWUM_Collector::force_check();
		if ( self::send( self::previous_month() ) ) {
			update_site_option( 'owum_last_sent', $month );
		}
	}

	public static function previous_month() {
		$first = strtotime( current_time( 'Y-m-01' ) . ' 12:00:00' );
		return gmdate( 'Y-m', strtotime( '-1 month', $first ) );
	}

	public static function recipients() {
		$s    = owum_settings();
		$list = array_filter( array_map( 'trim', explode( ',', (string) $s['emails'] ) ), 'is_email' );
		return array_values( $list );
	}

	/**
	 * @param string $ym Mês (Y-m) do histórico.
	 */
	public static function send( $ym ) {
		$to = self::recipients();
		if ( ! $to ) {
			return false;
		}
		$sent  = false;
		$error = '';
		try {
			$s       = owum_settings();
			$subject = sprintf( '[%s] Relatório de atualizações e segurança – %s', $s['client_name'], OWUM_Report::month_label( $ym ) );
			// Logos por endereço (funcionam com qualquer plugin de envio/SMTP).
			$body = '<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#ffffff;">' . OWUM_Report::html( $ym, 'print' ) . '</body></html>';

			$embed = array( __CLASS__, 'embed_logos' );
			add_action( 'phpmailer_init', $embed );
			$fail = function ( $e ) use ( &$error ) {
				$error = is_wp_error( $e ) ? $e->get_error_message() : '';
			};
			add_action( 'wp_mail_failed', $fail );
			$sent = wp_mail( $to, $subject, $body, array( 'Content-Type: text/html; charset=UTF-8' ) );
			remove_action( 'phpmailer_init', $embed );
			remove_action( 'wp_mail_failed', $fail );
		} catch ( \Throwable $e ) {
			$sent  = false;
			$error = $e->getMessage() . ' (' . basename( $e->getFile() ) . ':' . $e->getLine() . ')';
			OWUM_ErrorLog::add( 'error', 'Relatório por e-mail: ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString(), 'source' => 'Ondaweb Security Updater' ) );
		}
		update_site_option(
			'owum_last_mail',
			array(
				'when'  => current_time( 'mysql' ),
				'month' => $ym,
				'ok'    => (bool) $sent,
				'to'    => implode( ', ', $to ),
				'error' => $error,
			)
		);
		return (bool) $sent;
	}

	/**
	 * Quando o envio usa o PHPMailer do WordPress, embute os logos na mensagem
	 * (aparecem mesmo com imagens externas bloqueadas). Com outros plugins de
	 * envio, os logos continuam pelo endereço da imagem.
	 */
	public static function embed_logos( $phpmailer ) {
		if ( ! is_object( $phpmailer ) || ! method_exists( $phpmailer, 'addEmbeddedImage' ) || ! property_exists( $phpmailer, 'Body' ) ) {
			return;
		}
		foreach ( array( 'client', 'ondaweb' ) as $which ) {
			try {
				$l = owum_logo( $which );
				if ( ! $l || empty( $l['path'] ) || ! is_readable( $l['path'] ) ) {
					continue;
				}
				$cid = 'owum-logo-' . $which;
				if ( $phpmailer->addEmbeddedImage( $l['path'], $cid, basename( $l['path'] ), 'base64', $l['mime'] ) ) {
					$phpmailer->Body = str_replace( 'src="' . esc_attr( $l['url'] ) . '"', 'src="cid:' . $cid . '"', $phpmailer->Body );
				}
			} catch ( \Throwable $e ) {
				OWUM_ErrorLog::add( 'warning', 'Não foi possível embutir o logo no e-mail: ' . $e->getMessage(), array( 'source' => 'Ondaweb Security Updater' ), false );
			}
		}
	}
}
