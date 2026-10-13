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
		$s       = owum_settings();
		$subject = sprintf( '[%s] Relatório de atualizações e segurança – %s', $s['client_name'], OWUM_Report::month_label( $ym ) );
		$body    = '<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0;padding:24px;background:#ffffff;">' . OWUM_Report::html( $ym, 'email' ) . '</body></html>';

		// Logos embutidos no e-mail (aparecem mesmo com imagens externas bloqueadas).
		$embed = function ( $phpmailer ) {
			foreach ( array( 'client', 'ondaweb' ) as $which ) {
				$l = owum_logo( $which );
				if ( $l && $l['path'] && file_exists( $l['path'] ) ) {
					$phpmailer->addEmbeddedImage( $l['path'], 'owum-logo-' . $which, basename( $l['path'] ), 'base64', $l['mime'] );
				}
			}
		};
		add_action( 'phpmailer_init', $embed );
		$sent = wp_mail( $to, $subject, $body, array( 'Content-Type: text/html; charset=UTF-8' ) );
		remove_action( 'phpmailer_init', $embed );
		update_site_option(
			'owum_last_mail',
			array(
				'when'  => current_time( 'mysql' ),
				'month' => $ym,
				'ok'    => (bool) $sent,
				'to'    => implode( ', ', $to ),
			)
		);
		return $sent;
	}
}
