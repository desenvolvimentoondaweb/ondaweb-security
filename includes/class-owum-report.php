<?php
defined( 'ABSPATH' ) || exit;

/**
 * Relatório em HTML com estilos inline (compatível com e-mail e com impressão/PDF).
 */
class OWUM_Report {

	const C_TEXT   = '#1f2937';
	const C_MUTED  = '#6b7280';
	const C_LINE   = '#e5e7eb';
	const C_HEAD   = '#0b3b5c';
	const C_OK     = '#166534';
	const C_OK_BG  = '#dcfce7';
	const C_FREE   = '#1e40af';
	const C_FREEBG = '#dbeafe';
	const C_PAID   = '#9a3412';
	const C_PAIDBG = '#ffedd5';

	/** Intervalo [início, fim] de um mês no formato Y-m. */
	public static function month_range( $ym ) {
		$ts    = strtotime( $ym . '-01 00:00:00' );
		$start = gmdate( 'Y-m-01 00:00:00', $ts );
		$end   = gmdate( 'Y-m-t 23:59:59', $ts );
		return array( $start, $end );
	}

	public static function month_label( $ym ) {
		$names = array( 1 => 'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho', 'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro' );
		list( $y, $m ) = array_map( 'intval', explode( '-', $ym ) );
		return ( isset( $names[ $m ] ) ? $names[ $m ] : $m ) . ' de ' . $y;
	}

	public static function badge( $status ) {
		$map   = array(
			'ok'   => array( self::C_OK, self::C_OK_BG ),
			'free' => array( self::C_FREE, self::C_FREEBG ),
			'paid' => array( self::C_PAID, self::C_PAIDBG ),
		);
		$c     = isset( $map[ $status ] ) ? $map[ $status ] : $map['ok'];
		$label = OWUM_Collector::status_label( $status );
		return '<span style="display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap;color:' . $c[0] . ';background:' . $c[1] . ';">' . esc_html( $label ) . '</span>';
	}

	private static function th( $label, $align = 'left' ) {
		return '<th style="text-align:' . $align . ';padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:' . self::C_MUTED . ';border-bottom:2px solid ' . self::C_LINE . ';">' . esc_html( $label ) . '</th>';
	}

	private static function td( $html, $extra = '' ) {
		return '<td style="padding:8px 10px;font-size:13px;color:' . self::C_TEXT . ';border-bottom:1px solid ' . self::C_LINE . ';vertical-align:top;' . $extra . '">' . $html . '</td>';
	}

	private static function h2( $text, $sub = '' ) {
		$out = '<h2 style="font-size:16px;color:' . self::C_HEAD . ';margin:28px 0 4px;">' . esc_html( $text ) . '</h2>';
		if ( $sub ) {
			$out .= '<p style="margin:0 0 10px;font-size:12px;color:' . self::C_MUTED . ';">' . esc_html( $sub ) . '</p>';
		}
		return $out;
	}

	private static function table_open() {
		return '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin:6px 0 4px;">';
	}

	private static function empty_row( $cols, $text ) {
		return '<tr><td colspan="' . (int) $cols . '" style="padding:12px 10px;font-size:13px;color:' . self::C_MUTED . ';border-bottom:1px solid ' . self::C_LINE . ';">' . esc_html( $text ) . '</td></tr>';
	}

	/** Etiqueta "Correção de segurança" para itens com vulnerabilidade conhecida. */
	private static function sec_tag( $key ) {
		if ( ! OWSU_Vulns::for_key( $key ) ) {
			return '';
		}
		return ' <span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#991b1b;background:#fee2e2;white-space:nowrap;">Correção de segurança</span>';
	}

	/** Resumo de segurança para o cliente — sem detalhes técnicos. */
	private static function security_section( $ym, $sec_log ) {
		$scan = OWSU_Security::last_scan();
		if ( ! $scan ) {
			return '';
		}
		$sc    = $scan['score'];
		$pend  = $sc['count']['crit'] + $sc['count']['warn'];
		$vulns = array();
		foreach ( (array) OWSU_Vulns::get()['items'] as $it ) {
			$vulns[ $it['key'] ] = $it['name'];
		}
		$color = OWSU_Security::grade_color( $sc['grade'] );

		$o  = self::h2( 'Segurança', 'Situação na verificação de ' . mysql2date( 'd/m/Y', $scan['time'] ) . '. Os detalhes técnicos ficam com a equipe Ondaweb.' );
		$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:8px 0;margin:0 -8px;"><tr>';
		$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;text-align:center;vertical-align:middle;"><div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">Nota de segurança</div><div style="font-size:34px;font-weight:700;color:' . $color . ';line-height:1.2;">' . esc_html( $sc['grade'] ) . '</div><div style="font-size:12px;color:' . self::C_MUTED . ';">' . (int) $sc['score'] . ' de 100</div></td>';
		$cards = array(
			array( 'Pontos verificados', (string) $sc['total'], 'nesta análise', self::C_HEAD ),
			array( 'Em conformidade', (string) $sc['count']['ok'], 'sem necessidade de ação', self::C_OK ),
			array( 'Em tratamento', (string) $pend, 'acompanhados pela equipe', $pend ? self::C_PAID : self::C_OK ),
		);
		foreach ( $cards as $c ) {
			$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;vertical-align:top;"><div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">' . esc_html( $c[0] ) . '</div><div style="font-size:24px;font-weight:700;color:' . $c[3] . ';margin:4px 0;">' . esc_html( $c[1] ) . '</div><div style="font-size:12px;color:' . self::C_MUTED . ';">' . esc_html( $c[2] ) . '</div></td>';
		}
		$o .= '</tr></table>';

		if ( OWSU_Vulns::key() ) {
			if ( $vulns ) {
				$o .= '<p style="font-size:13px;margin:12px 0 0;">Foram identificadas falhas de segurança conhecidas em <strong>' . count( $vulns ) . '</strong> componente(s) instalado(s). As atualizações que as corrigem estão marcadas com <span style="display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:700;color:#991b1b;background:#fee2e2;">Correção de segurança</span> nas tabelas abaixo e devem ser priorizadas.</p>';
			} else {
				$o .= '<p style="font-size:13px;margin:12px 0 0;color:' . self::C_OK . ';">Nenhuma falha de segurança conhecida nas versões instaladas.</p>';
			}
		}

		// Só as correções que continuam valendo (a última ação do item no mês foi "aplicar" e ela segue ativa).
		$latest = array();
		foreach ( $sec_log as $r ) { // já em ordem do mais recente para o mais antigo
			if ( ! isset( $latest[ $r['item_key'] ] ) ) {
				$latest[ $r['item_key'] ] = $r;
			}
		}
		$applied = array_filter(
			$latest,
			function ( $r ) {
				return 'correcao' === $r['action'] && OWSU_Security::is_on( substr( $r['item_key'], 4 ) );
			}
		);
		if ( $applied ) {
			$o .= '<p style="font-size:13px;margin:14px 0 4px;"><strong>Melhorias de segurança aplicadas em ' . esc_html( self::month_label( $ym ) ) . ':</strong></p><ul style="margin:0 0 0 18px;padding:0;font-size:13px;">';
			foreach ( array_reverse( $applied ) as $r ) {
				$o .= '<li style="margin:2px 0;">' . esc_html( $r['item_name'] ) . ' <span style="color:' . self::C_MUTED . ';font-size:11px;">(' . esc_html( mysql2date( 'd/m/Y', $r['logged_at'] ) ) . ')</span></li>';
			}
			$o .= '</ul>';
		}
		return $o;
	}

	/**
	 * Monta o relatório.
	 *
	 * @param string $ym   Mês do histórico (Y-m).
	 * @param string $mode 'print' (logos por URL) ou 'email' (logos embutidos via CID).
	 */
	public static function html( $ym, $mode = 'print' ) {
		$settings        = owum_settings();
		$inv             = OWUM_Collector::inventory();
		list( $s, $e )   = self::month_range( $ym );
		$log             = OWUM_Logger::get( $s, $e );
		$log             = array_values(
			array_filter(
				$log,
				function ( $r ) {
					return 'inicio' !== $r['action'];
				}
			)
		);
		$sec_log         = array_values( array_filter( $log, function ( $r ) { return 'security' === $r['item_type']; } ) );
		$log             = array_values( array_filter( $log, function ( $r ) { return 'security' !== $r['item_type']; } ) );
		$items           = array_merge( $inv['plugins'], $inv['themes'] );
		$paid            = array_filter( $items, function ( $r ) { return 'paid' === $r['status']; } );
		$free            = array_filter( $items, function ( $r ) { return 'free' === $r['status']; } );
		$core            = $inv['core'];
		$updated_count   = count( array_filter( $log, function ( $r ) { return 'atualizado' === $r['action']; } ) );

		$o  = '<div style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Arial,sans-serif;color:' . self::C_TEXT . ';max-width:900px;margin:0 auto;">';

		// Logos.
		$logo_html = function ( $which, $align ) use ( $mode ) {
			$l = owum_logo( $which );
			if ( ! $l ) {
				return '';
			}
			$src = ( 'email' === $mode && $l['path'] && file_exists( $l['path'] ) ) ? 'cid:owum-logo-' . $which : $l['url'];
			$alt = 'client' === $which ? 'Logo do cliente' : 'Ondaweb';
			return '<img src="' . esc_attr( $src ) . '" alt="' . esc_attr( $alt ) . '" height="56" style="height:56px;max-height:56px;width:auto;max-width:220px;display:inline-block;border:0;">';
		};
		$lc = $logo_html( 'client', 'left' );
		$lo = $logo_html( 'ondaweb', 'right' );
		if ( $lc || $lo ) {
			$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:14px;"><tr>';
			$o .= '<td style="text-align:left;vertical-align:middle;">' . $lc . '</td>';
			$o .= '<td style="text-align:right;vertical-align:middle;">' . ( $lo ? '<div style="font-size:10px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;">Suporte técnico</div>' . $lo : '' ) . '</td>';
			$o .= '</tr></table>';
		}

		// Cabeçalho.
		$o .= '<div style="border-bottom:3px solid ' . self::C_HEAD . ';padding-bottom:12px;margin-bottom:16px;">';
		$o .= '<div style="font-size:12px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.06em;">Relatório de atualizações e segurança</div>';
		$o .= '<h1 style="font-size:22px;margin:4px 0;color:' . self::C_HEAD . ';">' . esc_html( $settings['client_name'] ) . '</h1>';
		$o .= '<div style="font-size:13px;color:' . self::C_MUTED . ';">Período: <strong style="color:' . self::C_TEXT . ';">' . esc_html( self::month_label( $ym ) ) . '</strong> · Situação das versões em ' . esc_html( current_time( 'd/m/Y' ) . ' às ' . current_time( 'H:i' ) ) . ( is_multisite() ? ' · ' . count( $inv['sites'] ) . ( 1 === count( $inv['sites'] ) ? ' site na rede' : ' sites na rede' ) : '' ) . '</div>';
		$o .= '</div>';

		// Resumo.
		$cards = array(
			array( 'WordPress', esc_html( $core['installed'] ), $core['available'] ? 'Disponível: ' . esc_html( $core['available'] ) : 'Versão mais recente', $core['available'] ? self::C_FREE : self::C_OK ),
			array( 'Atualizações no período', (string) $updated_count, 'registradas no histórico', self::C_HEAD ),
			array( 'Pendências da equipe', (string) count( $free ), 'aplicadas pela Ondaweb', self::C_FREE ),
			array( 'Pendências pagas', (string) count( $paid ), 'precisam de autorização', self::C_PAID ),
		);
		$o .= '<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:separate;border-spacing:8px 0;margin:0 -8px;"><tr>';
		foreach ( $cards as $c ) {
			$o .= '<td style="width:25%;border:1px solid ' . self::C_LINE . ';border-radius:8px;padding:12px;vertical-align:top;">';
			$o .= '<div style="font-size:11px;color:' . self::C_MUTED . ';text-transform:uppercase;letter-spacing:.04em;">' . esc_html( $c[0] ) . '</div>';
			$o .= '<div style="font-size:24px;font-weight:700;color:' . $c[3] . ';margin:4px 0;">' . $c[1] . '</div>';
			$o .= '<div style="font-size:12px;color:' . self::C_MUTED . ';">' . $c[2] . '</div>';
			$o .= '</td>';
		}
		$o .= '</tr></table>';

		$o .= self::security_section( $ym, $sec_log );

		// Pendências pagas.
		$o .= self::h2( 'Atualizações que precisam de autorização do cliente', 'Plugins/temas pagos com nova versão. A atualização depende de licença ativa ou de compra/renovação.' );
		$o .= self::table_open() . '<tr>' . self::th( 'Item' ) . self::th( 'Instalada' ) . self::th( 'Disponível' ) . self::th( 'Uso' ) . self::th( 'Observações / licença' ) . '</tr>';
		if ( ! $paid ) {
			$o .= self::empty_row( 5, 'Nenhuma pendência paga no momento.' );
		}
		foreach ( $paid as $r ) {
			$avail = esc_html( $r['available'] ) . ( 'manual' === $r['available_src'] ? ' <span style="color:' . self::C_MUTED . ';font-size:11px;">(informada manualmente)</span>' : '' );
			$o    .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['type'] ) ) . '</span>' ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_PAID . ';">' . $avail . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( esc_html( $r['obs'] ) ) . '</tr>';
		}
		$o .= '</table>';

		// Pendências gratuitas.
		$o .= self::h2( 'Atualizações disponíveis – aplicadas pela Ondaweb', 'Plugins gratuitos e plugins com licença fornecida pela Ondaweb. Não exigem ação do cliente.' );
		$o .= self::table_open() . '<tr>' . self::th( 'Item' ) . self::th( 'Instalada' ) . self::th( 'Disponível' ) . self::th( 'Uso' ) . '</tr>';
		if ( $core['available'] ) {
			$o .= '<tr>' . self::td( '<strong>WordPress (core)</strong>' . self::sec_tag( 'core' ) ) . self::td( esc_html( $core['installed'] ) ) . self::td( '<strong style="color:' . self::C_FREE . ';">' . esc_html( $core['available'] ) . '</strong>' ) . self::td( is_multisite() ? 'Rede (todos os sites)' : 'Site' ) . '</tr>';
		}
		if ( ! $free && ! $core['available'] ) {
			$o .= self::empty_row( 4, 'Tudo atualizado.' );
		}
		foreach ( $free as $r ) {
			$o .= '<tr>' . self::td( '<strong>' . esc_html( $r['name'] ) . '</strong>' . self::sec_tag( $r['key'] ) . '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['type'] ) . ' · ' . OWUM_Collector::tipo_label( $r['tipo'] ) ) . '</span>' ) . self::td( esc_html( $r['installed'] ) ) . self::td( '<strong style="color:' . self::C_FREE . ';">' . esc_html( $r['available'] ) . '</strong>' ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . '</tr>';
		}
		$o .= '</table>';

		// Histórico do mês.
		$o .= self::h2( 'Atualizações realizadas em ' . self::month_label( $ym ) );
		$o .= self::table_open() . '<tr>' . self::th( 'Data' ) . self::th( 'Item' ) . self::th( 'Ação' ) . self::th( 'Versão' ) . self::th( 'Origem' ) . '</tr>';
		if ( ! $log ) {
			$o .= self::empty_row( 5, 'Nenhuma alteração registrada neste período.' );
		}
		foreach ( $log as $r ) {
			$ver = $r['old_version'] && $r['new_version'] ? esc_html( $r['old_version'] ) . ' → <strong>' . esc_html( $r['new_version'] ) . '</strong>' : esc_html( $r['new_version'] ? $r['new_version'] : $r['old_version'] );
			$o  .= '<tr>' . self::td( esc_html( mysql2date( 'd/m/Y H:i', $r['logged_at'] ) ), 'white-space:nowrap;' ) . self::td( '<strong>' . esc_html( $r['item_name'] ) . '</strong><br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( OWUM_Logger::type_label( $r['item_type'] ) ) . '</span>' ) . self::td( esc_html( OWUM_Logger::action_label( $r['action'] ) ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( $r['source'] ) . ( $r['user_login'] && '—' !== $r['user_login'] ? '<br><span style="font-size:11px;color:' . self::C_MUTED . ';">' . esc_html( $r['user_login'] ) . '</span>' : '' ) ) . '</tr>';
		}
		$o .= '</table>';

		// Inventário.
		foreach ( array( 'plugins' => 'Inventário de plugins', 'themes' => 'Inventário de temas' ) as $k => $title ) {
			$o .= self::h2( $title, count( $inv[ $k ] ) . ( is_multisite() ? ' instalados na rede.' : ' instalados.' ) );
			$o .= self::table_open() . '<tr>' . self::th( 'Nome' ) . self::th( 'Versão' ) . self::th( 'Tipo' ) . self::th( 'Uso' ) . self::th( 'Situação' ) . '</tr>';
			foreach ( $inv[ $k ] as $r ) {
				$ver = esc_html( $r['installed'] ) . ( $r['available'] ? ' <span style="color:' . self::C_MUTED . ';">→ ' . esc_html( $r['available'] ) . '</span>' : '' );
				$o  .= '<tr>' . self::td( esc_html( $r['name'] ) ) . self::td( $ver, 'white-space:nowrap;' ) . self::td( esc_html( OWUM_Collector::tipo_label( $r['tipo'] ) ) ) . self::td( esc_html( OWUM_Collector::where_label( $r, $inv['sites'] ) ) ) . self::td( self::badge( $r['status'] ) ) . '</tr>';
			}
			$o .= '</table>';
		}

		$o .= '<p style="margin-top:28px;font-size:11px;color:' . self::C_MUTED . ';border-top:1px solid ' . self::C_LINE . ';padding-top:10px;">Relatório gerado automaticamente pelo Ondaweb Security Updater · ' . esc_html( network_home_url( '/' ) ) . '</p>';
		$o .= '</div>';

		return $o;
	}
}
