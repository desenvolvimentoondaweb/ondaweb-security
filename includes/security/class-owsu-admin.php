<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página "Segurança" e relatório técnico interno.
 */
class OWSU_Admin {

	public static function init() {
		foreach ( array( 'owsu_scan', 'owsu_vuln_update', 'owsu_apply', 'owsu_undo', 'owsu_tech_report' ) as $a ) {
			add_action( 'admin_post_' . $a, array( __CLASS__, $a ) );
		}
		add_action( 'wp_ajax_owsu_scan_step', array( __CLASS__, 'ajax_step' ) );
	}

	private static function url( $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => 'owum-security' ), $args ), $base );
	}

	private static function guard( $action ) {
		if ( ! current_user_can( owum_cap() ) ) {
			wp_die( 'Sem permissão.', 403 );
		}
		check_admin_referer( $action );
	}

	private static function back( $msg, $extra = array() ) {
		wp_safe_redirect( self::url( array_merge( array( 'owsu_msg' => rawurlencode( $msg ) ), $extra ) ) );
		exit;
	}

	/* Handlers ------------------------------------------------------------ */

	public static function owsu_scan() {
		self::guard( 'owsu_scan' );
		OWSU_Security::run_all();
		self::back( 'Verificação concluída.' );
	}

	public static function owsu_vuln_update() {
		self::guard( 'owsu_vuln_update' );
		$r = OWSU_Vulns::update();
		OWSU_Security::run_all();
		self::back( is_wp_error( $r ) ? 'Erro: ' . $r->get_error_message() : 'Base de vulnerabilidades atualizada e verificação concluída.' );
	}

	public static function owsu_apply() {
		self::guard( 'owsu_apply' );
		$id = isset( $_POST['check'] ) ? sanitize_key( wp_unslash( $_POST['check'] ) ) : ''; // phpcs:ignore
		if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
			self::back( 'Erro: verificação desconhecida.' );
		}
		@set_time_limit( 180 ); // phpcs:ignore
		$title = OWSU_Security::definitions()[ $id ]['title'];
		try {
			$r = OWSU_Security::apply( $id );
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'error', 'Aplicar correção "' . $title . '": ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ) );
			self::back( 'Erro inesperado ao aplicar a correção. O detalhe foi salvo no Registro de erros.', array( 'focus' => $id ) );
		}
		if ( is_wp_error( $r ) ) {
			OWUM_ErrorLog::op( 'Aplicar correção "' . $title . '"', $r->get_error_message() );
			self::back( 'Erro: ' . $r->get_error_message(), array( 'focus' => $id ) );
		}
		// A nova verificação roda via HTTP para refletir a correção recém-aplicada.
		self::safe_run_one( $id );
		$scan = OWSU_Security::last_scan();
		$res  = isset( $scan['results'][ $id ] ) ? $scan['results'][ $id ] : array( 'status' => 'info' );
		$msg  = 'Correção aplicada: ' . $title . '.';
		if ( in_array( $res['status'], array( 'crit', 'warn' ), true ) ) {
			$msg .= ' A verificação ainda aponta problema — veja os detalhes do item.';
		}
		self::back( $msg, array( 'focus' => $id ) );
	}

	public static function owsu_undo() {
		self::guard( 'owsu_undo' );
		$id = isset( $_POST['check'] ) ? sanitize_key( wp_unslash( $_POST['check'] ) ) : ''; // phpcs:ignore
		if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
			self::back( 'Erro: verificação desconhecida.' );
		}
		@set_time_limit( 180 ); // phpcs:ignore
		try {
			OWSU_Security::undo( $id );
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'error', 'Desfazer correção "' . OWSU_Security::definitions()[ $id ]['title'] . '": ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ) );
			self::back( 'Erro inesperado ao desfazer. O detalhe foi salvo no Registro de erros.', array( 'focus' => $id ) );
		}
		self::safe_run_one( $id );
		self::back( 'Correção desfeita: ' . OWSU_Security::definitions()[ $id ]['title'] . '.', array( 'focus' => $id ) );
	}

	/* Verificação passo a passo (barra de progresso) ------------------------ */

	private static function tmp_key() {
		return 'owsu_scan_tmp_' . get_current_user_id();
	}

	public static function ajax_step() {
		if ( ! current_user_can( owum_cap() ) || ! check_ajax_referer( 'owsu_scan_step', 'nonce', false ) ) {
			wp_send_json_error( array( 'msg' => 'Sessão expirada. Recarregue a página.' ), 403 );
		}
		@set_time_limit( 120 ); // phpcs:ignore
		$op = isset( $_POST['op'] ) ? sanitize_key( $_POST['op'] ) : ''; // phpcs:ignore

		if ( 'start' === $op ) {
			$steps = array();
			if ( ! empty( $_POST['vuln'] ) && OWSU_Vulns::key() ) { // phpcs:ignore
				$steps[] = array( 'id' => '__vuln', 'label' => 'Baixando a base de vulnerabilidades da Wordfence', 'group' => 'Pode levar até 1 minuto', 'slow' => 1 );
			}
			$groups = OWSU_Security::groups();
			foreach ( OWSU_Security::definitions() as $id => $d ) {
				$steps[] = array( 'id' => $id, 'label' => $d['title'], 'group' => $groups[ $d['group'] ] );
			}
			set_site_transient( self::tmp_key(), array( 'started' => current_time( 'mysql' ), 'results' => array(), 'notes' => array() ), HOUR_IN_SECONDS );
			wp_send_json_success( array( 'steps' => $steps ) );
		}

		$tmp = get_site_transient( self::tmp_key() );
		if ( ! is_array( $tmp ) ) {
			wp_send_json_error( array( 'msg' => 'A verificação expirou. Comece novamente.' ), 409 );
		}

		if ( 'step' === $op ) {
			$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : ''; // phpcs:ignore
			if ( '__vuln' === $id ) {
				$r = OWSU_Vulns::update();
				$v = OWSU_Vulns::get();
				if ( is_wp_error( $r ) ) {
					$tmp['notes'][] = 'Base de vulnerabilidades: ' . $r->get_error_message();
					set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
					wp_send_json_success( array( 'status' => 'warn', 'label' => 'Falhou', 'detail' => $r->get_error_message() ) );
				}
				wp_send_json_success( array( 'status' => 'ok', 'label' => 'OK', 'detail' => number_format_i18n( (int) $v['records'] ) . ' registros analisados' ) );
			}
			if ( ! isset( OWSU_Security::definitions()[ $id ] ) ) {
				wp_send_json_error( array( 'msg' => 'Verificação desconhecida.' ), 400 );
			}
			OWSU_Security::reset_http();
			$res                    = OWSU_Security::run_check( $id );
			$tmp['results'][ $id ]  = $res;
			set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
			wp_send_json_success( array( 'status' => $res['status'], 'label' => OWSU_Security::status_label( $res['status'] ), 'detail' => $res['detail'] ) );
		}

		if ( 'fail' === $op ) {
			// O navegador não recebeu resposta de uma etapa (erro 500, tempo esgotado etc.).
			$id   = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : ''; // phpcs:ignore
			$why  = isset( $_POST['why'] ) ? sanitize_text_field( wp_unslash( $_POST['why'] ) ) : ''; // phpcs:ignore
			$defs = OWSU_Security::definitions();
			OWUM_ErrorLog::add( 'error', 'Verificação "' . ( isset( $defs[ $id ] ) ? $defs[ $id ]['title'] : $id ) . '" não respondeu: ' . $why, array( 'source' => 'Ondaweb Security Updater', 'extra' => 'Etapa da verificação com barra de progresso.' ) );
			if ( isset( $defs[ $id ] ) ) {
				$tmp['results'][ $id ] = array( 'status' => 'info', 'detail' => 'Não foi possível verificar (' . $why . '). Detalhes no Registro de erros.', 'items' => array() );
				set_site_transient( self::tmp_key(), $tmp, HOUR_IN_SECONDS );
			}
			wp_send_json_success();
		}

		if ( 'finish' === $op ) {
			$results = array();
			foreach ( OWSU_Security::definitions() as $id => $d ) {
				$results[ $id ] = isset( $tmp['results'][ $id ] ) ? $tmp['results'][ $id ] : array( 'status' => 'info', 'detail' => 'Não verificado.', 'items' => array() );
			}
			$scan = array(
				'time'    => current_time( 'mysql' ),
				'results' => $results,
				'score'   => OWSU_Security::score( $results ),
			);
			update_site_option( 'owsu_scan', $scan );
			delete_site_transient( self::tmp_key() );
			$msg = 'Verificação concluída: nota ' . $scan['score']['grade'] . ' (' . $scan['score']['score'] . '/100).';
			if ( $tmp['notes'] ) {
				$msg = 'Erro: ' . implode( ' ', $tmp['notes'] ) . ' — ' . $msg;
			}
			wp_send_json_success( array( 'redirect' => self::url( array( 'owsu_msg' => rawurlencode( $msg ) ) ) ) );
		}
		wp_send_json_error( array( 'msg' => 'Operação inválida.' ), 400 );
	}

	private static function safe_run_one( $id ) {
		try {
			OWSU_Security::run_one( $id );
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'warning', 'Nova verificação de "' . $id . '" falhou: ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine() ), false );
		}
	}

	/* Página -------------------------------------------------------------- */

	private static function badge( $status ) {
		return '<span class="owsu-badge ' . esc_attr( $status ) . '">' . esc_html( OWSU_Security::status_label( $status ) ) . '</span>';
	}

	private static function action_form( $action, $id, $label, $class, $confirm ) {
		$busy = 'owsu_undo' === $action ? 'Desfazendo a correção e testando o site…' : 'Aplicando a correção e testando o site…';
		return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline" data-owum-confirm="' . esc_attr( $confirm ) . '" data-owum-busy="' . esc_attr( $busy ) . '">'
			. '<input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="check" value="' . esc_attr( $id ) . '">'
			. wp_nonce_field( $action, '_wpnonce', true, false )
			. '<button type="submit" class="button ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	private static function link( $action, $label, $class = 'page-title-action', $target = '' ) {
		$url = wp_nonce_url( add_query_arg( 'action', $action, admin_url( 'admin-post.php' ) ), $action );
		return '<a class="' . esc_attr( $class ) . '" href="' . esc_url( $url ) . '"' . ( $target ? ' target="' . esc_attr( $target ) . '"' : '' ) . '>' . esc_html( $label ) . '</a>';
	}

	public static function page() {
		$scan  = OWSU_Security::last_scan();
		$defs  = OWSU_Security::definitions();
		$fixes = OWSU_Security::fixes();
		$vul   = OWSU_Vulns::get();
		?>
		<style>
			.owsu-head{display:grid;grid-template-columns:200px 1fr;gap:16px;margin:16px 0}
			@media (max-width:782px){.owsu-head{grid-template-columns:1fr}}
			.owsu-grade{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:16px;text-align:center}
			.owsu-grade .g{font-size:56px;font-weight:700;line-height:1}
			.owsu-grade .s{color:#646970;margin-top:4px}
			.owsu-counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
			.owsu-counts>div{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:12px 14px}
			.owsu-counts .n{font-size:26px;font-weight:600}
			.owsu-counts .l{font-size:11px;text-transform:uppercase;color:#646970;letter-spacing:.04em}
			.owsu-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
			.owsu-badge.crit{background:#fee2e2;color:#991b1b}.owsu-badge.warn{background:#ffedd5;color:#9a3412}
			.owsu-badge.ok{background:#dcfce7;color:#166534}.owsu-badge.info{background:#e0e7ff;color:#3730a3}
			.owsu-table td{vertical-align:top}
			.owsu-table .why{color:#646970;font-size:12px;margin:2px 0 6px}
			.owsu-table .det{margin:0}
			.owsu-table ul.items{margin:6px 0 0 18px;list-style:disc;font-size:12px}
			.owsu-table details.howto summary{cursor:pointer;color:#2271b1;margin-top:6px}
			.owsu-table details.howto>div{margin-top:6px;padding:8px 12px;background:#fff;border-left:3px solid #2271b1}
			.owsu-table .applied{font-size:11px;color:#166534;display:block;margin-bottom:4px}
			.owsu-table tr.owsu-focus{outline:2px solid #2271b1}
			.owsu-filter{margin:6px 0 10px}
			.owsu-filter a{margin-right:10px;text-decoration:none}.owsu-filter a.current{font-weight:600;color:#000}
			tr.owsu-hide,h2.owsu-hide,table.owsu-hide{display:none}
			.owsu-vt td{font-size:12px}
		</style>
		<div class="wrap">
			<h1 class="wp-heading-inline">Segurança</h1>
			<?php
			echo str_replace( '<a ', '<a data-owsu-scan="0" ', self::link( 'owsu_scan', 'Executar verificação' ) ); // phpcs:ignore
			if ( OWSU_Vulns::key() ) {
				echo str_replace( '<a ', '<a data-owsu-scan="1" ', self::link( 'owsu_vuln_update', 'Atualizar base de vulnerabilidades' ) ); // phpcs:ignore
			}
			if ( $scan ) {
				echo self::link( 'owsu_tech_report', 'Relatório técnico (interno)', 'page-title-action', '_blank' ); // phpcs:ignore
			}
			?>
			<hr class="wp-header-end">
			<?php
			if ( ! empty( $_GET['owsu_msg'] ) ) { // phpcs:ignore
				$m   = sanitize_text_field( wp_unslash( rawurldecode( $_GET['owsu_msg'] ) ) ); // phpcs:ignore
				$cls = 0 === strpos( $m, 'Erro' ) ? 'notice-error' : 'notice-success';
				echo '<div class="notice ' . esc_attr( $cls ) . ' is-dismissible"><p>' . esc_html( $m ) . '</p></div>';
			}
			if ( ! OWSU_Vulns::key() ) {
				echo '<div class="notice notice-info"><p>Para verificar vulnerabilidades conhecidas, informe a chave da API Wordfence Intelligence em <a href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) ) . '">Configurações</a>.</p></div>';
			}
			if ( ! $scan ) {
				echo '<p>Nenhuma verificação feita ainda. Clique em <strong>Executar verificação</strong> (leva alguns segundos).</p></div>';
				return;
			}
			$sc = $scan['score'];
			?>
			<div class="owsu-head">
				<div class="owsu-grade">
					<div class="g" style="color:<?php echo esc_attr( OWSU_Security::grade_color( $sc['grade'] ) ); ?>"><?php echo esc_html( $sc['grade'] ); ?></div>
					<div class="s">Nota <?php echo (int) $sc['score']; ?>/100</div>
				</div>
				<div>
					<div class="owsu-counts">
						<div><div class="l">Críticos</div><div class="n" style="color:#991b1b"><?php echo (int) $sc['count']['crit']; ?></div></div>
						<div><div class="l">Atenção</div><div class="n" style="color:#9a3412"><?php echo (int) $sc['count']['warn']; ?></div></div>
						<div><div class="l">OK</div><div class="n" style="color:#166534"><?php echo (int) $sc['count']['ok']; ?></div></div>
						<div><div class="l">Informativos</div><div class="n" style="color:#3730a3"><?php echo (int) $sc['count']['info']; ?></div></div>
					</div>
					<p class="description">Última verificação: <?php echo esc_html( mysql2date( 'd/m/Y H:i', $scan['time'] ) ); ?>. A verificação também roda automaticamente uma vez por dia.
					<?php if ( OWSU_Vulns::key() ) : ?>
						Base de vulnerabilidades: <?php echo ! empty( $vul['time'] ) ? esc_html( mysql2date( 'd/m/Y H:i', $vul['time'] ) ) : 'não baixada'; ?>.
					<?php endif; ?></p>
				</div>
			</div>

			<div class="owsu-filter">
				<a href="#" class="current" data-f="all">Todos</a>
				<a href="#" data-f="pend">Somente pendências (<?php echo (int) ( $sc['count']['crit'] + $sc['count']['warn'] ); ?>)</a>
			</div>

			<?php
			$focus = isset( $_GET['focus'] ) ? sanitize_key( $_GET['focus'] ) : ''; // phpcs:ignore
			foreach ( OWSU_Security::groups() as $gid => $gname ) :
				$ids = array_keys( wp_list_filter( $defs, array( 'group' => $gid ) ) );
				if ( ! $ids ) {
					continue;
				}
				?>
				<h2><?php echo esc_html( $gname ); ?></h2>
				<table class="widefat owsu-table">
					<tbody>
					<?php foreach ( $ids as $id ) :
						$d = $defs[ $id ];
						$r = isset( $scan['results'][ $id ] ) ? $scan['results'][ $id ] : array( 'status' => 'info', 'detail' => 'Ainda não verificado.', 'items' => array() );
						$applied = OWSU_Security::is_on( $id );
						?>
						<tr id="owsu-<?php echo esc_attr( $id ); ?>" data-status="<?php echo esc_attr( $r['status'] ); ?>" class="<?php echo $focus === $id ? 'owsu-focus' : ''; ?>">
							<td style="width:90px"><?php echo self::badge( $r['status'] ); // phpcs:ignore ?></td>
							<td>
								<strong><?php echo esc_html( $d['title'] ); ?></strong>
								<p class="why"><?php echo esc_html( $d['why'] ); ?></p>
								<p class="det"><?php echo esc_html( $r['detail'] ); ?></p>
								<?php
								if ( $r['items'] && 'vulns' !== $id ) {
									$shown = array_slice( $r['items'], 0, 8 );
									$rest  = array_slice( $r['items'], 8 );
									echo '<ul class="items">';
									foreach ( $shown as $it ) {
										echo '<li>' . esc_html( $it ) . '</li>';
									}
									echo '</ul>';
									if ( $rest ) {
										echo '<details><summary style="cursor:pointer;color:#2271b1;font-size:12px;margin-left:18px">mais ' . count( $rest ) . '</summary><ul class="items">';
										foreach ( $rest as $it ) {
											echo '<li>' . esc_html( $it ) . '</li>';
										}
										echo '</ul></details>';
									}
								}
								?>
								<?php if ( 'vulns' === $id ) { self::vuln_table(); } ?>
								<details class="howto"><summary>Como corrigir</summary><div><?php echo wp_kses_post( $d['howto'] ); ?></div></details>
							</td>
							<td style="width:170px;text-align:right">
								<?php
								if ( $applied ) {
									echo '<span class="applied">✓ ' . ( ! empty( $fixes[ $id ]['when'] ) ? 'Aplicado em ' . esc_html( mysql2date( 'd/m/Y', $fixes[ $id ]['when'] ) ) : 'Ativo' ) . '</span>';
									if ( ! empty( $d['config'] ) ) {
										echo '<a class="button" href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) . '#owum-login' ) . '">Configurar</a> ';
									}
									echo self::action_form( 'owsu_undo', $id, 'Desfazer', '', 'login_url' === $id ? "Voltar o login para /wp-login.php?" : 'Desfazer esta correção?' ); // phpcs:ignore
								} elseif ( ! empty( $d['config'] ) && in_array( $r['status'], array( 'crit', 'warn' ), true ) ) {
									echo '<a class="button button-primary" href="' . esc_url( add_query_arg( 'page', 'owum-settings', is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ) ) . '#owum-login' ) . '">Configurar</a>';
								} elseif ( $d['fix'] && in_array( $r['status'], array( 'crit', 'warn' ), true ) ) {
									echo self::action_form( 'owsu_apply', $id, 'Aplicar correção', 'button-primary', "Aplicar a correção \"" . $d['title'] . "\"?\n\nEla pode ser desfeita a qualquer momento por este painel." ); // phpcs:ignore
								}
								?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endforeach; ?>
			<p class="description" style="margin-top:16px">Dados de vulnerabilidades: Wordfence Intelligence (Defiant, Inc.). As correções aplicadas ficam registradas no Histórico.</p>
		</div>
		<script>
		(function(){
			var f=document.querySelector('.owsu-filter');
			f.addEventListener('click',function(e){
				var a=e.target.closest('a');if(!a)return;e.preventDefault();
				f.querySelectorAll('a').forEach(function(x){x.classList.remove('current')});a.classList.add('current');
				var pend=a.dataset.f==='pend';
				document.querySelectorAll('.owsu-table').forEach(function(t){
					var vis=0;
					t.querySelectorAll(':scope>tbody>tr').forEach(function(tr){
						var hide=pend&&!(tr.dataset.status==='crit'||tr.dataset.status==='warn');
						tr.classList.toggle('owsu-hide',hide);if(!hide)vis++;
					});
					t.classList.toggle('owsu-hide',!vis);t.previousElementSibling.classList.toggle('owsu-hide',!vis);
				});
			});
			var el=document.querySelector('tr.owsu-focus');if(el)el.scrollIntoView({block:'center'});
		})();
		</script>
		<?php
	}

	private static function vuln_table() {
		$items = (array) OWSU_Vulns::get()['items'];
		if ( ! $items ) {
			return;
		}
		echo '<table class="widefat striped owsu-vt" style="margin-top:8px"><thead><tr><th>Item</th><th>Instalada</th><th>Vulnerabilidade</th><th>Gravidade</th><th>Corrigida em</th></tr></thead><tbody>';
		foreach ( $items as $it ) {
			$title = esc_html( $it['title'] ) . ( $it['cve'] ? ' <span class="description">(' . esc_html( $it['cve'] ) . ')</span>' : '' );
			if ( $it['ref'] ) {
				$title = '<a href="' . esc_url( $it['ref'] ) . '" target="_blank" rel="noopener">' . $title . '</a>';
			}
			$sev = $it['rating'] ? esc_html( $it['rating'] . ( $it['score'] ? ' (' . $it['score'] . ')' : '' ) ) : '—';
			echo '<tr><td><strong>' . esc_html( $it['name'] ) . '</strong></td><td>' . esc_html( $it['version'] ) . '</td><td>' . $title . '</td><td>' . $sev . '</td><td>' . ( $it['patched'] ? '<strong>' . esc_html( $it['patched'] ) . '</strong>' : '<span style="color:#991b1b">sem correção</span>' ) . '</td></tr>'; // phpcs:ignore
		}
		echo '</tbody></table>';
	}

	/* Relatório técnico (interno) ---------------------------------------- */

	public static function owsu_tech_report() {
		self::guard( 'owsu_tech_report' );
		$scan  = OWSU_Security::last_scan();
		$defs  = OWSU_Security::definitions();
		$fixes = OWSU_Security::fixes();
		$s     = owum_settings();
		if ( ! $scan ) {
			wp_die( 'Execute uma verificação primeiro.' );
		}
		$sc    = $scan['score'];
		$colors = array( 'crit' => array( '#991b1b', '#fee2e2' ), 'warn' => array( '#9a3412', '#ffedd5' ), 'ok' => array( '#166534', '#dcfce7' ), 'info' => array( '#3730a3', '#e0e7ff' ) );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( 'Seguranca-Tecnico-' . sanitize_title( $s['client_name'] ) . '-' . current_time( 'Y-m-d' ) ); ?></title>
<style>
	body{margin:0;background:#f3f4f6;font:13px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#1f2937}
	.bar{position:sticky;top:0;background:#7f1d1d;color:#fff;padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
	.bar button{font:inherit;padding:6px 12px;border:0;border-radius:4px;background:#fff;color:#7f1d1d;font-weight:600;cursor:pointer}
	.page{background:#fff;max-width:960px;margin:24px auto;padding:36px 40px}
	h1{font-size:20px;margin:0 0 4px;color:#7f1d1d} h2{font-size:15px;margin:24px 0 6px;color:#0b3b5c;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
	.conf{display:inline-block;background:#fee2e2;color:#991b1b;font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px;letter-spacing:.05em}
	.item{padding:8px 0;border-bottom:1px solid #f1f1f1;page-break-inside:avoid}
	.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:6px}
	.det{color:#374151;margin:2px 0}.muted{color:#6b7280;font-size:12px}
	ul{margin:4px 0 0 18px;font-size:12px}
	table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:5px 6px;border-bottom:1px solid #e5e7eb;vertical-align:top}
	@media print{body{background:#fff}.bar{display:none}.page{margin:0;padding:0;max-width:none}@page{size:A4;margin:14mm 12mm}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body>
<div class="bar"><button onclick="window.print()">Salvar como PDF / Imprimir</button><span>Documento interno — não encaminhar ao cliente.</span></div>
<div class="page">
	<span class="conf">CONFIDENCIAL – USO INTERNO</span>
	<h1>Relatório técnico de segurança — <?php echo esc_html( $s['client_name'] ); ?></h1>
	<div class="muted">Verificação de <?php echo esc_html( mysql2date( 'd/m/Y H:i', $scan['time'] ) ); ?> · <?php echo esc_html( OWSU_Security::home() ); ?> · Nota <?php echo (int) $sc['score']; ?>/100 (<?php echo esc_html( $sc['grade'] ); ?>) · <?php echo (int) $sc['count']['crit']; ?> críticos, <?php echo (int) $sc['count']['warn']; ?> atenção, <?php echo (int) $sc['count']['ok']; ?> OK</div>
	<?php
	foreach ( OWSU_Security::groups() as $gid => $gname ) {
		$ids = array_keys( wp_list_filter( $defs, array( 'group' => $gid ) ) );
		usort(
			$ids,
			function ( $a, $b ) use ( $scan ) {
				$rank = array( 'crit' => 0, 'warn' => 1, 'info' => 2, 'ok' => 3 );
				return $rank[ $scan['results'][ $a ]['status'] ] <=> $rank[ $scan['results'][ $b ]['status'] ];
			}
		);
		echo '<h2>' . esc_html( $gname ) . '</h2>';
		foreach ( $ids as $id ) {
			$r = $scan['results'][ $id ];
			$c = $colors[ $r['status'] ];
			echo '<div class="item"><span class="b" style="color:' . esc_attr( $c[0] ) . ';background:' . esc_attr( $c[1] ) . '">' . esc_html( OWSU_Security::status_label( $r['status'] ) ) . '</span><strong>' . esc_html( $defs[ $id ]['title'] ) . '</strong>';
			if ( ! empty( $fixes[ $id ]['on'] ) ) {
				echo ' <span class="muted">· correção aplicada em ' . esc_html( mysql2date( 'd/m/Y', $fixes[ $id ]['when'] ) ) . '</span>';
			}
			echo '<div class="det">' . esc_html( $r['detail'] ) . '</div>';
			if ( $r['items'] ) {
				echo '<ul>';
				foreach ( $r['items'] as $it ) {
					echo '<li>' . esc_html( $it ) . '</li>';
				}
				echo '</ul>';
			}
			echo '</div>';
		}
	}
	$vi = (array) OWSU_Vulns::get()['items'];
	if ( $vi ) {
		echo '<h2>Detalhe das vulnerabilidades</h2><table><tr><th>Item</th><th>Versão</th><th>Vulnerabilidade</th><th>CVSS</th><th>Corrigida em</th><th>Recomendação</th></tr>';
		foreach ( $vi as $it ) {
			echo '<tr><td>' . esc_html( $it['name'] ) . '</td><td>' . esc_html( $it['version'] ) . '</td><td>' . esc_html( $it['title'] ) . ( $it['cve'] ? '<br><span class="muted">' . esc_html( $it['cve'] ) . '</span>' : '' ) . '</td><td>' . esc_html( $it['rating'] . ' ' . ( $it['score'] ? $it['score'] : '' ) ) . '</td><td>' . esc_html( $it['patched'] ? $it['patched'] : 'sem correção' ) . '</td><td>' . esc_html( $it['remediation'] ) . '</td></tr>';
		}
		echo '</table><p class="muted">Fonte: Wordfence Intelligence (Defiant, Inc.).</p>';
	}
	?>
</div></body></html>
		<?php
		exit;
	}
}
