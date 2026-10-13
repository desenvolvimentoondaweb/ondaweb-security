<?php
defined( 'ABSPATH' ) || exit;

class OWUM_Admin {

	public static function init() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( __CLASS__, 'menu' ) );
		foreach ( array( 'owum_save_meta', 'owum_refresh', 'owum_report', 'owum_save_settings', 'owum_send_now', 'owum_rc_test' ) as $action ) {
			add_action( 'admin_post_' . $action, array( __CLASS__, $action ) );
		}
		$base = plugin_basename( OWUM_FILE );
		add_filter( 'network_admin_plugin_action_links_' . $base, array( __CLASS__, 'action_links' ) );
		add_filter( 'plugin_action_links_' . $base, array( __CLASS__, 'action_links' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
	}

	private static function page_url( $page = 'owum', $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), $base );
	}

	private static function action_url( $action, $args = array() ) {
		return wp_nonce_url( add_query_arg( array_merge( array( 'action' => $action ), $args ), admin_url( 'admin-post.php' ) ), $action );
	}

	private static function guard( $action ) {
		if ( ! current_user_can( owum_cap() ) ) {
			wp_die( 'Sem permissão.', 403 );
		}
		check_admin_referer( $action );
	}

	public static function menu() {
		$cap   = owum_cap();
		$count = self::pending_count();
		$bubble = $count ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $count . '</span></span>' : '';
		add_menu_page( 'Ondaweb Security Updater', 'Ondaweb Security' . $bubble, $cap, 'owum', array( __CLASS__, 'page_dashboard' ), 'dashicons-shield', 21 );
		add_submenu_page( 'owum', 'Atualizações', 'Atualizações', $cap, 'owum', array( __CLASS__, 'page_dashboard' ) );
		add_submenu_page( 'owum', 'Segurança', 'Segurança', $cap, 'owum-security', array( 'OWSU_Admin', 'page' ) );
		add_submenu_page( 'owum', 'Histórico de atualizações', 'Histórico', $cap, 'owum-history', array( __CLASS__, 'page_history' ) );
		add_submenu_page( 'owum', 'Configurações do relatório', 'Configurações', $cap, 'owum-settings', array( __CLASS__, 'page_settings' ) );
	}

	public static function enqueue( $hook ) {
		if ( false !== strpos( (string) $hook, 'owum-settings' ) ) {
			wp_enqueue_media();
		}
	}

	private static function logo_field( $which, $label, $help ) {
		$s  = owum_settings();
		$id = (int) $s[ 'logo_' . $which ];
		$l  = owum_logo( $which );
		?>
		<tr><th scope="row"><?php echo esc_html( $label ); ?></th>
			<td class="owum-logo" data-which="<?php echo esc_attr( $which ); ?>" data-default="<?php echo 'ondaweb' === $which ? esc_url( owum_default_logo()['url'] ) : ''; ?>">
				<input type="hidden" name="logo_<?php echo esc_attr( $which ); ?>" value="<?php echo (int) $id; ?>">
				<div class="owum-logo-preview" style="margin-bottom:8px;min-height:20px;"><?php if ( $l ) : ?><img src="<?php echo esc_url( $l['url'] ); ?>" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;"><?php endif; ?></div>
				<button type="button" class="button owum-logo-pick">Escolher imagem</button>
				<button type="button" class="button-link owum-logo-remove" style="margin-left:8px;color:#b32d2e;<?php echo $id ? '' : 'display:none;'; ?>"><?php echo 'ondaweb' === $which ? 'Voltar ao logo padrão' : 'Remover'; ?></button>
				<?php if ( 'ondaweb' === $which && ! $id ) : ?><span class="description" style="margin-left:8px">Usando o logo padrão incluído no plugin.</span><?php endif; ?>
				<p class="description"><?php echo esc_html( $help ); ?></p>
			</td></tr>
		<?php
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '"><strong>Abrir painel</strong></a>' );
		return $links;
	}

	private static function pending_count() {
		$n   = 0;
		$p   = get_site_transient( 'update_plugins' );
		$t   = get_site_transient( 'update_themes' );
		$n  += isset( $p->response ) ? count( (array) $p->response ) : 0;
		$n  += isset( $t->response ) ? count( (array) $t->response ) : 0;
		$scan = OWSU_Security::last_scan();
		$n   += $scan ? (int) $scan['score']['count']['crit'] : 0;
		return $n;
	}

	private static function styles() {
		?>
		<style>
			.owum-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
			.owum-card{background:#fff;border:1px solid #dcdcde;border-radius:6px;padding:14px 16px}
			.owum-card .l{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#646970}
			.owum-card .v{font-size:26px;font-weight:600;margin:4px 0}
			.owum-card .s{font-size:12px;color:#646970}
			.owum-ok{color:#166534}.owum-free{color:#1e40af}.owum-paid{color:#9a3412}
			.owum-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
			.owum-badge.ok{background:#dcfce7;color:#166534}.owum-badge.free{background:#dbeafe;color:#1e40af}.owum-badge.paid{background:#ffedd5;color:#9a3412}
			.owum-table td,.owum-table th{vertical-align:middle}
			.owum-table input.regular-text{width:100%}
			.owum-table input.small{width:90px}
			.owum-table details summary{cursor:pointer;color:#2271b1}
			.owum-table details ul{margin:6px 0 0 16px;list-style:disc;font-size:12px}
			.owum-unclassified{font-size:11px;color:#9a3412;display:block}
			.owum-toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0 4px}
			.owum-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0 10px;padding:10px;background:#fff;border:1px solid #dcdcde;border-radius:4px}
			.owum-filters label{font-size:12px;color:#50575e;display:flex;flex-direction:column;gap:2px}
			.owum-filters input[type=search]{min-width:200px}
			.owum-filters .owum-count{margin-left:auto;font-size:12px;color:#50575e;align-self:flex-end}
			.owum-table th.owum-sort{cursor:pointer;user-select:none;white-space:nowrap}
			.owum-table th.owum-sort:hover{color:#2271b1}
			.owum-table th.owum-sort::after{content:'↕';opacity:.35;margin-left:4px;font-size:11px}
			.owum-table th.owum-sort.asc::after{content:'▲';opacity:1}
			.owum-table th.owum-sort.desc::after{content:'▼';opacity:1}
			.owum-table tbody tr.owum-alt{background:#f6f7f7}
			.owum-table.striped>tbody>:nth-child(odd){background:transparent}
			tr.owum-hide{display:none}
		</style>
		<?php
	}

	private static function notice() {
		foreach ( array( 'owum_err' => 'notice-error', 'owum_ok' => 'notice-success', 'owum_warn' => 'notice-warning' ) as $k => $cls ) {
			if ( ! empty( $_GET[ $k ] ) ) { // phpcs:ignore
				echo '<div class="notice ' . esc_attr( $cls ) . ' is-dismissible"><p>' . esc_html( sanitize_text_field( wp_unslash( rawurldecode( $_GET[ $k ] ) ) ) ) . '</p></div>'; // phpcs:ignore
			}
		}
		if ( empty( $_GET['owum_msg'] ) ) { // phpcs:ignore
			return;
		}
		$msgs = array(
			'saved'    => 'Classificações salvas.',
			'checked'  => 'Verificação de atualizações concluída.',
			'settings' => 'Configurações salvas.',
			'sent'     => 'Relatório enviado por e-mail.',
			'notsent'  => 'Não foi possível enviar o e-mail. Verifique os destinatários e o envio de e-mails do servidor (SMTP).',
		);
		$key  = sanitize_key( $_GET['owum_msg'] ); // phpcs:ignore
		if ( isset( $msgs[ $key ] ) ) {
			$cls = 'notsent' === $key ? 'notice-error' : 'notice-success';
			echo '<div class="notice ' . esc_attr( $cls ) . ' is-dismissible"><p>' . esc_html( $msgs[ $key ] ) . '</p></div>';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Painel                                                              */
	/* ------------------------------------------------------------------ */

	public static function page_dashboard() {
		$inv   = OWUM_Collector::inventory();
		$items = array_merge( $inv['plugins'], $inv['themes'] );
		$paid  = count( array_filter( $items, function ( $r ) { return 'paid' === $r['status']; } ) );
		$free  = count( array_filter( $items, function ( $r ) { return 'free' === $r['status']; } ) );
		$core  = $inv['core'];
		$last  = get_site_option( 'owum_last_check' );
		$up    = get_site_transient( 'update_plugins' );
		$last  = $last ? $last : ( isset( $up->last_checked ) ? get_date_from_gmt( gmdate( 'Y-m-d H:i:s', $up->last_checked ) ) : '' );
		self::styles();
		?>
		<div class="wrap">
			<h1 class="wp-heading-inline">Atualizações</h1>
			<a class="page-title-action" href="<?php echo esc_url( self::action_url( 'owum_refresh' ) ); ?>">Verificar atualizações agora</a>
			<a class="page-title-action" target="_blank" href="<?php echo esc_url( self::action_url( 'owum_report', array( 'month' => current_time( 'Y-m' ) ) ) ); ?>">Relatório / PDF</a>
			<hr class="wp-header-end">
			<?php self::notice(); ?>

			<div class="owum-cards">
				<div class="owum-card"><div class="l">WordPress</div><div class="v <?php echo $core['available'] ? 'owum-free' : 'owum-ok'; ?>"><?php echo esc_html( $core['installed'] ); ?></div><div class="s"><?php echo $core['available'] ? 'Disponível: <strong>' . esc_html( $core['available'] ) . '</strong> — <a href="' . esc_url( is_multisite() ? network_admin_url( 'update-core.php' ) : admin_url( 'update-core.php' ) ) . '">atualizar</a>' : 'Versão mais recente'; ?></div></div>
				<?php if ( is_multisite() ) : ?>
				<div class="owum-card"><div class="l">Sites na rede</div><div class="v"><?php echo count( $inv['sites'] ); ?></div><div class="s"><?php echo count( $inv['plugins'] ); ?> plugins · <?php echo count( $inv['themes'] ); ?> temas</div></div>
				<?php else : ?>
				<div class="owum-card"><div class="l">Plugins instalados</div><div class="v"><?php echo count( $inv['plugins'] ); ?></div><div class="s"><?php echo count( $inv['themes'] ); ?> temas</div></div>
				<?php endif; ?>
				<div class="owum-card"><div class="l">Pendências da equipe</div><div class="v owum-free"><?php echo (int) $free; ?></div><div class="s">gratuitos + licença Ondaweb</div></div>
				<div class="owum-card"><div class="l">Pagas pendentes</div><div class="v owum-paid"><?php echo (int) $paid; ?></div><div class="s">solicitar ao cliente</div></div>
			</div>
			<p class="description">Última verificação: <?php echo $last ? esc_html( mysql2date( 'd/m/Y H:i', $last ) ) : '—'; ?>. Itens fora do wordpress.org são sugeridos como <strong>Pago (cliente)</strong>; marque como <strong>Licença Ondaweb</strong> os que a Ondaweb fornece e salve.</p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="owum_save_meta">
				<?php wp_nonce_field( 'owum_save_meta' ); ?>

				<?php
				self::items_table( 'Plugins', $inv['plugins'], $inv['sites'] );
				self::items_table( 'Temas', $inv['themes'], $inv['sites'] );
				?>
				<?php submit_button( 'Salvar classificações' ); ?>
			</form>
		</div>
		<script>
		(function(){
			function vcmp(a,b){
				if(a===b)return 0;if(!a)return -1;if(!b)return 1;
				var x=a.split(/[.\-+]/),y=b.split(/[.\-+]/);
				for(var i=0;i<Math.max(x.length,y.length);i++){
					var p=x[i]||'0',q=y[i]||'0',np=parseInt(p,10),nq=parseInt(q,10);
					if(!isNaN(np)&&!isNaN(nq)&&np!==nq)return np-nq;
					if(isNaN(np)||isNaN(nq)){var c=p.localeCompare(q);if(c)return c;}
				}
				return 0;
			}
			var rank={status:{paid:0,free:1,ok:2},tipo:{pago:0,ondaweb:1,gratuito:2,personalizado:3}};
			function tipoOf(tr){var s=tr.querySelector('select[name$="[tipo]"]');return s?s.value:'';}
			function val(tr,key){
				switch(key){
					case 'name':return tr.dataset.name;
					case 'installed':return tr.dataset.installed;
					case 'available':return tr.dataset.available;
					case 'status':return rank.status[tr.dataset.status];
					case 'tipo':return rank.tipo[tipoOf(tr)];
					case 'uso':return parseInt(tr.dataset.usoN,10);
				}
			}
			document.querySelectorAll('.owum-filters').forEach(function(box){
				var table=document.getElementById(box.dataset.table),tbody=table.querySelector('tbody');
				var rows=[].slice.call(tbody.querySelectorAll('tr'));
				var q=box.querySelector('[data-f=q]'),fs=box.querySelector('[data-f=status]'),ft=box.querySelector('[data-f=tipo]'),
					fu=box.querySelector('[data-f=uso]'),fsite=box.querySelector('[data-f=site]'),out=box.querySelector('.owum-count');
				function apply(){
					var term=q.value.trim().toLowerCase(),n=0;
					rows.forEach(function(tr){
						var ok=(!term||tr.dataset.name.indexOf(term)>-1)
							&&(!fs.value||tr.dataset.status===fs.value)
							&&(!ft.value||tipoOf(tr)===ft.value)
							&&(!fu.value||tr.dataset.uso===fu.value)
							&&(!fsite||!fsite.value||tr.dataset.uso==='rede'||tr.dataset.sites.indexOf('|'+fsite.value+'|')>-1);
						tr.classList.toggle('owum-hide',!ok);
						if(ok){tr.classList.toggle('owum-alt',n%2===1);n++;}
					});
					out.textContent='Mostrando '+n+' de '+rows.length;
				}
				q.addEventListener('keydown',function(e){if(e.key==='Enter')e.preventDefault();});
				[q,fs,ft,fu,fsite].forEach(function(el){if(el){el.addEventListener('input',apply);el.addEventListener('change',apply);}});
				tbody.addEventListener('change',function(e){if(e.target.matches('select[name$="[tipo]"]'))apply();});
				box.querySelector('[data-f=clear]').addEventListener('click',function(){q.value='';[fs,ft,fu,fsite].forEach(function(el){if(el)el.value='';});apply();});
				table.querySelectorAll('th.owum-sort').forEach(function(th){
					th.addEventListener('click',function(){
						var dir=th.classList.contains('asc')?'desc':'asc',key=th.dataset.key;
						table.querySelectorAll('th.owum-sort').forEach(function(h){h.classList.remove('asc','desc');});
						th.classList.add(dir);
						rows.sort(function(a,b){
							var va=val(a,key),vb=val(b,key),c;
							if(key==='installed'||key==='available')c=vcmp(va,vb);
							else if(typeof va==='number')c=va-vb;
							else c=String(va).localeCompare(String(vb),'pt-BR');
							if(!c)c=a.dataset.name.localeCompare(b.dataset.name,'pt-BR');
							return dir==='asc'?c:-c;
						});
						rows.forEach(function(tr){tbody.appendChild(tr);});
						apply();
					});
				});
				apply();
			});
		})();
		</script>
		<?php
	}

	private static function uso_kind( $r ) {
		if ( $r['network_active'] ) {
			return 'rede';
		}
		return $r['site_ids'] ? 'parcial' : 'inativo';
	}

	private static function items_table( $title, $rows, $sites ) {
		$id     = 'owum-' . sanitize_title( $title );
		$counts = array( 'all' => count( $rows ), 'paid' => 0, 'free' => 0, 'ok' => 0 );
		$uso    = array( 'rede' => 0, 'parcial' => 0, 'inativo' => 0 );
		foreach ( $rows as $r ) {
			$counts[ $r['status'] ]++;
			$uso[ self::uso_kind( $r ) ]++;
		}
		?>
		<h2><?php echo esc_html( $title ); ?></h2>
		<div class="owum-filters" data-table="<?php echo esc_attr( $id ); ?>">
			<label>Buscar<input type="search" data-f="q" placeholder="Nome do <?php echo 'Plugins' === $title ? 'plugin' : 'tema'; ?>"></label>
			<label>Situação<select data-f="status">
				<option value="">Todas (<?php echo (int) $counts['all']; ?>)</option>
				<option value="paid">Solicitar ao cliente (<?php echo (int) $counts['paid']; ?>)</option>
				<option value="free">Atualização disponível (<?php echo (int) $counts['free']; ?>)</option>
				<option value="ok">Atualizados (<?php echo (int) $counts['ok']; ?>)</option>
			</select></label>
			<label>Tipo<select data-f="tipo">
				<option value="">Todos</option>
				<option value="gratuito">Gratuito</option>
				<option value="ondaweb">Licença Ondaweb</option>
				<option value="pago">Pago (cliente)</option>
				<option value="personalizado">Personalizado</option>
			</select></label>
			<label>Uso<select data-f="uso">
				<option value="">Todos</option>
				<?php if ( $uso['rede'] ) : ?><option value="rede">Ativo na rede toda (<?php echo (int) $uso['rede']; ?>)</option><?php endif; ?>
				<option value="parcial"><?php echo is_multisite() ? 'Ativo em alguns sites' : 'Ativo'; ?> (<?php echo (int) $uso['parcial']; ?>)</option>
				<option value="inativo"><?php echo is_multisite() ? 'Inativo em todos' : 'Inativo'; ?> (<?php echo (int) $uso['inativo']; ?>)</option>
			</select></label>
			<?php if ( count( $sites ) > 1 ) : ?>
			<label>Ativo no site<select data-f="site">
				<option value="">Qualquer site</option>
				<?php foreach ( $sites as $sid => $info ) : ?>
					<option value="<?php echo (int) $sid; ?>"><?php echo esc_html( $info['name'] . ' — ' . $info['url'] ); ?></option>
				<?php endforeach; ?>
			</select></label>
			<?php endif; ?>
			<label>&nbsp;<button type="button" class="button" data-f="clear">Limpar filtros</button></label>
			<span class="owum-count"></span>
		</div>
		<table class="widefat striped owum-table" id="<?php echo esc_attr( $id ); ?>">
			<thead><tr>
				<th class="owum-sort" data-key="name">Nome</th><th class="owum-sort" data-key="installed">Instalada</th><th class="owum-sort" data-key="available">Disponível</th><th class="owum-sort" data-key="status">Situação</th><th class="owum-sort" data-key="tipo" style="width:150px">Tipo</th><th class="owum-sort" data-key="uso">Uso</th><th>Observações / licença / fornecedor</th><th title="Para plugins pagos que não avisam atualização sozinhos">Última versão conhecida</th>
			</tr></thead>
			<tbody>
			<?php foreach ( $rows as $r ) :
				$k     = $r['key'];
				$names = OWUM_Collector::where_list( $r, $sites );
				?>
				<tr data-status="<?php echo esc_attr( $r['status'] ); ?>" data-name="<?php echo esc_attr( function_exists( 'mb_strtolower' ) ? mb_strtolower( $r['name'] ) : strtolower( $r['name'] ) ); ?>" data-installed="<?php echo esc_attr( $r['installed'] ); ?>" data-available="<?php echo esc_attr( $r['available'] ); ?>" data-uso="<?php echo esc_attr( self::uso_kind( $r ) ); ?>" data-uso-n="<?php echo $r['network_active'] ? 100000 : count( $r['site_ids'] ); ?>" data-sites="|<?php echo esc_attr( implode( '|', $r['site_ids'] ) ); ?>|">
					<td><strong><?php echo esc_html( $r['name'] ); ?></strong><?php echo $r['wporg'] ? '<br><span class="description" style="font-size:11px">wordpress.org</span>' : ''; ?></td>
					<td><?php echo esc_html( $r['installed'] ); ?></td>
					<td><?php echo $r['available'] ? '<strong>' . esc_html( $r['available'] ) . '</strong>' . ( 'manual' === $r['available_src'] ? '<br><span class="description" style="font-size:11px">manual</span>' : '' ) : '—'; ?></td>
					<td><span class="owum-badge <?php echo esc_attr( $r['status'] ); ?>"><?php echo esc_html( OWUM_Collector::status_label( $r['status'] ) ); ?></span></td>
					<td>
						<select name="owum[<?php echo esc_attr( $k ); ?>][tipo]">
							<option value="gratuito" <?php selected( $r['tipo'], 'gratuito' ); ?>>Gratuito</option>
							<option value="ondaweb" <?php selected( $r['tipo'], 'ondaweb' ); ?>>Licença Ondaweb</option>
							<option value="pago" <?php selected( $r['tipo'], 'pago' ); ?>>Pago (cliente)</option>
							<option value="personalizado" <?php selected( $r['tipo'], 'personalizado' ); ?>>Personalizado</option>
						</select>
						<?php if ( ! $r['classified'] ) : ?><span class="owum-unclassified">sugestão automática</span><?php endif; ?>
					</td>
					<td>
						<?php if ( $r['network_active'] || ! $names ) : ?>
							<?php echo esc_html( OWUM_Collector::where_label( $r, $sites ) ); ?>
						<?php else : ?>
							<details><summary><?php echo esc_html( OWUM_Collector::where_label( $r, $sites ) ); ?></summary><ul><?php foreach ( $names as $n ) { echo '<li>' . esc_html( $n ) . '</li>'; } ?></ul></details>
						<?php endif; ?>
					</td>
					<td><input type="text" class="regular-text" name="owum[<?php echo esc_attr( $k ); ?>][obs]" value="<?php echo esc_attr( $r['obs'] ); ?>" placeholder="<?php echo 'pago' === $r['tipo'] ? 'Ex.: licença vence 03/2027 – conta do cliente' : ''; ?>"></td>
					<td><input type="text" class="small" name="owum[<?php echo esc_attr( $k ); ?>][ultima_conhecida]" value="<?php echo esc_attr( $r['known'] ); ?>" placeholder="ex.: 2.4.1"></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	public static function owum_save_meta() {
		self::guard( 'owum_save_meta' );
		$in   = isset( $_POST['owum'] ) && is_array( $_POST['owum'] ) ? wp_unslash( $_POST['owum'] ) : array(); // phpcs:ignore
		$meta = (array) get_site_option( 'owum_meta', array() );
		foreach ( $in as $key => $vals ) {
			$key = sanitize_text_field( $key );
			if ( ! preg_match( '/^(plugin|theme):/', $key ) ) {
				continue;
			}
			$meta[ $key ] = array(
				'tipo'             => ( isset( $vals['tipo'] ) && in_array( $vals['tipo'], array( 'pago', 'ondaweb', 'personalizado' ), true ) ) ? $vals['tipo'] : 'gratuito',
				'obs'              => isset( $vals['obs'] ) ? sanitize_text_field( $vals['obs'] ) : '',
				'ultima_conhecida' => isset( $vals['ultima_conhecida'] ) ? preg_replace( '/[^0-9A-Za-z.\-]/', '', $vals['ultima_conhecida'] ) : '',
			);
		}
		update_site_option( 'owum_meta', $meta );
		wp_safe_redirect( self::page_url( 'owum', array( 'owum_msg' => 'saved' ) ) );
		exit;
	}

	public static function owum_refresh() {
		self::guard( 'owum_refresh' );
		OWUM_Collector::force_check();
		OWUM_Logger::detect();
		wp_safe_redirect( self::page_url( 'owum', array( 'owum_msg' => 'checked' ) ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Relatório para impressão / PDF                                      */
	/* ------------------------------------------------------------------ */

	public static function owum_report() {
		self::guard( 'owum_report' );
		$ym = isset( $_GET['month'] ) && preg_match( '/^\d{4}-\d{2}$/', $_GET['month'] ) ? $_GET['month'] : current_time( 'Y-m' ); // phpcs:ignore
		$s  = owum_settings();
		$months = array();
		$first  = strtotime( current_time( 'Y-m-01' ) . ' 12:00:00' );
		for ( $i = 0; $i < 18; $i++ ) {
			$m            = gmdate( 'Y-m', strtotime( "-{$i} month", $first ) );
			$months[ $m ] = OWUM_Report::month_label( $m );
		}
		$title = 'Relatorio-Atualizacoes-' . sanitize_title( $s['client_name'] ) . '-' . $ym;
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( $title ); ?></title>
<style>
	body{margin:0;background:#f3f4f6;}
	.page{background:#fff;max-width:960px;margin:24px auto;padding:36px 40px;box-shadow:0 1px 3px rgba(0,0,0,.08);}
	.bar{position:sticky;top:0;background:#0b3b5c;color:#fff;padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font:14px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;}
	.bar select,.bar button,.bar a{font:inherit;padding:6px 12px;border-radius:4px;border:0;}
	.bar button{background:#fff;color:#0b3b5c;font-weight:600;cursor:pointer;}
	.bar a{color:#fff;text-decoration:underline;background:none;}
	.bar .hint{opacity:.8;font-size:12px;margin-left:auto;}
	@media print{
		@page{size:A4;margin:14mm 12mm;}
		body{background:#fff;}
		.bar{display:none;}
		.page{box-shadow:none;margin:0;padding:0;max-width:none;}
		tr,td{page-break-inside:avoid;}
		h2{page-break-after:avoid;}
		*{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
	}
</style>
</head>
<body>
<form class="bar" method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="owum_report">
	<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'owum_report' ) ); ?>">
	<label>Mês do histórico:
		<select name="month" onchange="this.form.submit()">
			<?php foreach ( $months as $m => $label ) : ?>
				<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $m, $ym ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<button type="button" onclick="window.print()">Salvar como PDF / Imprimir</button>
	<a href="<?php echo esc_url( self::page_url() ); ?>">Voltar ao painel</a>
	<span class="hint">Na janela de impressão, escolha “Salvar como PDF”.</span>
</form>
<div class="page"><?php echo OWUM_Report::html( $ym ); // phpcs:ignore -- já escapado ?></div>
</body>
</html>
		<?php
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Histórico                                                           */
	/* ------------------------------------------------------------------ */

	public static function page_history() {
		$ym   = isset( $_GET['month'] ) && preg_match( '/^(\d{4}-\d{2}|all)$/', $_GET['month'] ) ? $_GET['month'] : current_time( 'Y-m' ); // phpcs:ignore
		$type = isset( $_GET['type'] ) && in_array( $_GET['type'], array( 'core', 'plugin', 'theme', 'security' ), true ) ? $_GET['type'] : ''; // phpcs:ignore
		if ( 'all' === $ym ) {
			$rows = OWUM_Logger::get( null, null, $type, 2000 );
		} else {
			list( $s, $e ) = OWUM_Report::month_range( $ym );
			$rows          = OWUM_Logger::get( $s, $e, $type, 2000 );
		}
		$first  = strtotime( current_time( 'Y-m-01' ) . ' 12:00:00' );
		self::styles();
		?>
		<div class="wrap">
			<h1 class="wp-heading-inline">Histórico de atualizações</h1>
			<?php if ( 'all' !== $ym ) : ?>
				<a class="page-title-action" target="_blank" href="<?php echo esc_url( self::action_url( 'owum_report', array( 'month' => $ym ) ) ); ?>">Relatório deste mês / PDF</a>
			<?php endif; ?>
			<hr class="wp-header-end">
			<form method="get" class="owum-toolbar">
				<input type="hidden" name="page" value="owum-history">
				<select name="month">
					<option value="all" <?php selected( $ym, 'all' ); ?>>Todo o período</option>
					<?php for ( $i = 0; $i < 24; $i++ ) : $m = gmdate( 'Y-m', strtotime( "-{$i} month", $first ) ); ?>
						<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $ym, $m ); ?>><?php echo esc_html( OWUM_Report::month_label( $m ) ); ?></option>
					<?php endfor; ?>
				</select>
				<select name="type">
					<option value="">Todos os tipos</option>
					<option value="core" <?php selected( $type, 'core' ); ?>>WordPress</option>
					<option value="plugin" <?php selected( $type, 'plugin' ); ?>>Plugins</option>
					<option value="theme" <?php selected( $type, 'theme' ); ?>>Temas</option>
					<option value="security" <?php selected( $type, 'security' ); ?>>Segurança</option>
				</select>
				<?php submit_button( 'Filtrar', 'secondary', '', false ); ?>
				<span class="description"><?php echo count( $rows ); ?> registro(s)</span>
			</form>
			<table class="widefat striped owum-table">
				<thead><tr><th>Data</th><th>Tipo</th><th>Item</th><th>Ação</th><th>De</th><th>Para</th><th>Origem</th><th>Usuário</th><th>Notas</th></tr></thead>
				<tbody>
				<?php if ( ! $rows ) : ?>
					<tr><td colspan="9">Nenhum registro neste período.</td></tr>
				<?php endif; ?>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td style="white-space:nowrap"><?php echo esc_html( mysql2date( 'd/m/Y H:i', $r['logged_at'] ) ); ?></td>
						<td><?php echo esc_html( OWUM_Logger::type_label( $r['item_type'] ) ); ?></td>
						<td><strong><?php echo esc_html( $r['item_name'] ); ?></strong></td>
						<td><?php echo esc_html( OWUM_Logger::action_label( $r['action'] ) ); ?></td>
						<td><?php echo esc_html( $r['old_version'] ? $r['old_version'] : '—' ); ?></td>
						<td><strong><?php echo esc_html( $r['new_version'] ? $r['new_version'] : '—' ); ?></strong></td>
						<td><?php echo esc_html( $r['source'] ); ?></td>
						<td><?php echo esc_html( $r['user_login'] ); ?></td>
						<td><?php echo esc_html( (string) $r['notes'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Configurações                                                       */
	/* ------------------------------------------------------------------ */

	public static function page_settings() {
		$s     = owum_settings();
		$last  = get_site_option( 'owum_last_mail' );
		$next  = null;
		OWUM_Installer::on_main_site(
			function () use ( &$next ) {
				$next = wp_next_scheduled( 'owum_daily' );
			}
		);
		$prev  = OWUM_Mailer::previous_month();
		?>
		<div class="wrap">
			<h1>Configurações</h1>
			<?php self::notice(); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="owum_save_settings">
				<?php wp_nonce_field( 'owum_save_settings' ); ?>
				<h2>Relatório</h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="owum-client">Nome no relatório</label></th>
						<td><input id="owum-client" type="text" class="regular-text" name="client_name" value="<?php echo esc_attr( $s['client_name'] ); ?>"></td></tr>
					<?php
					self::logo_field( 'client', 'Logo do cliente', 'Aparece no canto superior esquerdo do relatório. Use PNG ou JPG (SVG não aparece no Gmail/Outlook).' );
					self::logo_field( 'ondaweb', 'Logo da Ondaweb', 'Aparece no canto superior direito, como suporte técnico. Já vem configurado; troque apenas se quiser outra versão.' );
					?>
					<tr><th scope="row"><label for="owum-emails">Destinatários</label></th>
						<td><input id="owum-emails" type="text" class="large-text" name="emails" value="<?php echo esc_attr( $s['emails'] ); ?>">
						<p class="description">Separe vários e-mails por vírgula.</p></td></tr>
					<tr><th scope="row">Envio mensal</th>
						<td><label><input type="checkbox" name="enabled" value="1" <?php checked( $s['enabled'], 1 ); ?>> Enviar automaticamente o relatório do mês anterior</label></td></tr>
					<tr><th scope="row"><label for="owum-day">Dia do envio</label></th>
						<td><select id="owum-day" name="day"><?php for ( $d = 1; $d <= 28; $d++ ) : ?><option value="<?php echo (int) $d; ?>" <?php selected( (int) $s['day'], $d ); ?>><?php echo (int) $d; ?></option><?php endfor; ?></select>
						<p class="description">Próxima execução da rotina diária: <?php echo $next ? esc_html( get_date_from_gmt( gmdate( 'Y-m-d H:i:s', $next ), 'd/m/Y H:i' ) ) : '<strong>não agendada</strong>'; ?>.
						O WP-Cron depende de visitas ao site; para garantir o horário, configure um cron real no servidor chamando <code><?php echo esc_html( site_url( 'wp-cron.php' ) ); ?></code>.</p></td></tr>
				</table>

				<h2>Vulnerabilidades</h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="owum-wfkey">Chave da API Wordfence Intelligence</label></th>
						<td><input id="owum-wfkey" type="password" autocomplete="off" class="regular-text" name="wf_key" value="<?php echo esc_attr( $s['wf_key'] ); ?>">
						<button type="button" class="button" onclick="var i=document.getElementById('owum-wfkey');i.type=i.type==='password'?'text':'password';">Mostrar</button>
						<p class="description">Gratuita. Gere em <a href="https://www.wordfence.com/threat-intel/vulnerabilities/" target="_blank" rel="noopener">wordfence.com</a> (conta Wordfence → Wordfence Intelligence → API key). Usada para verificar vulnerabilidades conhecidas uma vez por dia.</p></td></tr>
				</table>

				<?php self::login_section( $s ); ?>
				<?php submit_button( 'Salvar configurações' ); ?>
			</form>
			<script>
			window.addEventListener('load',function(){
				document.querySelectorAll('.owum-logo').forEach(function(box){
					var input=box.querySelector('input'),prev=box.querySelector('.owum-logo-preview'),rm=box.querySelector('.owum-logo-remove'),frame;
					box.querySelector('.owum-logo-pick').addEventListener('click',function(){
						if(!window.wp||!wp.media){alert('Biblioteca de mídia indisponível.');return;}
						if(!frame){frame=wp.media({title:'Escolher logo',button:{text:'Usar esta imagem'},library:{type:'image'},multiple:false});
							frame.on('select',function(){var a=frame.state().get('selection').first().toJSON();input.value=a.id;
								prev.innerHTML='<img src="'+a.url+'" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;">';rm.style.display='';});}
						frame.open();
					});
					rm.addEventListener('click',function(){input.value='0';var d=box.dataset.default;prev.innerHTML=d?'<img src="'+d+'" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;">':'';rm.style.display='none';});
				});
			});
			</script>

			<?php self::rc_test_box(); ?>

			<h2>Enviar agora</h2>
			<p>
				<a class="button" href="<?php echo esc_url( self::action_url( 'owum_send_now', array( 'month' => $prev ) ) ); ?>">Enviar relatório de <?php echo esc_html( OWUM_Report::month_label( $prev ) ); ?></a>
				<a class="button" href="<?php echo esc_url( self::action_url( 'owum_send_now', array( 'month' => current_time( 'Y-m' ) ) ) ); ?>">Enviar relatório do mês atual (parcial)</a>
			</p>
			<?php if ( is_array( $last ) ) : ?>
				<p class="description">Último envio: <?php echo esc_html( mysql2date( 'd/m/Y H:i', $last['when'] ) ); ?> — <?php echo esc_html( OWUM_Report::month_label( $last['month'] ) ); ?> para <?php echo esc_html( $last['to'] ); ?> — <?php echo $last['ok'] ? 'enviado' : '<strong style="color:#b32d2e">falhou</strong>'; ?>.</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Proteção do login                                                   */
	/* ------------------------------------------------------------------ */

	private static function login_section( $s ) {
		$slug    = OWSU_Login::saved_slug();
		$wps     = OWSU_Login::wps_active();
		$wpsslug = OWSU_Login::wps_slug();
		$off     = defined( 'OWSU_LOGIN_SLUG_OFF' ) && OWSU_LOGIN_SLUG_OFF;
		$main    = is_multisite() ? get_main_site_id() : null;
		$prefix  = trailingslashit( is_multisite() ? get_home_url( $main, '/' ) : home_url( '/' ) );
		$c       = OWSU_Captcha::cfg();
		$rc_off  = defined( 'OWSU_RECAPTCHA_OFF' ) && OWSU_RECAPTCHA_OFF;
		$rc_err  = get_site_option( 'owsu_rc_error' );
		?>
		<h2 id="owum-login">Proteção do login</h2>
		<?php if ( $wps ) : ?>
			<div class="notice notice-warning inline"><p><strong>O plugin WPS Hide Login está ativo</strong><?php echo $wpsslug ? ' (endereço atual: <code>/' . esc_html( $wpsslug ) . '</code>)' : ''; ?>. Para usar o recurso deste plugin: salve o mesmo endereço abaixo e depois desative o WPS Hide Login — o login continua no mesmo endereço, sem interrupção.</p></div>
		<?php endif; ?>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><label for="owum-slug">Endereço de login</label></th>
				<td>
					<code style="padding:6px 4px;background:none"><?php echo esc_html( $prefix ); ?></code><input id="owum-slug" type="text" class="regular-text" style="width:220px" name="login_slug" value="<?php echo esc_attr( $slug ? $slug : ( $wps ? $wpsslug : '' ) ); ?>" placeholder="ex.: acesso-restrito" autocomplete="off" spellcheck="false">
					<?php if ( OWSU_Login::slug() ) : ?>
						<p style="margin-top:8px"><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> Ativo: <a href="<?php echo esc_url( OWSU_Login::url( $main ) ); ?>" target="_blank"><strong><?php echo esc_html( OWSU_Login::url( $main ) ); ?></strong></a>
						<button type="button" class="button button-small" onclick="navigator.clipboard&&navigator.clipboard.writeText(<?php echo esc_attr( wp_json_encode( OWSU_Login::url( $main ) ) ); ?>);this.textContent='Copiado';">Copiar</button></p>
					<?php elseif ( $off && $slug ) : ?>
						<p style="margin-top:8px;color:#b32d2e"><strong>Desligado pela constante OWSU_LOGIN_SLUG_OFF no wp-config.php.</strong> Remova a constante para reativar.</p>
					<?php endif; ?>
					<p class="description">Substitui o <strong>/wp-login.php</strong>, que passa a responder "página não encontrada", assim como o <strong>/wp-admin</strong> para quem não está logado. Deixe em branco para usar o endereço padrão.<?php echo is_multisite() ? ' Vale para todos os sites da rede, cada um no seu próprio caminho.' : ''; ?> Ao salvar, o novo endereço é enviado por e-mail aos destinatários do relatório.</p>
					<p class="description">Use letras, números e hífen (mínimo 4 caracteres). Evite nomes óbvios como <code>login</code> ou <code>admin</code>.</p>
				</td></tr>
			<tr><th scope="row"><label for="owum-rcv">reCAPTCHA no login</label></th>
				<td>
					<select id="owum-rcv" name="rc_version">
						<option value="" <?php selected( $c['v'], '' ); ?>>Desativado</option>
						<option value="v2" <?php selected( $c['v'], 'v2' ); ?>>v2 — caixa "Não sou um robô"</option>
						<option value="v3" <?php selected( $c['v'], 'v3' ); ?>>v3 — invisível (por pontuação)</option>
					</select>
					<?php
					if ( OWSU_Captcha::active() ) {
						echo ' <span style="margin-left:8px"><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> Ativo no login, senha perdida e cadastro.</span>';
					} elseif ( $rc_off && OWSU_Captcha::verified() ) {
						echo ' <span style="margin-left:8px;color:#b32d2e"><strong>Desligado pela constante OWSU_RECAPTCHA_OFF.</strong></span>';
					} elseif ( OWSU_Captcha::configured() ) {
						echo ' <span style="margin-left:8px;color:#996800"><span class="dashicons dashicons-warning"></span> Aguardando teste — faça o teste abaixo para ativar.</span>';
					}
					?>
					<p class="description">Gere as chaves em <a href="<?php echo esc_url( OWSU_Captcha::ADMIN_URL ); ?>" target="_blank" rel="noopener"><strong>google.com/recaptcha/admin</strong></a>: escolha o mesmo tipo selecionado aqui (as chaves de v2 e v3 são diferentes) e cadastre o domínio <code><?php echo esc_html( wp_parse_url( home_url(), PHP_URL_HOST ) ); ?></code><?php echo is_multisite() ? ' e todos os domínios usados pela rede' : ''; ?>.</p>
				</td></tr>
			<tr class="owum-rc"><th scope="row"><label for="owum-rcsite">Chave do site</label></th>
				<td><input id="owum-rcsite" type="text" class="regular-text" name="rc_site" value="<?php echo esc_attr( $c['site'] ); ?>" autocomplete="off" spellcheck="false"></td></tr>
			<tr class="owum-rc"><th scope="row"><label for="owum-rcsecret">Chave secreta</label></th>
				<td><input id="owum-rcsecret" type="password" class="regular-text" name="rc_secret" value="<?php echo esc_attr( $c['secret'] ); ?>" autocomplete="off">
				<button type="button" class="button" onclick="var i=document.getElementById('owum-rcsecret');i.type=i.type==='password'?'text':'password';">Mostrar</button></td></tr>
			<tr class="owum-rc owum-rc3"><th scope="row"><label for="owum-rcscore">Pontuação mínima (v3)</label></th>
				<td><select id="owum-rcscore" name="rc_score"><?php foreach ( array( '0.3', '0.5', '0.7' ) as $v ) : ?><option value="<?php echo esc_attr( $v ); ?>" <?php selected( number_format( $c['score'], 1 ), $v ); ?>><?php echo esc_html( $v . ( '0.5' === $v ? ' (recomendado)' : ( '0.3' === $v ? ' (mais tolerante)' : ' (mais rígido)' ) ) ); ?></option><?php endforeach; ?></select>
				<p class="description">O Google dá uma nota de 0 (robô) a 1 (humano) para cada login.</p></td></tr>
		</table>
		<?php if ( is_array( $rc_err ) && OWSU_Captcha::active() ) : ?>
			<p class="description">Última falha de comunicação com o Google: <?php echo esc_html( mysql2date( 'd/m/Y H:i', $rc_err['time'] ) . ' — ' . $rc_err['msg'] ); ?>. Nessas falhas o login é liberado para não trancar o acesso.</p>
		<?php endif; ?>
		<details style="margin:4px 0 8px"><summary style="cursor:pointer;color:#2271b1">Recuperação de acesso (se ficar sem conseguir entrar)</summary>
			<p class="description" style="margin-top:6px">Adicione no <code>wp-config.php</code>, acima da linha "That's all, stop editing":</p>
			<pre style="background:#fff;border:1px solid #dcdcde;padding:8px;display:inline-block">define( 'OWSU_LOGIN_SLUG_OFF', true ); // volta o login para /wp-login.php
define( 'OWSU_RECAPTCHA_OFF', true );  // desliga o reCAPTCHA</pre>
			<p class="description">Ou renomeie a pasta do plugin por FTP. Depois de entrar, corrija a configuração e remova as linhas.</p>
		</details>
		<script>
		(function(){var s=document.getElementById('owum-rcv');function t(){document.querySelectorAll('.owum-rc').forEach(function(r){r.style.display=s.value?'':'none';});document.querySelectorAll('.owum-rc3').forEach(function(r){r.style.display=s.value==='v3'?'':'none';});}s.addEventListener('change',t);t();})();
		</script>
		<?php
	}

	/** Caixa de teste: o reCAPTCHA só é ativado depois que funciona de verdade neste domínio. */
	private static function rc_test_box() {
		if ( ! OWSU_Captcha::configured() || OWSU_Captcha::verified() ) {
			return;
		}
		$c = OWSU_Captcha::cfg();
		?>
		<div id="owum-rctest" style="background:#fff;border:1px solid #dcdcde;border-left:4px solid #dba617;padding:12px 16px;margin:16px 0;max-width:720px">
			<h3 style="margin-top:0">Testar e ativar o reCAPTCHA</h3>
			<p>Para evitar que chaves erradas bloqueiem o acesso, o reCAPTCHA só passa a valer no login depois deste teste.
			<?php echo 'v2' === $c['v'] ? 'Marque a caixa abaixo e clique em <strong>Testar e ativar</strong>.' : 'Clique em <strong>Testar e ativar</strong> (o v3 é invisível).'; ?></p>
			<form id="owsurctest" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="owum_rc_test">
				<?php wp_nonce_field( 'owum_rc_test' ); ?>
				<?php if ( 'v2' === $c['v'] ) : ?>
					<div class="g-recaptcha" data-sitekey="<?php echo esc_attr( $c['site'] ); ?>" style="margin:8px 0"></div>
				<?php else : ?>
					<input type="hidden" name="g-recaptcha-response" class="owsu-rc3" value="">
				<?php endif; ?>
				<?php submit_button( 'Testar e ativar', 'primary', 'submit', false ); ?>
			</form>
			<p class="description" style="margin-bottom:0">Se aparecer "Chave inválida" ou "Domínio inválido" na caixa do Google, confira as chaves e os domínios cadastrados.</p>
		</div>
		<?php if ( 'v2' === $c['v'] ) : ?>
			<script src="https://www.google.com/recaptcha/api.js?hl=pt-BR" async defer></script><?php // phpcs:ignore ?>
		<?php else : ?>
			<script src="https://www.google.com/recaptcha/api.js?render=<?php echo rawurlencode( $c['site'] ); ?>"></script><?php // phpcs:ignore ?>
			<script><?php echo OWSU_Captcha::v3_js( $c['site'] ); // phpcs:ignore ?></script>
		<?php endif; ?>
		<?php
	}

	public static function owum_rc_test() {
		self::guard( 'owum_rc_test' );
		$back  = self::page_url( 'owum-settings' ) . '#owum-login';
		$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : ''; // phpcs:ignore
		if ( '' === $token ) {
			wp_safe_redirect( add_query_arg( 'owum_err', rawurlencode( 'O teste não recebeu resposta do reCAPTCHA. Marque a caixa (v2) ou verifique se o script do Google carregou nesta página.' ), $back ) );
			exit;
		}
		$c = OWSU_Captcha::cfg();
		$r = OWSU_Captcha::verify( $token, 'settings_test', true, $c );
		if ( is_wp_error( $r ) ) {
			wp_safe_redirect( add_query_arg( 'owum_err', rawurlencode( 'Teste falhou: ' . wp_strip_all_tags( $r->get_error_message() ) ), $back ) );
			exit;
		}
		$s                = owum_settings();
		$s['rc_verified'] = OWSU_Captcha::hash( $c );
		update_site_option( 'owum_settings', $s );
		OWSU_Security::mark( 'login_captcha', true );
		wp_safe_redirect( add_query_arg( 'owum_ok', rawurlencode( 'Teste concluído: ' . OWSU_Captcha::label() . ' ativado no login, senha perdida e cadastro.' ), $back ) );
		exit;
	}

	public static function owum_save_settings() {
		self::guard( 'owum_save_settings' );
		$emails = isset( $_POST['emails'] ) ? sanitize_text_field( wp_unslash( $_POST['emails'] ) ) : '';
		$emails = implode( ', ', array_filter( array_map( 'trim', explode( ',', $emails ) ), 'is_email' ) );
		$old    = owum_settings();
		$new    = array_merge(
			$old,
			array(
				'client_name' => isset( $_POST['client_name'] ) ? sanitize_text_field( wp_unslash( $_POST['client_name'] ) ) : '',
				'emails'      => $emails,
				'enabled'     => empty( $_POST['enabled'] ) ? 0 : 1,
				'day'         => isset( $_POST['day'] ) ? max( 1, min( 28, (int) $_POST['day'] ) ) : 1,
				'logo_client' => isset( $_POST['logo_client'] ) ? absint( $_POST['logo_client'] ) : 0,
				'logo_ondaweb'=> isset( $_POST['logo_ondaweb'] ) ? absint( $_POST['logo_ondaweb'] ) : 0,
				'wf_key'      => isset( $_POST['wf_key'] ) ? preg_replace( '/[^A-Za-z0-9_\-.]/', '', wp_unslash( $_POST['wf_key'] ) ) : '',
				'rc_version'  => isset( $_POST['rc_version'] ) && in_array( $_POST['rc_version'], array( 'v2', 'v3' ), true ) ? $_POST['rc_version'] : '', // phpcs:ignore
				'rc_site'     => isset( $_POST['rc_site'] ) ? preg_replace( '/[^A-Za-z0-9_\-]/', '', wp_unslash( $_POST['rc_site'] ) ) : '',
				'rc_secret'   => isset( $_POST['rc_secret'] ) ? preg_replace( '/[^A-Za-z0-9_\-]/', '', wp_unslash( $_POST['rc_secret'] ) ) : '',
				'rc_score'    => isset( $_POST['rc_score'] ) ? max( 0.1, min( 0.9, (float) $_POST['rc_score'] ) ) : 0.5,
			)
		);
		$errors = array();
		$notes  = array();

		// Endereço de login.
		$slug = OWSU_Login::validate( isset( $_POST['login_slug'] ) ? wp_unslash( $_POST['login_slug'] ) : '' ); // phpcs:ignore
		if ( is_wp_error( $slug ) ) {
			$errors[] = $slug->get_error_message() . ' O endereço anterior foi mantido.';
		} else {
			$new['login_slug'] = $slug;
		}

		// Chave secreta do reCAPTCHA (confere se existe antes de salvar).
		if ( $new['rc_secret'] && $new['rc_secret'] !== $old['rc_secret'] ) {
			$chk = OWSU_Captcha::check_secret( $new['rc_secret'] );
			if ( is_wp_error( $chk ) ) {
				$errors[]         = $chk->get_error_message() . ' A chave anterior foi mantida.';
				$new['rc_secret'] = $old['rc_secret'];
			}
		}

		update_site_option( 'owum_settings', $new );

		if ( isset( $new['login_slug'] ) && $new['login_slug'] !== $old['login_slug'] ) {
			OWSU_Login::notify( $new['login_slug'] );
			OWSU_Security::mark( 'login_url', '' !== $new['login_slug'] );
			if ( '' !== $new['login_slug'] ) {
				$notes[] = 'Novo endereço de login: ' . OWSU_Login::url( is_multisite() ? get_main_site_id() : null, null, $new['login_slug'] ) . ' (enviado por e-mail aos destinatários).';
			}
		}
		$was = '' !== $old['rc_version'] && hash_equals( (string) $old['rc_verified'], md5( $old['rc_version'] . '|' . $old['rc_site'] . '|' . $old['rc_secret'] ) );
		if ( $was && ! OWSU_Captcha::verified() ) {
			OWSU_Security::mark( 'login_captcha', false );
			if ( OWSU_Captcha::configured() ) {
				$notes[] = 'As chaves do reCAPTCHA mudaram: faça o teste novamente para reativá-lo.';
			}
		}

		$args = array( 'owum_msg' => 'settings' );
		if ( $errors ) {
			$args['owum_err'] = rawurlencode( implode( ' ', $errors ) );
		}
		if ( $notes ) {
			$args['owum_warn'] = rawurlencode( implode( ' ', $notes ) );
		}
		wp_safe_redirect( self::page_url( 'owum-settings', $args ) . ( OWSU_Captcha::configured() && ! OWSU_Captcha::verified() ? '#owum-rctest' : '' ) );
		exit;
	}

	public static function owum_send_now() {
		self::guard( 'owum_send_now' );
		$ym = isset( $_GET['month'] ) && preg_match( '/^\d{4}-\d{2}$/', $_GET['month'] ) ? $_GET['month'] : OWUM_Mailer::previous_month(); // phpcs:ignore
		$ok = OWUM_Mailer::send( $ym );
		wp_safe_redirect( self::page_url( 'owum-settings', array( 'owum_msg' => $ok ? 'sent' : 'notsent' ) ) );
		exit;
	}
}
