<?php
defined( 'ABSPATH' ) || exit;

class OWUM_Admin {

	public static function init() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( __CLASS__, 'menu' ) );
		foreach ( array( 'owum_save_meta', 'owum_refresh', 'owum_report', 'owum_save_settings', 'owum_send_now', 'owum_rc_test', 'owum_err_clear', 'owum_err_export', 'owum_err_test' ) as $action ) {
			add_action( 'admin_post_' . $action, array( __CLASS__, $action ) );
		}
		$base = plugin_basename( OWUM_FILE );
		add_filter( 'network_admin_plugin_action_links_' . $base, array( __CLASS__, 'action_links' ) );
		add_filter( 'plugin_action_links_' . $base, array( __CLASS__, 'action_links' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'admin_footer', array( __CLASS__, 'progress_ui' ) );
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
			wp_die( esc_html__( 'You are not allowed to do this.', 'ondaweb-security' ), 403 );
		}
		check_admin_referer( $action );
	}

	public static function menu() {
		$cap   = owum_cap();
		$count = self::pending_count();
		$bubble = $count ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $count . '</span></span>' : '';
		add_menu_page( OWUM_PRODUCT, 'Ondaweb Security' . $bubble, $cap, 'owum', array( __CLASS__, 'page_dashboard' ), 'dashicons-shield', 21 );
		add_submenu_page( 'owum', __( 'Updates', 'ondaweb-security' ), __( 'Updates', 'ondaweb-security' ), $cap, 'owum', array( __CLASS__, 'page_dashboard' ) );
		add_submenu_page( 'owum', __( 'Security', 'ondaweb-security' ), __( 'Security', 'ondaweb-security' ), $cap, 'owum-security', array( 'OWSU_Admin', 'page' ) );
		add_submenu_page( 'owum', __( 'Update history', 'ondaweb-security' ), __( 'History', 'ondaweb-security' ), $cap, 'owum-history', array( __CLASS__, 'page_history' ) );
		$errs = OWUM_ErrorLog::unseen();
		add_submenu_page( 'owum', __( 'Error log', 'ondaweb-security' ), __( 'Error log', 'ondaweb-security' ) . ( $errs ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $errs . '</span></span>' : '' ), $cap, 'owum-errors', array( __CLASS__, 'page_errors' ) );
		add_submenu_page( 'owum', __( 'Settings', 'ondaweb-security' ), __( 'Settings', 'ondaweb-security' ), $cap, 'owum-settings', array( __CLASS__, 'page_settings' ) );
	}

	public static function enqueue( $hook ) {
		if ( false !== strpos( (string) $hook, 'owum-settings' ) ) {
			wp_enqueue_media();
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore
		if ( 0 === strpos( $page, 'owum' ) ) {
			wp_enqueue_style( 'owum-admin', plugins_url( 'assets/admin.css', OWUM_FILE ), array(), OWUM_VERSION );
		}
	}

	/** Ondaweb bar shown at the top of every screen of the plugin. */
	public static function brand_bar() {
		$s      = owum_settings();
		$client = $s['client_name'] ? $s['client_name'] : OWUM_Report::site_host();
		?>
		<div class="owum-brandbar">
			<div class="logo">
				<img src="<?php echo esc_url( plugins_url( 'assets/logo-ondaweb-white.png', OWUM_FILE ) ); ?>" alt="<?php echo esc_attr( OWUM_BRAND ); ?>">
				<span class="prod">Security Updater</span>
			</div>
			<div class="site"><b><?php esc_html_e( 'Client', 'ondaweb-security' ); ?></b><?php echo esc_html( $client ); ?></div>
		</div>
		<?php
	}

	private static function logo_field( $which, $label, $help ) {
		$s  = owum_settings();
		$id = (int) $s[ 'logo_' . $which ];
		$l  = owum_logo( $which );
		?>
		<tr><th scope="row"><?php echo esc_html( $label ); ?></th>
			<td class="owum-logo" data-which="<?php echo esc_attr( $which ); ?>" data-default="">
				<input type="hidden" name="logo_<?php echo esc_attr( $which ); ?>" value="<?php echo (int) $id; ?>">
				<div class="owum-logo-preview" style="margin-bottom:8px;min-height:20px;"><?php if ( $l ) : ?><img src="<?php echo esc_url( $l['url'] ); ?>" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;"><?php endif; ?></div>
				<button type="button" class="button owum-logo-pick"><?php esc_html_e( 'Choose image', 'ondaweb-security' ); ?></button>
				<button type="button" class="button-link owum-logo-remove" style="margin-left:8px;color:#b32d2e;<?php echo $id ? '' : 'display:none;'; ?>"><?php esc_html_e( 'Remove', 'ondaweb-security' ); ?></button>
				<p class="description"><?php echo esc_html( $help ); ?></p>
			</td></tr>
		<?php
	}

	/**
	 * Progress / loading window used on every screen of the plugin:
	 * - security check item by item (with a progress bar);
	 * - "working…" indicator for slow actions (apply a fix, send the report, etc.).
	 */
	public static function progress_ui() {
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore
		if ( 0 !== strpos( $page, 'owum' ) ) {
			return;
		}
		$cfg = array(
			'ajax'  => admin_url( 'admin-ajax.php' ),
			'nonce' => wp_create_nonce( 'owsu_scan_step' ),
			'i18n'  => array(
				'dontClose'  => __( 'Do not close this page.', 'ondaweb-security' ),
				'wait'       => __( 'Please wait', 'ondaweb-security' ),
				'processing' => __( 'Processing…', 'ondaweb-security' ),
				'fewSeconds' => __( 'This may take a few seconds. Do not close this page.', 'ondaweb-security' ),
				'serverErr'  => __( 'server error', 'ondaweb-security' ),
				'timeout'    => __( 'timed out', 'ondaweb-security' ),
				'noResponse' => __( 'no response from the server', 'ondaweb-security' ),
				'scanTitle'  => __( 'Checking the site\'s security', 'ondaweb-security' ),
				'scanSub'    => __( 'Each item is tested in turn. Do not close this page.', 'ondaweb-security' ),
				'cancelled'  => __( 'Cancelled.', 'ondaweb-security' ),
				'grading'    => __( 'Calculating the grade…', 'ondaweb-security' ),
				/* translators: %s: number of seconds (JavaScript placeholder) */
				'secsLeft'   => __( '≈ %s s left', 'ondaweb-security' ),
				'noAnswer'   => __( 'No response', 'ondaweb-security' ),
				'cantGoOn'   => __( 'Could not continue:', 'ondaweb-security' ),
				'close'      => __( 'Close', 'ondaweb-security' ),
			),
		);
		?>
		<style>
			#owum-modal{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:100000;display:none;align-items:center;justify-content:center;padding:16px}
			#owum-modal.on{display:flex}
			#owum-modal .box{background:#fff;border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,.25);width:100%;max-width:560px;padding:22px 24px;max-height:90vh;display:flex;flex-direction:column}
			#owum-modal h2{margin:0 0 4px;font-size:18px}
			#owum-modal .sub{color:#646970;margin:0 0 14px}
			#owum-modal .bar{height:10px;background:#f0f0f1;border-radius:6px;overflow:hidden}
			#owum-modal .bar span{display:block;height:100%;width:0;background:#2271b1;transition:width .3s}
			#owum-modal.busy .bar span{width:35%;animation:owumind 1.2s ease-in-out infinite}
			@keyframes owumind{0%{margin-left:-35%}100%{margin-left:100%}}
			#owum-modal .row{display:flex;justify-content:space-between;align-items:baseline;margin:8px 0 2px;gap:12px}
			#owum-modal .cur{font-weight:600}
			#owum-modal .grp{color:#646970;font-size:12px}
			#owum-modal .pct{font-variant-numeric:tabular-nums;color:#1d2327;font-weight:600}
			#owum-modal ul{list-style:none;margin:12px 0 0;padding:0;overflow:auto;border-top:1px solid #f0f0f1;flex:1;min-height:0}
			#owum-modal li{display:flex;gap:8px;align-items:baseline;padding:5px 0;border-bottom:1px solid #f6f7f7;font-size:12px}
			#owum-modal li b{flex:0 0 78px}
			#owum-modal .owsu-badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px;font-weight:600}
			#owum-modal .owsu-badge.crit{background:#fee2e2;color:#991b1b}#owum-modal .owsu-badge.warn{background:#ffedd5;color:#9a3412}
			#owum-modal .owsu-badge.ok{background:#dcfce7;color:#166534}#owum-modal .owsu-badge.info{background:#e0e7ff;color:#3730a3}
			#owum-modal .foot{display:flex;justify-content:space-between;align-items:center;margin-top:14px}
			#owum-modal .spin{display:inline-block;width:14px;height:14px;border:2px solid #c3c4c7;border-top-color:#2271b1;border-radius:50%;animation:owumspin .8s linear infinite;vertical-align:-2px;margin-right:6px}
			@keyframes owumspin{to{transform:rotate(360deg)}}
		</style>
		<div id="owum-modal" role="dialog" aria-modal="true" aria-live="polite">
			<div class="box">
				<h2 class="ttl"><?php esc_html_e( 'Working…', 'ondaweb-security' ); ?></h2>
				<p class="sub"><?php esc_html_e( 'Do not close this page.', 'ondaweb-security' ); ?></p>
				<div class="bar"><span></span></div>
				<div class="row"><span class="cur"><span class="spin"></span><span class="txt"><?php esc_html_e( 'Preparing…', 'ondaweb-security' ); ?></span></span><span class="pct"></span></div>
				<div class="grp"></div>
				<ul></ul>
				<div class="foot"><span class="grp tm"></span><button type="button" class="button cancel" style="display:none"><?php esc_html_e( 'Cancel', 'ondaweb-security' ); ?></button></div>
			</div>
		</div>
		<script>
		(function(){
			var C=<?php echo wp_json_encode( $cfg ); ?>,T=C.i18n;
			var M=document.getElementById('owum-modal');if(!M)return;
			var q=function(s){return M.querySelector(s);};
			function open(title,sub,busy){q('.ttl').textContent=title;q('.sub').textContent=sub||T.dontClose;M.classList.toggle('busy',!!busy);q('.bar span').style.width=busy?'':'0';q('ul').innerHTML='';q('.pct').textContent='';q('.grp').textContent='';q('.tm').textContent='';q('.cancel').style.display='none';M.classList.add('on');}
			window.owumBusy=function(msg){open(T.wait,msg||T.processing,true);q('.txt').textContent=msg||T.processing;q('.sub').textContent=T.fewSeconds;};
			// Slow actions: marked links and forms.
			document.addEventListener('click',function(e){var a=e.target.closest('a[data-owum-busy]');if(!a||e.ctrlKey||e.metaKey||a.target==='_blank')return;if(a.dataset.owumConfirm&&!confirm(a.dataset.owumConfirm)){e.preventDefault();return;}owumBusy(a.dataset.owumBusy);});
			document.addEventListener('submit',function(e){var f=e.target;if(!f.matches('form[data-owum-confirm],form[data-owum-busy]'))return;if(f.dataset.owumConfirm&&!confirm(f.dataset.owumConfirm)){e.preventDefault();return;}if(f.dataset.owumBusy)owumBusy(f.dataset.owumBusy);});
			window.addEventListener('pageshow',function(ev){if(ev.persisted)M.classList.remove('on');});

			// Security check item by item.
			function post(data,timeout){var fd=new FormData();fd.append('action','owsu_scan_step');fd.append('nonce',C.nonce);for(var k in data)fd.append(k,data[k]);
				var ctl=window.AbortController?new AbortController():null,t=ctl?setTimeout(function(){ctl.abort();},timeout||90000):0;
				return fetch(C.ajax,{method:'POST',body:fd,credentials:'same-origin',signal:ctl?ctl.signal:undefined}).then(function(r){clearTimeout(t);return r.text().then(function(x){var j=null;try{j=JSON.parse(x);}catch(err){}if(!r.ok||!j||!j.success){var m=(j&&j.data&&j.data.msg)?j.data.msg:('HTTP '+r.status+(r.status>=500?' – '+T.serverErr:''));throw new Error(m);}return j.data;});},function(err){clearTimeout(t);throw new Error(err&&err.name==='AbortError'?T.timeout:T.noResponse);});}
			function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
			var stop=false;
			function runScan(vuln){
				stop=false;open(T.scanTitle,T.scanSub);
				q('.cancel').style.display='';var t0=Date.now();
				post({op:'start',vuln:vuln?1:0}).then(function(d){
					var steps=d.steps,i=0,n=steps.length,ul=q('ul');
					function next(){
						if(stop){q('.txt').textContent=T.cancelled;setTimeout(function(){location.reload();},600);return;}
						if(i>=n){q('.txt').textContent=T.grading;q('.cancel').style.display='none';
							return post({op:'finish'}).then(function(r){q('.bar span').style.width='100%';q('.pct').textContent='100%';location.href=r.redirect;},fatal);}
						var s=steps[i];q('.txt').textContent=s.label;q('.grp').textContent=s.group;
						var p=Math.round(i/n*100);q('.bar span').style.width=p+'%';q('.pct').textContent=p+'%';
						var el=(Date.now()-t0)/1000;q('.tm').textContent=i?T.secsLeft.replace('%s',Math.max(1,Math.round(el/i*(n-i)))):'';
						post({op:'step',id:s.id},s.slow?300000:90000).then(function(r){
							ul.insertAdjacentHTML('afterbegin','<li><b><span class="owsu-badge '+esc(r.status)+'">'+esc(r.label)+'</span></b><span>'+esc(s.label)+'</span></li>');i++;next();
						},function(err){
							ul.insertAdjacentHTML('afterbegin','<li><b><span class="owsu-badge info">'+esc(T.noAnswer)+'</span></b><span>'+esc(s.label)+' — '+esc(err.message)+'</span></li>');
							post({op:'fail',id:s.id,why:err.message}).catch(function(){});i++;next();
						});
					}
					next();
				},fatal);
			}
			function fatal(err){q('.spin').style.display='none';q('.txt').textContent=T.cantGoOn+' '+err.message;q('.cancel').textContent=T.close;q('.cancel').style.display='';stop=true;}
			q('.cancel').addEventListener('click',function(){if(q('.cancel').textContent===T.close){location.reload();return;}stop=true;q('.cancel').disabled=true;});
			document.addEventListener('click',function(e){var a=e.target.closest('a[data-owsu-scan]');if(!a||!window.fetch)return;e.preventDefault();runScan(a.dataset.owsuScan==='1');});
		})();
		</script>
		<?php
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '"><strong>' . esc_html__( 'Open dashboard', 'ondaweb-security' ) . '</strong></a>' );
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
			'saved'    => __( 'Classifications saved.', 'ondaweb-security' ),
			'checked'  => __( 'Update check finished.', 'ondaweb-security' ),
			'settings' => __( 'Settings saved.', 'ondaweb-security' ),
			'sent'     => __( 'Report sent by email.', 'ondaweb-security' ),
			'notsent'  => __( 'The email could not be sent. The reason is shown below, under "Last sent", and in the Error log.', 'ondaweb-security' ),
		);
		$key  = sanitize_key( $_GET['owum_msg'] ); // phpcs:ignore
		if ( isset( $msgs[ $key ] ) ) {
			$cls = 'notsent' === $key ? 'notice-error' : 'notice-success';
			echo '<div class="notice ' . esc_attr( $cls ) . ' is-dismissible"><p>' . esc_html( $msgs[ $key ] ) . '</p></div>';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Dashboard                                                           */
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
		<div class="wrap owum-ui"><?php OWUM_Admin::brand_bar(); ?>
			<h1 class="wp-heading-inline"><?php esc_html_e( 'Updates', 'ondaweb-security' ); ?></h1>
			<a class="page-title-action" data-owum-busy="<?php esc_attr_e( 'Checking for updates on WordPress.org, GitHub and paid plugins…', 'ondaweb-security' ); ?>" href="<?php echo esc_url( self::action_url( 'owum_refresh' ) ); ?>"><?php esc_html_e( 'Check for updates now', 'ondaweb-security' ); ?></a>
			<a class="page-title-action" target="_blank" href="<?php echo esc_url( self::action_url( 'owum_report', array( 'month' => current_time( 'Y-m' ) ) ) ); ?>"><?php esc_html_e( 'Report / PDF', 'ondaweb-security' ); ?></a>
			<hr class="wp-header-end">
			<?php
			self::notice();
			$gh = get_site_option( 'owum_gh_check' );
			if ( is_array( $gh ) && empty( $gh['ok'] ) ) {
				echo '<div class="notice notice-warning"><p>' . sprintf(
					/* translators: 1: date and time, 2: error code, 3: link to the releases page */
					esc_html__( 'Could not check GitHub for a new version of this plugin on %1$s (%2$s). Click "Check for updates now" again later, or download the latest version from %3$s and install it under Plugins → Add New → Upload Plugin.', 'ondaweb-security' ),
					esc_html( owum_date( $gh['time'], true ) ),
					esc_html( $gh['code'] ? 'HTTP ' . $gh['code'] : __( 'no response', 'ondaweb-security' ) ),
					'<a href="' . esc_url( 'https://github.com/' . OWUM_Updater::REPO . '/releases/latest' ) . '" target="_blank" rel="noopener">GitHub</a>'
				) . '</p></div>';
			}
			?>

			<div class="owum-cards">
				<div class="owum-card"><div class="l">WordPress</div><div class="v <?php echo $core['available'] ? 'owum-free' : 'owum-ok'; ?>"><?php echo esc_html( $core['installed'] ); ?></div><div class="s"><?php
					/* translators: %s: version number (in bold) */
					echo $core['available'] ? sprintf( esc_html__( 'Available: %s', 'ondaweb-security' ), '<strong>' . esc_html( $core['available'] ) . '</strong>' ) . ' — <a href="' . esc_url( is_multisite() ? network_admin_url( 'update-core.php' ) : admin_url( 'update-core.php' ) ) . '">' . esc_html__( 'update', 'ondaweb-security' ) . '</a>' : esc_html__( 'Latest version', 'ondaweb-security' );
					?></div></div>
				<?php if ( is_multisite() ) : ?>
				<div class="owum-card"><div class="l"><?php esc_html_e( 'Sites in the network', 'ondaweb-security' ); ?></div><div class="v"><?php echo count( $inv['sites'] ); ?></div><div class="s"><?php echo esc_html( sprintf( /* translators: 1: number of plugins, 2: number of themes */ __( '%1$d plugins · %2$d themes', 'ondaweb-security' ), count( $inv['plugins'] ), count( $inv['themes'] ) ) ); ?></div></div>
				<?php else : ?>
				<div class="owum-card"><div class="l"><?php esc_html_e( 'Installed plugins', 'ondaweb-security' ); ?></div><div class="v"><?php echo count( $inv['plugins'] ); ?></div><div class="s"><?php echo esc_html( sprintf( /* translators: %d: number of themes */ _n( '%d theme', '%d themes', count( $inv['themes'] ), 'ondaweb-security' ), count( $inv['themes'] ) ) ); ?></div></div>
				<?php endif; ?>
				<div class="owum-card"><div class="l"><?php esc_html_e( 'Pending (team)', 'ondaweb-security' ); ?></div><div class="v owum-free"><?php echo (int) $free; ?></div><div class="s"><?php echo esc_html( sprintf( /* translators: %s: "Agency license" type label */ __( 'free + %s', 'ondaweb-security' ), OWUM_Collector::tipo_label( 'ondaweb' ) ) ); ?></div></div>
				<div class="owum-card"><div class="l"><?php esc_html_e( 'Pending (paid)', 'ondaweb-security' ); ?></div><div class="v owum-paid"><?php echo (int) $paid; ?></div><div class="s"><?php esc_html_e( 'ask the client', 'ondaweb-security' ); ?></div></div>
			</div>
			<p class="description"><?php
				/* translators: %s: date and time */
				echo esc_html( sprintf( __( 'Last check: %s.', 'ondaweb-security' ), $last ? owum_date( $last, true ) : '—' ) ) . ' ';
				/* translators: 1: "Paid (client)" type label, 2: "Agency license" type label */
				echo sprintf( esc_html__( 'Items not from wordpress.org are suggested as %1$s; mark the ones whose license you provide as %2$s, and save.', 'ondaweb-security' ), '<strong>' . esc_html( OWUM_Collector::tipo_label( 'pago' ) ) . '</strong>', '<strong>' . esc_html( OWUM_Collector::tipo_label( 'ondaweb' ) ) . '</strong>' );
			?></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="owum_save_meta">
				<?php wp_nonce_field( 'owum_save_meta' ); ?>

				<?php
				self::items_table( 'plugins', $inv['plugins'], $inv['sites'] );
				self::items_table( 'themes', $inv['themes'], $inv['sites'] );
				?>
				<?php submit_button( __( 'Save classifications', 'ondaweb-security' ) ); ?>
			</form>
		</div>
		<script>
		(function(){
			var L=document.documentElement.lang||undefined,SHOWING=<?php echo wp_json_encode( /* translators: 1: visible rows, 2: total rows (JavaScript placeholders) */ __( 'Showing %1$s of %2$s', 'ondaweb-security' ) ); ?>;
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
					out.textContent=SHOWING.replace('%1$s',n).replace('%2$s',rows.length);
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
							else c=String(va).localeCompare(String(vb),L);
							if(!c)c=a.dataset.name.localeCompare(b.dataset.name,L);
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

	/**
	 * @param string $kind 'plugins' or 'themes'.
	 */
	private static function items_table( $kind, $rows, $sites ) {
		$title  = 'plugins' === $kind ? __( 'Plugins', 'ondaweb-security' ) : __( 'Themes', 'ondaweb-security' );
		$id     = 'owum-' . $kind;
		$counts = array( 'all' => count( $rows ), 'paid' => 0, 'free' => 0, 'ok' => 0 );
		$uso    = array( 'rede' => 0, 'parcial' => 0, 'inativo' => 0 );
		foreach ( $rows as $r ) {
			$counts[ $r['status'] ]++;
			$uso[ self::uso_kind( $r ) ]++;
		}
		?>
		<h2><?php echo esc_html( $title ); ?></h2>
		<div class="owum-filters" data-table="<?php echo esc_attr( $id ); ?>">
			<label><?php esc_html_e( 'Search', 'ondaweb-security' ); ?><input type="search" data-f="q" placeholder="<?php echo 'plugins' === $kind ? esc_attr__( 'Plugin name', 'ondaweb-security' ) : esc_attr__( 'Theme name', 'ondaweb-security' ); ?>"></label>
			<label><?php esc_html_e( 'Status', 'ondaweb-security' ); ?><select data-f="status">
				<option value=""><?php echo esc_html( sprintf( /* translators: %d: count */ __( 'All (%d)', 'ondaweb-security' ), $counts['all'] ) ); ?></option>
				<option value="paid"><?php echo esc_html( OWUM_Collector::status_label( 'paid' ) . ' (' . (int) $counts['paid'] . ')' ); ?></option>
				<option value="free"><?php echo esc_html( OWUM_Collector::status_label( 'free' ) . ' (' . (int) $counts['free'] . ')' ); ?></option>
				<option value="ok"><?php echo esc_html( OWUM_Collector::status_label( 'ok' ) . ' (' . (int) $counts['ok'] . ')' ); ?></option>
			</select></label>
			<label><?php esc_html_e( 'Type', 'ondaweb-security' ); ?><select data-f="tipo">
				<option value=""><?php esc_html_e( 'All', 'ondaweb-security' ); ?></option>
				<?php foreach ( array( 'gratuito', 'ondaweb', 'pago', 'personalizado' ) as $t ) : ?>
					<option value="<?php echo esc_attr( $t ); ?>"><?php echo esc_html( OWUM_Collector::tipo_label( $t ) ); ?></option>
				<?php endforeach; ?>
			</select></label>
			<label><?php esc_html_e( 'Usage', 'ondaweb-security' ); ?><select data-f="uso">
				<option value=""><?php esc_html_e( 'All', 'ondaweb-security' ); ?></option>
				<?php if ( $uso['rede'] ) : ?><option value="rede"><?php echo esc_html( sprintf( /* translators: %d: count */ __( 'Active network-wide (%d)', 'ondaweb-security' ), $uso['rede'] ) ); ?></option><?php endif; ?>
				<option value="parcial"><?php echo esc_html( sprintf( is_multisite() ? /* translators: %d: count */ __( 'Active on some sites (%d)', 'ondaweb-security' ) : /* translators: %d: count */ __( 'Active (%d)', 'ondaweb-security' ), $uso['parcial'] ) ); ?></option>
				<option value="inativo"><?php echo esc_html( sprintf( is_multisite() ? /* translators: %d: count */ __( 'Inactive everywhere (%d)', 'ondaweb-security' ) : /* translators: %d: count */ __( 'Inactive (%d)', 'ondaweb-security' ), $uso['inativo'] ) ); ?></option>
			</select></label>
			<?php if ( count( $sites ) > 1 ) : ?>
			<label><?php esc_html_e( 'Active on site', 'ondaweb-security' ); ?><select data-f="site">
				<option value=""><?php esc_html_e( 'Any site', 'ondaweb-security' ); ?></option>
				<?php foreach ( $sites as $sid => $info ) : ?>
					<option value="<?php echo (int) $sid; ?>"><?php echo esc_html( $info['name'] . ' — ' . $info['url'] ); ?></option>
				<?php endforeach; ?>
			</select></label>
			<?php endif; ?>
			<label>&nbsp;<button type="button" class="button" data-f="clear"><?php esc_html_e( 'Clear filters', 'ondaweb-security' ); ?></button></label>
			<span class="owum-count"></span>
		</div>
		<table class="widefat striped owum-table" id="<?php echo esc_attr( $id ); ?>">
			<thead><tr>
				<th class="owum-sort" data-key="name"><?php esc_html_e( 'Name', 'ondaweb-security' ); ?></th><th class="owum-sort" data-key="installed"><?php esc_html_e( 'Installed', 'ondaweb-security' ); ?></th><th class="owum-sort" data-key="available"><?php esc_html_e( 'Available', 'ondaweb-security' ); ?></th><th class="owum-sort" data-key="status"><?php esc_html_e( 'Status', 'ondaweb-security' ); ?></th><th class="owum-sort" data-key="tipo" style="width:150px"><?php esc_html_e( 'Type', 'ondaweb-security' ); ?></th><th class="owum-sort" data-key="uso"><?php esc_html_e( 'Usage', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Notes / license / vendor', 'ondaweb-security' ); ?></th><th title="<?php esc_attr_e( 'For paid plugins that do not announce updates on their own', 'ondaweb-security' ); ?>"><?php esc_html_e( 'Latest known version', 'ondaweb-security' ); ?></th>
			</tr></thead>
			<tbody>
			<?php foreach ( $rows as $r ) :
				$k     = $r['key'];
				$names = OWUM_Collector::where_list( $r, $sites );
				?>
				<tr data-status="<?php echo esc_attr( $r['status'] ); ?>" data-name="<?php echo esc_attr( function_exists( 'mb_strtolower' ) ? mb_strtolower( $r['name'] ) : strtolower( $r['name'] ) ); ?>" data-installed="<?php echo esc_attr( $r['installed'] ); ?>" data-available="<?php echo esc_attr( $r['available'] ); ?>" data-uso="<?php echo esc_attr( self::uso_kind( $r ) ); ?>" data-uso-n="<?php echo $r['network_active'] ? 100000 : count( $r['site_ids'] ); ?>" data-sites="|<?php echo esc_attr( implode( '|', $r['site_ids'] ) ); ?>|">
					<td><strong><?php echo esc_html( $r['name'] ); ?></strong><?php echo $r['wporg'] ? '<br><span class="description" style="font-size:11px">wordpress.org</span>' : ''; ?></td>
					<td><?php echo esc_html( $r['installed'] ); ?></td>
					<td><?php echo $r['available'] ? '<strong>' . esc_html( $r['available'] ) . '</strong>' . ( 'manual' === $r['available_src'] ? '<br><span class="description" style="font-size:11px">' . esc_html__( 'manual', 'ondaweb-security' ) . '</span>' : '' ) : '—'; ?></td>
					<td><span class="owum-badge <?php echo esc_attr( $r['status'] ); ?>"><?php echo esc_html( OWUM_Collector::status_label( $r['status'] ) ); ?></span></td>
					<td>
						<select name="owum[<?php echo esc_attr( $k ); ?>][tipo]">
							<?php foreach ( array( 'gratuito', 'ondaweb', 'pago', 'personalizado' ) as $t ) : ?>
								<option value="<?php echo esc_attr( $t ); ?>" <?php selected( $r['tipo'], $t ); ?>><?php echo esc_html( OWUM_Collector::tipo_label( $t ) ); ?></option>
							<?php endforeach; ?>
						</select>
						<?php if ( ! $r['classified'] ) : ?><span class="owum-unclassified"><?php esc_html_e( 'automatic suggestion', 'ondaweb-security' ); ?></span><?php endif; ?>
					</td>
					<td>
						<?php if ( $r['network_active'] || ! $names ) : ?>
							<?php echo esc_html( OWUM_Collector::where_label( $r, $sites ) ); ?>
						<?php else : ?>
							<details><summary><?php echo esc_html( OWUM_Collector::where_label( $r, $sites ) ); ?></summary><ul><?php foreach ( $names as $n ) { echo '<li>' . esc_html( $n ) . '</li>'; } ?></ul></details>
						<?php endif; ?>
					</td>
					<td><input type="text" class="regular-text" name="owum[<?php echo esc_attr( $k ); ?>][obs]" value="<?php echo esc_attr( $r['obs'] ); ?>" placeholder="<?php echo 'pago' === $r['tipo'] ? esc_attr__( 'E.g. license expires 03/2027 – client account', 'ondaweb-security' ) : ''; ?>"></td>
					<td><input type="text" class="small" name="owum[<?php echo esc_attr( $k ); ?>][ultima_conhecida]" value="<?php echo esc_attr( $r['known'] ); ?>" placeholder="<?php esc_attr_e( 'e.g. 2.4.1', 'ondaweb-security' ); ?>"></td>
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
		@set_time_limit( 180 ); // phpcs:ignore
		OWUM_Collector::force_check();
		OWUM_Logger::detect();
		wp_safe_redirect( self::page_url( 'owum', array( 'owum_msg' => 'checked' ) ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Printable report / PDF                                              */
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
		$title = sanitize_title( __( 'Updates report', 'ondaweb-security' ) ) . '-' . sanitize_title( $s['client_name'] ) . '-' . $ym;
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( $title ); ?></title>
<style>
	body{margin:0;background:#eceeef;}
	.page{background:#fff;max-width:900px;margin:24px auto;padding:40px 44px;box-shadow:0 1px 3px rgba(0,0,0,.08);border-radius:6px;}
	.bar{position:sticky;top:0;z-index:2;background:#000;color:#fff;padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font:14px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;}
	.bar select,.bar button,.bar a{font:inherit;padding:6px 12px;border-radius:4px;border:0;}
	.bar button{background:#f58634;color:#fff;font-weight:600;cursor:pointer;}
	.bar a{color:#fff;text-decoration:underline;background:none;}
	.bar .hint{opacity:.8;font-size:12px;margin-left:auto;}
	@media print{
		body{background:#fff;}
		.bar{display:none;}
		.page{box-shadow:none;margin:0;padding:0;max-width:none;border-radius:0;}
	}
	<?php echo OWUM_Report::print_css(); // phpcs:ignore -- built from escaped values ?>
</style>
</head>
<body>
<form class="bar" method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<input type="hidden" name="action" value="owum_report">
	<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'owum_report' ) ); ?>">
	<label><?php esc_html_e( 'History month:', 'ondaweb-security' ); ?>
		<select name="month" onchange="this.form.submit()">
			<?php foreach ( $months as $m => $label ) : ?>
				<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $m, $ym ); ?>><?php echo esc_html( $label ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<button type="button" onclick="window.print()"><?php esc_html_e( 'Save as PDF / Print', 'ondaweb-security' ); ?></button>
	<a href="<?php echo esc_url( self::page_url() ); ?>"><?php esc_html_e( 'Back to the dashboard', 'ondaweb-security' ); ?></a>
	<span class="hint"><?php esc_html_e( 'In the print window, choose “Save as PDF”.', 'ondaweb-security' ); ?></span>
</form>
<div class="page"><?php echo OWUM_Report::html( $ym ); // phpcs:ignore -- already escaped ?></div>
</body>
</html>
		<?php
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* History                                                             */
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
		<div class="wrap owum-ui"><?php OWUM_Admin::brand_bar(); ?>
			<h1 class="wp-heading-inline"><?php esc_html_e( 'Update history', 'ondaweb-security' ); ?></h1>
			<?php if ( 'all' !== $ym ) : ?>
				<a class="page-title-action" target="_blank" href="<?php echo esc_url( self::action_url( 'owum_report', array( 'month' => $ym ) ) ); ?>"><?php esc_html_e( 'This month\'s report / PDF', 'ondaweb-security' ); ?></a>
			<?php endif; ?>
			<hr class="wp-header-end">
			<form method="get" class="owum-toolbar">
				<input type="hidden" name="page" value="owum-history">
				<select name="month">
					<option value="all" <?php selected( $ym, 'all' ); ?>><?php esc_html_e( 'All time', 'ondaweb-security' ); ?></option>
					<?php for ( $i = 0; $i < 24; $i++ ) : $m = gmdate( 'Y-m', strtotime( "-{$i} month", $first ) ); ?>
						<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $ym, $m ); ?>><?php echo esc_html( OWUM_Report::month_label( $m ) ); ?></option>
					<?php endfor; ?>
				</select>
				<select name="type">
					<option value=""><?php esc_html_e( 'All types', 'ondaweb-security' ); ?></option>
					<option value="core" <?php selected( $type, 'core' ); ?>>WordPress</option>
					<option value="plugin" <?php selected( $type, 'plugin' ); ?>><?php esc_html_e( 'Plugins', 'ondaweb-security' ); ?></option>
					<option value="theme" <?php selected( $type, 'theme' ); ?>><?php esc_html_e( 'Themes', 'ondaweb-security' ); ?></option>
					<option value="security" <?php selected( $type, 'security' ); ?>><?php esc_html_e( 'Security', 'ondaweb-security' ); ?></option>
				</select>
				<?php submit_button( __( 'Filter', 'ondaweb-security' ), 'secondary', '', false ); ?>
				<span class="description"><?php echo esc_html( sprintf( /* translators: %d: number of entries */ _n( '%d entry', '%d entries', count( $rows ), 'ondaweb-security' ), count( $rows ) ) ); ?></span>
			</form>
			<table class="widefat striped owum-table">
				<thead><tr><th><?php esc_html_e( 'Date', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Type', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Item', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Action', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'From', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'To', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Source', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'User', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Notes', 'ondaweb-security' ); ?></th></tr></thead>
				<tbody>
				<?php if ( ! $rows ) : ?>
					<tr><td colspan="9"><?php esc_html_e( 'No entries in this period.', 'ondaweb-security' ); ?></td></tr>
				<?php endif; ?>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td style="white-space:nowrap"><?php echo esc_html( owum_date( $r['logged_at'], true ) ); ?></td>
						<td><?php echo esc_html( OWUM_Logger::type_label( $r['item_type'] ) ); ?></td>
						<td><strong><?php echo esc_html( OWUM_Logger::item_label( $r ) ); ?></strong></td>
						<td><?php echo esc_html( OWUM_Logger::action_label( $r['action'] ) ); ?></td>
						<td><?php echo esc_html( $r['old_version'] ? $r['old_version'] : '—' ); ?></td>
						<td><strong><?php echo esc_html( $r['new_version'] ? $r['new_version'] : '—' ); ?></strong></td>
						<td><?php echo esc_html( OWUM_Logger::source_label( $r['source'] ) ); ?></td>
						<td><?php echo esc_html( $r['user_login'] ); ?></td>
						<td><?php echo esc_html( OWUM_Logger::notes_label( $r ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Settings                                                            */
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
		<div class="wrap owum-ui"><?php OWUM_Admin::brand_bar(); ?>
			<h1><?php esc_html_e( 'Settings', 'ondaweb-security' ); ?></h1>
			<?php self::notice(); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-owum-busy="<?php esc_attr_e( 'Saving settings…', 'ondaweb-security' ); ?>">
				<input type="hidden" name="action" value="owum_save_settings">
				<?php wp_nonce_field( 'owum_save_settings' ); ?>
				<h2><?php esc_html_e( 'Report', 'ondaweb-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="owum-client"><?php esc_html_e( 'Client name in the report', 'ondaweb-security' ); ?></label></th>
						<td><input id="owum-client" type="text" class="regular-text" name="client_name" value="<?php echo esc_attr( $s['client_name'] ); ?>"></td></tr>
					<?php self::logo_field( 'client', __( 'Client logo', 'ondaweb-security' ), __( 'Shown at the top of the report, next to the Ondaweb logo. Use PNG or JPG (SVG does not show in Gmail/Outlook).', 'ondaweb-security' ) ); ?>
					<tr><th scope="row"><label for="owum-emails"><?php esc_html_e( 'Recipients', 'ondaweb-security' ); ?></label></th>
						<td><input id="owum-emails" type="text" class="large-text" name="emails" value="<?php echo esc_attr( $s['emails'] ); ?>">
						<p class="description"><?php esc_html_e( 'Separate multiple emails with commas.', 'ondaweb-security' ); ?></p></td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Monthly email', 'ondaweb-security' ); ?></th>
						<td><label><input type="checkbox" name="enabled" value="1" <?php checked( $s['enabled'], 1 ); ?>> <?php esc_html_e( 'Automatically send the previous month\'s report', 'ondaweb-security' ); ?></label></td></tr>
					<tr><th scope="row"><label for="owum-day"><?php esc_html_e( 'Day of the month', 'ondaweb-security' ); ?></label></th>
						<td><select id="owum-day" name="day"><?php for ( $d = 1; $d <= 28; $d++ ) : ?><option value="<?php echo (int) $d; ?>" <?php selected( (int) $s['day'], $d ); ?>><?php echo (int) $d; ?></option><?php endfor; ?></select>
						<p class="description"><?php
							/* translators: %s: date and time, or "not scheduled" */
							echo sprintf( esc_html__( 'Next run of the daily routine: %s.', 'ondaweb-security' ), $next ? esc_html( owum_date_ts( $next, true ) ) : '<strong>' . esc_html__( 'not scheduled', 'ondaweb-security' ) . '</strong>' ) . ' ';
							/* translators: %s: wp-cron.php address */
							echo sprintf( esc_html__( 'WP-Cron depends on site visits; to guarantee the time, set up a real server cron calling %s.', 'ondaweb-security' ), '<code>' . esc_html( site_url( 'wp-cron.php' ) ) . '</code>' );
						?></p></td></tr>
				</table>

				<h2><?php esc_html_e( 'Vulnerabilities', 'ondaweb-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="owum-wfkey"><?php esc_html_e( 'Wordfence Intelligence API key', 'ondaweb-security' ); ?></label></th>
						<td><input id="owum-wfkey" type="password" autocomplete="off" class="regular-text" name="wf_key" value="<?php echo esc_attr( $s['wf_key'] ); ?>">
						<button type="button" class="button" onclick="var i=document.getElementById('owum-wfkey');i.type=i.type==='password'?'text':'password';"><?php esc_html_e( 'Show', 'ondaweb-security' ); ?></button>
						<p class="description"><?php
							/* translators: %s: link to wordfence.com */
							echo sprintf( esc_html__( 'Free. Create it at %s (Wordfence account → Wordfence Intelligence → API key). Used to check for known vulnerabilities once a day.', 'ondaweb-security' ), '<a href="https://www.wordfence.com/threat-intel/vulnerabilities/" target="_blank" rel="noopener">wordfence.com</a>' );
						?></p></td></tr>
				</table>

				<h2 id="owum-errors-cfg"><?php esc_html_e( 'Error alerts', 'ondaweb-security' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="owum-erremail"><?php esc_html_e( 'Developer email', 'ondaweb-security' ); ?></label></th>
						<td><input id="owum-erremail" type="text" class="large-text" name="err_email" value="<?php echo esc_attr( $s['err_email'] ); ?>">
						<p class="description"><?php esc_html_e( 'Receives the error alerts. Separate multiple emails with commas.', 'ondaweb-security' ); ?></p></td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Alerts', 'ondaweb-security' ); ?></th>
						<td><label><input type="checkbox" name="err_mail" value="1" <?php checked( $s['err_mail'], 1 ); ?>> <?php esc_html_e( 'Send an email right away when a fatal error or a plugin failure happens', 'ondaweb-security' ); ?></label>
						<p class="description"><?php esc_html_e( 'The same error sends at most one email every 6 hours (and at most 10 emails per hour overall).', 'ondaweb-security' ); ?></p>
						<label style="display:block;margin-top:8px"><input type="checkbox" name="err_site" value="1" <?php checked( $s['err_site'], 1 ); ?>> <?php esc_html_e( 'Also record fatal errors from other plugins, the theme and WordPress', 'ondaweb-security' ); ?></label>
						<p class="description"><?php esc_html_e( 'Unchecked, only this plugin\'s errors are recorded.', 'ondaweb-security' ); ?></p></td></tr>
				</table>

				<?php self::login_section( $s ); ?>
				<?php submit_button( __( 'Save settings', 'ondaweb-security' ) ); ?>
			</form>
			<script>
			window.addEventListener('load',function(){
				var LT=<?php echo wp_json_encode( array( 'nolib' => __( 'Media library unavailable.', 'ondaweb-security' ), 'title' => __( 'Choose logo', 'ondaweb-security' ), 'use' => __( 'Use this image', 'ondaweb-security' ) ) ); ?>;
				document.querySelectorAll('.owum-logo').forEach(function(box){
					var input=box.querySelector('input'),prev=box.querySelector('.owum-logo-preview'),rm=box.querySelector('.owum-logo-remove'),frame;
					box.querySelector('.owum-logo-pick').addEventListener('click',function(){
						if(!window.wp||!wp.media){alert(LT.nolib);return;}
						if(!frame){frame=wp.media({title:LT.title,button:{text:LT.use},library:{type:'image'},multiple:false});
							frame.on('select',function(){var a=frame.state().get('selection').first().toJSON();input.value=a.id;
								prev.innerHTML='<img src="'+a.url+'" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;">';rm.style.display='';});}
						frame.open();
					});
					rm.addEventListener('click',function(){input.value='0';var d=box.dataset.default;prev.innerHTML=d?'<img src="'+d+'" style="max-height:60px;max-width:240px;background:#fff;padding:6px;border:1px solid #dcdcde;border-radius:4px;">':'';rm.style.display='none';});
				});
			});
			</script>

			<?php self::rc_test_box(); ?>

			<h2><?php esc_html_e( 'Send now', 'ondaweb-security' ); ?></h2>
			<p>
				<a class="button" data-owum-busy="<?php esc_attr_e( 'Building and sending the report…', 'ondaweb-security' ); ?>" href="<?php echo esc_url( self::action_url( 'owum_send_now', array( 'month' => $prev ) ) ); ?>"><?php echo esc_html( sprintf( /* translators: %s: month and year */ __( 'Send the %s report', 'ondaweb-security' ), OWUM_Report::month_label( $prev ) ) ); ?></a>
				<a class="button" data-owum-busy="<?php esc_attr_e( 'Building and sending the report…', 'ondaweb-security' ); ?>" href="<?php echo esc_url( self::action_url( 'owum_send_now', array( 'month' => current_time( 'Y-m' ) ) ) ); ?>"><?php esc_html_e( 'Send this month\'s report (partial)', 'ondaweb-security' ); ?></a>
			</p>
			<?php if ( is_array( $last ) ) : ?>
				<p class="description"><?php
					echo esc_html(
						sprintf(
							/* translators: 1: date and time, 2: month and year, 3: recipients */
							__( 'Last sent: %1$s — %2$s to %3$s', 'ondaweb-security' ),
							owum_date( $last['when'], true ),
							OWUM_Report::month_label( $last['month'] ),
							$last['to']
						)
					) . ' — ' . ( $last['ok'] ? esc_html__( 'sent', 'ondaweb-security' ) : '<strong style="color:#b32d2e">' . esc_html__( 'failed', 'ondaweb-security' ) . '</strong>' . ( ! empty( $last['error'] ) ? ' — ' . esc_html( $last['error'] ) : '' ) ) . '.';
				?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/* ------------------------------------------------------------------ */
	/* Login protection                                                    */
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
		<h2 id="owum-login"><?php esc_html_e( 'Login protection', 'ondaweb-security' ); ?></h2>
		<?php if ( $wps ) : ?>
			<div class="notice notice-warning inline"><p><strong><?php esc_html_e( 'The WPS Hide Login plugin is active', 'ondaweb-security' ); ?></strong><?php echo $wpsslug ? ' (' . sprintf( /* translators: %s: current login address */ esc_html__( 'current address: %s', 'ondaweb-security' ), '<code>/' . esc_html( $wpsslug ) . '</code>' ) . ')' : ''; ?>. <?php esc_html_e( 'To use this plugin\'s feature instead: save the same address below, then deactivate WPS Hide Login — the login stays at the same address, with no interruption.', 'ondaweb-security' ); ?></p></div>
		<?php endif; ?>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><label for="owum-slug"><?php esc_html_e( 'Login address', 'ondaweb-security' ); ?></label></th>
				<td>
					<code style="padding:6px 4px;background:none"><?php echo esc_html( $prefix ); ?></code><input id="owum-slug" type="text" class="regular-text" style="width:220px" name="login_slug" value="<?php echo esc_attr( $slug ? $slug : ( $wps ? $wpsslug : '' ) ); ?>" placeholder="<?php esc_attr_e( 'e.g. private-access', 'ondaweb-security' ); ?>" autocomplete="off" spellcheck="false">
					<?php if ( OWSU_Login::slug() ) : ?>
						<p style="margin-top:8px"><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> <?php esc_html_e( 'Active:', 'ondaweb-security' ); ?> <a href="<?php echo esc_url( OWSU_Login::url( $main ) ); ?>" target="_blank"><strong><?php echo esc_html( OWSU_Login::url( $main ) ); ?></strong></a>
						<button type="button" class="button button-small" onclick="navigator.clipboard&&navigator.clipboard.writeText(<?php echo esc_attr( wp_json_encode( OWSU_Login::url( $main ) ) ); ?>);this.textContent=<?php echo esc_attr( wp_json_encode( __( 'Copied', 'ondaweb-security' ) ) ); ?>;"><?php esc_html_e( 'Copy', 'ondaweb-security' ); ?></button></p>
					<?php elseif ( $off && $slug ) : ?>
						<p style="margin-top:8px;color:#b32d2e"><strong><?php esc_html_e( 'Turned off by the OWSU_LOGIN_SLUG_OFF constant in wp-config.php.', 'ondaweb-security' ); ?></strong> <?php esc_html_e( 'Remove the constant to turn it back on.', 'ondaweb-security' ); ?></p>
					<?php endif; ?>
					<p class="description"><?php
						/* translators: 1: /wp-login.php, 2: /wp-admin */
						echo sprintf( esc_html__( 'Replaces %1$s, which starts answering "page not found", as does %2$s for anyone not logged in. Leave blank to use the default address.', 'ondaweb-security' ), '<strong>/wp-login.php</strong>', '<strong>/wp-admin</strong>' );
						echo is_multisite() ? ' ' . esc_html__( 'Applies to every site in the network, each under its own path.', 'ondaweb-security' ) : '';
						echo ' ' . esc_html__( 'When saved, the new address is emailed to the report recipients.', 'ondaweb-security' );
					?></p>
					<p class="description"><?php
						/* translators: 1: "login", 2: "admin" */
						echo sprintf( esc_html__( 'Use letters, numbers and hyphens (at least 4 characters). Avoid obvious names such as %1$s or %2$s.', 'ondaweb-security' ), '<code>login</code>', '<code>admin</code>' );
					?></p>
				</td></tr>
			<tr><th scope="row"><label for="owum-rcv"><?php esc_html_e( 'reCAPTCHA on login', 'ondaweb-security' ); ?></label></th>
				<td>
					<select id="owum-rcv" name="rc_version">
						<option value="" <?php selected( $c['v'], '' ); ?>><?php esc_html_e( 'Off', 'ondaweb-security' ); ?></option>
						<option value="v2" <?php selected( $c['v'], 'v2' ); ?>><?php esc_html_e( 'v2 — "I\'m not a robot" checkbox', 'ondaweb-security' ); ?></option>
						<option value="v3" <?php selected( $c['v'], 'v3' ); ?>><?php esc_html_e( 'v3 — invisible (score based)', 'ondaweb-security' ); ?></option>
					</select>
					<?php
					if ( OWSU_Captcha::active() ) {
						echo ' <span style="margin-left:8px"><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'Active on login, lost password and registration.', 'ondaweb-security' ) . '</span>';
					} elseif ( $rc_off && OWSU_Captcha::verified() ) {
						echo ' <span style="margin-left:8px;color:#b32d2e"><strong>' . esc_html__( 'Turned off by the OWSU_RECAPTCHA_OFF constant.', 'ondaweb-security' ) . '</strong></span>';
					} elseif ( OWSU_Captcha::configured() ) {
						echo ' <span style="margin-left:8px;color:#996800"><span class="dashicons dashicons-warning"></span> ' . esc_html__( 'Waiting for the test — run the test below to turn it on.', 'ondaweb-security' ) . '</span>';
					}
					?>
					<p class="description"><?php
						echo sprintf(
							/* translators: 1: link to the Google reCAPTCHA admin, 2: domain name */
							esc_html__( 'Create the keys at %1$s: choose the same type selected here (v2 and v3 keys are different) and register the domain %2$s', 'ondaweb-security' ),
							'<a href="' . esc_url( OWSU_Captcha::ADMIN_URL ) . '" target="_blank" rel="noopener"><strong>google.com/recaptcha/admin</strong></a>',
							'<code>' . esc_html( wp_parse_url( home_url(), PHP_URL_HOST ) ) . '</code>'
						);
						echo is_multisite() ? ' ' . esc_html__( 'and every domain used by the network', 'ondaweb-security' ) : '';
						echo '.';
					?></p>
				</td></tr>
			<tr class="owum-rc"><th scope="row"><label for="owum-rcsite"><?php esc_html_e( 'Site key', 'ondaweb-security' ); ?></label></th>
				<td><input id="owum-rcsite" type="text" class="regular-text" name="rc_site" value="<?php echo esc_attr( $c['site'] ); ?>" autocomplete="off" spellcheck="false"></td></tr>
			<tr class="owum-rc"><th scope="row"><label for="owum-rcsecret"><?php esc_html_e( 'Secret key', 'ondaweb-security' ); ?></label></th>
				<td><input id="owum-rcsecret" type="password" class="regular-text" name="rc_secret" value="<?php echo esc_attr( $c['secret'] ); ?>" autocomplete="off">
				<button type="button" class="button" onclick="var i=document.getElementById('owum-rcsecret');i.type=i.type==='password'?'text':'password';"><?php esc_html_e( 'Show', 'ondaweb-security' ); ?></button></td></tr>
			<tr class="owum-rc owum-rc3"><th scope="row"><label for="owum-rcscore"><?php esc_html_e( 'Minimum score (v3)', 'ondaweb-security' ); ?></label></th>
				<td><select id="owum-rcscore" name="rc_score"><?php
					$score_labels = array(
						'0.3' => __( '0.3 (more lenient)', 'ondaweb-security' ),
						'0.5' => __( '0.5 (recommended)', 'ondaweb-security' ),
						'0.7' => __( '0.7 (stricter)', 'ondaweb-security' ),
					);
					foreach ( $score_labels as $v => $lbl ) :
						?><option value="<?php echo esc_attr( $v ); ?>" <?php selected( number_format( $c['score'], 1 ), $v ); ?>><?php echo esc_html( $lbl ); ?></option><?php
					endforeach;
				?></select>
				<p class="description"><?php esc_html_e( 'Google gives every login a score from 0 (robot) to 1 (human).', 'ondaweb-security' ); ?></p></td></tr>
		</table>
		<?php if ( is_array( $rc_err ) && OWSU_Captcha::active() ) : ?>
			<p class="description"><?php echo esc_html( sprintf( /* translators: 1: date and time, 2: error message */ __( 'Last communication failure with Google: %1$s — %2$s. During such failures the login is allowed so access is never locked.', 'ondaweb-security' ), owum_date( $rc_err['time'], true ), $rc_err['msg'] ) ); ?></p>
		<?php endif; ?>
		<details style="margin:4px 0 8px"><summary style="cursor:pointer;color:#2271b1"><?php esc_html_e( 'Access recovery (if you cannot log in)', 'ondaweb-security' ); ?></summary>
			<p class="description" style="margin-top:6px"><?php
				/* translators: %s: wp-config.php */
				echo sprintf( esc_html__( 'Add to %s, above the line "That\'s all, stop editing":', 'ondaweb-security' ), '<code>wp-config.php</code>' );
			?></p>
			<pre style="background:#fff;border:1px solid #dcdcde;padding:8px;display:inline-block">define( 'OWSU_LOGIN_SLUG_OFF', true ); // <?php esc_html_e( 'login back at /wp-login.php', 'ondaweb-security' ); ?>

define( 'OWSU_RECAPTCHA_OFF', true );  // <?php esc_html_e( 'turns reCAPTCHA off', 'ondaweb-security' ); ?></pre>
			<p class="description"><?php esc_html_e( 'Or rename the plugin folder over FTP. Once logged in, fix the settings and remove the lines.', 'ondaweb-security' ); ?></p>
		</details>
		<script>
		(function(){var s=document.getElementById('owum-rcv');function t(){document.querySelectorAll('.owum-rc').forEach(function(r){r.style.display=s.value?'':'none';});document.querySelectorAll('.owum-rc3').forEach(function(r){r.style.display=s.value==='v3'?'':'none';});}s.addEventListener('change',t);t();})();
		</script>
		<?php
	}

	/** Test box: reCAPTCHA is only turned on after it really works on this domain. */
	private static function rc_test_box() {
		if ( ! OWSU_Captcha::configured() || OWSU_Captcha::verified() ) {
			return;
		}
		$c = OWSU_Captcha::cfg();
		?>
		<div id="owum-rctest" style="background:#fff;border:1px solid #dcdcde;border-left:4px solid #dba617;padding:12px 16px;margin:16px 0;max-width:720px">
			<h3 style="margin-top:0"><?php esc_html_e( 'Test and turn on reCAPTCHA', 'ondaweb-security' ); ?></h3>
			<p><?php esc_html_e( 'So that wrong keys never lock you out, reCAPTCHA only starts applying to the login after this test.', 'ondaweb-security' ); ?>
			<?php
			$btn = '<strong>' . esc_html__( 'Test and turn on', 'ondaweb-security' ) . '</strong>';
			/* translators: %s: "Test and turn on" button label */
			echo 'v2' === $c['v'] ? sprintf( esc_html__( 'Tick the box below and click %s.', 'ondaweb-security' ), $btn ) : sprintf( esc_html__( 'Click %s (v3 is invisible).', 'ondaweb-security' ), $btn ); // phpcs:ignore
			?></p>
			<form id="owsurctest" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="owum_rc_test">
				<?php wp_nonce_field( 'owum_rc_test' ); ?>
				<?php if ( 'v2' === $c['v'] ) : ?>
					<div class="g-recaptcha" data-sitekey="<?php echo esc_attr( $c['site'] ); ?>" style="margin:8px 0"></div>
				<?php else : ?>
					<input type="hidden" name="g-recaptcha-response" class="owsu-rc3" value="">
				<?php endif; ?>
				<?php submit_button( __( 'Test and turn on', 'ondaweb-security' ), 'primary', 'submit', false ); ?>
			</form>
			<p class="description" style="margin-bottom:0"><?php esc_html_e( 'If Google\'s box shows "Invalid key" or "Invalid domain", check the keys and the registered domains.', 'ondaweb-security' ); ?></p>
		</div>
		<?php if ( 'v2' === $c['v'] ) : ?>
			<script src="https://www.google.com/recaptcha/api.js?hl=<?php echo esc_attr( OWSU_Captcha::hl() ); ?>" async defer></script><?php // phpcs:ignore ?>
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
			wp_safe_redirect( add_query_arg( 'owum_err', rawurlencode( __( 'The test got no answer from reCAPTCHA. Tick the box (v2) or check whether Google\'s script loaded on this page.', 'ondaweb-security' ) ), $back ) );
			exit;
		}
		$c = OWSU_Captcha::cfg();
		$r = OWSU_Captcha::verify( $token, 'settings_test', true, $c );
		if ( is_wp_error( $r ) ) {
			wp_safe_redirect( add_query_arg( 'owum_err', rawurlencode( __( 'Test failed:', 'ondaweb-security' ) . ' ' . wp_strip_all_tags( $r->get_error_message() ) ), $back ) );
			exit;
		}
		$s                = owum_settings();
		$s['rc_verified'] = OWSU_Captcha::hash( $c );
		update_site_option( 'owum_settings', $s );
		OWSU_Security::mark( 'login_captcha', true );
		wp_safe_redirect( add_query_arg( 'owum_ok', rawurlencode( sprintf( /* translators: %s: reCAPTCHA version label */ __( 'Test passed: %s turned on for login, lost password and registration.', 'ondaweb-security' ), OWSU_Captcha::label() ) ), $back ) );
		exit;
	}

	/* ------------------------------------------------------------------ */
	/* Error log                                                           */
	/* ------------------------------------------------------------------ */

	public static function page_errors() {
		$log   = OWUM_ErrorLog::all();
		$level = isset( $_GET['level'] ) ? sanitize_key( $_GET['level'] ) : ''; // phpcs:ignore
		$seen  = (string) get_site_option( 'owum_errors_seen', '' );
		OWUM_ErrorLog::mark_seen();
		$counts = array( 'fatal' => 0, 'error' => 0, 'warning' => 0, 'notice' => 0 );
		foreach ( $log as $e ) {
			if ( isset( $counts[ $e['level'] ] ) ) {
				$counts[ $e['level'] ]++;
			}
		}
		$rows = $level ? array_filter( $log, function ( $e ) use ( $level ) { return $e['level'] === $level; } ) : $log;
		$s    = owum_settings();
		self::styles();
		?>
		<style>
			.owum-lv{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
			.owum-lv.fatal{background:#fee2e2;color:#991b1b}.owum-lv.error{background:#ffedd5;color:#9a3412}
			.owum-lv.warning{background:#fef9c3;color:#854d0e}.owum-lv.notice{background:#e0e7ff;color:#3730a3}
			.owum-err td{vertical-align:top}
			.owum-err .msg{font-family:Menlo,Consolas,monospace;font-size:12px;word-break:break-word}
			.owum-err .meta{color:#646970;font-size:12px;margin-top:4px}
			.owum-err tr.is-new td:first-child{box-shadow:inset 3px 0 0 #d63638}
			.owum-err pre{white-space:pre-wrap;font-size:11px;background:#f6f7f7;border:1px solid #dcdcde;padding:8px;max-height:260px;overflow:auto}
		</style>
		<div class="wrap owum-ui"><?php OWUM_Admin::brand_bar(); ?>
			<h1 class="wp-heading-inline"><?php esc_html_e( 'Error log', 'ondaweb-security' ); ?></h1>
			<a class="page-title-action" href="<?php echo esc_url( self::action_url( 'owum_err_export' ) ); ?>"><?php esc_html_e( 'Download (.txt)', 'ondaweb-security' ); ?></a>
			<a class="page-title-action" data-owum-busy="<?php esc_attr_e( 'Sending test email…', 'ondaweb-security' ); ?>" href="<?php echo esc_url( self::action_url( 'owum_err_test' ) ); ?>"><?php esc_html_e( 'Send test email', 'ondaweb-security' ); ?></a>
			<?php if ( $log ) : ?>
				<a class="page-title-action" href="<?php echo esc_url( self::action_url( 'owum_err_clear' ) ); ?>" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Delete the whole error log?', 'ondaweb-security' ) ) ); ?>);"><?php esc_html_e( 'Clear log', 'ondaweb-security' ); ?></a>
			<?php endif; ?>
			<hr class="wp-header-end">
			<?php self::notice(); ?>
			<p class="description"><?php
				echo esc_html( empty( $s['err_site'] ) ? __( 'Fatal errors (this plugin only), PHP warnings raised by this plugin and failed operations (fixes, emails, vulnerability database, checks). Identical errors are grouped.', 'ondaweb-security' ) : __( 'Fatal errors of the site, PHP warnings raised by this plugin and failed operations (fixes, emails, vulnerability database, checks). Identical errors are grouped.', 'ondaweb-security' ) );
				echo ' ' . esc_html__( 'Email alerts:', 'ondaweb-security' ) . ' ' . ( ! empty( $s['err_mail'] ) && $s['err_email'] ? '<strong>' . esc_html( $s['err_email'] ) . '</strong>' : '<strong>' . esc_html__( 'off', 'ondaweb-security' ) . '</strong>' );
			?> — <a href="<?php echo esc_url( self::page_url( 'owum-settings' ) . '#owum-errors-cfg' ); ?>"><?php esc_html_e( 'change', 'ondaweb-security' ); ?></a>.</p>
			<div class="owum-filter" style="margin:10px 0">
				<?php
				/* translators: %d: count */
				$links = array( '' => sprintf( __( 'All (%d)', 'ondaweb-security' ), count( $log ) ) );
				foreach ( $counts as $k => $n ) {
					$links[ $k ] = OWUM_ErrorLog::level_label( $k ) . ' (' . $n . ')';
				}
				foreach ( $links as $k => $label ) {
					echo '<a style="margin-right:12px;text-decoration:none;' . ( $k === $level ? 'font-weight:600;color:#000' : '' ) . '" href="' . esc_url( self::page_url( 'owum-errors', $k ? array( 'level' => $k ) : array() ) ) . '">' . esc_html( $label ) . '</a>';
				}
				?>
			</div>
			<table class="widefat striped owum-err">
				<thead><tr><th style="width:110px"><?php esc_html_e( 'Level', 'ondaweb-security' ); ?></th><th><?php esc_html_e( 'Message', 'ondaweb-security' ); ?></th><th style="width:220px"><?php esc_html_e( 'Origin', 'ondaweb-security' ); ?></th><th style="width:150px"><?php esc_html_e( 'Last time', 'ondaweb-security' ); ?></th><th style="width:70px"><?php esc_html_e( 'Times', 'ondaweb-security' ); ?></th></tr></thead>
				<tbody>
				<?php if ( ! $rows ) : ?>
					<tr><td colspan="5"><?php esc_html_e( 'No errors recorded.', 'ondaweb-security' ); ?></td></tr>
				<?php endif; ?>
				<?php foreach ( $rows as $e ) : ?>
					<tr class="<?php echo $e['last'] > $seen && in_array( $e['level'], array( 'fatal', 'error' ), true ) ? 'is-new' : ''; ?>">
						<td><span class="owum-lv <?php echo esc_attr( $e['level'] ); ?>"><?php echo esc_html( OWUM_ErrorLog::level_label( $e['level'] ) ); ?></span></td>
						<td>
							<div class="msg"><?php echo esc_html( $e['message'] ); ?></div>
							<div class="meta">
								<?php echo $e['file'] ? esc_html( $e['file'] . ( $e['line'] ? ':' . $e['line'] : '' ) ) . '<br>' : ''; ?>
								<?php echo esc_html( $e['url'] ); ?><?php echo $e['user'] ? ' · ' . esc_html( $e['user'] ) : ''; ?>
								<?php echo $e['extra'] ? '<br>' . esc_html( $e['extra'] ) : ''; ?>
								<?php echo $e['mailed'] ? '<br>' . esc_html( sprintf( /* translators: %s: date and time */ __( 'Alert sent on %s', 'ondaweb-security' ), owum_date( $e['mailed'], true ) ) ) : ''; ?>
							</div>
							<?php if ( $e['trace'] ) : ?>
								<details><summary style="cursor:pointer;color:#2271b1;font-size:12px;margin-top:4px"><?php esc_html_e( 'Stack trace', 'ondaweb-security' ); ?></summary><pre><?php echo esc_html( $e['trace'] ); ?></pre></details>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( OWUM_ErrorLog::source_label( $e['source'] ) ); ?></td>
						<td><?php echo esc_html( owum_date( $e['last'], true ) ); ?><?php echo $e['count'] > 1 ? '<br><span class="description">' . esc_html( sprintf( /* translators: %s: date and time */ __( 'since %s', 'ondaweb-security' ), owum_date( $e['first'], true ) ) ) . '</span>' : ''; ?></td>
						<td><?php echo (int) $e['count']; ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<p class="description"><?php echo esc_html( sprintf( /* translators: %d: maximum number of entries */ __( 'Keeps the %d most recent errors.', 'ondaweb-security' ), OWUM_ErrorLog::MAX ) ); ?></p>
		</div>
		<?php
	}

	public static function owum_err_clear() {
		self::guard( 'owum_err_clear' );
		OWUM_ErrorLog::clear();
		wp_safe_redirect( self::page_url( 'owum-errors', array( 'owum_ok' => rawurlencode( __( 'Error log cleared.', 'ondaweb-security' ) ) ) ) );
		exit;
	}

	public static function owum_err_export() {
		self::guard( 'owum_err_export' );
		/* translators: 1: site address, 2: date and time */
		$out = array( sprintf( __( 'Error log — %1$s — generated on %2$s', 'ondaweb-security' ), network_home_url( '/' ), owum_date( '', true ) ), str_repeat( '=', 70 ), '' );
		foreach ( OWUM_ErrorLog::all() as $e ) {
			$out[] = OWUM_ErrorLog::mail_body( $e );
			$out[] = str_repeat( '-', 70 );
		}
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . sanitize_title( __( 'errors', 'ondaweb-security' ) ) . '-' . sanitize_title( wp_parse_url( network_home_url(), PHP_URL_HOST ) ) . '-' . current_time( 'Y-m-d' ) . '.txt"' );
		echo implode( "\n", $out ); // phpcs:ignore
		exit;
	}

	public static function owum_err_test() {
		self::guard( 'owum_err_test' );
		$s  = owum_settings();
		$to = array_values( array_filter( array_map( 'trim', explode( ',', (string) $s['err_email'] ) ), 'is_email' ) );
		if ( ! $to ) {
			wp_safe_redirect( self::page_url( 'owum-errors', array( 'owum_err' => rawurlencode( __( 'No developer email is configured.', 'ondaweb-security' ) ) ) ) );
			exit;
		}
		$site = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
		/* translators: %s: plugin name */
		$body = sprintf( __( 'This is a test of the %s error alerts.', 'ondaweb-security' ), OWUM_PRODUCT ) . "\n\n" . __( 'Site', 'ondaweb-security' ) . ': ' . network_home_url( '/' ) . "\n" . __( 'Error log', 'ondaweb-security' ) . ': ' . OWUM_ErrorLog::page_url();
		$ok   = wp_mail( $to, '[' . $site . '] ' . __( 'Error alerts test', 'ondaweb-security' ), $body );
		/* translators: %s: email addresses */
		wp_safe_redirect( self::page_url( 'owum-errors', $ok ? array( 'owum_ok' => rawurlencode( sprintf( __( 'Test email sent to %s.', 'ondaweb-security' ), implode( ', ', $to ) ) ) ) : array( 'owum_err' => rawurlencode( __( 'The test email could not be sent. See the log below.', 'ondaweb-security' ) ) ) ) );
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
				'wf_key'      => isset( $_POST['wf_key'] ) ? preg_replace( '/[^A-Za-z0-9_\-.]/', '', wp_unslash( $_POST['wf_key'] ) ) : '',
				'rc_version'  => isset( $_POST['rc_version'] ) && in_array( $_POST['rc_version'], array( 'v2', 'v3' ), true ) ? $_POST['rc_version'] : '', // phpcs:ignore
				'rc_site'     => isset( $_POST['rc_site'] ) ? preg_replace( '/[^A-Za-z0-9_\-]/', '', wp_unslash( $_POST['rc_site'] ) ) : '',
				'rc_secret'   => isset( $_POST['rc_secret'] ) ? preg_replace( '/[^A-Za-z0-9_\-]/', '', wp_unslash( $_POST['rc_secret'] ) ) : '',
				'rc_score'    => isset( $_POST['rc_score'] ) ? max( 0.1, min( 0.9, (float) $_POST['rc_score'] ) ) : 0.5,
				'err_email'   => isset( $_POST['err_email'] ) ? implode( ', ', array_filter( array_map( 'trim', explode( ',', sanitize_text_field( wp_unslash( $_POST['err_email'] ) ) ) ), 'is_email' ) ) : $old['err_email'],
				'err_mail'    => empty( $_POST['err_mail'] ) ? 0 : 1,
				'err_site'    => empty( $_POST['err_site'] ) ? 0 : 1,
			)
		);
		$errors = array();
		$notes  = array();

		// Login address.
		$slug = OWSU_Login::validate( isset( $_POST['login_slug'] ) ? wp_unslash( $_POST['login_slug'] ) : '' ); // phpcs:ignore
		if ( is_wp_error( $slug ) ) {
			$errors[] = $slug->get_error_message() . ' ' . __( 'The previous address was kept.', 'ondaweb-security' );
		} else {
			$new['login_slug'] = $slug;
		}

		// reCAPTCHA secret key (checked with Google before saving).
		if ( $new['rc_secret'] && $new['rc_secret'] !== $old['rc_secret'] ) {
			$chk = OWSU_Captcha::check_secret( $new['rc_secret'] );
			if ( is_wp_error( $chk ) ) {
				$errors[]         = $chk->get_error_message() . ' ' . __( 'The previous key was kept.', 'ondaweb-security' );
				$new['rc_secret'] = $old['rc_secret'];
			}
		}

		update_site_option( 'owum_settings', $new );

		if ( isset( $new['login_slug'] ) && $new['login_slug'] !== $old['login_slug'] ) {
			OWSU_Login::notify( $new['login_slug'] );
			OWSU_Security::mark( 'login_url', '' !== $new['login_slug'] );
			if ( '' !== $new['login_slug'] ) {
				/* translators: %s: new login address */
				$notes[] = sprintf( __( 'New login address: %s (emailed to the recipients).', 'ondaweb-security' ), OWSU_Login::url( is_multisite() ? get_main_site_id() : null, null, $new['login_slug'] ) );
			}
		}
		$was = '' !== $old['rc_version'] && hash_equals( (string) $old['rc_verified'], md5( $old['rc_version'] . '|' . $old['rc_site'] . '|' . $old['rc_secret'] ) );
		if ( $was && ! OWSU_Captcha::verified() ) {
			OWSU_Security::mark( 'login_captcha', false );
			if ( OWSU_Captcha::configured() ) {
				$notes[] = __( 'The reCAPTCHA keys changed: run the test again to turn it back on.', 'ondaweb-security' );
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
		@set_time_limit( 180 ); // phpcs:ignore
		$ym = isset( $_GET['month'] ) && preg_match( '/^\d{4}-\d{2}$/', $_GET['month'] ) ? $_GET['month'] : OWUM_Mailer::previous_month(); // phpcs:ignore
		$ok = OWUM_Mailer::send( $ym );
		wp_safe_redirect( self::page_url( 'owum-settings', array( 'owum_msg' => $ok ? 'sent' : 'notsent' ) ) );
		exit;
	}
}
