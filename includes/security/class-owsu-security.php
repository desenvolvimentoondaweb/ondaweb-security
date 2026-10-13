<?php
defined( 'ABSPATH' ) || exit;

/**
 * Verificações de segurança, correções (aplicar/desfazer) e nota geral.
 */
class OWSU_Security {

	const MARK = 'Ondaweb Security';

	private static $http = array();
	private static $nc   = null;

	/* ------------------------------------------------------------------ */
	/* Estado                                                              */
	/* ------------------------------------------------------------------ */

	public static function fixes() {
		return (array) get_site_option( 'owsu_fixes', array() );
	}

	public static function is_on( $id ) {
		if ( 'login_url' === $id ) {
			return '' !== OWSU_Login::slug();
		}
		if ( 'login_captcha' === $id ) {
			return OWSU_Captcha::active();
		}
		$f = self::fixes();
		return ! empty( $f[ $id ]['on'] );
	}

	/** Registra ativação/desativação de recursos configurados fora do botão "Aplicar" (login). */
	public static function mark( $id, $on ) {
		$fixes = self::fixes();
		if ( $on ) {
			$fixes[ $id ] = array( 'on' => 1, 'when' => current_time( 'mysql' ), 'data' => null );
		} elseif ( isset( $fixes[ $id ] ) ) {
			unset( $fixes[ $id ] );
		} else {
			return;
		}
		update_site_option( 'owsu_fixes', $fixes );
		self::log( $id, $on ? 'correcao' : 'desfeito' );
		if ( self::last_scan() ) {
			self::run_one( $id );
		}
	}

	public static function last_scan() {
		$s = get_site_option( 'owsu_scan' );
		return is_array( $s ) ? $s : null;
	}

	public static function home() {
		return is_multisite() ? get_home_url( get_main_site_id(), '/' ) : home_url( '/' );
	}

	public static function site_url( $path = '' ) {
		return is_multisite() ? get_site_url( get_main_site_id(), $path ) : site_url( $path );
	}

	/** Pasta/URL base de uploads do site principal. */
	public static function uploads() {
		$switched = false;
		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( get_main_site_id() );
			$switched = true;
		}
		$u = wp_upload_dir( null, false );
		if ( $switched ) {
			restore_current_blog();
		}
		return array(
			'dir' => untrailingslashit( $u['basedir'] ),
			'url' => untrailingslashit( $u['baseurl'] ),
		);
	}

	public static function groups() {
		return array(
			'software' => 'Plugins, temas e vulnerabilidades',
			'headers'  => 'Cabeçalhos de segurança (HTTP)',
			'files'    => 'Arquivos, pastas e permissões',
			'wp'       => 'Configuração do WordPress',
			'exposure' => 'Exposição de informações',
			'users'    => 'Usuários e acesso',
			'server'   => 'Servidor, PHP e SSL',
		);
	}

	public static function status_label( $s ) {
		$l = array(
			'crit' => 'Crítico',
			'warn' => 'Atenção',
			'ok'   => 'OK',
			'info' => 'Informativo',
		);
		return isset( $l[ $s ] ) ? $l[ $s ] : $s;
	}

	/* ------------------------------------------------------------------ */
	/* Definições                                                          */
	/* ------------------------------------------------------------------ */

	private static function code( $text ) {
		return '<pre style="white-space:pre-wrap;background:#f6f7f7;border:1px solid #dcdcde;padding:8px;border-radius:4px;font-size:12px;">' . esc_html( $text ) . '</pre>';
	}

	private static function nginx_where() {
		return '<p>No <strong>Plesk</strong>: <em>Sites e Domínios → (domínio) → Hospedagem e DNS → Configurações do Apache e nginx → Diretivas adicionais do nginx</em>. Cole as linhas abaixo, salve e rode a verificação de novo.</p>';
	}

	private static function header_howto( $apache, $nginx ) {
		return '<p>Clique em <strong>Aplicar correção</strong> para o próprio WordPress enviar o cabeçalho. Se o site usa cache de página (WP Rocket, LiteSpeed, cache do nginx), prefira configurar no servidor, porque páginas servidas do cache não passam pelo PHP.</p>'
			. self::nginx_where() . self::code( $nginx )
			. '<p>Apache (.htaccess):</p>' . self::code( $apache );
	}

	public static function definitions() {
		static $d = null;
		if ( null !== $d ) {
			return $d;
		}
		$d = array(
			/* Software */
			'vulns'           => array(
				'group'  => 'software',
				'title'  => 'Vulnerabilidades conhecidas nas versões instaladas',
				'client' => 'Verificação de vulnerabilidades conhecidas',
				'why'    => 'Cruza as versões instaladas do WordPress, plugins e temas com a base Wordfence Intelligence.',
				'fix'    => false,
				'howto'  => '<p>Atualize cada item para a versão indicada como corrigida. Se não houver correção, desative e substitua o plugin/tema. Plugins pagos: solicite a atualização ao cliente informando que se trata de correção de segurança.</p>',
			),
			'wporg_closed'    => array(
				'group'  => 'software',
				'title'  => 'Plugins removidos ou abandonados no wordpress.org',
				'client' => 'Revisão de plugins sem manutenção',
				'why'    => 'Plugins fechados no repositório costumam ter falhas sem correção; plugins sem atualização há mais de 2 anos são um risco crescente.',
				'fix'    => false,
				'howto'  => '<p>Substitua os plugins fechados por alternativas mantidas. Para os sem atualização, avalie se ainda são necessários.</p>',
			),
			'inactive_items'  => array(
				'group'  => 'software',
				'title'  => 'Plugins e temas instalados mas não usados',
				'client' => 'Remoção de componentes sem uso',
				'why'    => 'Mesmo desativados, os arquivos continuam no servidor e podem ser explorados.',
				'fix'    => false,
				'howto'  => '<p>Remova pela tela de Plugins/Temas da rede. Mantenha apenas um tema padrão (Twenty...) recente como reserva.</p>',
			),

			/* Headers */
			'hdr_hsts'        => array(
				'group'  => 'headers',
				'title'  => 'HSTS (Strict-Transport-Security)',
				'client' => 'Navegação sempre em conexão segura (HTTPS)',
				'why'    => 'Obriga o navegador a usar HTTPS, impedindo que a conexão seja rebaixada para HTTP.',
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Strict-Transport-Security "max-age=31536000"', 'add_header Strict-Transport-Security "max-age=31536000" always;' ),
			),
			'hdr_nosniff'     => array(
				'group'  => 'headers',
				'title'  => 'X-Content-Type-Options',
				'client' => 'Proteção contra interpretação indevida de arquivos',
				'why'    => 'Impede o navegador de "adivinhar" o tipo de arquivo e executar conteúdo disfarçado.',
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set X-Content-Type-Options "nosniff"', 'add_header X-Content-Type-Options "nosniff" always;' ),
			),
			'hdr_frame'       => array(
				'group'  => 'headers',
				'title'  => 'Proteção contra clickjacking (X-Frame-Options)',
				'client' => 'Proteção contra exibição do site dentro de páginas falsas',
				'why'    => 'Impede que o site seja carregado em iframe por outros domínios para enganar o usuário.',
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set X-Frame-Options "SAMEORIGIN"', 'add_header X-Frame-Options "SAMEORIGIN" always;' ),
			),
			'hdr_referrer'    => array(
				'group'  => 'headers',
				'title'  => 'Referrer-Policy',
				'client' => 'Privacidade de links externos',
				'why'    => 'Evita vazar endereços internos (com parâmetros) para sites externos.',
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Referrer-Policy "strict-origin-when-cross-origin"', 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' ),
			),
			'hdr_permissions' => array(
				'group'  => 'headers',
				'title'  => 'Permissions-Policy',
				'client' => 'Bloqueio de câmera e microfone por scripts de terceiros',
				'why'    => 'Restringe recursos sensíveis do navegador (câmera, microfone, pagamento) que o site não usa.',
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Permissions-Policy "camera=(), microphone=(), payment=(), usb=(), geolocation=(self)"', 'add_header Permissions-Policy "camera=(), microphone=(), payment=(), usb=(), geolocation=(self)" always;' ),
			),
			'hdr_csp'         => array(
				'group'  => 'headers',
				'title'  => 'Content-Security-Policy (básica)',
				'client' => 'Política de segurança de conteúdo',
				'why'    => 'A correção aplica uma política básica e segura (força recursos em HTTPS e bloqueia iframes externos). Uma CSP completa, que restringe scripts, exige ajuste manual para não quebrar Elementor e serviços externos.',
				'fix'    => true,
				'howto'  => '<p>A correção automática aplica apenas <code>upgrade-insecure-requests; frame-ancestors \'self\'</code>. Para uma política completa, comece em modo de teste (<code>Content-Security-Policy-Report-Only</code>), observe o console do navegador por alguns dias e só então ative.</p>',
			),
			'hdr_powered'     => array(
				'group'  => 'headers',
				'title'  => 'Exposição de tecnologia (X-Powered-By)',
				'client' => 'Ocultação de informações técnicas do servidor',
				'why'    => 'Informar a versão do PHP/painel ajuda atacantes a escolher exploits.',
				'fix'    => true,
				'howto'  => '<p>O plugin remove o cabeçalho gerado pelo PHP. Se continuar aparecendo (ex.: <code>PleskLin</code>), ele vem do servidor.</p>' . self::nginx_where() . self::code( "proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;" ) . '<p>Também é possível desligar <code>expose_php</code> nas configurações de PHP do domínio no Plesk.</p>',
			),

			/* Files */
			'up_php_exec'     => array(
				'group'  => 'files',
				'title'  => 'Execução de PHP na pasta de uploads',
				'client' => 'Bloqueio de execução de scripts na pasta de arquivos enviados',
				'why'    => 'É a forma mais comum de invasão: um arquivo malicioso enviado como "imagem" é executado no servidor.',
				'fix'    => true,
				'howto'  => '<p>A correção grava regras no <code>.htaccess</code> da pasta uploads (Apache). No Plesk, arquivos estáticos podem ser atendidos direto pelo nginx; se a verificação continuar falhando após aplicar, adicione:</p>' . self::nginx_where() . self::code( "location ~* ^/wp-content/uploads/.*\\.(php[0-9]?|phtml|phar|pht)\$ {\n    deny all;\n}" ),
			),
			'up_listing'      => array(
				'group'  => 'files',
				'title'  => 'Listagem de diretório em uploads',
				'client' => 'Bloqueio de listagem de arquivos',
				'why'    => 'Sem bloqueio, qualquer pessoa pode navegar e baixar todos os arquivos enviados.',
				'fix'    => true,
				'howto'  => '<p>A correção adiciona <code>Options -Indexes</code> no <code>.htaccess</code> de uploads. No nginx, a listagem é controlada por <code>autoindex</code>; verifique se está <code>off</code>:</p>' . self::nginx_where() . self::code( 'autoindex off;' ),
			),
			'up_php_files'    => array(
				'group'  => 'files',
				'title'  => 'Arquivos PHP dentro de uploads',
				'client' => 'Varredura de arquivos suspeitos',
				'why'    => 'A pasta uploads não deveria conter scripts. Arquivos PHP ali são forte indício de invasão.',
				'fix'    => false,
				'howto'  => '<p>Abra cada arquivo listado pelo gerenciador de arquivos do Plesk. Se não reconhecer, faça uma cópia para análise e remova. Em seguida rode uma varredura completa (Wordfence) e troque as senhas de administradores, FTP e banco de dados.</p>',
			),
			'perm_wpconfig'   => array(
				'group'  => 'files',
				'title'  => 'Permissão do wp-config.php',
				'client' => 'Proteção do arquivo de configuração',
				'why'    => 'O wp-config.php contém a senha do banco de dados e não deve ser legível por outros usuários do servidor.',
				'fix'    => true,
				'howto'  => '<p>Recomendado <code>640</code> (ou <code>600</code>). No Plesk: Gerenciador de Arquivos → wp-config.php → Alterar permissões. Por SSH:</p>' . self::code( 'chmod 640 wp-config.php' ),
			),
			'perm_writable'   => array(
				'group'  => 'files',
				'title'  => 'Pastas e arquivos com permissão de escrita para todos (777/666)',
				'client' => 'Ajuste de permissões de pastas e arquivos',
				'why'    => 'Permissão de escrita global permite que outros processos do servidor alterem o site.',
				'fix'    => true,
				'howto'  => '<p>Padrão recomendado: pastas <code>755</code>, arquivos <code>644</code>. Por SSH, na pasta do site:</p>' . self::code( "find . -type d -perm -o+w -exec chmod 755 {} \\;\nfind . -type f -perm -o+w -exec chmod 644 {} \\;" ),
			),
			'exposed_files'   => array(
				'group'  => 'files',
				'title'  => 'Arquivos sensíveis acessíveis publicamente',
				'client' => 'Bloqueio de acesso a arquivos sensíveis',
				'why'    => 'Backups (.sql, .zip), .env, .git e debug.log podem expor senhas e dados. readme.html e license.txt revelam a versão do WordPress.',
				'fix'    => true,
				'howto'  => '<p>A correção bloqueia esses arquivos via <code>.htaccess</code>. Backups e cópias na raiz do site devem ser <strong>removidos ou movidos</strong> para fora da pasta pública. Se o bloqueio não funcionar (nginx servindo direto):</p>' . self::nginx_where() . self::code( "location ~ /\\.(?!well-known) { deny all; }\nlocation ~* /(readme\\.html|license\\.txt|wp-config-sample\\.php)\$ { deny all; }\nlocation ~* \\.(sql|bak|old|orig|save|swp|log)\$ { deny all; }" ),
			),

			/* WordPress */
			'file_edit'       => array(
				'group'  => 'wp',
				'title'  => 'Editor de arquivos do painel',
				'client' => 'Desativação do editor de código do painel',
				'why'    => 'Se uma conta de administrador for comprometida, o editor permite inserir código malicioso direto nos plugins e temas.',
				'fix'    => true,
				'howto'  => '<p>A correção bloqueia o editor pelo plugin. Alternativa definitiva no <code>wp-config.php</code>:</p>' . self::code( "define( 'DISALLOW_FILE_EDIT', true );" ),
			),
			'debug_display'   => array(
				'group'  => 'wp',
				'title'  => 'Modo de depuração / exibição de erros',
				'client' => 'Ocultação de mensagens de erro técnicas',
				'why'    => 'Erros exibidos na tela revelam caminhos do servidor e detalhes internos.',
				'fix'    => true,
				'howto'  => '<p>A correção oculta os erros na tela. O ideal é ajustar o <code>wp-config.php</code> de produção:</p>' . self::code( "define( 'WP_DEBUG', false );\ndefine( 'WP_DEBUG_DISPLAY', false );" ),
			),
			'salts'           => array(
				'group'  => 'wp',
				'title'  => 'Chaves de segurança (salts) do wp-config',
				'client' => 'Chaves de segurança das sessões',
				'why'    => 'Chaves ausentes ou padrão facilitam a falsificação de sessões de login.',
				'fix'    => false,
				'howto'  => '<p>Gere novas chaves em <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener">api.wordpress.org/secret-key/1.1/salt</a> e substitua o bloco correspondente no <code>wp-config.php</code>. Todos os usuários precisarão fazer login novamente.</p>',
			),
			'force_ssl_admin' => array(
				'group'  => 'wp',
				'title'  => 'Painel administrativo somente em HTTPS',
				'client' => 'Acesso ao painel apenas por conexão segura',
				'why'    => 'Garante que senhas e cookies do painel nunca trafeguem sem criptografia.',
				'fix'    => true,
				'howto'  => '<p>Alternativa no <code>wp-config.php</code>:</p>' . self::code( "define( 'FORCE_SSL_ADMIN', true );" ),
			),
			'auto_updates'    => array(
				'group'  => 'wp',
				'title'  => 'Atualizações automáticas de segurança do WordPress',
				'client' => 'Atualizações automáticas de segurança',
				'why'    => 'As versões de correção (ex.: 6.8.1 → 6.8.2) trazem correções urgentes e devem ser aplicadas automaticamente.',
				'fix'    => false,
				'howto'  => '<p>Remova do <code>wp-config.php</code> as linhas <code>AUTOMATIC_UPDATER_DISABLED</code> e <code>WP_AUTO_UPDATE_CORE = false</code>, ou use:</p>' . self::code( "define( 'WP_AUTO_UPDATE_CORE', 'minor' );" ),
			),

			/* Exposure */
			'xmlrpc'          => array(
				'group'  => 'exposure',
				'title'  => 'XML-RPC',
				'client' => 'Desativação de interface antiga usada em ataques de senha',
				'why'    => 'O xmlrpc.php permite testar centenas de senhas em uma única requisição. Só é necessário para Jetpack ou o app antigo do WordPress.',
				'fix'    => true,
				'howto'  => '<p>A correção desativa o XML-RPC pelo plugin. Não aplique se o site usa Jetpack ou publicação pelo aplicativo móvel antigo.</p>',
			),
			'user_enum'       => array(
				'group'  => 'exposure',
				'title'  => 'Listagem pública de usuários',
				'client' => 'Ocultação dos nomes de usuário',
				'why'    => 'A API REST e o parâmetro ?author= revelam os logins dos usuários, metade do caminho para um ataque de senha.',
				'fix'    => true,
				'howto'  => '<p>A correção bloqueia a listagem de usuários na API para visitantes não logados, o redirecionamento ?author= e o sitemap de usuários. O editor e o painel continuam funcionando normalmente.</p>',
			),
			'generator'       => array(
				'group'  => 'exposure',
				'title'  => 'Versão do WordPress no código-fonte',
				'client' => 'Ocultação da versão do WordPress',
				'why'    => 'A tag "generator" informa a versão exata do WordPress a qualquer visitante.',
				'fix'    => true,
				'howto'  => '<p>A correção remove a tag. Plugins como o Elementor podem adicionar a própria tag; desative nas configurações do plugin, se existir.</p>',
			),

			/* Users */
			'admin_username'  => array(
				'group'  => 'users',
				'title'  => 'Usuário com login "admin"',
				'client' => 'Revisão de nomes de usuário previsíveis',
				'why'    => '"admin" é o primeiro login testado em ataques automatizados.',
				'fix'    => false,
				'howto'  => '<p>Crie um novo administrador com outro login, entre com ele, e exclua o usuário "admin" atribuindo o conteúdo ao novo usuário.</p>',
			),
			'admin_count'     => array(
				'group'  => 'users',
				'title'  => 'Administradores e último acesso',
				'client' => 'Revisão de contas administrativas',
				'why'    => 'Cada conta administrativa é uma porta de entrada. Contas sem uso devem ser removidas ou rebaixadas.',
				'fix'    => false,
				'howto'  => '<p>Revise a lista. O último acesso é registrado pelo plugin a partir da sua instalação. Rebaixe ou remova contas de pessoas que não precisam mais de acesso.</p>',
			),
			'twofa'           => array(
				'group'  => 'users',
				'title'  => 'Autenticação em dois fatores (2FA)',
				'client' => 'Login com verificação em duas etapas',
				'why'    => 'Com 2FA, uma senha vazada não basta para invadir o painel.',
				'fix'    => false,
				'howto'  => '<p>Recomendado: <strong>Wordfence</strong> (gratuito, inclui 2FA e firewall) ou o plugin <strong>Two-Factor</strong>. Ative ao menos para administradores.</p>',
			),
			'login_url'       => array(
				'group'  => 'users',
				'title'  => 'Endereço de login personalizado',
				'client' => 'Endereço de acesso ao painel personalizado',
				'why'    => 'Robôs atacam o /wp-login.php e o /wp-admin de todos os sites WordPress. Com um endereço próprio, esses ataques nem chegam ao formulário de login.',
				'fix'    => false,
				'config' => true,
				'howto'  => '<p>Em <strong>Configurações → Proteção do login</strong>, informe o endereço desejado (ex.: <code>acesso-restrito</code>) e salve. Substitui o plugin WPS Hide Login, que pode ser desativado depois.</p>',
			),
			'login_captcha'   => array(
				'group'  => 'users',
				'title'  => 'Verificação anti-robô no login (reCAPTCHA)',
				'client' => 'Verificação anti-robô no login (reCAPTCHA)',
				'why'    => 'Impede que robôs testem senhas e enviem pedidos de "esqueci a senha" em massa.',
				'fix'    => false,
				'config' => true,
				'howto'  => '<p>Em <strong>Configurações → Proteção do login</strong>, escolha v2 ou v3, cole as chaves geradas em <a href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noopener">google.com/recaptcha/admin</a>, salve e faça o teste para ativar.</p>',
			),
			'login_limit'     => array(
				'group'  => 'users',
				'title'  => 'Limite de tentativas de login',
				'client' => 'Proteção contra tentativas repetidas de senha',
				'why'    => 'Sem limite, robôs podem testar senhas indefinidamente.',
				'fix'    => false,
				'howto'  => '<p>O <strong>Wordfence</strong> já cobre isso. Alternativa leve: <strong>Limit Login Attempts Reloaded</strong>. No Plesk também é possível ativar o <em>Fail2Ban</em> com o filtro do WordPress (WordPress Toolkit).</p>',
			),

			/* Server */
			'https'           => array(
				'group'  => 'server',
				'title'  => 'Site em HTTPS',
				'client' => 'Conexão segura (HTTPS)',
				'why'    => 'Sem HTTPS, senhas e dados de formulários trafegam sem criptografia.',
				'fix'    => false,
				'howto'  => '<p>Emita um certificado (Plesk → SSL/TLS → Let\'s Encrypt) e altere o endereço do site para https em Rede → Sites.</p>',
			),
			'ssl_expiry'      => array(
				'group'  => 'server',
				'title'  => 'Validade do certificado SSL',
				'client' => 'Validade do certificado de segurança',
				'why'    => 'Um certificado vencido derruba o acesso e exibe alertas de segurança aos visitantes.',
				'fix'    => false,
				'howto'  => '<p>No Plesk: <em>SSL/TLS Certificates</em> → verifique se a renovação automática (Let\'s Encrypt) está ativa e renove manualmente se necessário.</p>',
			),
			'php_version'     => array(
				'group'  => 'server',
				'title'  => 'Versão do PHP',
				'client' => 'Versão do PHP com suporte de segurança',
				'why'    => 'Versões do PHP fora do período de suporte não recebem correções de segurança.',
				'fix'    => false,
				'howto'  => '<p>No Plesk: <em>Sites e Domínios → (domínio) → Configurações de PHP</em> → escolha a versão mais recente suportada (8.3 ou 8.4). Teste antes em ambiente de homologação ou com backup, principalmente os plugins pagos.</p>',
			),
		);
		return $d;
	}

	/* ------------------------------------------------------------------ */
	/* Execução                                                            */
	/* ------------------------------------------------------------------ */

	private static function r( $status, $detail, $items = array() ) {
		return array(
			'status' => $status,
			'detail' => $detail,
			'items'  => array_values( (array) $items ),
		);
	}

	public static function run_all() {
		self::$http = array();
		self::$nc   = null;
		@set_time_limit( 300 ); // phpcs:ignore
		$results = array();
		foreach ( self::definitions() as $id => $def ) {
			$m = 'check_' . $id;
			$results[ $id ] = self::run_check( $id );
		}
		$scan = array(
			'time'    => current_time( 'mysql' ),
			'results' => $results,
			'score'   => self::score( $results ),
		);
		update_site_option( 'owsu_scan', $scan );
		return $scan;
	}

	/** Executa uma verificação isolada; falhas viram resultado "Informativo" e vão para o registro de erros. */
	public static function run_check( $id ) {
		$m = 'check_' . $id;
		try {
			return self::$m();
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'warning', 'Verificação "' . $id . '" não concluída: ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ), false );
			return self::r( 'info', 'Não foi possível verificar: ' . $e->getMessage() );
		}
	}

	public static function reset_http() {
		self::$http = array();
		self::$nc   = null;
	}

	/** Reexecuta uma verificação só (após aplicar/desfazer). */
	public static function run_one( $id ) {
		self::$http = array();
		self::$nc   = null;
		$scan       = self::last_scan();
		if ( ! $scan ) {
			return self::run_all();
		}
		$scan['results'][ $id ]  = self::run_check( $id );
		$scan['score']           = self::score( $scan['results'] );
		update_site_option( 'owsu_scan', $scan );
		return $scan;
	}

	public static function score( $results ) {
		$score = 100;
		$count = array( 'crit' => 0, 'warn' => 0, 'ok' => 0, 'info' => 0 );
		foreach ( $results as $r ) {
			$count[ $r['status'] ]++;
			if ( 'crit' === $r['status'] ) {
				$score -= 10;
			} elseif ( 'warn' === $r['status'] ) {
				$score -= 3;
			}
		}
		$score = max( 0, $score );
		if ( $score >= 90 ) {
			$grade = 'A';
		} elseif ( $score >= 75 ) {
			$grade = 'B';
		} elseif ( $score >= 60 ) {
			$grade = 'C';
		} elseif ( $score >= 40 ) {
			$grade = 'D';
		} else {
			$grade = 'E';
		}
		return array(
			'score' => $score,
			'grade' => $grade,
			'count' => $count,
			'total' => count( $results ),
		);
	}

	public static function grade_color( $grade ) {
		$c = array( 'A' => '#166534', 'B' => '#3f6212', 'C' => '#a16207', 'D' => '#c2410c', 'E' => '#b91c1c' );
		return isset( $c[ $grade ] ) ? $c[ $grade ] : '#1f2937';
	}

	/* ------------------------------------------------------------------ */
	/* HTTP local (loopback)                                               */
	/* ------------------------------------------------------------------ */

	private static function http( $url, $args = array() ) {
		$key = md5( $url . wp_json_encode( $args ) );
		if ( array_key_exists( $key, self::$http ) ) {
			return self::$http[ $key ];
		}
		$args = wp_parse_args(
			$args,
			array(
				'timeout'     => 10,
				'sslverify'   => false,
				'redirection' => 3,
				'user-agent'  => 'Ondaweb Security Check',
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			)
		);
		$res               = wp_remote_request( $url, $args );
		self::$http[ $key ] = is_wp_error( $res ) ? null : $res;
		return self::$http[ $key ];
	}

	private static function home_res() {
		if ( null === self::$nc ) {
			self::$nc = (string) time();
		}
		return self::http( add_query_arg( 'owsu_nc', self::$nc, self::home() ) );
	}

	private static function header_value( $name ) {
		$r = self::home_res();
		if ( ! $r ) {
			return null;
		}
		$h = wp_remote_retrieve_header( $r, $name );
		return is_array( $h ) ? implode( ', ', $h ) : (string) $h;
	}

	private static function accessible( $url ) {
		$r = self::http( $url, array( 'redirection' => 0 ) );
		return $r && 200 === (int) wp_remote_retrieve_response_code( $r ) && '' !== trim( wp_remote_retrieve_body( $r ) );
	}

	private static function is_https() {
		return 0 === strpos( self::home(), 'https://' );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: software                                              */
	/* ------------------------------------------------------------------ */

	private static function check_vulns() {
		$v = OWSU_Vulns::get();
		if ( ! OWSU_Vulns::key() ) {
			return self::r( 'info', 'Configure a chave da API Wordfence Intelligence em Configurações para ativar esta verificação.' );
		}
		if ( empty( $v['time'] ) ) {
			return self::r( 'info', 'A base de vulnerabilidades ainda não foi baixada. Clique em "Atualizar base de vulnerabilidades".' );
		}
		$items = array();
		$crit  = false;
		foreach ( (array) $v['items'] as $it ) {
			$sev   = $it['rating'] ? $it['rating'] . ( $it['score'] ? ' ' . $it['score'] : '' ) : 'sem classificação';
			$fix   = $it['patched'] ? 'corrigido em ' . $it['patched'] : 'sem correção disponível';
			$items[] = sprintf( '%s %s — %s (%s; %s)', $it['name'], $it['version'], $it['title'], $sev, $fix );
			if ( in_array( strtolower( $it['rating'] ), array( 'high', 'critical' ), true ) || (float) $it['score'] >= 7 || ! $it['patched'] ) {
				$crit = true;
			}
		}
		$when = mysql2date( 'd/m/Y H:i', $v['time'] );
		if ( ! empty( $v['error'] ) ) {
			$note = ' Última tentativa de atualização falhou: ' . $v['error'];
		} else {
			$note = '';
		}
		if ( ! $items ) {
			return self::r( 'ok', 'Nenhuma vulnerabilidade conhecida nas versões instaladas (base de ' . $when . ').' . $note );
		}
		return self::r( $crit ? 'crit' : 'warn', count( $items ) . ' vulnerabilidade(s) conhecida(s) nas versões instaladas (base de ' . $when . ').' . $note, $items );
	}

	private static function check_wporg_closed() {
		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		OWUM_Collector::load_includes();
		$items  = array();
		$closed = false;
		$failed = 0;
		$tested = 0;
		foreach ( get_plugins() as $file => $data ) {
			$slug = false !== strpos( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
			$tkey = 'owsu_wporg_' . md5( $slug );
			$info = get_site_transient( $tkey );
			if ( false === $info ) {
				$res = plugins_api( 'plugin_information', array( 'slug' => $slug, 'fields' => array( 'sections' => false, 'last_updated' => true, 'description' => false, 'reviews' => false, 'banners' => false, 'icons' => false ) ) );
				if ( is_wp_error( $res ) ) {
					$msg = strtolower( $res->get_error_message() );
					if ( false !== strpos( $msg, 'closed' ) ) {
						$info = array( 'state' => 'closed' );
					} elseif ( false !== strpos( $msg, 'not found' ) ) {
						$info = array( 'state' => 'none' );
					} else {
						$failed++;
						continue; // falha de rede: não guarda cache
					}
				} else {
					$info = array( 'state' => 'ok', 'updated' => isset( $res->last_updated ) ? $res->last_updated : '' );
				}
				set_site_transient( $tkey, $info, 7 * DAY_IN_SECONDS );
			}
			$tested++;
			if ( 'closed' === $info['state'] ) {
				$items[] = $data['Name'] . ' — removido do wordpress.org (fechado)';
				$closed  = true;
			} elseif ( 'ok' === $info['state'] && $info['updated'] ) {
				$ts = strtotime( $info['updated'] );
				if ( $ts && $ts < strtotime( '-2 years' ) ) {
					$items[] = $data['Name'] . ' — sem atualização desde ' . gmdate( 'm/Y', $ts );
				}
			}
		}
		if ( $failed && ! $tested ) {
			return self::r( 'info', 'Não foi possível consultar o wordpress.org a partir do servidor.' );
		}
		if ( ! $items ) {
			return self::r( 'ok', 'Nenhum plugin fechado ou abandonado encontrado.' );
		}
		return self::r( $closed ? 'crit' : 'warn', count( $items ) . ' plugin(s) exigem atenção.', $items );
	}

	private static function check_inactive_items() {
		$inv     = OWUM_Collector::inventory();
		$own     = 'plugin:' . plugin_basename( OWUM_FILE );
		$items   = array();
		foreach ( $inv['plugins'] as $key => $p ) {
			if ( $key !== $own && ! $p['network_active'] && ! $p['site_ids'] && 'plugin:sqlite-database-integration/load.php' !== $key ) {
				$items[] = 'Plugin: ' . $p['name'] . ' ' . $p['installed'];
			}
		}
		// Mantém o tema padrão do WordPress como reserva.
		$keep = 'theme:' . ( defined( 'WP_DEFAULT_THEME' ) ? WP_DEFAULT_THEME : 'twentytwentyfive' );
		foreach ( $inv['themes'] as $key => $t ) {
			if ( ! $t['site_ids'] && $key !== $keep ) {
				$items[] = 'Tema: ' . $t['name'] . ' ' . $t['installed'];
			}
		}
		if ( ! $items ) {
			return self::r( 'ok', 'Todos os plugins e temas instalados estão em uso.' );
		}
		return self::r( 'warn', count( $items ) . ' item(ns) instalado(s) sem uso em nenhum site.', $items );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: cabeçalhos                                            */
	/* ------------------------------------------------------------------ */

	private static function header_check( $id, $name ) {
		$v = self::header_value( $name );
		if ( null === $v ) {
			return self::r( 'info', 'Não foi possível acessar a página inicial para ler os cabeçalhos.' );
		}
		if ( '' !== $v ) {
			return self::r( 'ok', ( self::is_on( $id ) ? 'Ativado pelo plugin — ' : 'Presente — ' ) . $name . ': ' . $v );
		}
		if ( self::is_on( $id ) ) {
			return self::r( 'warn', 'Correção ativa, mas o cabeçalho não aparece na página inicial (provável cache de página). Configure no servidor.' );
		}
		return self::r( 'warn', 'Cabeçalho ' . $name . ' ausente.' );
	}

	private static function check_hdr_hsts() {
		if ( ! self::is_https() ) {
			return self::r( 'info', 'Não se aplica: o site não está em HTTPS.' );
		}
		return self::header_check( 'hdr_hsts', 'strict-transport-security' );
	}

	private static function check_hdr_nosniff() {
		return self::header_check( 'hdr_nosniff', 'x-content-type-options' );
	}

	private static function check_hdr_frame() {
		$csp = self::header_value( 'content-security-policy' );
		if ( $csp && false !== stripos( $csp, 'frame-ancestors' ) && ! self::header_value( 'x-frame-options' ) ) {
			return self::r( 'ok', 'Protegido pela diretiva frame-ancestors da Content-Security-Policy.' );
		}
		return self::header_check( 'hdr_frame', 'x-frame-options' );
	}

	private static function check_hdr_referrer() {
		return self::header_check( 'hdr_referrer', 'referrer-policy' );
	}

	private static function check_hdr_permissions() {
		return self::header_check( 'hdr_permissions', 'permissions-policy' );
	}

	private static function check_hdr_csp() {
		$r = self::header_check( 'hdr_csp', 'content-security-policy' );
		if ( 'warn' === $r['status'] && ! self::is_on( 'hdr_csp' ) ) {
			$r['detail'] = 'Nenhuma Content-Security-Policy definida.';
		}
		return $r;
	}

	private static function check_hdr_powered() {
		$v = self::header_value( 'x-powered-by' );
		if ( null === $v ) {
			return self::r( 'info', 'Não foi possível acessar a página inicial para ler os cabeçalhos.' );
		}
		$server = self::header_value( 'server' );
		$extra  = ( $server && preg_match( '/\d/', $server ) ) ? ' O cabeçalho Server também informa versão: ' . $server . '.' : '';
		if ( '' === $v ) {
			return self::r( $extra ? 'info' : 'ok', 'X-Powered-By não exposto.' . $extra );
		}
		if ( self::is_on( 'hdr_powered' ) ) {
			return self::r( 'warn', 'O plugin já remove o cabeçalho do PHP, mas o servidor ainda envia: X-Powered-By: ' . $v . '. Veja "Como corrigir".' . $extra );
		}
		return self::r( 'warn', 'Exposto: X-Powered-By: ' . $v . '.' . $extra );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: arquivos                                              */
	/* ------------------------------------------------------------------ */

	private static function check_up_php_exec() {
		$u    = self::uploads();
		$name = 'owsu-test-' . wp_generate_password( 10, false, false ) . '.php';
		$file = $u['dir'] . '/' . $name;
		if ( ! wp_is_writable( $u['dir'] ) || false === @file_put_contents( $file, '<?php echo "OWSU" . "-EXEC-OK";' ) ) { // phpcs:ignore
			return self::r( 'info', 'Não foi possível criar o arquivo de teste na pasta uploads.' );
		}
		$r = self::http( $u['url'] . '/' . $name, array( 'redirection' => 0 ) );
		@unlink( $file ); // phpcs:ignore
		if ( ! $r ) {
			return self::r( 'info', 'O servidor não respondeu ao teste (requisição local bloqueada).' );
		}
		$code = (int) wp_remote_retrieve_response_code( $r );
		if ( false !== strpos( wp_remote_retrieve_body( $r ), 'OWSU-EXEC-OK' ) ) {
			$msg = 'Um arquivo PHP enviado para uploads é executado pelo servidor.';
			if ( self::is_on( 'up_php_exec' ) ) {
				$msg .= ' A regra .htaccess já foi aplicada, mas o servidor não a respeita (nginx/PHP-FPM direto). Aplique a diretiva do nginx indicada em "Como corrigir".';
			}
			return self::r( 'crit', $msg );
		}
		return self::r( 'ok', 'PHP não é executado em uploads (resposta HTTP ' . $code . ').' . ( self::is_on( 'up_php_exec' ) ? ' Regra aplicada pelo plugin.' : '' ) );
	}

	private static function check_up_listing() {
		$u = self::uploads();
		$r = self::http( $u['url'] . '/', array( 'redirection' => 0 ) );
		if ( ! $r ) {
			return self::r( 'info', 'O servidor não respondeu ao teste.' );
		}
		$body = wp_remote_retrieve_body( $r );
		if ( 200 === (int) wp_remote_retrieve_response_code( $r ) && preg_match( '/<title>\s*Index of|Directory listing for/i', $body ) ) {
			return self::r( 'warn', 'A pasta uploads lista todos os arquivos ao ser acessada pelo navegador.' . ( self::is_on( 'up_listing' ) ? ' A regra .htaccess está aplicada, mas o servidor não a respeita.' : '' ) );
		}
		return self::r( 'ok', 'Listagem de diretório bloqueada.' );
	}

	private static function check_up_php_files() {
		$u     = self::uploads();
		$items = array();
		$n     = 0;
		$start = microtime( true );
		if ( ! is_dir( $u['dir'] ) ) {
			return self::r( 'info', 'Pasta uploads não encontrada.' );
		}
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $u['dir'], FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( ++$n > 200000 || microtime( true ) - $start > 12 ) {
				$items[] = '(varredura interrompida por limite de tempo/quantidade)';
				break;
			}
			$ext = strtolower( $f->getExtension() );
			if ( ! in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht', 'phps' ), true ) ) {
				continue;
			}
			if ( 0 === strpos( $f->getFilename(), 'owsu-test-' ) ) {
				continue;
			}
			if ( 'index.php' === $f->getFilename() && $f->getSize() < 200 && false !== strpos( (string) @file_get_contents( $f->getPathname() ), 'Silence' ) ) { // phpcs:ignore
				continue;
			}
			$items[] = 'uploads' . substr( $f->getPathname(), strlen( $u['dir'] ) ) . ' (' . size_format( $f->getSize() ) . ', ' . gmdate( 'd/m/Y', $f->getMTime() ) . ')';
			if ( count( $items ) >= 100 ) {
				$items[] = '(lista limitada a 100 arquivos)';
				break;
			}
		}
		if ( ! $items ) {
			return self::r( 'ok', 'Nenhum arquivo PHP encontrado em uploads (' . number_format_i18n( $n ) . ' arquivos verificados).' );
		}
		return self::r( 'crit', 'Arquivos PHP encontrados na pasta uploads. Verifique imediatamente.', $items );
	}

	public static function wpconfig_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		if ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			return dirname( ABSPATH ) . '/wp-config.php';
		}
		return '';
	}

	/** O processo PHP é o dono do arquivo? (só então é seguro mudar permissões) */
	private static function php_owns( $path ) {
		if ( ! function_exists( 'posix_geteuid' ) ) {
			return @fileowner( $path ) === @fileowner( __FILE__ ); // phpcs:ignore
		}
		return @fileowner( $path ) === posix_geteuid(); // phpcs:ignore
	}

	private static function check_perm_wpconfig() {
		$p = self::wpconfig_path();
		if ( ! $p ) {
			return self::r( 'info', 'wp-config.php não localizado.' );
		}
		clearstatcache( true, $p );
		$perm = fileperms( $p ) & 0777;
		$txt  = 'Permissão atual: ' . sprintf( '%04o', $perm ) . '.';
		if ( $perm & 0022 ) {
			return self::r( 'crit', $txt . ' O arquivo pode ser alterado por outros usuários.' );
		}
		if ( $perm & 0004 ) {
			return self::r( 'warn', $txt . ' Legível por qualquer usuário do servidor; recomendado 640.' . ( self::php_owns( $p ) ? '' : ' (O plugin não pode corrigir: o PHP não é o dono do arquivo.)' ) );
		}
		return self::r( 'ok', $txt );
	}

	private static function writable_scan() {
		$root  = untrailingslashit( ABSPATH );
		$found = array();
		$n     = 0;
		$start = microtime( true );
		$it    = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( ++$n > 200000 || microtime( true ) - $start > 12 ) {
				break;
			}
			if ( $f->isLink() ) {
				continue;
			}
			$perm = $f->getPerms() & 0777;
			if ( $perm & 0002 ) {
				$found[ $f->getPathname() ] = $perm;
				if ( count( $found ) >= 500 ) {
					break;
				}
			}
		}
		return $found;
	}

	private static function check_perm_writable() {
		$found = self::writable_scan();
		if ( ! $found ) {
			return self::r( 'ok', 'Nenhuma pasta ou arquivo com escrita liberada para todos.' );
		}
		$items = array();
		foreach ( array_slice( $found, 0, 100, true ) as $path => $perm ) {
			$items[] = substr( $path, strlen( ABSPATH ) ) . ' (' . sprintf( '%04o', $perm ) . ')';
		}
		return self::r( 'warn', count( $found ) . ' item(ns) com permissão de escrita para todos.', $items );
	}

	/** Arquivos sensíveis candidatos: [caminho => [url, gravidade]]. */
	private static function sensitive_candidates() {
		$root  = ABSPATH;
		$base  = trailingslashit( self::site_url() );
		$list  = array();
		$add   = function ( $path, $sev ) use ( &$list, $root, $base ) {
			if ( file_exists( $path ) ) {
				$rel           = ltrim( str_replace( '\\', '/', substr( $path, strlen( $root ) ) ), '/' );
				$list[ $path ] = array( $base . $rel, $sev, $rel );
			}
		};
		foreach ( array( 'readme.html', 'license.txt', 'wp-config-sample.php' ) as $f ) {
			$add( $root . $f, 'warn' );
		}
		foreach ( array( '.env', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.save', 'wp-config.php.orig', 'wp-config.php~', 'wp-config.bak', 'wp-config.old', 'error_log', 'php_errorlog' ) as $f ) {
			$add( $root . $f, 'crit' );
		}
		if ( is_dir( $root . '.git' ) ) {
			$add( $root . '.git/HEAD', 'crit' );
		}
		$add( WP_CONTENT_DIR . '/debug.log', 'crit' );
		foreach ( array( '*.sql', '*.sql.gz', '*.zip', '*.tar', '*.tar.gz', '*.tgz', '*.rar', '*.7z', '*.bak', '*.log' ) as $pattern ) {
			foreach ( (array) glob( $root . $pattern ) as $f ) {
				if ( $f ) {
					$add( $f, 'crit' );
				}
			}
		}
		return $list;
	}

	private static function check_exposed_files() {
		$items = array();
		$worst = 'ok';
		foreach ( self::sensitive_candidates() as $path => $c ) {
			list( $url, $sev, $rel ) = $c;
			if ( self::accessible( $url ) ) {
				$items[] = $rel . ' — acessível publicamente';
				if ( 'crit' === $sev ) {
					$worst = 'crit';
				} elseif ( 'ok' === $worst ) {
					$worst = 'warn';
				}
			} elseif ( 'crit' === $sev && preg_match( '/\.(sql|gz|zip|tar|tgz|rar|7z|bak)$/i', $rel ) ) {
				$items[] = $rel . ' — bloqueado, mas recomenda-se remover/mover o arquivo';
				if ( 'ok' === $worst ) {
					$worst = 'info';
				}
			}
		}
		if ( 'ok' === $worst ) {
			return self::r( 'ok', 'Nenhum arquivo sensível acessível.' . ( self::is_on( 'exposed_files' ) ? ' Bloqueio aplicado pelo plugin.' : '' ) );
		}
		$msg = 'Arquivos sensíveis encontrados.';
		if ( self::is_on( 'exposed_files' ) && in_array( $worst, array( 'crit', 'warn' ), true ) ) {
			$msg .= ' O bloqueio .htaccess está aplicado, mas o servidor entrega estes arquivos diretamente (nginx). Veja "Como corrigir".';
		}
		return self::r( $worst, $msg, $items );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: WordPress                                             */
	/* ------------------------------------------------------------------ */

	private static function check_file_edit() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return self::r( 'ok', 'Desativado no wp-config.php (DISALLOW_FILE_EDIT).' );
		}
		if ( self::is_on( 'file_edit' ) ) {
			return self::r( 'ok', 'Desativado pelo plugin.' );
		}
		return self::r( 'warn', 'Administradores podem editar o código de plugins e temas pelo painel.' );
	}

	private static function check_debug_display() {
		$wp_debug = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display  = in_array( strtolower( (string) ini_get( 'display_errors' ) ), array( '1', 'on', 'stdout', 'true' ), true );
		if ( $wp_debug && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) && ! self::is_on( 'debug_display' ) ) {
			$display = true;
		}
		if ( $display ) {
			return self::r( 'crit', 'Erros do PHP são exibidos na tela para os visitantes.' . ( $wp_debug ? ' WP_DEBUG está ativo.' : '' ) );
		}
		if ( $wp_debug ) {
			return self::r( 'warn', 'WP_DEBUG está ativo em produção (erros ocultos' . ( self::is_on( 'debug_display' ) ? ' pelo plugin' : '' ) . '). Desative no wp-config.php.' );
		}
		return self::r( 'ok', 'Erros não são exibidos aos visitantes.' . ( self::is_on( 'debug_display' ) ? ' (reforçado pelo plugin)' : '' ) );
	}

	private static function check_salts() {
		$bad = array();
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $k ) {
			if ( ! defined( $k ) ) {
				$bad[] = $k . ' — não definida';
			} elseif ( 'put your unique phrase here' === constant( $k ) || strlen( (string) constant( $k ) ) < 32 ) {
				$bad[] = $k . ' — padrão ou fraca';
			}
		}
		if ( ! $bad ) {
			return self::r( 'ok', 'As 8 chaves estão definidas e são fortes.' );
		}
		return self::r( 'crit', 'Chaves de segurança ausentes ou fracas no wp-config.php.', $bad );
	}

	private static function check_force_ssl_admin() {
		if ( ! self::is_https() ) {
			return self::r( 'info', 'Não se aplica: o site não está em HTTPS.' );
		}
		if ( ( defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN ) ) {
			return self::r( 'ok', 'FORCE_SSL_ADMIN ativo no wp-config.php.' );
		}
		if ( self::is_on( 'force_ssl_admin' ) ) {
			return self::r( 'ok', 'Painel forçado em HTTPS pelo plugin.' );
		}
		return self::r( 'warn', 'O painel pode ser acessado por HTTP.' );
	}

	private static function check_auto_updates() {
		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			return self::r( 'warn', 'Todas as atualizações automáticas estão desativadas (AUTOMATIC_UPDATER_DISABLED).' );
		}
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
			return self::r( 'warn', 'Atualizações automáticas de segurança do WordPress desativadas (WP_AUTO_UPDATE_CORE = false).' );
		}
		return self::r( 'ok', 'Atualizações de segurança do WordPress são aplicadas automaticamente.' );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: exposição                                             */
	/* ------------------------------------------------------------------ */

	private static function check_xmlrpc() {
		$r = self::http(
			self::site_url( 'xmlrpc.php' ),
			array(
				'method'      => 'POST',
				'redirection' => 0,
				'headers'     => array( 'Content-Type' => 'text/xml' ),
				'body'        => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
			)
		);
		$jetpack = self::plugin_active( array( 'jetpack' ) );
		if ( ! $r ) {
			return self::r( 'info', 'Não foi possível testar o xmlrpc.php.' );
		}
		$body = wp_remote_retrieve_body( $r );
		if ( false !== strpos( $body, 'system.multicall' ) || false !== strpos( $body, 'wp.getUsersBlogs' ) ) {
			return self::r( 'warn', 'XML-RPC ativo e aceitando métodos de login.' . ( $jetpack ? ' Atenção: o Jetpack está ativo e depende do XML-RPC.' : '' ) );
		}
		return self::r( 'ok', 'XML-RPC bloqueado (HTTP ' . (int) wp_remote_retrieve_response_code( $r ) . ').' . ( self::is_on( 'xmlrpc' ) ? ' Desativado pelo plugin.' : '' ) );
	}

	private static function check_user_enum() {
		$found = array();
		$url   = is_multisite() ? get_rest_url( get_main_site_id(), 'wp/v2/users' ) : get_rest_url( null, 'wp/v2/users' );
		$r     = self::http( $url, array( 'redirection' => 0 ) );
		if ( $r && 200 === (int) wp_remote_retrieve_response_code( $r ) ) {
			$data = json_decode( wp_remote_retrieve_body( $r ), true );
			if ( is_array( $data ) && $data ) {
				foreach ( array_slice( $data, 0, 5 ) as $u ) {
					if ( isset( $u['slug'] ) ) {
						$found[] = 'API REST revela o usuário: ' . $u['slug'];
					}
				}
			}
		}
		$r2 = self::http( add_query_arg( 'author', 1, self::home() ), array( 'redirection' => 0 ) );
		if ( $r2 ) {
			$loc = (string) wp_remote_retrieve_header( $r2, 'location' );
			if ( preg_match( '#/author/([^/]+)#', $loc, $m ) ) {
				$found[] = '?author=1 redireciona para /author/' . $m[1];
			}
		}
		if ( ! $r && ! $r2 ) {
			return self::r( 'info', 'Não foi possível testar.' );
		}
		if ( ! $found ) {
			return self::r( 'ok', 'Os nomes de usuário não são revelados publicamente.' . ( self::is_on( 'user_enum' ) ? ' Bloqueado pelo plugin.' : '' ) );
		}
		return self::r( 'warn', 'Logins de usuários podem ser descobertos por qualquer visitante.', $found );
	}

	private static function check_generator() {
		$r = self::home_res();
		if ( ! $r ) {
			return self::r( 'info', 'Não foi possível acessar a página inicial.' );
		}
		if ( preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+content=["\'](WordPress[^"\']*)/i', wp_remote_retrieve_body( $r ), $m ) ) {
			return self::r( 'warn', 'A página inicial informa: ' . $m[1] . '.' );
		}
		return self::r( 'ok', 'A versão do WordPress não aparece no código da página.' );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: usuários                                              */
	/* ------------------------------------------------------------------ */

	private static function check_admin_username() {
		$found = array();
		foreach ( array( 'admin', 'administrator', 'administrador', 'adm', 'webmaster' ) as $login ) {
			$u = get_user_by( 'login', $login );
			if ( $u && ( is_super_admin( $u->ID ) || user_can( $u, 'manage_options' ) ) ) {
				$found[] = $login;
			}
		}
		if ( ! $found ) {
			return self::r( 'ok', 'Nenhum administrador com login previsível.' );
		}
		return self::r( 'warn', 'Administrador com login previsível: ' . implode( ', ', $found ) . '.' );
	}

	private static function check_admin_count() {
		$since = (int) get_site_option( 'owsu_tracking_since' );
		$users = array();
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u ) {
					$users[ $u->ID ] = array( $u, 'Super Admin' );
				}
			}
		}
		$args = array( 'role' => 'administrator', 'number' => 200 );
		if ( is_multisite() ) {
			$args['blog_id'] = get_main_site_id();
		}
		foreach ( get_users( $args ) as $u ) {
			if ( ! isset( $users[ $u->ID ] ) ) {
				$users[ $u->ID ] = array( $u, 'Administrador do site principal' );
			}
		}
		$items = array();
		$stale = 0;
		foreach ( $users as $row ) {
			list( $u, $role ) = $row;
			$last = (int) get_user_meta( $u->ID, 'owsu_last_login', true );
			if ( $last ) {
				$when = 'último acesso ' . wp_date( 'd/m/Y', $last );
				if ( $last < strtotime( '-180 days' ) ) {
					$stale++;
					$when .= ' (mais de 6 meses)';
				}
			} else {
				$when = $since ? 'sem acesso desde ' . wp_date( 'd/m/Y', $since ) : 'último acesso ainda não registrado';
				if ( $since && $since < strtotime( '-180 days' ) ) {
					$stale++;
				}
			}
			$items[] = $u->user_login . ' (' . $u->user_email . ') — ' . $role . ' — ' . $when;
		}
		$n = count( $users );
		if ( $stale ) {
			return self::r( 'warn', $n . ' conta(s) administrativa(s); ' . $stale . ' sem uso há mais de 6 meses.', $items );
		}
		if ( $n > 5 ) {
			return self::r( 'warn', $n . ' contas administrativas. Revise se todas são necessárias.', $items );
		}
		return self::r( 'info', $n . ' conta(s) administrativa(s).', $items );
	}

	public static function active_plugin_slugs() {
		$files = array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) );
		$files = array_merge( $files, is_multisite() ? (array) get_blog_option( get_main_site_id(), 'active_plugins', array() ) : (array) get_option( 'active_plugins', array() ) );
		return array_map(
			function ( $f ) {
				return false !== strpos( $f, '/' ) ? dirname( $f ) : basename( $f, '.php' );
			},
			$files
		);
	}

	private static function plugin_active( $slugs ) {
		return (bool) array_intersect( $slugs, self::active_plugin_slugs() );
	}

	private static function check_twofa() {
		$known = array( 'wordfence', 'two-factor', 'wp-2fa', 'better-wp-security', 'ithemes-security-pro', 'google-authenticator', 'miniorange-2-factor-authentication', 'all-in-one-wp-security-and-firewall', 'wordfence-login-security', 'loginizer-security', 'wp-cerber' );
		$hit   = array_values( array_intersect( $known, self::active_plugin_slugs() ) );
		if ( $hit ) {
			return self::r( 'ok', 'Plugin com 2FA ativo: ' . implode( ', ', $hit ) . '. Confirme que os administradores ativaram o 2FA.' );
		}
		return self::r( 'warn', 'Nenhum plugin de autenticação em dois fatores ativo.' );
	}

	private static function check_login_url() {
		if ( OWSU_Login::wps_active() ) {
			return self::r( 'ok', 'Endereço de login alterado pelo plugin WPS Hide Login. Este plugin pode substituí-lo (veja Configurações → Proteção do login).' );
		}
		$slug = OWSU_Login::slug();
		if ( '' === $slug ) {
			if ( defined( 'OWSU_LOGIN_SLUG_OFF' ) && OWSU_LOGIN_SLUG_OFF && OWSU_Login::saved_slug() ) {
				return self::r( 'warn', 'Desligado pela constante OWSU_LOGIN_SLUG_OFF no wp-config.php.' );
			}
			return self::r( 'warn', 'O login usa o endereço padrão /wp-login.php.' );
		}
		$base  = trailingslashit( self::site_url() );
		$old   = self::http( $base . 'wp-login.php', array( 'redirection' => 0 ) );
		$admin = self::http( $base . 'wp-admin/', array( 'redirection' => 0 ) );
		$new   = self::http( OWSU_Login::url( is_multisite() ? get_main_site_id() : null ), array( 'redirection' => 0 ) );
		if ( ! $old && ! $new ) {
			return self::r( 'info', 'Endereço configurado (/' . $slug . '), mas não foi possível testá-lo a partir do servidor.' );
		}
		$items = array();
		if ( $new && false === strpos( wp_remote_retrieve_body( $new ), 'user_login' ) ) {
			$items[] = 'O novo endereço não exibiu o formulário de login (HTTP ' . (int) wp_remote_retrieve_response_code( $new ) . '). Verifique se os links permanentes estão ativos.';
		}
		if ( $old && 200 === (int) wp_remote_retrieve_response_code( $old ) && false !== strpos( wp_remote_retrieve_body( $old ), 'user_login' ) ) {
			$items[] = '/wp-login.php continua exibindo o formulário de login.';
		}
		if ( $admin && 302 === (int) wp_remote_retrieve_response_code( $admin ) && false !== strpos( (string) wp_remote_retrieve_header( $admin, 'location' ), $slug ) ) {
			$items[] = '/wp-admin redireciona para o novo endereço e o revela.';
		}
		if ( $items ) {
			return self::r( 'warn', 'Endereço configurado (/' . $slug . '), mas há falhas.', $items );
		}
		return self::r( 'ok', 'Login em /' . $slug . '; /wp-login.php e /wp-admin não revelam o formulário para visitantes.' );
	}

	private static function check_login_captcha() {
		if ( OWSU_Captcha::active() ) {
			return self::r( 'ok', OWSU_Captcha::label() . ' ativo no login, senha perdida e cadastro.' );
		}
		if ( defined( 'OWSU_RECAPTCHA_OFF' ) && OWSU_RECAPTCHA_OFF && OWSU_Captcha::verified() ) {
			return self::r( 'warn', 'reCAPTCHA desligado pela constante OWSU_RECAPTCHA_OFF no wp-config.php.' );
		}
		if ( OWSU_Captcha::configured() ) {
			return self::r( 'warn', 'reCAPTCHA configurado, mas ainda não testado. Faça o teste em Configurações para ativá-lo.' );
		}
		$known = array( 'advanced-google-recaptcha', 'login-recaptcha', 'google-captcha', 'simple-google-recaptcha', 'simple-cloudflare-turnstile', 'cloudflare-turnstile', 'wp-recaptcha-integration', 'invisible-recaptcha', 'all-in-one-wp-security-and-firewall', 'better-wp-security', 'wp-cerber', 'loginizer-security' );
		$hit   = array_values( array_intersect( $known, self::active_plugin_slugs() ) );
		if ( $hit ) {
			return self::r( 'ok', 'Proteção anti-robô fornecida por: ' . implode( ', ', $hit ) . '.' );
		}
		return self::r( 'warn', 'O formulário de login não tem verificação anti-robô.' );
	}

	private static function check_login_limit() {
		$known = array( 'wordfence', 'limit-login-attempts-reloaded', 'loginizer', 'better-wp-security', 'ithemes-security-pro', 'all-in-one-wp-security-and-firewall', 'wp-cerber', 'jetpack', 'wps-limit-login' );
		$hit   = array_values( array_intersect( $known, self::active_plugin_slugs() ) );
		if ( $hit ) {
			return self::r( 'ok', 'Proteção de login ativa via: ' . implode( ', ', $hit ) . '.' );
		}
		return self::r( 'warn', 'Nenhum plugin limita tentativas de login (o servidor ainda pode ter Fail2Ban; verifique no Plesk).' );
	}

	/* ------------------------------------------------------------------ */
	/* Verificações: servidor                                              */
	/* ------------------------------------------------------------------ */

	private static function check_https() {
		if ( self::is_https() ) {
			return self::r( 'ok', 'O site principal usa HTTPS.' );
		}
		return self::r( 'crit', 'O endereço do site está configurado sem HTTPS.' );
	}

	private static function check_ssl_expiry() {
		if ( ! self::is_https() ) {
			return self::r( 'info', 'Não se aplica: o site não está em HTTPS.' );
		}
		if ( ! function_exists( 'openssl_x509_parse' ) || ! function_exists( 'stream_socket_client' ) ) {
			return self::r( 'info', 'Extensão OpenSSL indisponível no PHP.' );
		}
		$host = wp_parse_url( self::home(), PHP_URL_HOST );
		$ctx  = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);
		$c = @stream_socket_client( 'ssl://' . $host . ':443', $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx ); // phpcs:ignore
		if ( ! $c ) {
			return self::r( 'info', 'Não foi possível conectar em ' . $host . ':443 (' . $errstr . ').' );
		}
		$params = stream_context_get_params( $c );
		fclose( $c ); // phpcs:ignore
		$cert = isset( $params['options']['ssl']['peer_certificate'] ) ? openssl_x509_parse( $params['options']['ssl']['peer_certificate'] ) : null;
		if ( ! $cert ) {
			return self::r( 'info', 'Não foi possível ler o certificado.' );
		}
		$to     = (int) $cert['validTo_time_t'];
		$days   = (int) floor( ( $to - time() ) / DAY_IN_SECONDS );
		$issuer = isset( $cert['issuer']['O'] ) ? $cert['issuer']['O'] : ( isset( $cert['issuer']['CN'] ) ? $cert['issuer']['CN'] : '' );
		$txt    = 'Válido até ' . wp_date( 'd/m/Y', $to ) . ( $issuer ? ' (emitido por ' . $issuer . ')' : '' ) . '.';
		if ( $days < 0 ) {
			return self::r( 'crit', 'Certificado VENCIDO. ' . $txt );
		}
		if ( $days < 7 ) {
			return self::r( 'crit', 'Vence em ' . $days . ' dia(s). ' . $txt );
		}
		if ( $days < 20 ) {
			return self::r( 'warn', 'Vence em ' . $days . ' dias. Confirme a renovação automática. ' . $txt );
		}
		return self::r( 'ok', $txt . ' Faltam ' . $days . ' dias.' );
	}

	private static function check_php_version() {
		global $wpdb;
		$eol    = array(
			'7.4' => '2022-11-28',
			'8.0' => '2023-11-26',
			'8.1' => '2025-12-31',
			'8.2' => '2026-12-31',
			'8.3' => '2027-12-31',
			'8.4' => '2028-12-31',
			'8.5' => '2029-12-31',
		);
		$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
		$db     = method_exists( $wpdb, 'db_server_info' ) ? $wpdb->db_server_info() : '';
		$extra  = $db ? ' Banco de dados: ' . $db . '.' : '';
		if ( ! isset( $eol[ $branch ] ) ) {
			if ( version_compare( $branch, '7.4', '<' ) ) {
				return self::r( 'crit', 'PHP ' . PHP_VERSION . ' está sem suporte há anos.' . $extra );
			}
			return self::r( 'ok', 'PHP ' . PHP_VERSION . '.' . $extra );
		}
		$end = strtotime( $eol[ $branch ] );
		$txt = 'PHP ' . PHP_VERSION . ' — suporte de segurança ' . ( $end < time() ? 'encerrado em ' : 'até ' ) . wp_date( 'd/m/Y', $end ) . '.';
		if ( $end < time() ) {
			return self::r( 'crit', $txt . $extra );
		}
		if ( $end < strtotime( '+180 days' ) ) {
			return self::r( 'warn', $txt . ' Planeje a atualização.' . $extra );
		}
		return self::r( 'ok', $txt . $extra );
	}

	/* ------------------------------------------------------------------ */
	/* Aplicar / desfazer                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * @return true|WP_Error
	 */
	public static function apply( $id ) {
		$defs = self::definitions();
		if ( empty( $defs[ $id ]['fix'] ) ) {
			return new WP_Error( 'owsu', 'Esta verificação não tem correção automática.' );
		}
		$data = null;
		switch ( $id ) {
			case 'perm_wpconfig':
				$p = self::wpconfig_path();
				if ( ! $p || ! self::php_owns( $p ) ) {
					return new WP_Error( 'owsu', 'O PHP não é o dono do wp-config.php; altere a permissão pelo Plesk ou SSH.' );
				}
				clearstatcache( true, $p );
				$data = fileperms( $p ) & 0777;
				if ( ! @chmod( $p, 0640 ) ) { // phpcs:ignore
					return new WP_Error( 'owsu', 'Não foi possível alterar a permissão.' );
				}
				break;
			case 'perm_writable':
				$data = array();
				foreach ( self::writable_scan() as $path => $perm ) {
					if ( self::php_owns( $path ) && @chmod( $path, is_dir( $path ) ? 0755 : 0644 ) ) { // phpcs:ignore
						$data[ $path ] = $perm;
					}
				}
				if ( ! $data ) {
					return new WP_Error( 'owsu', 'Nenhuma permissão pôde ser alterada (o PHP não é dono dos arquivos). Use o comando indicado em "Como corrigir".' );
				}
				break;
		}
		$fixes        = self::fixes();
		$fixes[ $id ] = array(
			'on'   => 1,
			'when' => current_time( 'mysql' ),
			'data' => $data,
		);
		update_site_option( 'owsu_fixes', $fixes );

		if ( in_array( $id, array( 'up_php_exec', 'up_listing', 'exposed_files' ), true ) ) {
			$r = self::sync_htaccess();
			if ( ! is_wp_error( $r ) && ! self::site_healthy() ) {
				$r = new WP_Error( 'owsu', 'O servidor rejeitou a regra .htaccess (erro 500). A correção foi revertida automaticamente; use as instruções de "Como corrigir".' );
			}
			if ( is_wp_error( $r ) ) {
				unset( $fixes[ $id ] );
				update_site_option( 'owsu_fixes', $fixes );
				self::sync_htaccess();
				return $r;
			}
		}
		self::log( $id, 'correcao' );
		return true;
	}

	/** Depois de mexer no .htaccess: a página inicial e um arquivo de uploads continuam respondendo sem erro 5xx? */
	private static function site_healthy() {
		self::$http = array();
		$u    = self::uploads();
		$name = 'owsu-probe-' . wp_generate_password( 8, false, false ) . '.txt';
		$made = false !== @file_put_contents( $u['dir'] . '/' . $name, 'ok' ); // phpcs:ignore
		$ok   = true;
		$urls = array( add_query_arg( 'owsu_hc', time(), self::home() ) );
		if ( $made ) {
			$urls[] = $u['url'] . '/' . $name;
		}
		foreach ( $urls as $url ) {
			$r = wp_remote_get( $url, array( 'timeout' => 15, 'sslverify' => false, 'redirection' => 2 ) );
			if ( ! is_wp_error( $r ) && (int) wp_remote_retrieve_response_code( $r ) >= 500 ) {
				$ok = false;
			}
		}
		if ( $made ) {
			@unlink( $u['dir'] . '/' . $name ); // phpcs:ignore
		}
		self::$http = array();
		return $ok;
	}

	public static function undo( $id ) {
		if ( in_array( $id, array( 'login_url', 'login_captcha' ), true ) ) {
			$s = owum_settings();
			if ( 'login_url' === $id ) {
				$s['login_slug'] = '';
				update_site_option( 'owum_settings', $s );
				OWSU_Login::notify( '' );
			} else {
				$s['rc_verified'] = '';
				update_site_option( 'owum_settings', $s );
			}
			$fixes = self::fixes();
			unset( $fixes[ $id ] );
			update_site_option( 'owsu_fixes', $fixes );
			self::log( $id, 'desfeito' );
			return true;
		}
		$fixes = self::fixes();
		if ( empty( $fixes[ $id ] ) ) {
			return true;
		}
		$data = isset( $fixes[ $id ]['data'] ) ? $fixes[ $id ]['data'] : null;
		if ( 'perm_wpconfig' === $id && $data ) {
			@chmod( self::wpconfig_path(), (int) $data ); // phpcs:ignore
		}
		if ( 'perm_writable' === $id && is_array( $data ) ) {
			foreach ( $data as $path => $perm ) {
				@chmod( $path, (int) $perm ); // phpcs:ignore
			}
		}
		unset( $fixes[ $id ] );
		update_site_option( 'owsu_fixes', $fixes );
		if ( in_array( $id, array( 'up_php_exec', 'up_listing', 'exposed_files' ), true ) ) {
			self::sync_htaccess();
		}
		self::log( $id, 'desfeito' );
		return true;
	}

	private static function log( $id, $action ) {
		$d = self::definitions()[ $id ];
		OWUM_Logger::add(
			array(
				'item_type' => 'security',
				'item_key'  => 'sec:' . $id,
				'item_name' => $d['client'],
				'action'    => $action,
				'source'    => OWUM_Logger::source(),
				'notes'     => $d['title'],
			)
		);
	}

	/* ------------------------------------------------------------------ */
	/* .htaccess                                                           */
	/* ------------------------------------------------------------------ */

	private static function deny_block( $files_match ) {
		return array(
			'<FilesMatch "' . $files_match . '">',
			'  <IfModule mod_authz_core.c>',
			'    Require all denied',
			'  </IfModule>',
			'  <IfModule !mod_authz_core.c>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'</FilesMatch>',
		);
	}

	public static function clear_htaccess() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$u = self::uploads();
		self::write_block( $u['dir'] . '/.htaccess', array() );
		self::write_block( get_home_path() . '.htaccess', array() );
	}

	public static function sync_htaccess() {
		$u       = self::uploads();
		$uploads = array();
		if ( self::is_on( 'up_listing' ) ) {
			$uploads[] = 'Options -Indexes';
		}
		if ( self::is_on( 'up_php_exec' ) ) {
			$uploads = array_merge( $uploads, self::deny_block( '\.(?i:php[0-9]?|phtml|phar|pht|phps)$' ) );
		}
		$root = array();
		if ( self::is_on( 'exposed_files' ) ) {
			$root   = self::deny_block( '^(readme\.html|license\.txt|wp-config-sample\.php|debug\.log|error_log|php_errorlog|\.env)$|\.(sql|bak|old|orig|save|swp)$|~$' );
			$root[] = 'RedirectMatch 404 /\.git';
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$ok1 = self::write_block( $u['dir'] . '/.htaccess', $uploads );
		$ok2 = self::write_block( get_home_path() . '.htaccess', $root );
		if ( ! $ok1 || ! $ok2 ) {
			return new WP_Error( 'owsu', 'Não foi possível gravar o arquivo .htaccess (sem permissão de escrita). Use as instruções de "Como corrigir".' );
		}
		return true;
	}

	/** Grava (ou remove, se $lines vazio) o bloco do plugin no início do arquivo. */
	private static function write_block( $file, $lines ) {
		$current = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore
		$pattern = '/# BEGIN ' . preg_quote( self::MARK, '/' ) . '.*?# END ' . preg_quote( self::MARK, '/' ) . "\R?/s";
		$clean   = preg_replace( $pattern, '', $current );
		if ( $lines ) {
			$block = '# BEGIN ' . self::MARK . "\n# Regras gerenciadas pelo plugin Ondaweb Security Updater. Para remover, use \"Desfazer\" no painel.\n" . implode( "\n", $lines ) . "\n# END " . self::MARK . "\n";
			$new   = $block . ltrim( $clean );
		} else {
			$new = $clean;
		}
		if ( $new === $current ) {
			return true;
		}
		if ( '' === trim( $new ) && file_exists( $file ) && '' === trim( $clean ) && ! $lines ) {
			// Arquivo criado só pelo plugin: remove.
			return @unlink( $file ) || true; // phpcs:ignore
		}
		if ( ( file_exists( $file ) && ! wp_is_writable( $file ) ) || ( ! file_exists( $file ) && ! wp_is_writable( dirname( $file ) ) ) ) {
			return false;
		}
		return false !== @file_put_contents( $file, $new, LOCK_EX ); // phpcs:ignore
	}
}
