<?php
defined( 'ABSPATH' ) || exit;

/**
 * Security checks, fixes (apply/undo) and overall grade.
 */
class OWSU_Security {

	const MARK = 'Ondaweb Security';

	private static $http = array();
	private static $nc   = null;

	/* ------------------------------------------------------------------ */
	/* State                                                               */
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

	/** Records features turned on/off outside the "Apply" button (login settings). */
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

	/** Base uploads folder/URL of the main site. */
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
			'software' => __( 'Plugins, themes and vulnerabilities', 'ondaweb-security' ),
			'headers'  => __( 'Security headers (HTTP)', 'ondaweb-security' ),
			'files'    => __( 'Files, folders and permissions', 'ondaweb-security' ),
			'wp'       => __( 'WordPress configuration', 'ondaweb-security' ),
			'exposure' => __( 'Information exposure', 'ondaweb-security' ),
			'users'    => __( 'Users and access', 'ondaweb-security' ),
			'server'   => __( 'Server, PHP and SSL', 'ondaweb-security' ),
		);
	}

	public static function status_label( $s ) {
		$l = array(
			'crit' => __( 'Critical', 'ondaweb-security' ),
			'warn' => __( 'Warning', 'ondaweb-security' ),
			'ok'   => 'OK',
			'info' => __( 'Informational', 'ondaweb-security' ),
		);
		return isset( $l[ $s ] ) ? $l[ $s ] : $s;
	}

	/* ------------------------------------------------------------------ */
	/* Definitions                                                         */
	/* ------------------------------------------------------------------ */

	private static function code( $text ) {
		return '<pre style="white-space:pre-wrap;background:#f6f7f7;border:1px solid #dcdcde;padding:8px;border-radius:4px;font-size:12px;">' . esc_html( $text ) . '</pre>';
	}

	private static function nginx_where() {
		return __( '<p>On nginx (Plesk: <em>Websites & Domains → (domain) → Hosting & DNS → Apache & nginx Settings → Additional nginx directives</em>), paste the lines below, save and run the check again.</p>', 'ondaweb-security' );
	}

	private static function header_howto( $apache, $nginx ) {
		return __( '<p>Click <strong>Apply fix</strong> to have WordPress itself send the header. If the site uses page caching (WP Rocket, LiteSpeed, nginx cache), prefer configuring it on the server, because pages served from cache do not go through PHP.</p>', 'ondaweb-security' )
			. self::nginx_where() . self::code( $nginx )
			. __( '<p>Apache (.htaccess):</p>', 'ondaweb-security' ) . self::code( $apache );
	}

	public static function definitions() {
		static $d = null;
		if ( null !== $d ) {
			return $d;
		}
		$d = array(
			'vulns'            => array(
				'group'  => 'software',
				'title'  => __( 'Known vulnerabilities in the installed versions', 'ondaweb-security' ),
				'client' => __( 'Known vulnerability check', 'ondaweb-security' ),
				'why'    => __( 'Matches the installed versions of WordPress, plugins and themes against the Wordfence Intelligence database.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Update each item to the version listed as fixed. If there is no fix, deactivate and replace the plugin/theme. Paid plugins: ask the client for the update, explaining that it is a security fix.</p>', 'ondaweb-security' ),
			),
			'wporg_closed'     => array(
				'group'  => 'software',
				'title'  => __( 'Plugins removed or abandoned on wordpress.org', 'ondaweb-security' ),
				'client' => __( 'Review of unmaintained plugins', 'ondaweb-security' ),
				'why'    => __( 'Plugins closed in the repository often have unfixed flaws; plugins not updated for more than 2 years are a growing risk.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Replace closed plugins with maintained alternatives. For the ones without updates, assess whether they are still needed.</p>', 'ondaweb-security' ),
			),
			'inactive_items'   => array(
				'group'  => 'software',
				'title'  => __( 'Plugins and themes installed but not used', 'ondaweb-security' ),
				'client' => __( 'Removal of unused components', 'ondaweb-security' ),
				'why'    => __( 'Even when deactivated, the files remain on the server and can be exploited.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Remove them from the Plugins/Themes screen. Keep only one recent default theme (Twenty...) as a fallback.</p>', 'ondaweb-security' ),
			),
			'hdr_hsts'         => array(
				'group'  => 'headers',
				'title'  => __( 'HSTS (Strict-Transport-Security)', 'ondaweb-security' ),
				'client' => __( 'Browsing always over a secure connection (HTTPS)', 'ondaweb-security' ),
				'why'    => __( 'Forces the browser to use HTTPS, preventing the connection from being downgraded to HTTP.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Strict-Transport-Security "max-age=31536000"', 'add_header Strict-Transport-Security "max-age=31536000" always;' ),
			),
			'hdr_nosniff'      => array(
				'group'  => 'headers',
				'title'  => __( 'X-Content-Type-Options', 'ondaweb-security' ),
				'client' => __( 'Protection against files being misinterpreted', 'ondaweb-security' ),
				'why'    => __( 'Stops the browser from "guessing" the file type and running disguised content.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set X-Content-Type-Options "nosniff"', 'add_header X-Content-Type-Options "nosniff" always;' ),
			),
			'hdr_frame'        => array(
				'group'  => 'headers',
				'title'  => __( 'Clickjacking protection (X-Frame-Options)', 'ondaweb-security' ),
				'client' => __( 'Protection against the site being shown inside fake pages', 'ondaweb-security' ),
				'why'    => __( 'Prevents other domains from loading the site in an iframe to trick the user.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set X-Frame-Options "SAMEORIGIN"', 'add_header X-Frame-Options "SAMEORIGIN" always;' ),
			),
			'hdr_referrer'     => array(
				'group'  => 'headers',
				'title'  => __( 'Referrer-Policy', 'ondaweb-security' ),
				'client' => __( 'Privacy of external links', 'ondaweb-security' ),
				'why'    => __( 'Avoids leaking internal addresses (with parameters) to external sites.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Referrer-Policy "strict-origin-when-cross-origin"', 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' ),
			),
			'hdr_permissions'  => array(
				'group'  => 'headers',
				'title'  => __( 'Permissions-Policy', 'ondaweb-security' ),
				'client' => __( 'Camera and microphone blocked for third-party scripts', 'ondaweb-security' ),
				'why'    => __( 'Restricts sensitive browser features (camera, microphone, payment) that the site does not use.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => self::header_howto( 'Header always set Permissions-Policy "camera=(), microphone=(), payment=(), usb=(), geolocation=(self)"', 'add_header Permissions-Policy "camera=(), microphone=(), payment=(), usb=(), geolocation=(self)" always;' ),
			),
			'hdr_csp'          => array(
				'group'  => 'headers',
				'title'  => __( 'Content-Security-Policy (basic)', 'ondaweb-security' ),
				'client' => __( 'Content security policy', 'ondaweb-security' ),
				'why'    => __( 'The fix applies a basic, safe policy (forces resources over HTTPS and blocks external iframes). A full CSP, restricting scripts, needs manual tuning so it does not break Elementor and external services.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The automatic fix only applies <code>upgrade-insecure-requests; frame-ancestors \'self\'</code>. For a full policy, start in test mode (<code>Content-Security-Policy-Report-Only</code>), watch the browser console for a few days and only then enable it.</p>', 'ondaweb-security' ),
			),
			'hdr_powered'      => array(
				'group'  => 'headers',
				'title'  => __( 'Technology exposure (X-Powered-By)', 'ondaweb-security' ),
				'client' => __( 'Server technical information hidden', 'ondaweb-security' ),
				'why'    => __( 'Revealing the PHP/control panel version helps attackers pick exploits.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The plugin removes the header generated by PHP. If it still shows up (e.g. <code>PleskLin</code>), it comes from the server.</p>', 'ondaweb-security' ) . self::nginx_where() . self::code( 'proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;' ) . __( '<p>You can also turn off <code>expose_php</code> in the PHP settings of the domain.</p>', 'ondaweb-security' ),
			),
			'up_php_exec'      => array(
				'group'  => 'files',
				'title'  => __( 'PHP execution in the uploads folder', 'ondaweb-security' ),
				'client' => __( 'Script execution blocked in the uploaded files folder', 'ondaweb-security' ),
				'why'    => __( 'This is the most common way in: a malicious file uploaded as an "image" is executed on the server.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix writes rules to the <code>.htaccess</code> of the uploads folder (Apache). With nginx, static files may be served directly; if the check still fails after applying, add:</p>', 'ondaweb-security' ) . self::nginx_where() . self::code( 'location ~* ^/wp-content/uploads/.*\\.(php[0-9]?|phtml|phar|pht)$ {
    deny all;
}' ),
			),
			'up_listing'       => array(
				'group'  => 'files',
				'title'  => __( 'Directory listing in uploads', 'ondaweb-security' ),
				'client' => __( 'File listing blocked', 'ondaweb-security' ),
				'why'    => __( 'Without blocking, anyone can browse and download every uploaded file.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix adds <code>Options -Indexes</code> to the uploads <code>.htaccess</code>. On nginx, listing is controlled by <code>autoindex</code>; make sure it is <code>off</code>:</p>', 'ondaweb-security' ) . self::nginx_where() . self::code( 'autoindex off;' ),
			),
			'up_php_files'     => array(
				'group'  => 'files',
				'title'  => __( 'PHP files inside uploads', 'ondaweb-security' ),
				'client' => __( 'Scan for suspicious files', 'ondaweb-security' ),
				'why'    => __( 'The uploads folder should not contain scripts. PHP files there are a strong sign of an intrusion.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Open each listed file with your hosting file manager. If you do not recognize it, make a copy for analysis and remove it. Then run a full scan (Wordfence) and change the passwords of administrators, FTP and database.</p>', 'ondaweb-security' ),
			),
			'perm_wpconfig'    => array(
				'group'  => 'files',
				'title'  => __( 'wp-config.php permissions', 'ondaweb-security' ),
				'client' => __( 'Configuration file protection', 'ondaweb-security' ),
				'why'    => __( 'wp-config.php holds the database password and must not be readable by other users on the server.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>Recommended <code>640</code> (or <code>600</code>). In your hosting file manager: wp-config.php → Change permissions. Over SSH:</p>', 'ondaweb-security' ) . self::code( 'chmod 640 wp-config.php' ),
			),
			'perm_writable'    => array(
				'group'  => 'files',
				'title'  => __( 'Folders and files writable by everyone (777/666)', 'ondaweb-security' ),
				'client' => __( 'Folder and file permissions adjusted', 'ondaweb-security' ),
				'why'    => __( 'World-writable permissions let other processes on the server change the site.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>Recommended standard: folders <code>755</code>, files <code>644</code>. Over SSH, in the site folder:</p>', 'ondaweb-security' ) . self::code( 'find . -type d -perm -o+w -exec chmod 755 {} \\;
find . -type f -perm -o+w -exec chmod 644 {} \\;' ),
			),
			'exposed_files'    => array(
				'group'  => 'files',
				'title'  => __( 'Sensitive files publicly accessible', 'ondaweb-security' ),
				'client' => __( 'Access to sensitive files blocked', 'ondaweb-security' ),
				'why'    => __( 'Backups (.sql, .zip), .env, .git and debug.log can expose passwords and data. readme.html and license.txt reveal the WordPress version.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix blocks these files through <code>.htaccess</code>. Backups and copies in the site root should be <strong>removed or moved</strong> out of the public folder. If the block does not work (nginx serving directly):</p>', 'ondaweb-security' ) . self::nginx_where() . self::code( 'location ~ /\\.(?!well-known) { deny all; }
location ~* /(readme\\.html|license\\.txt|wp-config-sample\\.php)$ { deny all; }
location ~* \\.(sql|bak|old|orig|save|swp|log)$ { deny all; }' ),
			),
			'file_edit'        => array(
				'group'  => 'wp',
				'title'  => __( 'Dashboard file editor', 'ondaweb-security' ),
				'client' => __( 'Dashboard code editor disabled', 'ondaweb-security' ),
				'why'    => __( 'If an administrator account is compromised, the editor allows malicious code to be inserted straight into plugins and themes.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix blocks the editor through the plugin. Permanent alternative in <code>wp-config.php</code>:</p>', 'ondaweb-security' ) . self::code( 'define( \'DISALLOW_FILE_EDIT\', true );' ),
			),
			'debug_display'    => array(
				'group'  => 'wp',
				'title'  => __( 'Debug mode / error display', 'ondaweb-security' ),
				'client' => __( 'Technical error messages hidden', 'ondaweb-security' ),
				'why'    => __( 'Errors shown on screen reveal server paths and internal details.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix hides errors on screen. Ideally, adjust the production <code>wp-config.php</code>:</p>', 'ondaweb-security' ) . self::code( 'define( \'WP_DEBUG\', false );
define( \'WP_DEBUG_DISPLAY\', false );' ),
			),
			'salts'            => array(
				'group'  => 'wp',
				'title'  => __( 'Security keys (salts) in wp-config', 'ondaweb-security' ),
				'client' => __( 'Session security keys', 'ondaweb-security' ),
				'why'    => __( 'Missing or default keys make it easier to forge login sessions.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Generate new keys at <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener">api.wordpress.org/secret-key/1.1/salt</a> and replace the matching block in <code>wp-config.php</code>. All users will have to log in again.</p>', 'ondaweb-security' ),
			),
			'force_ssl_admin'  => array(
				'group'  => 'wp',
				'title'  => __( 'Admin dashboard over HTTPS only', 'ondaweb-security' ),
				'client' => __( 'Dashboard access over a secure connection only', 'ondaweb-security' ),
				'why'    => __( 'Ensures dashboard passwords and cookies never travel unencrypted.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>Alternative in <code>wp-config.php</code>:</p>', 'ondaweb-security' ) . self::code( 'define( \'FORCE_SSL_ADMIN\', true );' ),
			),
			'auto_updates'     => array(
				'group'  => 'wp',
				'title'  => __( 'WordPress automatic security updates', 'ondaweb-security' ),
				'client' => __( 'Automatic security updates', 'ondaweb-security' ),
				'why'    => __( 'Maintenance releases (e.g. 6.8.1 → 6.8.2) carry urgent fixes and should be applied automatically.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Remove the <code>AUTOMATIC_UPDATER_DISABLED</code> and <code>WP_AUTO_UPDATE_CORE = false</code> lines from <code>wp-config.php</code>, or use:</p>', 'ondaweb-security' ) . self::code( 'define( \'WP_AUTO_UPDATE_CORE\', \'minor\' );' ),
			),
			'xmlrpc'           => array(
				'group'  => 'exposure',
				'title'  => __( 'XML-RPC', 'ondaweb-security' ),
				'client' => __( 'Legacy interface used in password attacks disabled', 'ondaweb-security' ),
				'why'    => __( 'xmlrpc.php lets attackers try hundreds of passwords in a single request. It is only needed for Jetpack or the old WordPress app.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix disables XML-RPC through the plugin. Do not apply it if the site uses Jetpack or publishing from the old mobile app.</p>', 'ondaweb-security' ),
			),
			'user_enum'        => array(
				'group'  => 'exposure',
				'title'  => __( 'Public user listing', 'ondaweb-security' ),
				'client' => __( 'Usernames hidden', 'ondaweb-security' ),
				'why'    => __( 'The REST API and the ?author= parameter reveal user logins, half the way to a password attack.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix blocks the user listing in the API for logged-out visitors, the ?author= redirect and the users sitemap. The editor and the dashboard keep working normally.</p>', 'ondaweb-security' ),
			),
			'generator'        => array(
				'group'  => 'exposure',
				'title'  => __( 'WordPress version in the page source', 'ondaweb-security' ),
				'client' => __( 'WordPress version hidden', 'ondaweb-security' ),
				'why'    => __( 'The "generator" tag tells any visitor the exact WordPress version.', 'ondaweb-security' ),
				'fix'    => true,
				'howto'  => __( '<p>The fix removes the tag. Plugins such as Elementor may add their own tag; turn it off in the plugin settings, if available.</p>', 'ondaweb-security' ),
			),
			'admin_username'   => array(
				'group'  => 'users',
				'title'  => __( 'User with the "admin" login', 'ondaweb-security' ),
				'client' => __( 'Review of predictable usernames', 'ondaweb-security' ),
				'why'    => __( '"admin" is the first login tried in automated attacks.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Create a new administrator with a different login, log in with it, and delete the "admin" user, attributing its content to the new user.</p>', 'ondaweb-security' ),
			),
			'admin_count'      => array(
				'group'  => 'users',
				'title'  => __( 'Administrators and last login', 'ondaweb-security' ),
				'client' => __( 'Review of administrative accounts', 'ondaweb-security' ),
				'why'    => __( 'Every administrative account is a way in. Unused accounts should be removed or downgraded.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Review the list. The last login is recorded by the plugin since it was installed. Downgrade or remove accounts of people who no longer need access.</p>', 'ondaweb-security' ),
			),
			'twofa'            => array(
				'group'  => 'users',
				'title'  => __( 'Two-factor authentication (2FA)', 'ondaweb-security' ),
				'client' => __( 'Login with two-step verification', 'ondaweb-security' ),
				'why'    => __( 'With 2FA, a leaked password is not enough to break into the dashboard.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Recommended: <strong>Wordfence</strong> (free, includes 2FA and firewall) or the <strong>Two-Factor</strong> plugin. Enable it at least for administrators.</p>', 'ondaweb-security' ),
			),
			'login_url'        => array(
				'group'  => 'users',
				'title'  => __( 'Custom login address', 'ondaweb-security' ),
				'client' => __( 'Custom dashboard access address', 'ondaweb-security' ),
				'why'    => __( 'Bots attack /wp-login.php and /wp-admin on every WordPress site. With a custom address, those attacks never reach the login form.', 'ondaweb-security' ),
				'fix'    => false,
				'config' => true,
				'howto'  => __( '<p>In <strong>Settings → Login protection</strong>, enter the address you want (e.g. <code>restricted-access</code>) and save. It replaces the WPS Hide Login plugin, which can be deactivated afterwards.</p>', 'ondaweb-security' ),
			),
			'login_captcha'    => array(
				'group'  => 'users',
				'title'  => __( 'Anti-bot check on login (reCAPTCHA)', 'ondaweb-security' ),
				'client' => __( 'Anti-bot check on login (reCAPTCHA)', 'ondaweb-security' ),
				'why'    => __( 'Stops bots from trying passwords and sending "lost password" requests in bulk.', 'ondaweb-security' ),
				'fix'    => false,
				'config' => true,
				'howto'  => __( '<p>In <strong>Settings → Login protection</strong>, choose v2 or v3, paste the keys generated at <a href="https://www.google.com/recaptcha/admin/create" target="_blank" rel="noopener">google.com/recaptcha/admin</a>, save and run the test to activate it.</p>', 'ondaweb-security' ),
			),
			'login_limit'      => array(
				'group'  => 'users',
				'title'  => __( 'Login attempt limit', 'ondaweb-security' ),
				'client' => __( 'Protection against repeated password attempts', 'ondaweb-security' ),
				'why'    => __( 'Without a limit, bots can try passwords indefinitely.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p><strong>Wordfence</strong> already covers this. Lightweight alternative: <strong>Limit Login Attempts Reloaded</strong>. On the server, <em>Fail2Ban</em> with the WordPress filter can also be enabled (Plesk: WordPress Toolkit).</p>', 'ondaweb-security' ),
			),
			'https'            => array(
				'group'  => 'server',
				'title'  => __( 'Site on HTTPS', 'ondaweb-security' ),
				'client' => __( 'Secure connection (HTTPS)', 'ondaweb-security' ),
				'why'    => __( 'Without HTTPS, passwords and form data travel unencrypted.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>Issue a certificate (e.g. Let\'s Encrypt in your hosting panel) and change the site address to https (Settings → General, or Network → Sites).</p>', 'ondaweb-security' ),
			),
			'ssl_expiry'       => array(
				'group'  => 'server',
				'title'  => __( 'SSL certificate validity', 'ondaweb-security' ),
				'client' => __( 'Security certificate validity', 'ondaweb-security' ),
				'why'    => __( 'An expired certificate takes the site down and shows security warnings to visitors.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>In your hosting panel (Plesk: <em>SSL/TLS Certificates</em>), check that automatic renewal (Let\'s Encrypt) is active and renew manually if needed.</p>', 'ondaweb-security' ),
			),
			'php_version'      => array(
				'group'  => 'server',
				'title'  => __( 'PHP version', 'ondaweb-security' ),
				'client' => __( 'PHP version with security support', 'ondaweb-security' ),
				'why'    => __( 'PHP versions out of their support period receive no security fixes.', 'ondaweb-security' ),
				'fix'    => false,
				'howto'  => __( '<p>In your hosting panel (Plesk: <em>Websites & Domains → (domain) → PHP Settings</em>), choose the latest supported version (8.3 or 8.4). Test first on staging or with a backup, especially paid plugins.</p>', 'ondaweb-security' ),
			),
		);
		return $d;
	}

	/* ------------------------------------------------------------------ */
	/* Running                                                             */
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

	/** Runs one check; failures become an "Informational" result and go to the error log. */
	public static function run_check( $id ) {
		$m = 'check_' . $id;
		try {
			return self::$m();
		} catch ( \Throwable $e ) {
			OWUM_ErrorLog::add( 'warning', sprintf( /* translators: %s: check id */ __( 'Check "%s" did not finish', 'ondaweb-security' ), $id ) . ': ' . $e->getMessage(), array( 'file' => $e->getFile(), 'line' => $e->getLine(), 'trace' => $e->getTraceAsString() ), false );
			return self::r( 'info', __( 'Could not check:', 'ondaweb-security' ) . ' ' . $e->getMessage() );
		}
	}

	public static function reset_http() {
		self::$http = array();
		self::$nc   = null;
	}

	/** Re-runs a single check (after apply/undo). */
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
	/* Local HTTP (loopback)                                               */
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
				'user-agent'  => OWUM_PRODUCT . ' Check',
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
	/* Checks: software                                                    */
	/* ------------------------------------------------------------------ */

	private static function check_vulns() {
		$v = OWSU_Vulns::get();
		if ( ! OWSU_Vulns::key() ) {
			return self::r( 'info', __( 'Set the Wordfence Intelligence API key in Settings to enable this check.', 'ondaweb-security' ) );
		}
		if ( empty( $v['time'] ) ) {
			return self::r( 'info', __( 'The vulnerability database has not been downloaded yet. Click "Update vulnerability database".', 'ondaweb-security' ) );
		}
		$items = array();
		$crit  = false;
		foreach ( (array) $v['items'] as $it ) {
			$sev   = $it['rating'] ? $it['rating'] . ( $it['score'] ? ' ' . $it['score'] : '' ) : __( 'unrated', 'ondaweb-security' );
			$fix   = $it['patched'] ? sprintf( /* translators: %s: version */ __( 'fixed in %s', 'ondaweb-security' ), $it['patched'] ) : __( 'no fix available', 'ondaweb-security' );
			$items[] = sprintf( '%s %s — %s (%s; %s)', $it['name'], $it['version'], $it['title'], $sev, $fix );
			if ( in_array( strtolower( $it['rating'] ), array( 'high', 'critical' ), true ) || (float) $it['score'] >= 7 || ! $it['patched'] ) {
				$crit = true;
			}
		}
		$when = owum_date( $v['time'], true );
		if ( ! empty( $v['error'] ) ) {
			$note = ' ' . __( 'The last update attempt failed:', 'ondaweb-security' ) . ' ' . $v['error'];
		} else {
			$note = '';
		}
		if ( ! $items ) {
			return self::r( 'ok', sprintf( /* translators: %s: date of the database */ __( 'No known vulnerabilities in the installed versions (database of %s).', 'ondaweb-security' ), $when ) . $note );
		}
		return self::r( $crit ? 'crit' : 'warn', sprintf( /* translators: 1: count, 2: date of the database */ __( '%1$d known vulnerability(ies) in the installed versions (database of %2$s).', 'ondaweb-security' ), count( $items ), $when ) . $note, $items );
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
						continue; // network failure: do not cache
					}
				} else {
					$info = array( 'state' => 'ok', 'updated' => isset( $res->last_updated ) ? $res->last_updated : '' );
				}
				set_site_transient( $tkey, $info, 7 * DAY_IN_SECONDS );
			}
			$tested++;
			if ( 'closed' === $info['state'] ) {
				$items[] = $data['Name'] . ' — ' . __( 'removed from wordpress.org (closed)', 'ondaweb-security' );
				$closed  = true;
			} elseif ( 'ok' === $info['state'] && $info['updated'] ) {
				$ts = strtotime( $info['updated'] );
				if ( $ts && $ts < strtotime( '-2 years' ) ) {
					$items[] = $data['Name'] . ' — ' . sprintf( /* translators: %s: month and year */ __( 'not updated since %s', 'ondaweb-security' ), date_i18n( /* translators: PHP date format: month and year */ _x( 'm/Y', 'month and year', 'ondaweb-security' ), $ts ) );
				}
			}
		}
		if ( $failed && ! $tested ) {
			return self::r( 'info', __( 'Could not reach wordpress.org from the server.', 'ondaweb-security' ) );
		}
		if ( ! $items ) {
			return self::r( 'ok', __( 'No closed or abandoned plugin found.', 'ondaweb-security' ) );
		}
		return self::r( $closed ? 'crit' : 'warn', sprintf( /* translators: %d: count */ __( '%d plugin(s) need attention.', 'ondaweb-security' ), count( $items ) ), $items );
	}

	private static function check_inactive_items() {
		$inv     = OWUM_Collector::inventory();
		$own     = 'plugin:' . plugin_basename( OWUM_FILE );
		$items   = array();
		foreach ( $inv['plugins'] as $key => $p ) {
			if ( $key !== $own && ! $p['network_active'] && ! $p['site_ids'] && 'plugin:sqlite-database-integration/load.php' !== $key ) {
				$items[] = __( 'Plugin', 'ondaweb-security' ) . ': ' . $p['name'] . ' ' . $p['installed'];
			}
		}
		// Keeps the WordPress default theme as a fallback.
		$keep = 'theme:' . ( defined( 'WP_DEFAULT_THEME' ) ? WP_DEFAULT_THEME : 'twentytwentyfive' );
		foreach ( $inv['themes'] as $key => $t ) {
			if ( ! $t['site_ids'] && $key !== $keep ) {
				$items[] = __( 'Theme', 'ondaweb-security' ) . ': ' . $t['name'] . ' ' . $t['installed'];
			}
		}
		if ( ! $items ) {
			return self::r( 'ok', __( 'All installed plugins and themes are in use.', 'ondaweb-security' ) );
		}
		return self::r( 'warn', sprintf( /* translators: %d: count */ __( '%d installed item(s) not used on any site.', 'ondaweb-security' ), count( $items ) ), $items );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: headers                                                     */
	/* ------------------------------------------------------------------ */

	private static function header_check( $id, $name ) {
		$v = self::header_value( $name );
		if ( null === $v ) {
			return self::r( 'info', __( 'Could not open the home page to read the headers.', 'ondaweb-security' ) );
		}
		if ( '' !== $v ) {
			return self::r( 'ok', ( self::is_on( $id ) ? __( 'Enabled by the plugin', 'ondaweb-security' ) : __( 'Present', 'ondaweb-security' ) ) . ' — ' . $name . ': ' . $v );
		}
		if ( self::is_on( $id ) ) {
			return self::r( 'warn', __( 'Fix active, but the header does not show on the home page (probably page cache). Configure it on the server.', 'ondaweb-security' ) );
		}
		return self::r( 'warn', sprintf( /* translators: %s: header name */ __( 'Header %s missing.', 'ondaweb-security' ), $name ) );
	}

	private static function check_hdr_hsts() {
		if ( ! self::is_https() ) {
			return self::r( 'info', __( 'Not applicable: the site is not on HTTPS.', 'ondaweb-security' ) );
		}
		return self::header_check( 'hdr_hsts', 'strict-transport-security' );
	}

	private static function check_hdr_nosniff() {
		return self::header_check( 'hdr_nosniff', 'x-content-type-options' );
	}

	private static function check_hdr_frame() {
		$csp = self::header_value( 'content-security-policy' );
		if ( $csp && false !== stripos( $csp, 'frame-ancestors' ) && ! self::header_value( 'x-frame-options' ) ) {
			return self::r( 'ok', __( 'Protected by the frame-ancestors directive of the Content-Security-Policy.', 'ondaweb-security' ) );
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
			$r['detail'] = __( 'No Content-Security-Policy defined.', 'ondaweb-security' );
		}
		return $r;
	}

	private static function check_hdr_powered() {
		$v = self::header_value( 'x-powered-by' );
		if ( null === $v ) {
			return self::r( 'info', __( 'Could not open the home page to read the headers.', 'ondaweb-security' ) );
		}
		$server = self::header_value( 'server' );
		$extra  = ( $server && preg_match( '/\d/', $server ) ) ? ' ' . sprintf( /* translators: %s: value of the Server header */ __( 'The Server header also reveals a version: %s.', 'ondaweb-security' ), $server ) : '';
		if ( '' === $v ) {
			return self::r( $extra ? 'info' : 'ok', __( 'X-Powered-By not exposed.', 'ondaweb-security' ) . $extra );
		}
		if ( self::is_on( 'hdr_powered' ) ) {
			return self::r( 'warn', sprintf( /* translators: %s: header and value */ __( 'The plugin already removes the PHP header, but the server still sends: %s. See "How to fix".', 'ondaweb-security' ), 'X-Powered-By: ' . $v ) . $extra );
		}
		return self::r( 'warn', sprintf( /* translators: %s: header and value */ __( 'Exposed: %s.', 'ondaweb-security' ), 'X-Powered-By: ' . $v ) . $extra );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: files                                                       */
	/* ------------------------------------------------------------------ */

	private static function check_up_php_exec() {
		$u    = self::uploads();
		$name = 'owsu-test-' . wp_generate_password( 10, false, false ) . '.php';
		$file = $u['dir'] . '/' . $name;
		if ( ! wp_is_writable( $u['dir'] ) || false === @file_put_contents( $file, '<?php echo "OWSU" . "-EXEC-OK";' ) ) { // phpcs:ignore
			return self::r( 'info', __( 'Could not create the test file in the uploads folder.', 'ondaweb-security' ) );
		}
		$r = self::http( $u['url'] . '/' . $name, array( 'redirection' => 0 ) );
		@unlink( $file ); // phpcs:ignore
		if ( ! $r ) {
			return self::r( 'info', __( 'The server did not answer the test (local request blocked).', 'ondaweb-security' ) );
		}
		$code = (int) wp_remote_retrieve_response_code( $r );
		if ( false !== strpos( wp_remote_retrieve_body( $r ), 'OWSU-EXEC-OK' ) ) {
			$msg = __( 'A PHP file uploaded to uploads is executed by the server.', 'ondaweb-security' );
			if ( self::is_on( 'up_php_exec' ) ) {
				$msg .= ' ' . __( 'The .htaccess rule has already been applied, but the server ignores it (nginx/PHP-FPM directly). Apply the nginx directive shown in "How to fix".', 'ondaweb-security' );
			}
			return self::r( 'crit', $msg );
		}
		return self::r( 'ok', sprintf( /* translators: %d: HTTP status code */ __( 'PHP is not executed in uploads (HTTP response %d).', 'ondaweb-security' ), $code ) . ( self::is_on( 'up_php_exec' ) ? ' ' . __( 'Rule applied by the plugin.', 'ondaweb-security' ) : '' ) );
	}

	private static function check_up_listing() {
		$u = self::uploads();
		$r = self::http( $u['url'] . '/', array( 'redirection' => 0 ) );
		if ( ! $r ) {
			return self::r( 'info', __( 'The server did not answer the test.', 'ondaweb-security' ) );
		}
		$body = wp_remote_retrieve_body( $r );
		if ( 200 === (int) wp_remote_retrieve_response_code( $r ) && preg_match( '/<title>\s*Index of|Directory listing for/i', $body ) ) {
			return self::r( 'warn', __( 'The uploads folder lists every file when opened in the browser.', 'ondaweb-security' ) . ( self::is_on( 'up_listing' ) ? ' ' . __( 'The .htaccess rule is applied, but the server ignores it.', 'ondaweb-security' ) : '' ) );
		}
		return self::r( 'ok', __( 'Directory listing blocked.', 'ondaweb-security' ) );
	}

	private static function check_up_php_files() {
		$u     = self::uploads();
		$items = array();
		$n     = 0;
		$start = microtime( true );
		if ( ! is_dir( $u['dir'] ) ) {
			return self::r( 'info', __( 'Uploads folder not found.', 'ondaweb-security' ) );
		}
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $u['dir'], FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
		foreach ( $it as $f ) {
			if ( ++$n > 200000 || microtime( true ) - $start > 12 ) {
				$items[] = '(' . __( 'scan stopped by time/quantity limit', 'ondaweb-security' ) . ')';
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
			$items[] = 'uploads' . substr( $f->getPathname(), strlen( $u['dir'] ) ) . ' (' . size_format( $f->getSize() ) . ', ' . owum_date_ts( $f->getMTime() ) . ')';
			if ( count( $items ) >= 100 ) {
				$items[] = '(' . __( 'list limited to 100 files', 'ondaweb-security' ) . ')';
				break;
			}
		}
		if ( ! $items ) {
			return self::r( 'ok', sprintf( /* translators: %s: number of files */ __( 'No PHP file found in uploads (%s files checked).', 'ondaweb-security' ), number_format_i18n( $n ) ) );
		}
		return self::r( 'crit', __( 'PHP files found in the uploads folder. Check them immediately.', 'ondaweb-security' ), $items );
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

	/** Does the PHP process own the file? (only then is it safe to change permissions) */
	private static function php_owns( $path ) {
		if ( ! function_exists( 'posix_geteuid' ) ) {
			return @fileowner( $path ) === @fileowner( __FILE__ ); // phpcs:ignore
		}
		return @fileowner( $path ) === posix_geteuid(); // phpcs:ignore
	}

	private static function check_perm_wpconfig() {
		$p = self::wpconfig_path();
		if ( ! $p ) {
			return self::r( 'info', __( 'wp-config.php not found.', 'ondaweb-security' ) );
		}
		clearstatcache( true, $p );
		$perm = fileperms( $p ) & 0777;
		$txt  = sprintf( /* translators: %s: file permission, e.g. 0644 */ __( 'Current permission: %s.', 'ondaweb-security' ), sprintf( '%04o', $perm ) );
		if ( $perm & 0022 ) {
			return self::r( 'crit', $txt . ' ' . __( 'The file can be changed by other users.', 'ondaweb-security' ) );
		}
		if ( $perm & 0004 ) {
			return self::r( 'warn', $txt . ' ' . __( 'Readable by any user on the server; 640 recommended.', 'ondaweb-security' ) . ( self::php_owns( $p ) ? '' : ' ' . __( '(The plugin cannot fix it: PHP does not own the file.)', 'ondaweb-security' ) ) );
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
			return self::r( 'ok', __( 'No folder or file writable by everyone.', 'ondaweb-security' ) );
		}
		$items = array();
		foreach ( array_slice( $found, 0, 100, true ) as $path => $perm ) {
			$items[] = substr( $path, strlen( ABSPATH ) ) . ' (' . sprintf( '%04o', $perm ) . ')';
		}
		return self::r( 'warn', sprintf( /* translators: %d: count */ __( '%d item(s) writable by everyone.', 'ondaweb-security' ), count( $found ) ), $items );
	}

	/** Candidate sensitive files: [path => [url, severity, relative path]]. */
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
				$items[] = $rel . ' — ' . __( 'publicly accessible', 'ondaweb-security' );
				if ( 'crit' === $sev ) {
					$worst = 'crit';
				} elseif ( 'ok' === $worst ) {
					$worst = 'warn';
				}
			} elseif ( 'crit' === $sev && preg_match( '/\.(sql|gz|zip|tar|tgz|rar|7z|bak)$/i', $rel ) ) {
				$items[] = $rel . ' — ' . __( 'blocked, but removing/moving the file is recommended', 'ondaweb-security' );
				if ( 'ok' === $worst ) {
					$worst = 'info';
				}
			}
		}
		if ( 'ok' === $worst ) {
			return self::r( 'ok', __( 'No sensitive file accessible.', 'ondaweb-security' ) . ( self::is_on( 'exposed_files' ) ? ' ' . __( 'Block applied by the plugin.', 'ondaweb-security' ) : '' ) );
		}
		$msg = __( 'Sensitive files found.', 'ondaweb-security' );
		if ( self::is_on( 'exposed_files' ) && in_array( $worst, array( 'crit', 'warn' ), true ) ) {
			$msg .= ' ' . __( 'The .htaccess block is applied, but the server delivers these files directly (nginx). See "How to fix".', 'ondaweb-security' );
		}
		return self::r( $worst, $msg, $items );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: WordPress                                                   */
	/* ------------------------------------------------------------------ */

	private static function check_file_edit() {
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return self::r( 'ok', __( 'Disabled in wp-config.php (DISALLOW_FILE_EDIT).', 'ondaweb-security' ) );
		}
		if ( self::is_on( 'file_edit' ) ) {
			return self::r( 'ok', __( 'Disabled by the plugin.', 'ondaweb-security' ) );
		}
		return self::r( 'warn', __( 'Administrators can edit plugin and theme code from the dashboard.', 'ondaweb-security' ) );
	}

	private static function check_debug_display() {
		$wp_debug = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display  = in_array( strtolower( (string) ini_get( 'display_errors' ) ), array( '1', 'on', 'stdout', 'true' ), true );
		if ( $wp_debug && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) && ! self::is_on( 'debug_display' ) ) {
			$display = true;
		}
		if ( $display ) {
			return self::r( 'crit', __( 'PHP errors are displayed on screen to visitors.', 'ondaweb-security' ) . ( $wp_debug ? ' ' . __( 'WP_DEBUG is on.', 'ondaweb-security' ) : '' ) );
		}
		if ( $wp_debug ) {
			return self::r( 'warn', self::is_on( 'debug_display' ) ? __( 'WP_DEBUG is on in production (errors hidden by the plugin). Turn it off in wp-config.php.', 'ondaweb-security' ) : __( 'WP_DEBUG is on in production (errors hidden). Turn it off in wp-config.php.', 'ondaweb-security' ) );
		}
		return self::r( 'ok', __( 'Errors are not displayed to visitors.', 'ondaweb-security' ) . ( self::is_on( 'debug_display' ) ? ' ' . __( '(reinforced by the plugin)', 'ondaweb-security' ) : '' ) );
	}

	private static function check_salts() {
		$bad = array();
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $k ) {
			if ( ! defined( $k ) ) {
				$bad[] = $k . ' — ' . __( 'not defined', 'ondaweb-security' );
			} elseif ( 'put your unique phrase here' === constant( $k ) || strlen( (string) constant( $k ) ) < 32 ) {
				$bad[] = $k . ' — ' . __( 'default or weak', 'ondaweb-security' );
			}
		}
		if ( ! $bad ) {
			return self::r( 'ok', __( 'All 8 keys are defined and strong.', 'ondaweb-security' ) );
		}
		return self::r( 'crit', __( 'Missing or weak security keys in wp-config.php.', 'ondaweb-security' ), $bad );
	}

	private static function check_force_ssl_admin() {
		if ( ! self::is_https() ) {
			return self::r( 'info', __( 'Not applicable: the site is not on HTTPS.', 'ondaweb-security' ) );
		}
		if ( ( defined( 'FORCE_SSL_ADMIN' ) && FORCE_SSL_ADMIN ) ) {
			return self::r( 'ok', __( 'FORCE_SSL_ADMIN on in wp-config.php.', 'ondaweb-security' ) );
		}
		if ( self::is_on( 'force_ssl_admin' ) ) {
			return self::r( 'ok', __( 'Dashboard forced to HTTPS by the plugin.', 'ondaweb-security' ) );
		}
		return self::r( 'warn', __( 'The dashboard can be accessed over HTTP.', 'ondaweb-security' ) );
	}

	private static function check_auto_updates() {
		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			return self::r( 'warn', __( 'All automatic updates are disabled (AUTOMATIC_UPDATER_DISABLED).', 'ondaweb-security' ) );
		}
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
			return self::r( 'warn', __( 'WordPress automatic security updates disabled (WP_AUTO_UPDATE_CORE = false).', 'ondaweb-security' ) );
		}
		return self::r( 'ok', __( 'WordPress security updates are applied automatically.', 'ondaweb-security' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: exposure                                                    */
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
			return self::r( 'info', __( 'Could not test xmlrpc.php.', 'ondaweb-security' ) );
		}
		$body = wp_remote_retrieve_body( $r );
		if ( false !== strpos( $body, 'system.multicall' ) || false !== strpos( $body, 'wp.getUsersBlogs' ) ) {
			return self::r( 'warn', __( 'XML-RPC active and accepting login methods.', 'ondaweb-security' ) . ( $jetpack ? ' ' . __( 'Note: Jetpack is active and depends on XML-RPC.', 'ondaweb-security' ) : '' ) );
		}
		return self::r( 'ok', sprintf( /* translators: %d: HTTP status code */ __( 'XML-RPC blocked (HTTP %d).', 'ondaweb-security' ), (int) wp_remote_retrieve_response_code( $r ) ) . ( self::is_on( 'xmlrpc' ) ? ' ' . __( 'Disabled by the plugin.', 'ondaweb-security' ) : '' ) );
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
						$found[] = __( 'REST API reveals the user:', 'ondaweb-security' ) . ' ' . $u['slug'];
					}
				}
			}
		}
		$r2 = self::http( add_query_arg( 'author', 1, self::home() ), array( 'redirection' => 0 ) );
		if ( $r2 ) {
			$loc = (string) wp_remote_retrieve_header( $r2, 'location' );
			if ( preg_match( '#/author/([^/]+)#', $loc, $m ) ) {
				$found[] = sprintf( /* translators: %s: URL path */ __( '?author=1 redirects to %s', 'ondaweb-security' ), '/author/' . $m[1] );
			}
		}
		if ( ! $r && ! $r2 ) {
			return self::r( 'info', __( 'Could not test.', 'ondaweb-security' ) );
		}
		if ( ! $found ) {
			return self::r( 'ok', __( 'Usernames are not publicly revealed.', 'ondaweb-security' ) . ( self::is_on( 'user_enum' ) ? ' ' . __( 'Blocked by the plugin.', 'ondaweb-security' ) : '' ) );
		}
		return self::r( 'warn', __( 'User logins can be discovered by any visitor.', 'ondaweb-security' ), $found );
	}

	private static function check_generator() {
		$r = self::home_res();
		if ( ! $r ) {
			return self::r( 'info', __( 'Could not open the home page.', 'ondaweb-security' ) );
		}
		if ( preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+content=["\'](WordPress[^"\']*)/i', wp_remote_retrieve_body( $r ), $m ) ) {
			return self::r( 'warn', sprintf( /* translators: %s: generator tag content */ __( 'The home page states: %s.', 'ondaweb-security' ), $m[1] ) );
		}
		return self::r( 'ok', __( 'The WordPress version does not show in the page source.', 'ondaweb-security' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: users                                                       */
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
			return self::r( 'ok', __( 'No administrator with a predictable login.', 'ondaweb-security' ) );
		}
		return self::r( 'warn', sprintf( /* translators: %s: list of logins */ __( 'Administrator with a predictable login: %s.', 'ondaweb-security' ), implode( ', ', $found ) ) );
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
				$users[ $u->ID ] = array( $u, is_multisite() ? __( 'Main site administrator', 'ondaweb-security' ) : __( 'Administrator', 'ondaweb-security' ) );
			}
		}
		$items = array();
		$stale = 0;
		foreach ( $users as $row ) {
			list( $u, $role ) = $row;
			$last = (int) get_user_meta( $u->ID, 'owsu_last_login', true );
			if ( $last ) {
				$when = sprintf( /* translators: %s: date */ __( 'last login %s', 'ondaweb-security' ), owum_date_ts( $last ) );
				if ( $last < strtotime( '-180 days' ) ) {
					$stale++;
					$when .= ' ' . __( '(more than 6 months)', 'ondaweb-security' );
				}
			} else {
				$when = $since ? sprintf( /* translators: %s: date */ __( 'no login since %s', 'ondaweb-security' ), owum_date_ts( $since ) ) : __( 'last login not recorded yet', 'ondaweb-security' );
				if ( $since && $since < strtotime( '-180 days' ) ) {
					$stale++;
				}
			}
			$items[] = $u->user_login . ' (' . $u->user_email . ') — ' . $role . ' — ' . $when;
		}
		$n = count( $users );
		if ( $stale ) {
			return self::r( 'warn', sprintf( /* translators: 1: number of accounts, 2: number of unused accounts */ __( '%1$d administrative account(s); %2$d unused for more than 6 months.', 'ondaweb-security' ), $n, $stale ), $items );
		}
		if ( $n > 5 ) {
			return self::r( 'warn', sprintf( /* translators: %d: number of accounts */ __( '%d administrative accounts. Check whether all of them are needed.', 'ondaweb-security' ), $n ), $items );
		}
		return self::r( 'info', sprintf( /* translators: %d: number of accounts */ __( '%d administrative account(s).', 'ondaweb-security' ), $n ), $items );
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
			return self::r( 'ok', sprintf( /* translators: %s: plugin list */ __( 'Plugin with 2FA active: %s. Make sure the administrators have turned 2FA on.', 'ondaweb-security' ), implode( ', ', $hit ) ) );
		}
		return self::r( 'warn', __( 'No two-factor authentication plugin active.', 'ondaweb-security' ) );
	}

	private static function check_login_url() {
		if ( OWSU_Login::wps_active() ) {
			return self::r( 'ok', __( 'Login address changed by the WPS Hide Login plugin. This plugin can replace it (see Settings → Login protection).', 'ondaweb-security' ) );
		}
		$slug = OWSU_Login::slug();
		if ( '' === $slug ) {
			if ( defined( 'OWSU_LOGIN_SLUG_OFF' ) && OWSU_LOGIN_SLUG_OFF && OWSU_Login::saved_slug() ) {
				return self::r( 'warn', __( 'Turned off by the OWSU_LOGIN_SLUG_OFF constant in wp-config.php.', 'ondaweb-security' ) );
			}
			return self::r( 'warn', __( 'The login uses the default address /wp-login.php.', 'ondaweb-security' ) );
		}
		$base  = trailingslashit( self::site_url() );
		$old   = self::http( $base . 'wp-login.php', array( 'redirection' => 0 ) );
		$admin = self::http( $base . 'wp-admin/', array( 'redirection' => 0 ) );
		$new   = self::http( OWSU_Login::url( is_multisite() ? get_main_site_id() : null ), array( 'redirection' => 0 ) );
		if ( ! $old && ! $new ) {
			return self::r( 'info', sprintf( /* translators: %s: login path */ __( 'Address set (%s), but it could not be tested from the server.', 'ondaweb-security' ), '/' . $slug ) );
		}
		$items = array();
		if ( $new && false === strpos( wp_remote_retrieve_body( $new ), 'user_login' ) ) {
			$items[] = sprintf( /* translators: %d: HTTP status code */ __( 'The new address did not show the login form (HTTP %d). Check that permalinks are enabled.', 'ondaweb-security' ), (int) wp_remote_retrieve_response_code( $new ) );
		}
		if ( $old && 200 === (int) wp_remote_retrieve_response_code( $old ) && false !== strpos( wp_remote_retrieve_body( $old ), 'user_login' ) ) {
			$items[] = __( '/wp-login.php still shows the login form.', 'ondaweb-security' );
		}
		if ( $admin && 302 === (int) wp_remote_retrieve_response_code( $admin ) && false !== strpos( (string) wp_remote_retrieve_header( $admin, 'location' ), $slug ) ) {
			$items[] = __( '/wp-admin redirects to the new address and reveals it.', 'ondaweb-security' );
		}
		if ( $items ) {
			return self::r( 'warn', sprintf( /* translators: %s: login path */ __( 'Address set (%s), but there are problems.', 'ondaweb-security' ), '/' . $slug ), $items );
		}
		return self::r( 'ok', sprintf( /* translators: %s: login path */ __( 'Login at %s; /wp-login.php and /wp-admin do not reveal the form to visitors.', 'ondaweb-security' ), '/' . $slug ) );
	}

	private static function check_login_captcha() {
		if ( OWSU_Captcha::active() ) {
			return self::r( 'ok', sprintf( /* translators: %s: reCAPTCHA version */ __( '%s active on login, lost password and registration.', 'ondaweb-security' ), OWSU_Captcha::label() ) );
		}
		if ( defined( 'OWSU_RECAPTCHA_OFF' ) && OWSU_RECAPTCHA_OFF && OWSU_Captcha::verified() ) {
			return self::r( 'warn', __( 'reCAPTCHA turned off by the OWSU_RECAPTCHA_OFF constant in wp-config.php.', 'ondaweb-security' ) );
		}
		if ( OWSU_Captcha::configured() ) {
			return self::r( 'warn', __( 'reCAPTCHA configured but not tested yet. Run the test in Settings to activate it.', 'ondaweb-security' ) );
		}
		$known = array( 'advanced-google-recaptcha', 'login-recaptcha', 'google-captcha', 'simple-google-recaptcha', 'simple-cloudflare-turnstile', 'cloudflare-turnstile', 'wp-recaptcha-integration', 'invisible-recaptcha', 'all-in-one-wp-security-and-firewall', 'better-wp-security', 'wp-cerber', 'loginizer-security' );
		$hit   = array_values( array_intersect( $known, self::active_plugin_slugs() ) );
		if ( $hit ) {
			return self::r( 'ok', sprintf( /* translators: %s: plugin list */ __( 'Anti-bot protection provided by: %s.', 'ondaweb-security' ), implode( ', ', $hit ) ) );
		}
		return self::r( 'warn', __( 'The login form has no anti-bot check.', 'ondaweb-security' ) );
	}

	private static function check_login_limit() {
		$known = array( 'wordfence', 'limit-login-attempts-reloaded', 'loginizer', 'better-wp-security', 'ithemes-security-pro', 'all-in-one-wp-security-and-firewall', 'wp-cerber', 'jetpack', 'wps-limit-login' );
		$hit   = array_values( array_intersect( $known, self::active_plugin_slugs() ) );
		if ( $hit ) {
			return self::r( 'ok', sprintf( /* translators: %s: plugin list */ __( 'Login protection active through: %s.', 'ondaweb-security' ), implode( ', ', $hit ) ) );
		}
		return self::r( 'warn', __( 'No plugin limits login attempts (the server may still have Fail2Ban; check your hosting panel).', 'ondaweb-security' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Checks: server                                                      */
	/* ------------------------------------------------------------------ */

	private static function check_https() {
		if ( self::is_https() ) {
			return self::r( 'ok', __( 'The main site uses HTTPS.', 'ondaweb-security' ) );
		}
		return self::r( 'crit', __( 'The site address is set without HTTPS.', 'ondaweb-security' ) );
	}

	private static function check_ssl_expiry() {
		if ( ! self::is_https() ) {
			return self::r( 'info', __( 'Not applicable: the site is not on HTTPS.', 'ondaweb-security' ) );
		}
		if ( ! function_exists( 'openssl_x509_parse' ) || ! function_exists( 'stream_socket_client' ) ) {
			return self::r( 'info', __( 'OpenSSL extension unavailable in PHP.', 'ondaweb-security' ) );
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
			return self::r( 'info', sprintf( /* translators: 1: host and port, 2: error message */ __( 'Could not connect to %1$s (%2$s).', 'ondaweb-security' ), $host . ':443', $errstr ) );
		}
		$params = stream_context_get_params( $c );
		fclose( $c ); // phpcs:ignore
		$cert = isset( $params['options']['ssl']['peer_certificate'] ) ? openssl_x509_parse( $params['options']['ssl']['peer_certificate'] ) : null;
		if ( ! $cert ) {
			return self::r( 'info', __( 'Could not read the certificate.', 'ondaweb-security' ) );
		}
		$to     = (int) $cert['validTo_time_t'];
		$days   = (int) floor( ( $to - time() ) / DAY_IN_SECONDS );
		$issuer = isset( $cert['issuer']['O'] ) ? $cert['issuer']['O'] : ( isset( $cert['issuer']['CN'] ) ? $cert['issuer']['CN'] : '' );
		$txt    = $issuer ? sprintf( /* translators: 1: date, 2: certificate issuer */ __( 'Valid until %1$s (issued by %2$s).', 'ondaweb-security' ), owum_date_ts( $to ), $issuer ) : sprintf( /* translators: %s: date */ __( 'Valid until %s.', 'ondaweb-security' ), owum_date_ts( $to ) );
		if ( $days < 0 ) {
			return self::r( 'crit', __( 'Certificate EXPIRED.', 'ondaweb-security' ) . ' ' . $txt );
		}
		if ( $days < 7 ) {
			return self::r( 'crit', sprintf( /* translators: %d: number of days */ __( 'Expires in %d day(s).', 'ondaweb-security' ), $days ) . ' ' . $txt );
		}
		if ( $days < 20 ) {
			return self::r( 'warn', sprintf( /* translators: %d: number of days */ __( 'Expires in %d days. Confirm that automatic renewal is on.', 'ondaweb-security' ), $days ) . ' ' . $txt );
		}
		return self::r( 'ok', $txt . ' ' . sprintf( /* translators: %d: number of days */ __( '%d days left.', 'ondaweb-security' ), $days ) );
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
		$extra  = $db ? ' ' . sprintf( /* translators: %s: database server version */ __( 'Database: %s.', 'ondaweb-security' ), $db ) : '';
		if ( ! isset( $eol[ $branch ] ) ) {
			if ( version_compare( $branch, '7.4', '<' ) ) {
				return self::r( 'crit', sprintf( /* translators: %s: PHP version */ __( 'PHP %s has been unsupported for years.', 'ondaweb-security' ), PHP_VERSION ) . $extra );
			}
			return self::r( 'ok', 'PHP ' . PHP_VERSION . '.' . $extra );
		}
		$end = strtotime( $eol[ $branch ] );
		$txt = sprintf( $end < time() ? /* translators: 1: PHP version, 2: date */ __( 'PHP %1$s — security support ended on %2$s.', 'ondaweb-security' ) : /* translators: 1: PHP version, 2: date */ __( 'PHP %1$s — security support until %2$s.', 'ondaweb-security' ), PHP_VERSION, owum_date_ts( $end ) );
		if ( $end < time() ) {
			return self::r( 'crit', $txt . $extra );
		}
		if ( $end < strtotime( '+180 days' ) ) {
			return self::r( 'warn', $txt . ' ' . __( 'Plan the upgrade.', 'ondaweb-security' ) . $extra );
		}
		return self::r( 'ok', $txt . $extra );
	}

	/* ------------------------------------------------------------------ */
	/* Apply / undo                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * @return true|WP_Error
	 */
	public static function apply( $id ) {
		$defs = self::definitions();
		if ( empty( $defs[ $id ]['fix'] ) ) {
			return new WP_Error( 'owsu', __( 'This check has no automatic fix.', 'ondaweb-security' ) );
		}
		$data = null;
		switch ( $id ) {
			case 'perm_wpconfig':
				$p = self::wpconfig_path();
				if ( ! $p || ! self::php_owns( $p ) ) {
					return new WP_Error( 'owsu', __( 'PHP does not own wp-config.php; change the permission through your hosting panel or SSH.', 'ondaweb-security' ) );
				}
				clearstatcache( true, $p );
				$data = fileperms( $p ) & 0777;
				if ( ! @chmod( $p, 0640 ) ) { // phpcs:ignore
					return new WP_Error( 'owsu', __( 'Could not change the permission.', 'ondaweb-security' ) );
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
					return new WP_Error( 'owsu', __( 'No permission could be changed (PHP does not own the files). Use the command shown in "How to fix".', 'ondaweb-security' ) );
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
				$r = new WP_Error( 'owsu', __( 'The server rejected the .htaccess rule (error 500). The fix was reverted automatically; use the instructions in "How to fix".', 'ondaweb-security' ) );
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

	/** After changing .htaccess: do the home page and an uploads file still answer without a 5xx error? */
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
			return new WP_Error( 'owsu', __( 'Could not write the .htaccess file (no write permission). Use the instructions in "How to fix".', 'ondaweb-security' ) );
		}
		return true;
	}

	/** Writes (or removes, when $lines is empty) the plugin block at the top of the file. */
	private static function write_block( $file, $lines ) {
		$current = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore
		$pattern = '/# BEGIN ' . preg_quote( self::MARK, '/' ) . '.*?# END ' . preg_quote( self::MARK, '/' ) . "\R?/s";
		$clean   = preg_replace( $pattern, '', $current );
		if ( $lines ) {
			$block = '# BEGIN ' . self::MARK . "\n# Rules managed by the " . OWUM_PRODUCT . " plugin. To remove them, use \"Undo\" in its Security panel.\n" . implode( "\n", $lines ) . "\n# END " . self::MARK . "\n";
			$new   = $block . ltrim( $clean );
		} else {
			$new = $clean;
		}
		if ( $new === $current ) {
			return true;
		}
		if ( '' === trim( $new ) && file_exists( $file ) && '' === trim( $clean ) && ! $lines ) {
			// File created only by the plugin: remove it.
			return @unlink( $file ) || true; // phpcs:ignore
		}
		if ( ( file_exists( $file ) && ! wp_is_writable( $file ) ) || ( ! file_exists( $file ) && ! wp_is_writable( dirname( $file ) ) ) ) {
			return false;
		}
		return false !== @file_put_contents( $file, $new, LOCK_EX ); // phpcs:ignore
	}
}
