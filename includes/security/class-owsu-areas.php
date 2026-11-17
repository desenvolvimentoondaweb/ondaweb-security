<?php
defined( 'ABSPATH' ) || exit;

/**
 * Client-facing view of the security checks: 9 areas, each with what it covers,
 * the risk it reduces and the actions (one or more per check). Used by the report.
 */
class OWSU_Areas {

	public static function all() {
		static $a = null;
		if ( null !== $a ) {
			return $a;
		}
		$a = array(
			'headers' => array(
				'icon'    => 'cross',
				'title'   => __( 'Security headers', 'ondaweb-security' ),
				'scope'   => __( 'Instructions the server sends to the browser: mandatory HTTPS, blocking display inside third-party pages and rules for loading content.', 'ondaweb-security' ),
				'intro'   => __( 'Instructions sent by the server with every response, telling the visitor\'s browser to treat the site more safely.', 'ondaweb-security' ),
				'risk'    => __( 'Interception of data in transit, use of the site inside fake pages and execution of unauthorized content in the visitor\'s browser.', 'ondaweb-security' ),
				'actions' => array(
					array( 'hdr_hsts', __( 'HSTS (mandatory HTTPS)', 'ondaweb-security' ), __( 'the browser only accesses the site over an encrypted connection, even if the visitor types the address without https.', 'ondaweb-security' ) ),
					array( 'hdr_frame', __( 'Clickjacking protection', 'ondaweb-security' ), __( 'prevents the site from being shown inside third-party pages to trick visitors into clicking without noticing.', 'ondaweb-security' ) ),
					array( 'hdr_nosniff', __( 'Nosniff', 'ondaweb-security' ), __( 'the browser respects the file type stated by the server and does not try to interpret a file as another format.', 'ondaweb-security' ) ),
					array( 'hdr_referrer', __( 'Referrer policy', 'ondaweb-security' ), __( 'limits the browsing information passed on to other sites when the visitor clicks an external link.', 'ondaweb-security' ) ),
					array( 'hdr_permissions', __( 'Permissions policy', 'ondaweb-security' ), __( 'restricts the use of browser features by the site\'s pages.', 'ondaweb-security' ) ),
					array( 'hdr_csp', __( 'Structural Content Security Policy (CSP)', 'ondaweb-security' ), __( 'sets rules for the content the page can load, reducing the room for code injection.', 'ondaweb-security' ) ),
				),
			),
			'admin' => array(
				'icon'    => 'chip',
				'title'   => __( 'Administrative access', 'ondaweb-security' ),
				'scope'   => __( 'WordPress login screen and dashboard: access address, barriers against bots, attempt limit and a second authentication step.', 'ondaweb-security' ),
				'intro'   => __( 'Layers of protection around the WordPress dashboard, the most targeted point in automated intrusion attempts.', 'ondaweb-security' ),
				'risk'    => __( 'Improper access to the dashboard through brute force, leaked passwords or automation against the default login address.', 'ondaweb-security' ),
				'actions' => array(
					array( 'login_url', __( 'Custom login address', 'ondaweb-security' ), __( 'the access screen is no longer at the default WordPress address, the first target of bots.', 'ondaweb-security' ) ),
					array( 'login_url', __( '<code>/wp-login.php</code> and <code>/wp-admin</code> blocked for visitors', 'ondaweb-security' ), __( 'the default addresses do not answer anyone who is not logged in.', 'ondaweb-security' ) ),
					array( 'login_captcha', __( 'reCAPTCHA on login', 'ondaweb-security' ), __( 'makes access attempts by automated scripts harder.', 'ondaweb-security' ) ),
					array( 'login_limit', __( 'Attempt limit', 'ondaweb-security' ), __( 'stops sequences of password trial and error (brute force).', 'ondaweb-security' ) ),
					array( 'twofa', __( 'Two-factor authentication', 'ondaweb-security' ), __( 'besides the password, access requires a second confirmation; a leaked password alone does not open the dashboard.', 'ondaweb-security' ) ),
					array( 'force_ssl_admin', __( 'Dashboard over HTTPS only', 'ondaweb-security' ), __( 'username and password always travel encrypted.', 'ondaweb-security' ) ),
					array( 'admin_username', __( 'No predictable login', 'ondaweb-security' ), __( 'there is no administrator with the "admin" login, the first one tried by bots.', 'ondaweb-security' ) ),
				),
			),
			'enum' => array(
				'icon'    => 'bars',
				'title'   => __( 'Protection against user enumeration', 'ondaweb-security' ),
				'scope'   => __( 'Points of the site that could reveal login names: REST API, author lookup and sitemaps.', 'ondaweb-security' ),
				'intro'   => __( 'Enumerating users means discovering a site\'s login names. With the name in hand, the attacker already has half of the credential.', 'ondaweb-security' ),
				'risk'    => __( 'Collection of usernames to aim password attacks and phishing attempts at the team.', 'ondaweb-security' ),
				'actions' => array(
					array( 'user_enum', __( 'REST API', 'ondaweb-security' ), __( 'the user listing was blocked in the WordPress data interface.', 'ondaweb-security' ) ),
					array( 'user_enum', __( '<code>?author=</code> address', 'ondaweb-security' ), __( 'the lookup that revealed the login name from the author number no longer answers.', 'ondaweb-security' ) ),
					array( 'user_enum', __( 'Sitemaps', 'ondaweb-security' ), __( 'the authors sitemap was removed.', 'ondaweb-security' ) ),
				),
			),
			'xmlrpc' => array(
				'icon'    => 'plug',
				'title'   => __( 'XML-RPC', 'ondaweb-security' ),
				'scope'   => __( 'Old WordPress remote communication interface, disabled because it is a channel widely used in password attacks.', 'ondaweb-security' ),
				'intro'   => __( 'Old WordPress remote communication interface, rarely used today and often exploited.', 'ondaweb-security' ),
				'risk'    => __( 'Mass brute force and abuse of the channel for overload attacks.', 'ondaweb-security' ),
				'actions' => array(
					array( 'xmlrpc', __( 'Interface disabled', 'ondaweb-security' ), __( 'the site no longer accepts requests through this channel, which allows testing many passwords in a single call and can be used to overload the site.', 'ondaweb-security' ) ),
				),
			),
			'exposure' => array(
				'icon'    => 'cross',
				'title'   => __( 'Less exposed information', 'ondaweb-security' ),
				'scope'   => __( 'Technical data visible to any visitor: WordPress version and server technology.', 'ondaweb-security' ),
				'intro'   => __( 'The less the site reveals about what is installed, the harder it is to look for known flaws of a specific version.', 'ondaweb-security' ),
				'risk'    => __( 'Mapping of the environment by scanning tools, which match exposed versions against public flaws.', 'ondaweb-security' ),
				'actions' => array(
					array( 'generator', __( 'WordPress version removed from the page source', 'ondaweb-security' ), __( 'the generator meta tag, which stated the exact version, was removed from the pages.', 'ondaweb-security' ) ),
					array( 'hdr_powered', __( '<code>X-Powered-By</code> header removed', 'ondaweb-security' ), __( 'the server no longer states the technology in use.', 'ondaweb-security' ) ),
				),
			),
			'files' => array(
				'icon'    => 'chip',
				'title'   => __( 'Files and folders', 'ondaweb-security' ),
				'scope'   => __( 'Uploads folder, directory listing, sensitive files and permissions of the configuration file.', 'ondaweb-security' ),
				'intro'   => __( 'Server rules that prevent running and reading files that should not be reachable from the internet.', 'ondaweb-security' ),
				'risk'    => __( 'Execution of code sent by upload, leakage of credentials, backups and internal information about the environment.', 'ondaweb-security' ),
				'actions' => array(
					array( 'up_php_exec', __( 'PHP execution blocked in uploads', 'ondaweb-security' ), __( 'even if a malicious file is sent to the media folder, it is not executed.', 'ondaweb-security' ) ),
					array( 'up_listing', __( 'Directory listing disabled', 'ondaweb-security' ), __( 'the content of the folders cannot be browsed through the address.', 'ondaweb-security' ) ),
					array( 'exposed_files', __( 'Sensitive files blocked', 'ondaweb-security' ), __( '<code>.env</code>, <code>.git</code>, backups, logs, readme and license are not delivered to visitors.', 'ondaweb-security' ) ),
					array( 'perm_wpconfig', __( 'Restricted permission on <code>wp-config.php</code>', 'ondaweb-security' ), __( 'the file with the database credentials is limited to the owner and group on the server.', 'ondaweb-security' ) ),
					array( 'perm_writable', __( 'No world-writable permissions', 'ondaweb-security' ), __( 'folders and files cannot be changed by other processes on the server.', 'ondaweb-security' ) ),
					array( 'up_php_files', __( 'Uploads folder free of scripts', 'ondaweb-security' ), __( 'a full scan confirms there are no PHP files among the uploaded files.', 'ondaweb-security' ) ),
				),
			),
			'wp' => array(
				'icon'    => 'bars',
				'title'   => __( 'WordPress configuration', 'ondaweb-security' ),
				'scope'   => __( 'Internal system settings: file editor, error display, security keys and automatic updates.', 'ondaweb-security' ),
				'intro'   => __( 'Internal settings that limit the damage of a compromised account and keep the system core up to date.', 'ondaweb-security' ),
				'risk'    => __( 'Code changed from a hijacked account, exposure of internal details and flaws that were already fixed staying in place.', 'ondaweb-security' ),
				'actions' => array(
					array( 'file_edit', __( 'Dashboard file editor disabled', 'ondaweb-security' ), __( 'the code of themes and plugins cannot be changed from inside the dashboard.', 'ondaweb-security' ) ),
					array( 'debug_display', __( 'Error display disabled', 'ondaweb-security' ), __( 'technical messages, which reveal paths and internal details, are not shown to visitors.', 'ondaweb-security' ) ),
					array( 'salts', __( 'Strong security keys', 'ondaweb-security' ), __( 'they protect sessions and login cookies.', 'ondaweb-security' ) ),
					array( 'auto_updates', __( 'Automatic core security updates on', 'ondaweb-security' ), __( 'WordPress security fixes are applied without depending on manual action.', 'ondaweb-security' ) ),
				),
			),
			'server' => array(
				'icon'    => 'plug',
				'title'   => __( 'Server', 'ondaweb-security' ),
				'scope'   => __( 'Environment the site runs on: HTTPS certificate and PHP version with security support.', 'ondaweb-security' ),
				'intro'   => __( 'The base the site runs on: encrypted connection and a PHP version with active support.', 'ondaweb-security' ),
				'risk'    => __( '"Not secure" warnings in the browser and exposure to flaws of PHP versions without support.', 'ondaweb-security' ),
				'actions' => array(
					array( 'https', __( 'Site on HTTPS', 'ondaweb-security' ), __( 'every access to the site uses an encrypted connection.', 'ondaweb-security' ) ),
					array( 'ssl_expiry', __( 'HTTPS with a valid certificate', 'ondaweb-security' ), '' ),
					array( 'php_version', __( 'PHP with security support', 'ondaweb-security' ), '' ),
				),
			),
			'software' => array(
				'icon'    => 'cross',
				'title'   => __( 'Plugins and themes', 'ondaweb-security' ),
				'scope'   => __( 'Components installed in WordPress: maintenance status of each item and presence of unused items.', 'ondaweb-security' ),
				'intro'   => __( 'Each installed plugin or theme is more code to maintain. Unmaintained or unused items widen the exposure without any benefit.', 'ondaweb-security' ),
				'risk'    => __( 'Exploitation of flaws in components that no longer receive fixes.', 'ondaweb-security' ),
				'actions' => array(
					array( 'vulns', __( 'No known vulnerabilities', 'ondaweb-security' ), __( 'the installed versions were checked against the Wordfence Intelligence database.', 'ondaweb-security' ) ),
					array( 'wporg_closed', __( 'No removed or abandoned plugins', 'ondaweb-security' ), __( 'no installed item stopped being maintained or was taken out of the repository.', 'ondaweb-security' ) ),
					array( 'inactive_items', __( 'No installed but unused items', 'ondaweb-security' ), __( 'there are no idle plugins or themes in the environment.', 'ondaweb-security' ) ),
				),
			),
		);
		return $a;
	}
}
