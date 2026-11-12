<?php
defined( 'ABSPATH' ) || exit;

class OWUM_Installer {

	const DB_VERSION = '1';

	public static function table() {
		global $wpdb;
		return $wpdb->base_prefix . 'owum_log';
	}

	public static function activate() {
		// Brand-new install (never activated before): starts neutral, without the Ondaweb branding.
		if ( false === get_site_option( 'owum_db_version' ) && ! get_site_option( 'owum_mig_brand' ) ) {
			update_site_option( 'owum_mig_brand', 'fresh' );
		}
		self::create_table();

		// First version snapshot: baseline for the update history.
		if ( ! is_array( get_site_option( 'owum_snapshot' ) ) ) {
			$snap = OWUM_Collector::snapshot();
			update_site_option( 'owum_snapshot', $snap );
			OWUM_Logger::add(
				array(
					'item_type'   => 'core',
					'item_key'    => 'core',
					'item_name'   => OWUM_PRODUCT,
					'action'      => 'inicio',
					'new_version' => $snap['core']['version'],
					'source'      => 'system',
					'notes'       => wp_json_encode( array( 'plugins' => count( $snap['plugin'] ), 'themes' => count( $snap['theme'] ) ) ),
				)
			);
		}

		self::schedule();
		if ( OWSU_Security::fixes() ) {
			OWSU_Security::sync_htaccess();
		}
	}

	public static function deactivate() {
		// .htaccess rules stop applying with the plugin; they are kept and restored on reactivation.
		OWSU_Security::clear_htaccess();
		self::on_main_site(
			function () {
				wp_clear_scheduled_hook( 'owum_daily' );
			}
		);
	}

	public static function create_table() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		$sql     = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			logged_at datetime NOT NULL,
			item_type varchar(20) NOT NULL,
			item_key varchar(255) NOT NULL,
			item_name varchar(255) NOT NULL,
			action varchar(20) NOT NULL,
			old_version varchar(50) NOT NULL DEFAULT '',
			new_version varchar(50) NOT NULL DEFAULT '',
			user_login varchar(60) NOT NULL DEFAULT '',
			source varchar(50) NOT NULL DEFAULT '',
			notes text NULL,
			PRIMARY KEY  (id),
			KEY logged_at (logged_at),
			KEY item_key (item_key(100))
		) {$charset};";
		dbDelta( $sql );
		update_site_option( 'owum_db_version', self::DB_VERSION );
	}

	/** Ensures table and schedule even if the plugin was copied over FTP without a proper activation. */
	public static function maybe_upgrade() {
		if ( get_site_option( 'owum_db_version' ) !== self::DB_VERSION ) {
			self::activate();
		}
		// 1.1.1: child themes previously classified as paid/agency license become "Custom".
		if ( ! get_site_option( 'owum_mig_child_themes' ) ) {
			$meta = (array) get_site_option( 'owum_meta', array() );
			foreach ( wp_get_themes() as $slug => $theme ) {
				$k = 'theme:' . $slug;
				if ( $theme->parent() && isset( $meta[ $k ]['tipo'] ) && in_array( $meta[ $k ]['tipo'], array( 'pago', 'ondaweb' ), true ) ) {
					$meta[ $k ]['tipo'] = 'personalizado';
				}
			}
			update_site_option( 'owum_meta', $meta );
			update_site_option( 'owum_mig_child_themes', 1 );
		}
		if ( ! get_site_option( 'owum_mig_brand' ) ) {
			self::migrate_brand();
		}
		if ( is_admin() && is_main_site() && ! wp_next_scheduled( 'owum_daily' ) ) {
			self::schedule();
		}
	}

	/**
	 * 1.5.0: branding became configurable (white label). Installs that existed before keep
	 * exactly what they had: Ondaweb name and bundled logo, Elementor Pro as agency license,
	 * and the same email recipients.
	 */
	public static function migrate_brand() {
		$saved = get_site_option( 'owum_settings' );
		$saved = is_array( $saved ) ? $saved : array();
		$keep  = array(
			'brand_name'         => 'Ondaweb',
			'brand_url'          => 'https://ondaweb.com.br',
			'brand_logo_default' => 1,
			'agency_licensed'    => array( 'plugin:elementor-pro/elementor-pro.php' ),
			'emails'             => 'suporte@ondaweb.com.br',
			'err_email'          => 'desenvolvimento.ondaweb@gmail.com',
		);
		foreach ( $keep as $k => $v ) {
			if ( ! array_key_exists( $k, $saved ) ) {
				$saved[ $k ] = $v;
			}
		}
		update_site_option( 'owum_settings', $saved );
		update_site_option( 'owum_mig_brand', 'legacy' );
	}

	public static function schedule() {
		self::on_main_site(
			function () {
				if ( ! wp_next_scheduled( 'owum_daily' ) ) {
					wp_schedule_event( time() + 10 * MINUTE_IN_SECONDS, 'daily', 'owum_daily' );
				}
			}
		);
	}

	/** The cron event lives on the network's main site. */
	public static function on_main_site( callable $fn ) {
		$switched = false;
		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( get_main_site_id() );
			$switched = true;
		}
		$fn();
		if ( $switched ) {
			restore_current_blog();
		}
	}
}
