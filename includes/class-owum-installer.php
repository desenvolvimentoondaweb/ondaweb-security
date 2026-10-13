<?php
defined( 'ABSPATH' ) || exit;

class OWUM_Installer {

	const DB_VERSION = '1';

	public static function table() {
		global $wpdb;
		return $wpdb->base_prefix . 'owum_log';
	}

	public static function activate() {
		self::create_table();

		// Primeira "foto" das versões: serve de base para o histórico.
		if ( ! is_array( get_site_option( 'owum_snapshot' ) ) ) {
			$snap = OWUM_Collector::snapshot();
			update_site_option( 'owum_snapshot', $snap );
			OWUM_Logger::add(
				array(
					'item_type'   => 'core',
					'item_key'    => 'core',
					'item_name'   => 'Ondaweb Security Updater',
					'action'      => 'inicio',
					'new_version' => $snap['core']['version'],
					'source'      => 'Sistema',
					'notes'       => sprintf( 'Início do monitoramento: %d plugins e %d temas registrados.', count( $snap['plugin'] ), count( $snap['theme'] ) ),
				)
			);
		}

		self::schedule();
		if ( OWSU_Security::fixes() ) {
			OWSU_Security::sync_htaccess();
		}
	}

	public static function deactivate() {
		// As regras .htaccess deixam de valer junto com o plugin; ficam guardadas para a reativação.
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

	/** Garante tabela e agendamento mesmo se o plugin for copiado via FTP sem ativação "oficial". */
	public static function maybe_upgrade() {
		if ( get_site_option( 'owum_db_version' ) !== self::DB_VERSION ) {
			self::activate();
		}
		// 1.1.1: temas filhos classificados antes como pago/licença passam a "Personalizado".
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
		if ( is_admin() && is_main_site() && ! wp_next_scheduled( 'owum_daily' ) ) {
			self::schedule();
		}
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

	/** O cron fica no site principal da rede. */
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
