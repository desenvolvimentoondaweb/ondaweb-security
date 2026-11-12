<?php
defined( 'ABSPATH' ) || exit;

/**
 * History: compares the previous snapshot with the current one and records every change.
 * Works for updates made in the dashboard, automatic updates, WP-CLI and FTP.
 *
 * Action and source are stored as codes and translated on display. Rows recorded by
 * versions before 1.5 hold Portuguese source labels; those are mapped too.
 */
class OWUM_Logger {

	public static function init() {
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 99, 2 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_change' ) );
		add_action( 'deleted_theme', array( __CLASS__, 'on_change' ) );
		add_action( 'owum_daily', array( __CLASS__, 'detect' ), 5 );
		add_action( 'admin_init', array( __CLASS__, 'maybe_detect' ) );
	}

	public static function on_upgrade( $upgrader, $extra ) {
		$type = isset( $extra['type'] ) ? $extra['type'] : '';
		if ( ! in_array( $type, array( 'plugin', 'theme', 'core' ), true ) ) {
			return; // translations etc.
		}
		self::sync( self::source() );
	}

	public static function on_change() {
		self::sync( self::source() );
	}

	/** Detects external (FTP) changes, at most once an hour while browsing the dashboard. */
	public static function maybe_detect() {
		if ( wp_doing_ajax() || get_site_transient( 'owum_detect_lock' ) ) {
			return;
		}
		set_site_transient( 'owum_detect_lock', 1, HOUR_IN_SECONDS );
		self::detect();
	}

	public static function detect() {
		self::sync( 'external' );
	}

	public static function source() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( wp_doing_cron() ) {
			return 'cron';
		}
		return 'panel';
	}

	public static function sync( $source ) {
		$old = get_site_option( 'owum_snapshot' );
		$new = OWUM_Collector::snapshot();
		if ( ! is_array( $old ) ) {
			update_site_option( 'owum_snapshot', $new );
			return 0;
		}

		$count = 0;

		if ( isset( $old['core']['version'] ) && $old['core']['version'] !== $new['core']['version'] ) {
			$count += self::log_diff( 'core', 'core', 'WordPress', $old['core']['version'], $new['core']['version'], $source );
		}

		foreach ( array( 'plugin', 'theme' ) as $type ) {
			$before = isset( $old[ $type ] ) ? $old[ $type ] : array();
			$after  = $new[ $type ];
			foreach ( $after as $id => $item ) {
				$prev = isset( $before[ $id ] ) ? $before[ $id ]['version'] : null;
				if ( null === $prev || $prev !== $item['version'] ) {
					$count += self::log_diff( $type, $type . ':' . $id, $item['name'], (string) $prev, $item['version'], $source, null === $prev );
				}
			}
			foreach ( $before as $id => $item ) {
				if ( ! isset( $after[ $id ] ) ) {
					$count += self::log_diff( $type, $type . ':' . $id, $item['name'], $item['version'], '', $source );
				}
			}
		}

		update_site_option( 'owum_snapshot', $new );
		return $count;
	}

	private static function log_diff( $type, $key, $name, $from, $to, $source, $is_new = false ) {
		if ( $is_new ) {
			$action = 'instalado';
		} elseif ( '' === $to ) {
			$action = 'removido';
		} elseif ( version_compare( $to, $from, '<' ) ) {
			$action = 'revertido';
		} else {
			$action = 'atualizado';
		}
		self::add(
			array(
				'item_type'   => $type,
				'item_key'    => $key,
				'item_name'   => $name,
				'action'      => $action,
				'old_version' => $from,
				'new_version' => $to,
				'source'      => $source,
			)
		);
		return 1;
	}

	public static function add( array $row ) {
		global $wpdb;
		$user = wp_get_current_user();
		$row  = wp_parse_args(
			$row,
			array(
				'logged_at'   => current_time( 'mysql' ),
				'item_type'   => '',
				'item_key'    => '',
				'item_name'   => '',
				'action'      => '',
				'old_version' => '',
				'new_version' => '',
				'user_login'  => ( $user && $user->exists() ) ? $user->user_login : '—',
				'source'      => '',
				'notes'       => '',
			)
		);
		$wpdb->insert( OWUM_Installer::table(), $row );
	}

	/**
	 * Rows between two dates (Y-m-d H:i:s, local time).
	 */
	public static function get( $start = null, $end = null, $type = '', $limit = 500 ) {
		global $wpdb;
		$table = OWUM_Installer::table();
		$where = array( '1=1' );
		$args  = array();
		if ( $start ) {
			$where[] = 'logged_at >= %s';
			$args[]  = $start;
		}
		if ( $end ) {
			$where[] = 'logged_at <= %s';
			$args[]  = $end;
		}
		if ( $type ) {
			$where[] = 'item_type = %s';
			$args[]  = $type;
		}
		$args[] = (int) $limit;
		$sql    = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . ' ORDER BY logged_at DESC, id DESC LIMIT %d';
		return $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore
	}

	public static function action_label( $action ) {
		$labels = array(
			'atualizado' => __( 'Updated', 'ondaweb-security' ),
			'instalado'  => __( 'Installed', 'ondaweb-security' ),
			'removido'   => __( 'Removed', 'ondaweb-security' ),
			'revertido'  => __( 'Rolled back', 'ondaweb-security' ),
			'inicio'     => __( 'Monitoring started', 'ondaweb-security' ),
			'correcao'   => __( 'Security fix applied', 'ondaweb-security' ),
			'desfeito'   => __( 'Security fix undone', 'ondaweb-security' ),
		);
		return isset( $labels[ $action ] ) ? $labels[ $action ] : $action;
	}

	public static function type_label( $type ) {
		$labels = array(
			'core'     => 'WordPress',
			'plugin'   => __( 'Plugin', 'ondaweb-security' ),
			'theme'    => __( 'Theme', 'ondaweb-security' ),
			'security' => __( 'Security', 'ondaweb-security' ),
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : $type;
	}

	/** Where a change came from (stored code, or legacy Portuguese label). */
	public static function source_label( $source ) {
		$labels = array(
			'panel'                   => __( 'Dashboard', 'ondaweb-security' ),
			'cli'                     => 'WP-CLI',
			'cron'                    => __( 'Automatic (WP-Cron)', 'ondaweb-security' ),
			'external'                => __( 'Detected (FTP/external)', 'ondaweb-security' ),
			'system'                  => __( 'System', 'ondaweb-security' ),
			'Painel'                  => __( 'Dashboard', 'ondaweb-security' ),
			'WP-CLI'                  => 'WP-CLI',
			'Automática (WP-Cron)'    => __( 'Automatic (WP-Cron)', 'ondaweb-security' ),
			'Detectada (FTP/externa)' => __( 'Detected (FTP/external)', 'ondaweb-security' ),
			'Sistema'                 => __( 'System', 'ondaweb-security' ),
		);
		return isset( $labels[ $source ] ) ? $labels[ $source ] : $source;
	}

	/** Display name of a row: security fixes use the (translated) check name. */
	public static function item_label( $row ) {
		if ( 'security' === $row['item_type'] && 0 === strpos( $row['item_key'], 'sec:' ) ) {
			$defs = OWSU_Security::definitions();
			$id   = substr( $row['item_key'], 4 );
			if ( isset( $defs[ $id ] ) ) {
				return $defs[ $id ]['client'];
			}
		}
		return $row['item_name'];
	}

	/** Notes of a row, translated when stored as data. */
	public static function notes_label( $row ) {
		$n = (string) $row['notes'];
		if ( 'inicio' === $row['action'] ) {
			$d = json_decode( $n, true );
			if ( is_array( $d ) ) {
				/* translators: 1: number of plugins, 2: number of themes */
				return sprintf( __( 'Monitoring started: %1$d plugins and %2$d themes recorded.', 'ondaweb-security' ), (int) $d['plugins'], (int) $d['themes'] );
			}
		}
		if ( 'security' === $row['item_type'] && 0 === strpos( $row['item_key'], 'sec:' ) ) {
			$defs = OWSU_Security::definitions();
			$id   = substr( $row['item_key'], 4 );
			if ( isset( $defs[ $id ] ) ) {
				return $defs[ $id ]['title'];
			}
		}
		return $n;
	}
}
