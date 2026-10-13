<?php
defined( 'ABSPATH' ) || exit;

/**
 * Histórico: compara a "foto" anterior com a atual e registra cada mudança.
 * Funciona para atualizações pelo painel, automáticas, WP-CLI e feitas por FTP.
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
			return; // traduções etc.
		}
		self::sync( self::source() );
	}

	public static function on_change() {
		self::sync( self::source() );
	}

	/** Verificação de mudanças externas (FTP), no máximo 1x por hora ao navegar pelo painel. */
	public static function maybe_detect() {
		if ( wp_doing_ajax() || get_site_transient( 'owum_detect_lock' ) ) {
			return;
		}
		set_site_transient( 'owum_detect_lock', 1, HOUR_IN_SECONDS );
		self::detect();
	}

	public static function detect() {
		self::sync( 'Detectada (FTP/externa)' );
	}

	public static function source() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'WP-CLI';
		}
		if ( wp_doing_cron() ) {
			return 'Automática (WP-Cron)';
		}
		return 'Painel';
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
	 * Registros entre duas datas (formato Y-m-d H:i:s, horário local).
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
			'atualizado' => 'Atualizado',
			'instalado'  => 'Instalado',
			'removido'   => 'Removido',
			'revertido'  => 'Versão revertida',
			'inicio'     => 'Início do monitoramento',
			'correcao'   => 'Correção de segurança aplicada',
			'desfeito'   => 'Correção de segurança desfeita',
		);
		return isset( $labels[ $action ] ) ? $labels[ $action ] : $action;
	}

	public static function type_label( $type ) {
		$labels = array(
			'core'   => 'WordPress',
			'plugin' => 'Plugin',
			'theme'    => 'Tema',
			'security' => 'Segurança',
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : $type;
	}
}
