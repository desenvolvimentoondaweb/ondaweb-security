<?php
defined( 'ABSPATH' ) || exit;

/**
 * Lê versões instaladas, atualizações disponíveis e em quais sites cada item está ativo.
 */
class OWUM_Collector {

	public static function load_includes() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-includes/update.php';
	}

	/** Versão real do core lida do arquivo (o global $wp_version fica desatualizado logo após um upgrade). */
	public static function core_version() {
		$wp_version = '';
		include ABSPATH . WPINC . '/version.php';
		return $wp_version;
	}

	/** Foto atual das versões instaladas. */
	public static function snapshot() {
		self::load_includes();
		wp_clean_plugins_cache( false );
		wp_clean_themes_cache( false );

		$snap = array(
			'core'   => array(
				'name'    => 'WordPress',
				'version' => self::core_version(),
			),
			'plugin' => array(),
			'theme'  => array(),
		);
		foreach ( get_plugins() as $file => $data ) {
			$snap['plugin'][ $file ] = array(
				'name'    => $data['Name'],
				'version' => $data['Version'],
			);
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$snap['theme'][ $slug ] = array(
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'core'    => 'the WordPress team' === $theme->get( 'Author' ), // temas padrão "Twenty"
				'child'   => (bool) $theme->parent(),
			);
		}
		return $snap;
	}

	/** Força nova consulta de atualizações em wordpress.org e nos plugins pagos. */
	public static function force_check() {
		self::load_includes();
		delete_site_transient( 'update_plugins' );
		OWUM_Updater::flush();
		delete_site_transient( 'update_themes' );
		delete_site_transient( 'update_core' );
		wp_version_check( array(), true );
		wp_update_plugins();
		wp_update_themes();
		update_site_option( 'owum_last_check', current_time( 'mysql' ) );
	}

	/** Lista de sites da rede: id => [nome, url]. */
	public static function sites() {
		$out = array();
		if ( ! is_multisite() ) {
			$out[1] = array(
				'name' => get_bloginfo( 'name' ),
				'url'  => home_url( '/' ),
			);
			return $out;
		}
		foreach ( get_sites( array( 'number' => 0, 'deleted' => 0 ) ) as $site ) {
			$out[ (int) $site->blog_id ] = array(
				'name' => $site->blogname ? $site->blogname : $site->domain . $site->path,
				'url'  => $site->domain . $site->path,
			);
		}
		return $out;
	}

	/** Informações do core. */
	public static function core() {
		self::load_includes();
		$installed = self::core_version();
		$available = '';
		$updates   = get_core_updates( array( 'dismissed' => true ) );
		if ( is_array( $updates ) ) {
			foreach ( $updates as $u ) {
				if ( isset( $u->response, $u->current ) && 'upgrade' === $u->response && version_compare( $u->current, $installed, '>' ) ) {
					$available = $u->current;
					break;
				}
			}
		}
		return array(
			'name'      => 'WordPress',
			'installed' => $installed,
			'available' => $available,
			'status'    => $available ? 'free' : 'ok',
		);
	}

	/**
	 * Inventário completo.
	 *
	 * @return array{core:array,plugins:array,themes:array,sites:array}
	 */
	public static function inventory() {
		self::load_includes();
		$snap  = self::snapshot();
		$meta  = (array) get_site_option( 'owum_meta', array() );
		$sites = self::sites();
		$up_p  = get_site_transient( 'update_plugins' );
		$up_t  = get_site_transient( 'update_themes' );

		// Mapa de ativação por site.
		$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$plugin_sites   = array();
		$theme_sites    = array();
		foreach ( $sites as $id => $info ) {
			$active = is_multisite() ? (array) get_blog_option( $id, 'active_plugins', array() ) : (array) get_option( 'active_plugins', array() );
			foreach ( $active as $file ) {
				$plugin_sites[ $file ][] = $id;
			}
			$ss = is_multisite() ? get_blog_option( $id, 'stylesheet' ) : get_option( 'stylesheet' );
			$tp = is_multisite() ? get_blog_option( $id, 'template' ) : get_option( 'template' );
			if ( $ss ) {
				$theme_sites[ $ss ][] = $id;
			}
			if ( $tp && $tp !== $ss ) {
				$theme_sites[ $tp ][] = $id; // tema pai em uso por um tema filho
			}
		}

		$plugins = array();
		foreach ( $snap['plugin'] as $file => $p ) {
			$key   = 'plugin:' . $file;
			$wporg = false;
			$new   = '';
			if ( isset( $up_p->response[ $file ] ) ) {
				$r     = $up_p->response[ $file ];
				$new   = isset( $r->new_version ) ? $r->new_version : '';
				$wporg = isset( $r->id ) && false !== strpos( (string) $r->id, 'w.org/' );
			} elseif ( isset( $up_p->no_update[ $file ] ) ) {
				$r     = $up_p->no_update[ $file ];
				$wporg = isset( $r->id ) && false !== strpos( (string) $r->id, 'w.org/' );
			}
			$plugins[ $key ] = self::build_row( $key, 'plugin', $p, $new, $wporg, $meta, in_array( $file, $network_active, true ), isset( $plugin_sites[ $file ] ) ? $plugin_sites[ $file ] : array() );
		}

		$themes = array();
		foreach ( $snap['theme'] as $slug => $t ) {
			$key   = 'theme:' . $slug;
			$wporg = false;
			$new   = '';
			if ( isset( $up_t->response[ $slug ] ) ) {
				$r     = (array) $up_t->response[ $slug ];
				$new   = isset( $r['new_version'] ) ? $r['new_version'] : '';
				$wporg = isset( $r['url'] ) && false !== strpos( (string) $r['url'], 'wordpress.org' );
			} elseif ( isset( $up_t->no_update[ $slug ] ) ) {
				$wporg = true;
			}
			$themes[ $key ] = self::build_row( $key, 'theme', $t, $new, $wporg, $meta, false, isset( $theme_sites[ $slug ] ) ? $theme_sites[ $slug ] : array() );
		}

		$sort = function ( $a, $b ) {
			$rank = array( 'paid' => 0, 'free' => 1, 'ok' => 2 );
			$c    = $rank[ $a['status'] ] <=> $rank[ $b['status'] ];
			return $c ? $c : strcasecmp( $a['name'], $b['name'] );
		};
		uasort( $plugins, $sort );
		uasort( $themes, $sort );

		return array(
			'core'    => self::core(),
			'plugins' => $plugins,
			'themes'  => $themes,
			'sites'   => $sites,
		);
	}

	private static function build_row( $key, $type, $item, $new, $wporg, $meta, $network_active, $site_ids ) {
		$m       = isset( $meta[ $key ] ) ? (array) $meta[ $key ] : array();
		$own     = 'plugin:' . plugin_basename( OWUM_FILE ) === $key || ! empty( $item['core'] );
		if ( ! empty( $m['tipo'] ) ) {
			$tipo = $m['tipo'];
		} elseif ( ! empty( $item['child'] ) ) {
			$tipo = 'personalizado'; // tema filho: feito para o site, não recebe atualizações
		} elseif ( $wporg || $own ) {
			$tipo = 'gratuito';
		} elseif ( in_array( $key, self::ondaweb_defaults(), true ) ) {
			$tipo = 'ondaweb';
		} else {
			$tipo = 'pago';
		}
		$known   = isset( $m['ultima_conhecida'] ) ? trim( $m['ultima_conhecida'] ) : '';
		$manual  = false;

		// Plugin pago sem aviso automático: usa a "última versão conhecida" informada manualmente.
		if ( '' === $new && '' !== $known && version_compare( $known, $item['version'], '>' ) ) {
			$new    = $known;
			$manual = true;
		}

		$status = 'ok';
		if ( 'personalizado' === $tipo && ! $manual ) {
			$new = '';
		}
		if ( '' !== $new && version_compare( $new, $item['version'], '>' ) ) {
			$status = ( 'pago' === $tipo ) ? 'paid' : 'free';
		} else {
			$new = '';
		}

		return array(
			'key'            => $key,
			'type'           => $type,
			'name'           => $item['name'],
			'installed'      => $item['version'],
			'available'      => $new,
			'available_src'  => $manual ? 'manual' : 'auto',
			'status'         => $status,
			'tipo'           => $tipo,
			'classified'     => ! empty( $m['tipo'] ),
			'wporg'          => $wporg,
			'obs'            => isset( $m['obs'] ) ? $m['obs'] : '',
			'known'          => $known,
			'network_active' => $network_active,
			'site_ids'       => array_values( array_unique( $site_ids ) ),
		);
	}

	/** Plugins pagos cuja licença é fornecida pela Ondaweb (classificação inicial). */
	public static function ondaweb_defaults() {
		return apply_filters( 'owum_ondaweb_licensed', array( 'plugin:elementor-pro/elementor-pro.php' ) );
	}

	public static function tipo_label( $tipo ) {
		$labels = array(
			'gratuito' => 'Gratuito',
			'ondaweb'  => 'Licença Ondaweb',
			'pago'          => 'Pago (cliente)',
			'personalizado' => 'Personalizado',
		);
		return isset( $labels[ $tipo ] ) ? $labels[ $tipo ] : $tipo;
	}

	/** Texto curto sobre onde o item está ativo. */
	public static function where_label( $row, $sites ) {
		if ( $row['network_active'] ) {
			return 'Rede (todos os sites)';
		}
		$n = count( $row['site_ids'] );
		if ( 0 === $n ) {
			return 'Inativo';
		}
		if ( ! is_multisite() ) {
			return 'Ativo';
		}
		return 1 === $n ? '1 site' : $n . ' sites';
	}

	public static function where_list( $row, $sites ) {
		$names = array();
		foreach ( $row['site_ids'] as $id ) {
			if ( isset( $sites[ $id ] ) ) {
				$names[] = $sites[ $id ]['name'];
			}
		}
		return $names;
	}

	public static function status_label( $status ) {
		$labels = array(
			'ok'   => 'Atualizado',
			'free' => 'Atualização disponível',
			'paid' => 'Solicitar ao cliente',
		);
		return isset( $labels[ $status ] ) ? $labels[ $status ] : $status;
	}
}
