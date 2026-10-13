<?php
defined( 'ABSPATH' ) || exit;

/**
 * Atualizações do próprio plugin a partir das versões publicadas no GitHub.
 *
 * Usa o mecanismo oficial do WordPress para plugins de fora do wordpress.org
 * (cabeçalho "Update URI" + filtro update_plugins_github.com, WP 5.8+).
 * A atualização aparece na tela de Plugins como qualquer outra e pode ser automática.
 */
class OWUM_Updater {

	const REPO  = 'desenvolvimentoondaweb/ondaweb-security';
	const ASSET = 'ondaweb-update-manager.zip';
	const CACHE = 'owum_gh_release';

	public static function init() {
		add_filter( 'update_plugins_github.com', array( __CLASS__, 'check' ), 10, 4 );
		add_filter( 'plugins_api', array( __CLASS__, 'info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_folder' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'flush' ), 10, 0 );
	}

	public static function basename() {
		return plugin_basename( OWUM_FILE );
	}

	public static function slug() {
		return dirname( self::basename() );
	}

	public static function flush() {
		delete_site_transient( self::CACHE );
	}

	/**
	 * Última versão publicada no GitHub (com cache de 6 horas).
	 *
	 * @return array|null
	 */
	public static function release( $force = false ) {
		$cached = get_site_transient( self::CACHE );
		if ( ! $force && is_array( $cached ) ) {
			return empty( $cached['version'] ) ? null : $cached;
		}
		$res = wp_remote_get(
			apply_filters( 'owum_release_api', 'https://api.github.com/repos/' . self::REPO . '/releases/latest' ),
			array(
				'timeout' => 15,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'Ondaweb-Security-Updater/' . OWUM_VERSION . '; ' . home_url(),
				),
			)
		);
		$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
		$data = 200 === $code ? json_decode( wp_remote_retrieve_body( $res ), true ) : null;
		$rel  = null;
		if ( is_array( $data ) && ! empty( $data['tag_name'] ) && empty( $data['draft'] ) && empty( $data['prerelease'] ) ) {
			$package = '';
			foreach ( (array) ( isset( $data['assets'] ) ? $data['assets'] : array() ) as $a ) {
				if ( isset( $a['name'], $a['browser_download_url'] ) && self::ASSET === $a['name'] ) {
					$package = $a['browser_download_url'];
				}
			}
			if ( $package ) {
				$rel = array(
					'version'   => ltrim( (string) $data['tag_name'], 'vV' ),
					'package'   => esc_url_raw( $package ),
					'url'       => esc_url_raw( isset( $data['html_url'] ) ? $data['html_url'] : 'https://github.com/' . self::REPO ),
					'notes'     => isset( $data['body'] ) ? (string) $data['body'] : '',
					'published' => isset( $data['published_at'] ) ? (string) $data['published_at'] : '',
				);
			}
		}
		// Falha de rede ou limite da API: tenta de novo em 1 hora, sem travar o painel.
		set_site_transient( self::CACHE, $rel ? $rel : array( 'version' => '' ), $rel ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		update_site_option( 'owum_gh_check', array( 'time' => current_time( 'mysql' ), 'ok' => (bool) $rel, 'code' => $code ) );
		return $rel;
	}

	/** Chamado pelo WordPress ao verificar atualizações de plugins com "Update URI" no github.com. */
	public static function check( $update, $plugin_data, $plugin_file, $locales = array() ) {
		if ( self::basename() !== $plugin_file ) {
			return $update;
		}
		$rel = self::release();
		if ( ! $rel ) {
			return $update;
		}
		return array(
			'id'           => 'github.com/' . self::REPO,
			'slug'         => self::slug(),
			'plugin'       => $plugin_file,
			'version'      => $rel['version'],
			'url'          => $rel['url'],
			'package'      => $rel['package'],
			'tested'       => get_bloginfo( 'version' ),
			'requires_php' => '7.4',
			'icons'        => array( '1x' => plugins_url( 'assets/icon-128.png', OWUM_FILE ) ),
		);
	}

	/** Janela "Ver detalhes" da atualização. */
	public static function info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || self::slug() !== $args->slug ) {
			return $result;
		}
		$rel = self::release();
		if ( ! $rel ) {
			return $result;
		}
		return (object) array(
			'name'          => 'Ondaweb Security Updater',
			'slug'          => self::slug(),
			'version'       => $rel['version'],
			'author'        => '<a href="https://ondaweb.com.br">Ondaweb</a>',
			'homepage'      => 'https://github.com/' . self::REPO,
			'requires'      => '5.8',
			'requires_php'  => '7.4',
			'tested'        => get_bloginfo( 'version' ),
			'last_updated'  => $rel['published'],
			'download_link' => $rel['package'],
			'sections'      => array(
				'changelog'   => self::markdown( $rel['notes'] ),
				'description' => '<p>Inventário de versões, histórico de atualizações, verificações e correções de segurança e relatório mensal para clientes da Ondaweb.</p>',
			),
			'banners'       => array(),
		);
	}

	/** Garante que a pasta instalada continue com o mesmo nome (mantém histórico e configurações). */
	public static function fix_folder( $source, $remote_source, $upgrader, $extra = array() ) {
		if ( empty( $extra['plugin'] ) || self::basename() !== $extra['plugin'] ) {
			return $source;
		}
		$want = trailingslashit( $remote_source ) . self::slug() . '/';
		if ( untrailingslashit( $source ) === untrailingslashit( $want ) ) {
			return $source;
		}
		global $wp_filesystem;
		if ( $wp_filesystem && $wp_filesystem->move( $source, $want, true ) ) {
			return $want;
		}
		return new WP_Error( 'owum_folder', 'Não foi possível preparar a pasta da atualização.' );
	}

	/** Markdown simples (títulos, listas, negrito, links) para HTML. */
	public static function markdown( $md ) {
		$md = trim( str_replace( "\r", '', (string) $md ) );
		if ( '' === $md ) {
			return '<p>Sem notas para esta versão.</p>';
		}
		$html = '';
		$list = false;
		foreach ( explode( "\n", $md ) as $line ) {
			$line = rtrim( $line );
			$text = esc_html( ltrim( preg_replace( '/^(#{1,6}|[-*])\s+/', '', $line ) ) );
			$text = preg_replace( '/\*\*(.+?)\*\*/', '<strong>$1</strong>', $text );
			$text = preg_replace( '/`(.+?)`/', '<code>$1</code>', $text );
			$text = preg_replace( '/\[(.+?)\]\((https?:[^)\s]+)\)/', '<a href="$2" target="_blank">$1</a>', $text );
			$is_li = (bool) preg_match( '/^\s*[-*]\s+/', $line );
			if ( $list && ! $is_li ) {
				$html .= '</ul>';
				$list  = false;
			}
			if ( '' === trim( $line ) ) {
				continue;
			}
			if ( preg_match( '/^#{1,6}\s+/', $line ) ) {
				$html .= '<h4>' . $text . '</h4>';
			} elseif ( $is_li ) {
				if ( ! $list ) {
					$html .= '<ul>';
					$list  = true;
				}
				$html .= '<li>' . $text . '</li>';
			} else {
				$html .= '<p>' . $text . '</p>';
			}
		}
		return $html . ( $list ? '</ul>' : '' );
	}
}
