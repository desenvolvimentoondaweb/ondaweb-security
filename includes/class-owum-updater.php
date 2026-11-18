<?php
defined( 'ABSPATH' ) || exit;

/**
 * Updates of the plugin itself from the releases published on GitHub.
 *
 * Uses the official WordPress mechanism for plugins outside wordpress.org
 * ("Update URI" header + update_plugins_github.com filter, WP 5.8+).
 * The update shows up on the Plugins screen like any other and can be automatic.
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
	 * Latest release published on GitHub (cached for 6 hours).
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
		// API unavailable (shared hosting often hits GitHub's 60 requests/hour limit per IP):
		// find the latest release through the public release page, which has no such limit.
		if ( ! $rel ) {
			$rel = self::release_from_page();
			if ( $rel ) {
				$code = 'page';
			}
		}
		// Network failure: try again in 1 hour, without blocking the dashboard.
		set_site_transient( self::CACHE, $rel ? $rel : array( 'version' => '' ), $rel ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		update_site_option( 'owum_gh_check', array( 'time' => current_time( 'mysql' ), 'ok' => (bool) $rel, 'code' => $code ) );
		return $rel;
	}

	/**
	 * Fallback without the GitHub API: github.com/<repo>/releases/latest redirects to the
	 * latest tag, and the package has a fixed download address for each tag.
	 *
	 * @return array|null
	 */
	public static function release_from_page() {
		$res = wp_remote_head(
			'https://github.com/' . self::REPO . '/releases/latest',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array( 'User-Agent' => 'Ondaweb-Security-Updater/' . OWUM_VERSION ),
			)
		);
		if ( is_wp_error( $res ) ) {
			return null;
		}
		$loc = (string) wp_remote_retrieve_header( $res, 'location' );
		if ( ! preg_match( '#/releases/tag/(v?(\d+\.\d+(?:\.\d+)?))$#', $loc, $m ) ) {
			return null;
		}
		return array(
			'version'   => $m[2],
			'package'   => 'https://github.com/' . self::REPO . '/releases/download/' . rawurlencode( $m[1] ) . '/' . self::ASSET,
			'url'       => esc_url_raw( $loc ),
			'notes'     => '',
			'published' => '',
		);
	}

	/** Called by WordPress when checking updates of plugins whose "Update URI" is on github.com. */
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

	/** "View details" window of the update. */
	public static function info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || self::slug() !== $args->slug ) {
			return $result;
		}
		$rel = self::release();
		if ( ! $rel ) {
			return $result;
		}
		return (object) array(
			'name'          => OWUM_PRODUCT,
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
				'description' => '<p>' . esc_html__( 'Version inventory, update history, security checks and fixes, and a monthly client report.', 'ondaweb-security' ) . '</p>',
			),
			'banners'       => array(),
		);
	}

	/** Keeps the installed folder name (preserves history and settings). */
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
		return new WP_Error( 'owum_folder', __( 'Could not prepare the update folder.', 'ondaweb-security' ) );
	}

	/** Simple Markdown (headings, lists, bold, links) to HTML. */
	public static function markdown( $md ) {
		$md = trim( str_replace( "\r", '', (string) $md ) );
		if ( '' === $md ) {
			return '<p>' . esc_html__( 'No notes for this version.', 'ondaweb-security' ) . '</p>';
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
