<?php
defined( 'ABSPATH' ) || exit;

/**
 * Vulnerabilidades conhecidas: base Wordfence Intelligence (API v3).
 * O arquivo da base é grande, então é baixado para disco e lido em fluxo,
 * um registro por vez, sem carregar tudo na memória.
 */
class OWSU_Vulns {

	const FEED_URL = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

	public static function key() {
		$s = owum_settings();
		return isset( $s['wf_key'] ) ? trim( (string) $s['wf_key'] ) : '';
	}

	public static function get() {
		$v = get_site_option( 'owsu_vulns' );
		return is_array( $v ) ? $v : array( 'time' => '', 'error' => '', 'items' => array() );
	}

	/** Vulnerabilidades de um item do inventário (ex.: "plugin:elementor-pro/elementor-pro.php"). */
	public static function for_key( $key ) {
		$out = array();
		foreach ( (array) self::get()['items'] as $it ) {
			if ( $it['key'] === $key ) {
				$out[] = $it;
			}
		}
		return $out;
	}

	/** Mapa do que está instalado, no formato da base: tipo => slug => [versão, nome, chave do inventário]. */
	public static function targets() {
		$snap = OWUM_Collector::snapshot();
		$t    = array(
			'core'   => array( 'wordpress' => array( $snap['core']['version'], 'WordPress', 'core' ) ),
			'plugin' => array(),
			'theme'  => array(),
		);
		foreach ( $snap['plugin'] as $file => $p ) {
			$slug = false !== strpos( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
			if ( 'hello' === $slug ) {
				$slug = 'hello-dolly';
			}
			$t['plugin'][ $slug ] = array( $p['version'], $p['name'], 'plugin:' . $file );
		}
		foreach ( $snap['theme'] as $slug => $th ) {
			$t['theme'][ $slug ] = array( $th['version'], $th['name'], 'theme:' . $slug );
		}
		return $t;
	}

	/**
	 * Baixa a base e atualiza a lista de vulnerabilidades encontradas.
	 *
	 * @return true|WP_Error
	 */
	public static function update() {
		$key  = self::key();
		$prev = self::get();
		if ( ! $key ) {
			return new WP_Error( 'owsu', 'Chave da API Wordfence Intelligence não configurada.' );
		}
		@set_time_limit( 900 ); // phpcs:ignore
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$tmp = wp_tempnam( 'owsu-wf' );
		$res = wp_remote_get(
			apply_filters( 'owsu_feed_url', self::FEED_URL ),
			array(
				'timeout'    => 300,
				'stream'     => true,
				'filename'   => $tmp,
				'user-agent' => 'Ondaweb Security Updater/' . OWUM_VERSION,
				'headers'    => array(
					'Authorization' => 'Bearer ' . $key,
					'Accept'        => 'application/json',
				),
			)
		);
		$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
		if ( 200 !== $code ) {
			if ( is_wp_error( $res ) ) {
				$msg = 'Falha ao baixar a base: ' . $res->get_error_message();
			} elseif ( in_array( $code, array( 401, 403 ), true ) ) {
				$msg = 'A Wordfence recusou a chave de API (HTTP ' . $code . '). Confira a chave em Configurações.';
			} else {
				$msg = 'A Wordfence respondeu HTTP ' . $code . '.';
			}
			@unlink( $tmp ); // phpcs:ignore
			$prev['error'] = $msg;
			update_site_option( 'owsu_vulns', $prev );
			OWUM_ErrorLog::op( 'Base de vulnerabilidades', $msg );
			return new WP_Error( 'owsu', $msg );
		}
		$result = self::scan_file( $tmp, self::targets() );
		@unlink( $tmp ); // phpcs:ignore
		if ( is_wp_error( $result ) ) {
			OWUM_ErrorLog::op( 'Base de vulnerabilidades', $result->get_error_message() );
			$prev['error'] = $result->get_error_message();
			update_site_option( 'owsu_vulns', $prev );
			return $result;
		}
		update_site_option(
			'owsu_vulns',
			array(
				'time'    => current_time( 'mysql' ),
				'error'   => '',
				'items'   => $result['items'],
				'records' => $result['records'],
			)
		);
		return true;
	}

	/** Testa se uma versão está dentro de uma faixa afetada da base. */
	public static function in_range( $v, $r ) {
		$from = isset( $r['from_version'] ) ? (string) $r['from_version'] : '*';
		$to   = isset( $r['to_version'] ) ? (string) $r['to_version'] : '*';
		if ( '*' !== $from ) {
			$c = version_compare( $v, $from );
			if ( $c < 0 || ( 0 === $c && empty( $r['from_inclusive'] ) ) ) {
				return false;
			}
		}
		if ( '*' !== $to ) {
			$c = version_compare( $v, $to );
			if ( $c > 0 || ( 0 === $c && empty( $r['to_inclusive'] ) ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Lê o JSON da base em fluxo. Formato: { "<id>": { ...registro... }, ... }
	 *
	 * @return array|WP_Error ['items' => [...], 'records' => int]
	 */
	public static function scan_file( $file, $targets ) {
		$fh = @fopen( $file, 'rb' ); // phpcs:ignore
		if ( ! $fh ) {
			return new WP_Error( 'owsu', 'Não foi possível ler a base baixada.' );
		}
		$buf     = '';
		$pos     = 0;
		$depth   = 0;
		$in_str  = false;
		$start   = -1;
		$records = 0;
		$items   = array();
		$seen    = array();

		$handle = function ( $json ) use ( $targets, &$items, &$seen, &$records ) {
			$records++;
			$rec = json_decode( $json, true );
			if ( ! is_array( $rec ) || empty( $rec['software'] ) || ! empty( $rec['informational'] ) ) {
				return;
			}
			foreach ( $rec['software'] as $sw ) {
				$type = isset( $sw['type'] ) ? $sw['type'] : '';
				$slug = isset( $sw['slug'] ) ? $sw['slug'] : '';
				if ( ! isset( $targets[ $type ][ $slug ] ) ) {
					continue;
				}
				list( $ver, $name, $key ) = $targets[ $type ][ $slug ];
				$hit = false;
				foreach ( (array) ( isset( $sw['affected_versions'] ) ? $sw['affected_versions'] : array() ) as $range ) {
					if ( self::in_range( $ver, $range ) ) {
						$hit = true;
						break;
					}
				}
				if ( ! $hit ) {
					continue;
				}
				$id = $key . '|' . ( isset( $rec['id'] ) ? $rec['id'] : md5( $json ) );
				if ( isset( $seen[ $id ] ) ) {
					continue;
				}
				$seen[ $id ] = 1;
				$patched     = isset( $sw['patched_versions'] ) ? (array) $sw['patched_versions'] : array();
				usort( $patched, 'version_compare' );
				$items[] = array(
					'key'         => $key,
					'type'        => $type,
					'name'        => $name,
					'version'     => $ver,
					'title'       => isset( $rec['title'] ) ? trim( (string) $rec['title'] ) : '',
					'cve'         => isset( $rec['cve'] ) ? (string) $rec['cve'] : '',
					'score'       => isset( $rec['cvss']['score'] ) ? (float) $rec['cvss']['score'] : 0,
					'rating'      => isset( $rec['cvss']['rating'] ) ? (string) $rec['cvss']['rating'] : '',
					'patched'     => $patched ? $patched[0] : '',
					'remediation' => isset( $sw['remediation'] ) ? trim( (string) $sw['remediation'] ) : '',
					'ref'         => ! empty( $rec['references'][0] ) ? esc_url_raw( $rec['references'][0] ) : '',
					'published'   => isset( $rec['published'] ) ? substr( (string) $rec['published'], 0, 10 ) : '',
				);
			}
		};

		while ( true ) {
			$len = strlen( $buf );
			if ( $pos >= $len - 1 ) {
				if ( feof( $fh ) && $pos >= $len ) {
					break;
				}
				if ( ! feof( $fh ) ) {
					// Descarta o que já foi consumido e lê mais 1 MB.
					$cut = $start >= 0 ? $start : $pos;
					$buf = substr( $buf, $cut ) . fread( $fh, 1048576 );
					$pos -= $cut;
					if ( $start >= 0 ) {
						$start = 0;
					}
					continue;
				}
			}
			if ( $in_str ) {
				$pos += strcspn( $buf, "\"\\", $pos );
				if ( $pos >= $len ) {
					continue;
				}
				if ( '\\' === $buf[ $pos ] ) {
					$pos += 2;
					continue;
				}
				$in_str = false;
				$pos++;
				continue;
			}
			$pos += strcspn( $buf, "{}\"", $pos );
			if ( $pos >= $len ) {
				continue;
			}
			$c = $buf[ $pos ];
			if ( '"' === $c ) {
				$in_str = true;
			} elseif ( '{' === $c ) {
				$depth++;
				if ( 2 === $depth ) {
					$start = $pos;
				}
			} else {
				if ( 2 === $depth && $start >= 0 ) {
					$handle( substr( $buf, $start, $pos - $start + 1 ) );
					$start = -1;
				}
				$depth--;
			}
			$pos++;
		}
		fclose( $fh ); // phpcs:ignore

		if ( 0 === $records ) {
			return new WP_Error( 'owsu', 'A base baixada está vazia ou em formato inesperado.' );
		}
		usort(
			$items,
			function ( $a, $b ) {
				return $b['score'] <=> $a['score'];
			}
		);
		return array( 'items' => $items, 'records' => $records );
	}
}
