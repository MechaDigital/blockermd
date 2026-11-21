<?php
/**
 * Updates from GitHub releases.
 *
 * Each release must have a tag like "v0.2.0" and an attached asset named
 * "blockermd.zip" whose top folder is "0-blockermd" (the release workflow in
 * the repo builds exactly that). Public repos need no credentials.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Updater {

	const SLUG      = 'blockermd';
	const ASSET     = 'blockermd.zip';
	const CACHE_KEY = 'blockermd_release';

	public static function register_hooks() {
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'inject_update' ) );
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_folder_name' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'clear_cache' ), 10, 0 );
	}

	public static function repo() {
		if ( defined( 'BLOCKERMD_UPDATE_REPO' ) && BLOCKERMD_UPDATE_REPO ) {
			return (string) BLOCKERMD_UPDATE_REPO;
		}
		return (string) BlockerMD_Settings::get( 'update_repo' );
	}

	private static function basename() {
		return plugin_basename( BLOCKERMD_FILE );
	}

	/** Latest release info, cached for 6 hours. Returns array or null. */
	public static function latest() {
		$repo = self::repo();
		if ( '' === $repo ) {
			return null;
		}
		$cached = get_site_transient( self::CACHE_KEY );
		if ( is_array( $cached ) && isset( $cached['repo'] ) && $cached['repo'] === $repo ) {
			return $cached['release'];
		}

		$release  = null;
		$response = wp_remote_get(
			'https://api.github.com/repos/' . $repo . '/releases/latest',
			array(
				'timeout' => 8,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'BlockerMD/' . BLOCKERMD_VERSION . '; ' . home_url(),
				),
			)
		);

		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( is_array( $data ) && ! empty( $data['tag_name'] ) && ! empty( $data['assets'] ) ) {
				foreach ( $data['assets'] as $asset ) {
					if ( isset( $asset['name'], $asset['browser_download_url'] ) && self::ASSET === $asset['name'] ) {
						$release = array(
							'version'   => ltrim( (string) $data['tag_name'], 'vV' ),
							'package'   => (string) $asset['browser_download_url'],
							'url'       => (string) ( isset( $data['html_url'] ) ? $data['html_url'] : 'https://github.com/' . $repo ),
							'notes'     => (string) ( isset( $data['body'] ) ? $data['body'] : '' ),
							'published' => (string) ( isset( $data['published_at'] ) ? $data['published_at'] : '' ),
						);
						break;
					}
				}
			}
		}

		// Cache failures too (for 1 hour) so a GitHub outage can't slow wp-admin.
		set_site_transient( self::CACHE_KEY, array( 'repo' => $repo, 'release' => $release ), $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		return $release;
	}

	public static function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$release = self::latest();
		if ( ! $release ) {
			return $transient;
		}

		$item = (object) array(
			'id'            => 'github.com/' . self::repo(),
			'slug'          => self::SLUG,
			'plugin'        => self::basename(),
			'new_version'   => $release['version'],
			'url'           => $release['url'],
			'package'       => $release['package'],
			'tested'        => get_bloginfo( 'version' ),
			'requires_php'  => '7.4',
			'icons'         => array(),
			'banners'       => array(),
		);

		if ( version_compare( $release['version'], BLOCKERMD_VERSION, '>' ) ) {
			$transient->response[ self::basename() ] = $item;
		} else {
			// Listing it here lets the "Enable auto-updates" link appear.
			$transient->no_update[ self::basename() ] = $item;
		}
		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || self::SLUG !== $args->slug ) {
			return $result;
		}
		$release = self::latest();
		if ( ! $release ) {
			return $result;
		}
		return (object) array(
			'name'          => 'BlockerMD',
			'slug'          => self::SLUG,
			'version'       => $release['version'],
			'author'        => 'Mecha Digital',
			'homepage'      => $release['url'],
			'download_link' => $release['package'],
			'last_updated'  => $release['published'],
			'requires_php'  => '7.4',
			'sections'      => array(
				'changelog' => wpautop( esc_html( $release['notes'] ) ),
			),
		);
	}

	/** Make sure the unpacked folder is "0-blockermd" whatever the zip called it. */
	public static function fix_folder_name( $source, $remote_source, $upgrader, $hook_extra = array() ) {
		if ( empty( $hook_extra['plugin'] ) || self::basename() !== $hook_extra['plugin'] ) {
			return $source;
		}
		$wanted = trailingslashit( $remote_source ) . dirname( self::basename() ) . '/';
		if ( untrailingslashit( $source ) === untrailingslashit( $wanted ) ) {
			return $source;
		}
		global $wp_filesystem;
		if ( $wp_filesystem && $wp_filesystem->move( $source, $wanted, true ) ) {
			return $wanted;
		}
		return $source;
	}

	public static function clear_cache() {
		delete_site_transient( self::CACHE_KEY );
	}
}
