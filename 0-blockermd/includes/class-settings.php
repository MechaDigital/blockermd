<?php
/**
 * Settings: one autoloaded option, merged over defaults.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Settings {

	const OPTION = 'blockermd_settings';

	/** @var array|null */
	private static $cache = null;

	public static function defaults() {
		return array(
			// "log" = record what would be blocked but let everything through.
			// New installs start here so a site can be watched before enforcing.
			'mode'                 => 'log',

			// Admin noise control.
			'hide_ocp_widget'      => 1,

			// Admin cleanup (v0.3). Performance settings, not block rules.
			'dash_remove_all'      => 1,   // Remove every dashboard widget + Welcome panel.
			'dash_keep_widgets'    => '',  // Widget IDs to keep, one per line.
			'heartbeat_control'    => 1,   // Off on Dashboard, 120s elsewhere, default in editors.
			'wc_admin_trim'        => 0,   // WooCommerce marketing/inbox/suggestions. Off until tested on a store.
			'admin_badge'          => 1,   // Status badge in the admin bar (admins only).

			// admin-ajax (v0.3). Both run in Log only and Blocking modes.
			'ajax_noaction'        => 1,   // Answer action-less admin-ajax requests before WP loads.
			'ajax_log'             => 1,   // Count admin-ajax requests by action.

			// Scanner probes. One pattern per line, matched against a whole
			// path segment (so "actuator" matches /actuator/env, not /actuators-guide).
			'probe_paths'          => implode(
				"\n",
				array(
					'.env', '.git', '.svn', '.hg', '.aws', '.ssh', '.vscode', '.idea', '.DS_Store',
					'phpinfo', 'info.php', 'php_info.php', 'test.php',
					'private.key', 'server.key', 'id_rsa', 'rclone.conf', 'credentials.json',
					'openai', 'actuator', 'telescope', '_profiler', '_ignition',
					'phpmyadmin', 'pma', 'myadmin', 'adminer', 'adminer.php',
					'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.save', 'wp-config.php.orig', 'wp-config.php.txt', 'wp-config.bak',
					'config.json', 'config.yml', 'docker-compose.yml', 'web.config',
					'backup.sql', 'dump.sql', 'db.sql', 'database.sql', 'backup.zip',
					'vendor/phpunit', 'cgi-bin', 'shell.php', 'cmd.php', 'eval-stdin.php',
					'debug.log', 'error_log', 'server-status', 'HNAP1', 'boaform',
				)
			),

			// Behaviour scoring (per client IP, rolling window).
			'score_window'         => 600,  // seconds
			'score_threshold'      => 20,
			'probe_points'         => 10,
			'not_found_points'     => 2,
			'odd_query_points'     => 5,
			'ban_minutes'          => 60,

			// Login brute force.
			'login_max_failures'   => 5,
			'login_failure_window' => 900,  // seconds
			'login_max_posts'      => 30,   // POSTs to wp-login.php / xmlrpc.php per window
			'login_post_window'    => 300,  // seconds
			'login_lockout_minutes'=> 30,

			// Crawlers. User-agent substrings, one per line, case-insensitive.
			'bot_block_list'       => '',
			'bot_limit_list'       => implode(
				"\n",
				array( 'SemrushBot', 'AhrefsBot', 'MJ12bot', 'DotBot', 'Baiduspider', 'YandexBot', 'PetalBot', 'Bytespider', 'BLEXBot', 'DataForSeoBot', 'SeekportBot' )
			),
			'bot_limit_per_minute' => 6,
			'block_bot_oembed'     => 1,

			// User enumeration (v0.4): anonymous /wp-json/wp/v2/users, ?rest_route=/wp/v2/users, ?author=N.
			'block_user_enum'      => 1,

			// Never touched by any rule. One IP per line.
			'allow_ips'            => '',

			// Trust the IP of any administrator who logs in successfully.
			'trust_on_login'       => 1,
			'trust_days'           => 30,

			// Housekeeping.
			'log_retention_days'   => 30,
			'offender_min_hits'    => 10,  // "repeat offender" export threshold (blocks in 24h)

			// Updates from GitHub releases ("owner/repo"). Empty = off.
			'update_repo'          => 'MechaDigital/blockermd',

			// Hub reporting. Empty hub_url = the built-in default hub.
			'report_to_hub'        => 1,
			'hub_url'              => '',
			'hub_enabled'          => 0,  // "This site is the hub".
		);
	}

	public static function all() {
		if ( null === self::$cache ) {
			$saved       = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
		}
		return self::$cache;
	}

	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	public static function enforcing() {
		return 'block' === self::get( 'mode' );
	}

	/** Split a textarea setting into a clean list. */
	public static function lines( $key ) {
		$raw = (string) self::get( $key );
		$out = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( $line );
			if ( '' !== $line && '#' !== $line[0] ) {
				$out[] = $line;
			}
		}
		return $out;
	}

	public static function save( array $input ) {
		$defaults = self::defaults();
		$clean    = array();

		$clean['mode']            = ( isset( $input['mode'] ) && 'block' === $input['mode'] ) ? 'block' : 'log';
		$clean['hide_ocp_widget'] = empty( $input['hide_ocp_widget'] ) ? 0 : 1;
		$clean['block_bot_oembed']= empty( $input['block_bot_oembed'] ) ? 0 : 1;
		$clean['block_user_enum'] = empty( $input['block_user_enum'] ) ? 0 : 1;
		$clean['trust_on_login']  = empty( $input['trust_on_login'] ) ? 0 : 1;

		foreach ( array( 'dash_remove_all', 'heartbeat_control', 'wc_admin_trim', 'admin_badge', 'ajax_noaction', 'ajax_log' ) as $key ) {
			$clean[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}

		foreach ( array( 'probe_paths', 'bot_block_list', 'bot_limit_list', 'allow_ips', 'dash_keep_widgets' ) as $key ) {
			$clean[ $key ] = isset( $input[ $key ] ) ? sanitize_textarea_field( wp_unslash( $input[ $key ] ) ) : $defaults[ $key ];
		}

		$ints = array(
			'score_window'          => array( 60, 86400 ),
			'score_threshold'       => array( 1, 1000 ),
			'probe_points'          => array( 0, 1000 ),
			'not_found_points'      => array( 0, 1000 ),
			'odd_query_points'      => array( 0, 1000 ),
			'ban_minutes'           => array( 1, 10080 ),
			'login_max_failures'    => array( 1, 100 ),
			'login_failure_window'  => array( 60, 86400 ),
			'login_max_posts'       => array( 1, 1000 ),
			'login_post_window'     => array( 60, 86400 ),
			'login_lockout_minutes' => array( 1, 10080 ),
			'bot_limit_per_minute'  => array( 1, 600 ),
			'log_retention_days'    => array( 1, 365 ),
			'offender_min_hits'     => array( 1, 10000 ),
			'trust_days'            => array( 1, 365 ),
		);
		foreach ( $ints as $key => $range ) {
			$val           = isset( $input[ $key ] ) ? (int) $input[ $key ] : (int) $defaults[ $key ];
			$clean[ $key ] = max( $range[0], min( $range[1], $val ) );
		}

		$clean['report_to_hub'] = empty( $input['report_to_hub'] ) ? 0 : 1;
		$clean['hub_enabled']   = empty( $input['hub_enabled'] ) ? 0 : 1;
		$hub                    = isset( $input['hub_url'] ) ? esc_url_raw( trim( wp_unslash( $input['hub_url'] ) ), array( 'https', 'http' ) ) : '';
		$clean['hub_url']       = untrailingslashit( $hub );

		$repo                 = isset( $input['update_repo'] ) ? trim( sanitize_text_field( wp_unslash( $input['update_repo'] ) ) ) : '';
		$clean['update_repo'] = preg_match( '#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $repo ) ? $repo : '';

		update_option( self::OPTION, $clean, true );
		self::$cache = null;

		if ( $clean['hub_enabled'] && class_exists( 'BlockerMD_Hub' ) ) {
			BlockerMD_Hub::install();
		}
		return $clean;
	}
}
