<?php
/**
 * Hub side: receives signed summaries from client sites.
 *
 * Only active when "This site is the hub" is switched on. The hub never sends
 * commands to client sites; it only listens and shows numbers.
 *
 *   POST /wp-json/blockermd-hub/v1/enroll   a site introduces itself (public key)
 *   POST /wp-json/blockermd-hub/v1/report   an approved site sends a summary
 *
 * Every request is signed with the site's Ed25519 key and carries a
 * timestamp; old or replayed requests are refused.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Hub {

	const NS            = 'blockermd-hub/v1';
	const DB_VERSION    = 2; // 2: reports.ajax (v0.3)
	const MAX_BODY      = 262144; // 256 KB
	const CLOCK_SKEW    = 600;    // seconds
	const MAX_PENDING   = 50;
	const ENROLL_PER_IP = 20;     // per hour
	const KEEP_DAYS     = 30;

	public static function enabled() {
		return (bool) BlockerMD_Settings::get( 'hub_enabled' );
	}

	public static function sites_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockermd_hub_sites';
	}

	public static function reports_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockermd_hub_reports';
	}

	public static function ips_table() {
		global $wpdb;
		return $wpdb->prefix . 'blockermd_hub_ips';
	}

	public static function register_hooks() {
		add_action( 'admin_init', array( __CLASS__, 'maybe_install' ) );
		add_action( BlockerMD_Log::CRON_HOOK, array( __CLASS__, 'prune' ) );
		if ( self::enabled() ) {
			add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		}
	}

	public static function maybe_install() {
		if ( self::enabled() && (int) get_option( 'blockermd_hub_db_version' ) !== self::DB_VERSION ) {
			self::install();
		}
	}

	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$c = $wpdb->get_charset_collate();

		dbDelta(
			'CREATE TABLE ' . self::sites_table() . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			site_uuid varchar(36) NOT NULL,
			home_url varchar(255) NOT NULL DEFAULT '',
			name varchar(190) NOT NULL DEFAULT '',
			public_key varchar(64) NOT NULL DEFAULT '',
			status varchar(10) NOT NULL DEFAULT 'pending',
			version varchar(20) NOT NULL DEFAULT '',
			mode varchar(10) NOT NULL DEFAULT '',
			last_ip varchar(45) NOT NULL DEFAULT '',
			created int(10) unsigned NOT NULL DEFAULT 0,
			approved_at int(10) unsigned NOT NULL DEFAULT 0,
			last_report int(10) unsigned NOT NULL DEFAULT 0,
			last_ts int(10) unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY site_uuid (site_uuid),
			KEY status (status)
		) {$c};"
		);
		dbDelta(
			'CREATE TABLE ' . self::reports_table() . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			site_uuid varchar(36) NOT NULL,
			received int(10) unsigned NOT NULL DEFAULT 0,
			period_start int(10) unsigned NOT NULL DEFAULT 0,
			period_end int(10) unsigned NOT NULL DEFAULT 0,
			blocks int(10) unsigned NOT NULL DEFAULT 0,
			totals longtext NOT NULL,
			top_paths longtext NOT NULL,
			ajax longtext NOT NULL,
			PRIMARY KEY  (id),
			KEY site_end (site_uuid, period_end),
			KEY period_end (period_end)
		) {$c};"
		);
		dbDelta(
			'CREATE TABLE ' . self::ips_table() . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			site_uuid varchar(36) NOT NULL,
			period_end int(10) unsigned NOT NULL DEFAULT 0,
			ip varchar(45) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 0,
			rules varchar(255) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY ip_end (ip, period_end),
			KEY period_end (period_end)
		) {$c};"
		);
		update_option( 'blockermd_hub_db_version', self::DB_VERSION, false );
	}

	public static function routes() {
		register_rest_route(
			self::NS,
			'/enroll',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'enroll' ),
				'permission_callback' => '__return_true', // Authenticated by signature below.
			)
		);
		register_rest_route(
			self::NS,
			'/report',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'report' ),
				'permission_callback' => '__return_true', // Authenticated by signature below.
			)
		);
	}

	/* ------------------------------------------------------------------ */

	private static function fail( $code, $message, $status = '' ) {
		$data = array( 'message' => $message );
		if ( $status ) {
			$data['status'] = $status;
		}
		return new WP_REST_Response( $data, $code );
	}

	/** Parse + basic checks shared by both endpoints. Returns array or WP_REST_Response. */
	private static function read_request( WP_REST_Request $request ) {
		if ( (int) get_option( 'blockermd_hub_db_version' ) !== self::DB_VERSION ) {
			self::install();
		}
		$raw = (string) $request->get_body();
		if ( '' === $raw || strlen( $raw ) > self::MAX_BODY ) {
			return self::fail( 400, 'Bad body.' );
		}
		$sig = base64_decode( (string) $request->get_header( 'x_blockermd_signature' ), true );
		if ( false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return self::fail( 401, 'Missing or malformed signature.' );
		}
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) || empty( $data['site_id'] ) || ! isset( $data['ts'] ) ) {
			return self::fail( 400, 'Bad payload.' );
		}
		if ( ! preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string) $data['site_id'] ) ) {
			return self::fail( 400, 'Bad site id.' );
		}
		if ( abs( time() - (int) $data['ts'] ) > self::CLOCK_SKEW ) {
			return self::fail( 400, 'Clock skew too large; check the server time.' );
		}
		return array( 'raw' => $raw, 'sig' => $sig, 'data' => $data );
	}

	private static function verify( $raw, $sig, $public_key_b64 ) {
		$pk = base64_decode( (string) $public_key_b64, true );
		if ( false === $pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
			return false;
		}
		try {
			return sodium_crypto_sign_verify_detached( $sig, $raw, $pk );
		} catch ( Exception $e ) {
			return false;
		}
	}

	private static function get_site( $site_uuid ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . self::sites_table() . ' WHERE site_uuid = %s', $site_uuid ) );
	}

	private static function clean_url( $url ) {
		$url = esc_url_raw( (string) $url, array( 'http', 'https' ) );
		return substr( $url, 0, 255 );
	}

	public static function enroll( WP_REST_Request $request ) {
		global $wpdb;
		$req = self::read_request( $request );
		if ( $req instanceof WP_REST_Response ) {
			return $req;
		}
		$d = $req['data'];

		if ( ! self::verify( $req['raw'], $req['sig'], isset( $d['public_key'] ) ? $d['public_key'] : '' ) ) {
			return self::fail( 401, 'Signature does not match the public key.' );
		}
		$home = self::clean_url( isset( $d['home_url'] ) ? $d['home_url'] : '' );
		if ( '' === $home ) {
			return self::fail( 400, 'Bad home_url.' );
		}

		$site = self::get_site( $d['site_id'] );
		if ( $site ) {
			if ( hash_equals( (string) $site->public_key, (string) $d['public_key'] ) ) {
				return new WP_REST_Response( array( 'status' => $site->status ), 'approved' === $site->status ? 200 : 202 );
			}
			if ( 'pending' !== $site->status ) {
				// An approved or rejected site can't silently swap keys.
				return self::fail( 409, 'This site id is registered with a different key. Remove it on the hub to re-enroll.', $site->status );
			}
		}

		// Throttle new requests to join.
		$ip = BlockerMD_Gate::client_ip();
		if ( BlockerMD_Store::incr( 'hubenroll:' . $ip, 1, HOUR_IN_SECONDS ) > self::ENROLL_PER_IP ) {
			return self::fail( 429, 'Too many enrollment requests.' );
		}
		if ( ! $site ) {
			$pending = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . self::sites_table() . ' WHERE status = %s', 'pending' ) );
			if ( $pending >= self::MAX_PENDING ) {
				return self::fail( 429, 'Too many sites waiting for approval.' );
			}
		}

		$row = array(
			'site_uuid'    => $d['site_id'],
			'home_url'   => $home,
			'name'       => substr( sanitize_text_field( isset( $d['name'] ) ? $d['name'] : '' ), 0, 190 ),
			'public_key' => (string) $d['public_key'],
			'status'     => 'pending',
			'version'    => substr( sanitize_text_field( isset( $d['version'] ) ? $d['version'] : '' ), 0, 20 ),
			'last_ip'    => $ip,
		);
		if ( $site ) {
			$wpdb->update( self::sites_table(), $row, array( 'site_uuid' => $d['site_id'] ) );
		} else {
			$row['created'] = time();
			$wpdb->insert( self::sites_table(), $row );
		}
		return new WP_REST_Response( array( 'status' => 'pending' ), 202 );
	}

	public static function report( WP_REST_Request $request ) {
		global $wpdb;
		$req = self::read_request( $request );
		if ( $req instanceof WP_REST_Response ) {
			return $req;
		}
		$d    = $req['data'];
		$site = self::get_site( $d['site_id'] );

		if ( ! $site ) {
			return self::fail( 404, 'Unknown site.' );
		}
		if ( ! self::verify( $req['raw'], $req['sig'], $site->public_key ) ) {
			return self::fail( 401, 'Bad signature.' );
		}
		if ( 'approved' !== $site->status ) {
			return self::fail( 403, 'Not approved yet.', $site->status );
		}
		if ( (int) $d['ts'] <= (int) $site->last_ts ) {
			return self::fail( 409, 'Replay or out-of-order report.' );
		}

		$end   = isset( $d['period_end'] ) ? (int) $d['period_end'] : (int) $d['ts'];
		$start = isset( $d['period_start'] ) ? (int) $d['period_start'] : $end - HOUR_IN_SECONDS;

		$totals = array();
		$blocks = 0;
		foreach ( array_slice( (array) ( isset( $d['totals'] ) ? $d['totals'] : array() ), 0, 60 ) as $t ) {
			if ( ! is_array( $t ) ) {
				continue;
			}
			$row      = array(
				'rule'   => substr( preg_replace( '/[^a-z0-9_:]/', '', strtolower( isset( $t['rule'] ) ? (string) $t['rule'] : '' ) ), 0, 40 ),
				'action' => substr( sanitize_key( isset( $t['action'] ) ? (string) $t['action'] : '' ), 0, 10 ),
				'hits'   => max( 0, (int) ( isset( $t['hits'] ) ? $t['hits'] : 0 ) ),
				'ips'    => max( 0, (int) ( isset( $t['ips'] ) ? $t['ips'] : 0 ) ),
			);
			$totals[]    = $row;
			if ( in_array( $row['action'], array( 'block', 'limit', 'ban', 'lock' ), true ) ) {
				$blocks += $row['hits'];
			}
		}
		$paths = array();
		foreach ( array_slice( (array) ( isset( $d['top_paths'] ) ? $d['top_paths'] : array() ), 0, 20 ) as $p ) {
			if ( is_array( $p ) && isset( $p['path'] ) ) {
				$paths[] = array( 'path' => substr( sanitize_text_field( (string) $p['path'] ), 0, 255 ), 'hits' => max( 0, (int) ( isset( $p['hits'] ) ? $p['hits'] : 0 ) ) );
			}
		}

		$ajax = array();
		foreach ( array_slice( (array) ( isset( $d['ajax_actions'] ) ? $d['ajax_actions'] : array() ), 0, 20 ) as $a ) {
			if ( ! is_array( $a ) || ! isset( $a['action'] ) ) {
				continue;
			}
			$row = array( 'action' => substr( preg_replace( '/[^A-Za-z0-9_\-.:\/\[\]?]/', '?', (string) $a['action'] ), 0, 64 ) );
			foreach ( array( 'hits', 'get', 'post', 'user', 'bot', 'other' ) as $f ) {
				$row[ $f ] = max( 0, (int) ( isset( $a[ $f ] ) ? $a[ $f ] : 0 ) );
			}
			if ( '' !== $row['action'] ) {
				$ajax[] = $row;
			}
		}

		$wpdb->insert(
			self::reports_table(),
			array(
				'site_uuid'      => $site->site_uuid,
				'received'     => time(),
				'period_start' => max( 0, $start ),
				'period_end'   => max( 0, $end ),
				'blocks'       => $blocks,
				'totals'       => wp_json_encode( $totals ),
				'top_paths'    => wp_json_encode( $paths ),
				'ajax'         => wp_json_encode( $ajax ),
			)
		);

		foreach ( array_slice( (array) ( isset( $d['top_ips'] ) ? $d['top_ips'] : array() ), 0, 50 ) as $i ) {
			if ( ! is_array( $i ) || empty( $i['ip'] ) || ! filter_var( $i['ip'], FILTER_VALIDATE_IP ) ) {
				continue;
			}
			$wpdb->insert(
				self::ips_table(),
				array(
					'site_uuid'    => $site->site_uuid,
					'period_end' => max( 0, $end ),
					'ip'         => $i['ip'],
					'hits'       => max( 0, (int) ( isset( $i['hits'] ) ? $i['hits'] : 0 ) ),
					'rules'      => substr( preg_replace( '/[^a-z0-9_:,\- ]/i', '', isset( $i['rules'] ) ? (string) $i['rules'] : '' ), 0, 255 ),
				)
			);
		}

		$wpdb->update(
			self::sites_table(),
			array(
				'last_report' => time(),
				'last_ts'     => (int) $d['ts'],
				'version'     => substr( sanitize_text_field( isset( $d['version'] ) ? $d['version'] : '' ), 0, 20 ),
				'mode'        => ( isset( $d['mode'] ) && 'block' === $d['mode'] ) ? 'block' : 'log',
				'last_ip'     => BlockerMD_Gate::client_ip(),
				'home_url'    => self::clean_url( isset( $d['home_url'] ) ? $d['home_url'] : $site->home_url ),
				'name'        => substr( sanitize_text_field( isset( $d['name'] ) ? $d['name'] : $site->name ), 0, 190 ),
			),
			array( 'site_uuid' => $site->site_uuid )
		);

		return new WP_REST_Response( array( 'status' => 'approved', 'ok' => true ), 200 );
	}

	/* ---------- Site management (hub dashboard) ---------- */

	public static function set_status( $site_uuid, $status ) {
		global $wpdb;
		$data = array( 'status' => $status );
		if ( 'approved' === $status ) {
			$data['approved_at'] = time();
		}
		$wpdb->update( self::sites_table(), $data, array( 'site_uuid' => $site_uuid ) );
	}

	public static function remove_site( $site_uuid ) {
		global $wpdb;
		$wpdb->delete( self::sites_table(), array( 'site_uuid' => $site_uuid ) );
		$wpdb->delete( self::reports_table(), array( 'site_uuid' => $site_uuid ) );
		$wpdb->delete( self::ips_table(), array( 'site_uuid' => $site_uuid ) );
	}

	public static function prune() {
		global $wpdb;
		if ( (int) get_option( 'blockermd_hub_db_version' ) !== self::DB_VERSION ) {
			return;
		}
		$cut = time() - self::KEEP_DAYS * DAY_IN_SECONDS;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::reports_table() . ' WHERE period_end < %d', $cut ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::ips_table() . ' WHERE period_end < %d', $cut ) );
	}

	/* ---------- Queries for the dashboard ---------- */

	public static function sites() {
		global $wpdb;
		$now = time();
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT s.*,
					( SELECT COALESCE(SUM(r.blocks),0) FROM ' . self::reports_table() . ' r WHERE r.site_uuid = s.site_uuid AND r.period_end > %d ) AS blocks_24h,
					( SELECT COALESCE(SUM(r.blocks),0) FROM ' . self::reports_table() . ' r WHERE r.site_uuid = s.site_uuid AND r.period_end > %d ) AS blocks_7d
				FROM ' . self::sites_table() . ' s ORDER BY s.status DESC, s.name ASC',
				$now - DAY_IN_SECONDS,
				$now - 7 * DAY_IN_SECONDS
			)
		);
	}

	public static function rule_totals( $hours = 24 ) {
		global $wpdb;
		$rows = $wpdb->get_col( $wpdb->prepare( 'SELECT totals FROM ' . self::reports_table() . ' WHERE period_end > %d', time() - $hours * HOUR_IN_SECONDS ) );
		$sum  = array();
		foreach ( (array) $rows as $json ) {
			foreach ( (array) json_decode( (string) $json, true ) as $t ) {
				if ( ! is_array( $t ) || empty( $t['rule'] ) ) {
					continue;
				}
				$k = $t['rule'] . '|' . $t['action'];
				if ( ! isset( $sum[ $k ] ) ) {
					$sum[ $k ] = array( 'rule' => $t['rule'], 'action' => $t['action'], 'hits' => 0 );
				}
				$sum[ $k ]['hits'] += (int) $t['hits'];
			}
		}
		usort(
			$sum,
			function ( $a, $b ) {
				return $b['hits'] - $a['hits'];
			}
		);
		return $sum;
	}

	/**
	 * admin-ajax actions over the last N hours: summed across sites, and per site.
	 * Returns array( 'all' => [ action => [hits, sites, get, post, user, bot, other] ], 'sites' => [ site_uuid => [ action => hits ] ] ).
	 */
	public static function ajax_actions( $hours = 24 ) {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT site_uuid, ajax FROM ' . self::reports_table() . ' WHERE period_end > %d', time() - $hours * HOUR_IN_SECONDS ) );
		$all  = array();
		$per  = array();
		foreach ( (array) $rows as $r ) {
			foreach ( (array) json_decode( (string) $r->ajax, true ) as $a ) {
				if ( ! is_array( $a ) || empty( $a['action'] ) ) {
					continue;
				}
				$k = (string) $a['action'];
				if ( ! isset( $all[ $k ] ) ) {
					$all[ $k ] = array( 'hits' => 0, 'sites' => array(), 'get' => 0, 'post' => 0, 'user' => 0, 'bot' => 0, 'other' => 0 );
				}
				foreach ( array( 'hits', 'get', 'post', 'user', 'bot', 'other' ) as $f ) {
					$all[ $k ][ $f ] += isset( $a[ $f ] ) ? (int) $a[ $f ] : 0;
				}
				$all[ $k ]['sites'][ $r->site_uuid ] = true;
				$per[ $r->site_uuid ][ $k ] = ( isset( $per[ $r->site_uuid ][ $k ] ) ? $per[ $r->site_uuid ][ $k ] : 0 ) + ( isset( $a['hits'] ) ? (int) $a['hits'] : 0 );
			}
		}
		foreach ( $all as $k => $v ) {
			$all[ $k ]['sites'] = count( $v['sites'] );
		}
		uasort(
			$all,
			function ( $a, $b ) {
				return $b['hits'] - $a['hits'];
			}
		);
		foreach ( $per as $sid => $list ) {
			arsort( $list );
			$per[ $sid ] = $list;
		}
		return array( 'all' => $all, 'sites' => $per );
	}

	public static function cross_site_ips( $hours = 24, $limit = 50 ) {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ip, sites, hits, site_ids FROM ( SELECT ip, COUNT(DISTINCT site_uuid) AS sites, SUM(hits) AS hits, GROUP_CONCAT(DISTINCT site_uuid) AS site_ids FROM ' . self::ips_table() . ' WHERE period_end > %d GROUP BY ip ) AS x ORDER BY sites DESC, hits DESC LIMIT %d',
				time() - $hours * HOUR_IN_SECONDS,
				$limit
			)
		);
	}
}
