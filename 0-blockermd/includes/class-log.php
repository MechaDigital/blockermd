<?php
/**
 * Block log: a small custom table, pruned daily.
 *
 * To keep floods from turning into database floods, the same IP + rule is
 * written at most once every 10 seconds; repeats in that window bump a hit
 * counter on the row instead.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Log {

	const THROTTLE_SECONDS = 10;
	const CRON_HOOK        = 'blockermd_prune';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'blockermd_log';
	}

	public static function register_hooks() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );
		add_action( 'admin_init', array( __CLASS__, 'maybe_upgrade' ) );
	}

	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		$sql     = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ts datetime NOT NULL,
			ip varchar(45) NOT NULL DEFAULT '',
			rule varchar(40) NOT NULL DEFAULT '',
			action varchar(10) NOT NULL DEFAULT '',
			hits int(10) unsigned NOT NULL DEFAULT 1,
			path varchar(255) NOT NULL DEFAULT '',
			ua varchar(255) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY ts (ts),
			KEY ip (ip)
		) {$charset};";
		dbDelta( $sql );

		update_option( 'blockermd_db_version', BLOCKERMD_DB_VERSION, true );

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function maybe_upgrade() {
		if ( (int) get_option( 'blockermd_db_version' ) !== BLOCKERMD_DB_VERSION ) {
			self::install();
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function write( $ip, $rule, $action, $path, $ua ) {
		global $wpdb;
		if ( ! isset( $wpdb ) || (int) get_option( 'blockermd_db_version' ) !== BLOCKERMD_DB_VERSION ) {
			return;
		}

		$throttle_key = 'logrow:' . $ip . '|' . $rule;
		$row_id       = BlockerMD_Store::get( $throttle_key );
		$suppress     = $wpdb->suppress_errors( true );

		if ( $row_id ) {
			$wpdb->query( $wpdb->prepare( 'UPDATE ' . self::table() . ' SET hits = hits + 1 WHERE id = %d', (int) $row_id ) );
		} else {
			$ok = $wpdb->insert(
				self::table(),
				array(
					'ts'     => gmdate( 'Y-m-d H:i:s' ),
					'ip'     => substr( (string) $ip, 0, 45 ),
					'rule'   => substr( (string) $rule, 0, 40 ),
					'action' => substr( (string) $action, 0, 10 ),
					'hits'   => 1,
					'path'   => substr( (string) $path, 0, 255 ),
					'ua'     => substr( (string) $ua, 0, 255 ),
				),
				array( '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
			);
			if ( $ok ) {
				BlockerMD_Store::set( $throttle_key, (int) $wpdb->insert_id, self::THROTTLE_SECONDS );
			}
		}

		$wpdb->suppress_errors( $suppress );
	}

	public static function prune() {
		global $wpdb;
		$days = (int) BlockerMD_Settings::get( 'log_retention_days' );
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::table() . ' WHERE ts < %s',
				gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS )
			)
		);
	}

	/* ---------- Reporting (admin page only) ---------- */

	private static function since( $hours ) {
		return gmdate( 'Y-m-d H:i:s', time() - $hours * HOUR_IN_SECONDS );
	}

	public static function totals( $hours = 24 ) {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT rule, action, SUM(hits) AS hits, COUNT(DISTINCT ip) AS ips FROM ' . self::table() . ' WHERE ts >= %s GROUP BY rule, action ORDER BY hits DESC',
				self::since( $hours )
			)
		);
	}

	public static function top( $column, $hours = 24, $limit = 10 ) {
		global $wpdb;
		$column = in_array( $column, array( 'ip', 'path', 'ua' ), true ) ? $column : 'ip';
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$column} AS label, SUM(hits) AS hits FROM " . self::table() . " WHERE ts >= %s GROUP BY {$column} ORDER BY hits DESC LIMIT %d",
				self::since( $hours ),
				$limit
			)
		);
	}

	public static function recent( $limit = 50 ) {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM ' . self::table() . ' ORDER BY id DESC LIMIT %d', $limit )
		);
	}

	/** IPs with at least $min hits in the last 24h, for pushing to the server firewall. */
	public static function offenders( $min ) {
		global $wpdb;
		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ip, total, rules FROM ( SELECT ip, SUM(hits) AS total, GROUP_CONCAT(DISTINCT rule) AS rules FROM ' . self::table() . ' WHERE ts >= %s GROUP BY ip ) AS t WHERE total >= %d ORDER BY total DESC LIMIT 200',
				self::since( 24 ),
				(int) $min
			)
		);
	}

	/**
	 * Compact summary of everything logged in (start, end], for the hub.
	 * Rows are bucketed by insert time; the hits added to a row in its 10-second
	 * throttle window go with it.
	 */
	public static function summary( $start, $end ) {
		global $wpdb;
		$from = gmdate( 'Y-m-d H:i:s', (int) $start );
		$to   = gmdate( 'Y-m-d H:i:s', (int) $end );
		$t    = self::table();
		$out  = array( 'totals' => array(), 'top_ips' => array(), 'top_paths' => array() );

		if ( (int) get_option( 'blockermd_db_version' ) !== BLOCKERMD_DB_VERSION ) {
			return $out;
		}

		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT rule, action, SUM(hits) AS hits, COUNT(DISTINCT ip) AS ips FROM {$t} WHERE ts > %s AND ts <= %s GROUP BY rule, action ORDER BY hits DESC LIMIT 50", $from, $to ) ) as $r ) {
			$out['totals'][] = array( 'rule' => $r->rule, 'action' => $r->action, 'hits' => (int) $r->hits, 'ips' => (int) $r->ips );
		}
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT ip, total, rules FROM ( SELECT ip, SUM(hits) AS total, GROUP_CONCAT(DISTINCT rule) AS rules FROM {$t} WHERE ts > %s AND ts <= %s GROUP BY ip ) AS x ORDER BY total DESC LIMIT 50", $from, $to ) ) as $r ) {
			$out['top_ips'][] = array( 'ip' => $r->ip, 'hits' => (int) $r->total, 'rules' => (string) $r->rules );
		}
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT path, SUM(hits) AS hits FROM {$t} WHERE ts > %s AND ts <= %s GROUP BY path ORDER BY hits DESC LIMIT 20", $from, $to ) ) as $r ) {
			$out['top_paths'][] = array( 'path' => $r->path, 'hits' => (int) $r->hits );
		}
		return $out;
	}
}
