<?php
/**
 * admin-ajax: early answer for action-less requests (F1) and per-action
 * counting (F2). Both run in Log only and Blocking modes; neither blocks.
 *
 * Storage is counters only (Redis, then APCu, then transients), never
 * per-request database rows:
 *   na:<hour>                       action-less requests answered early
 *   ax:<hour>:<action>:m:<GET|POST> per-action counters for the live hour
 *   ax:<hour>:<action>:c:<client>   client = user | bot | other
 *   ax:<hour>:<action>:s:<class>    status class = 2xx | 3xx | 4xx | 5xx
 *   ax:<hour>:<action>:ip           small ip => count array (approximate)
 *   axlist                          action => last hour seen (cap 200)
 *   axh:<hour>                      one compact rolled-up array per past hour
 * <hour> is the Unix time divided by 3600 (UTC hours).
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Ajax {

	const CRON_HOOK    = 'blockermd_ajax_rollup';
	const MAX_ACTIONS  = 200;
	const MAX_NAME     = 64;
	const MAX_IPS      = 25;              // per action per hour
	const TTL_LIVE     = 26 * HOUR_IN_SECONDS;
	const TTL_ROLLED   = 8 * DAY_IN_SECONDS;
	const OTHER        = 'other';

	const FIELDS = array( 'm:GET', 'm:POST', 'c:user', 'c:bot', 'c:other', 's:2xx', 's:3xx', 's:4xx', 's:5xx' );

	/** @var array|null Pending action record, written on shutdown. */
	private static $pending = null;

	/* ---------- Front door (called from BlockerMD_Gate::run) ---------- */

	public static function is_ajax_request() {
		if ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) {
			return false;
		}
		$path = BlockerMD_Gate::request_path();
		return '/wp-admin/admin-ajax.php' === substr( strtolower( $path ), -24 );
	}

	/** The action WordPress would use ($_REQUEST, POST wins), or null if it would refuse. */
	public static function request_action() {
		foreach ( array( $_POST, $_GET ) as $src ) { // phpcs:ignore WordPress.Security.NonceVerification
			if ( isset( $src['action'] ) ) {
				return ( is_scalar( $src['action'] ) && ! empty( $src['action'] ) ) ? (string) $src['action'] : null;
			}
		}
		return null;
	}

	public static function handle_request( $ip, $ua ) {
		if ( ! self::is_ajax_request() ) {
			return;
		}
		$action = self::request_action();

		if ( null === $action ) {
			if ( BlockerMD_Settings::get( 'ajax_noaction' ) ) {
				self::answer_empty();
			}
			return;
		}

		if ( BlockerMD_Settings::get( 'ajax_log' ) ) {
			self::$pending = array(
				'action' => $action,
				'method' => ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) ) ? 'POST' : 'GET',
				'client' => self::client_type( $ua ),
				'ip'     => (string) $ip,
			);
			// Late on WordPress's own shutdown hook, so the response status is
			// known and the object cache is still open.
			add_action( 'shutdown', array( __CLASS__, 'record' ), PHP_INT_MAX - 1 );
		}
	}

	/** Same answer WordPress core gives (wp_die( '0', 400 )), without loading WordPress. */
	private static function answer_empty() {
		BlockerMD_Store::incr( 'na:' . self::hour(), 1, self::TTL_ROLLED );
		if ( ! headers_sent() ) {
			http_response_code( 400 );
			header( 'Content-Type: text/html; charset=UTF-8' );
			header( 'Cache-Control: no-store' );
			header( 'X-Robots-Tag: noindex' );
		}
		echo '0';
		exit;
	}

	private static function client_type( $ua ) {
		foreach ( array_keys( $_COOKIE ) as $name ) {
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
				return 'user';
			}
		}
		if ( '' !== $ua ) {
			if ( preg_match( BlockerMD_Gate::GENERIC_BOT, $ua ) ) {
				return 'bot';
			}
			foreach ( array( 'bot_limit_list', 'bot_block_list' ) as $list ) {
				foreach ( BlockerMD_Settings::lines( $list ) as $needle ) {
					if ( false !== stripos( $ua, $needle ) ) {
						return 'bot';
					}
				}
			}
		}
		return 'other';
	}

	/* ---------- Counting ---------- */

	public static function hour( $time = null ) {
		return intdiv( null === $time ? time() : (int) $time, HOUR_IN_SECONDS );
	}

	/** Make an action name safe for keys and display: printable, max 64 chars. */
	public static function clean_name( $name ) {
		$name = preg_replace( '/[^A-Za-z0-9_\-.:\/\[\]]/', '?', (string) $name );
		return substr( $name, 0, self::MAX_NAME );
	}

	/** The counter name for this action: itself, or "other" once 200 are known. */
	private static function slot( $name, $hour ) {
		$list = BlockerMD_Store::get( 'axlist' );
		$list = is_array( $list ) ? $list : array();
		if ( isset( $list[ $name ] ) ) {
			if ( (int) $list[ $name ] < $hour - 24 ) { // Refresh "last seen" at most once a day.
				$list[ $name ] = $hour;
				BlockerMD_Store::set( 'axlist', $list, self::TTL_ROLLED );
			}
			return $name;
		}
		if ( count( $list ) >= self::MAX_ACTIONS ) {
			return self::OTHER;
		}
		$list[ $name ] = $hour;
		BlockerMD_Store::set( 'axlist', $list, self::TTL_ROLLED );
		return $name;
	}

	public static function record() {
		$p = self::$pending;
		self::$pending = null;
		if ( ! $p ) {
			return;
		}
		$hour = self::hour();
		$name = self::clean_name( $p['action'] );
		$name = self::OTHER === $name ? $name : self::slot( $name, $hour );
		$base = 'ax:' . $hour . ':' . $name . ':';

		$code  = http_response_code();
		$class = ( is_int( $code ) && $code >= 200 && $code < 600 ) ? intdiv( $code, 100 ) . 'xx' : '2xx';

		BlockerMD_Store::incr( $base . 'm:' . $p['method'], 1, self::TTL_LIVE );
		BlockerMD_Store::incr( $base . 'c:' . $p['client'], 1, self::TTL_LIVE );
		BlockerMD_Store::incr( $base . 's:' . $class, 1, self::TTL_LIVE );

		if ( '' !== $p['ip'] ) {
			$ips = BlockerMD_Store::get( $base . 'ip' );
			$ips = is_array( $ips ) ? $ips : array();
			if ( isset( $ips[ $p['ip'] ] ) ) {
				$ips[ $p['ip'] ]++;
			} elseif ( count( $ips ) < self::MAX_IPS ) {
				$ips[ $p['ip'] ] = 1;
			}
			BlockerMD_Store::set( $base . 'ip', $ips, self::TTL_LIVE );
		}
	}

	/* ---------- Hourly rollup ---------- */

	public static function register_hooks() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'rollup' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
	}

	public static function ensure_schedule() {
		if ( BlockerMD_Settings::get( 'ajax_log' ) && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + wp_rand( 60, 600 ), 'hourly', self::CRON_HOOK );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/** Live counters for one hour, as action => row. */
	private static function read_live( $hour ) {
		$list    = BlockerMD_Store::get( 'axlist' );
		$actions = is_array( $list ) ? array_keys( $list ) : array();
		$actions[] = self::OTHER;

		$keys = array();
		foreach ( $actions as $a ) {
			foreach ( self::FIELDS as $f ) {
				$keys[] = 'ax:' . $hour . ':' . $a . ':' . $f;
			}
			$keys[] = 'ax:' . $hour . ':' . $a . ':ip';
		}
		$vals = BlockerMD_Store::get_multi( $keys );

		$out = array();
		foreach ( $actions as $a ) {
			$row = self::empty_row();
			$any = false;
			foreach ( self::FIELDS as $f ) {
				$k = 'ax:' . $hour . ':' . $a . ':' . $f;
				if ( isset( $vals[ $k ] ) ) {
					$row[ $f ] = (int) $vals[ $k ];
					$any       = true;
				}
			}
			$ipk = 'ax:' . $hour . ':' . $a . ':ip';
			if ( isset( $vals[ $ipk ] ) && is_array( $vals[ $ipk ] ) ) {
				$row['ips'] = array_map( 'intval', $vals[ $ipk ] );
			}
			if ( $any ) {
				$out[ $a ] = $row;
			}
		}
		return $out;
	}

	private static function empty_row() {
		$row        = array_fill_keys( self::FIELDS, 0 );
		$row['ips'] = array();
		return $row;
	}

	/** Fold finished hours into one compact key each. Safe to run any time. */
	public static function rollup() {
		$now  = self::hour();
		$last = (int) BlockerMD_Store::get( 'axroll_last' );
		if ( $last < $now - 25 ) {
			$last = $now - 25; // Live counters are gone after ~26 hours.
		}
		for ( $h = $last + 1; $h < $now; $h++ ) {
			BlockerMD_Store::set( 'axh:' . $h, self::read_live( $h ), self::TTL_ROLLED );
		}
		if ( $last < $now - 1 ) {
			BlockerMD_Store::set( 'axroll_last', $now - 1, self::TTL_ROLLED );
		}
		self::prune_list( $now );
	}

	/** Forget actions not seen for 8 days so the 200 slots free up. */
	private static function prune_list( $now ) {
		$list = BlockerMD_Store::get( 'axlist' );
		if ( ! is_array( $list ) ) {
			return;
		}
		$keep = array_filter(
			$list,
			function ( $seen ) use ( $now ) {
				return (int) $seen >= $now - 8 * 24;
			}
		);
		if ( count( $keep ) !== count( $list ) ) {
			BlockerMD_Store::set( 'axlist', $keep, self::TTL_ROLLED );
		}
	}

	/* ---------- Reading ---------- */

	/**
	 * Merged per-action rows for hours [from, to], newest data from live
	 * counters. Each row gets 'total' and 'ips' (sorted, desc).
	 */
	public static function range( $from_hour, $to_hour ) {
		$now    = self::hour();
		$rolled = array();
		for ( $h = $from_hour; $h <= $to_hour && $h < $now; $h++ ) {
			$rolled[] = 'axh:' . $h;
		}
		$vals  = BlockerMD_Store::get_multi( $rolled );
		$hours = array();
		foreach ( $rolled as $k ) {
			if ( isset( $vals[ $k ] ) && is_array( $vals[ $k ] ) ) {
				$hours[] = $vals[ $k ];
			} else {
				// Not rolled yet (cron late): read the live counters if they are still there.
				$h = (int) substr( $k, 4 );
				if ( $h >= $now - 25 ) {
					$hours[] = self::read_live( $h );
				}
			}
		}
		if ( $to_hour >= $now ) {
			$hours[] = self::read_live( $now );
		}

		$sum = array();
		foreach ( $hours as $rows ) {
			foreach ( (array) $rows as $action => $row ) {
				if ( ! isset( $sum[ $action ] ) ) {
					$sum[ $action ] = self::empty_row();
				}
				foreach ( self::FIELDS as $f ) {
					$sum[ $action ][ $f ] += isset( $row[ $f ] ) ? (int) $row[ $f ] : 0;
				}
				foreach ( (array) ( isset( $row['ips'] ) ? $row['ips'] : array() ) as $ip => $n ) {
					$sum[ $action ]['ips'][ $ip ] = ( isset( $sum[ $action ]['ips'][ $ip ] ) ? $sum[ $action ]['ips'][ $ip ] : 0 ) + (int) $n;
				}
			}
		}
		foreach ( $sum as $action => $row ) {
			$sum[ $action ]['total'] = $row['m:GET'] + $row['m:POST'];
			arsort( $sum[ $action ]['ips'] );
		}
		uasort(
			$sum,
			function ( $a, $b ) {
				return $b['total'] - $a['total'];
			}
		);
		return $sum;
	}

	/** Rows for the last N hours (including the current one). */
	public static function last_hours( $hours ) {
		$now = self::hour();
		return self::range( $now - $hours + 1, $now );
	}

	/** Action-less requests answered early in hours [from, to]. */
	public static function noaction_count( $from_hour, $to_hour ) {
		$keys = array();
		for ( $h = $from_hour; $h <= $to_hour; $h++ ) {
			$keys[] = 'na:' . $h;
		}
		$total = 0;
		foreach ( BlockerMD_Store::get_multi( $keys ) as $v ) {
			$total += (int) $v;
		}
		return $total;
	}

	/** Compact top-N list for hub reports. */
	public static function top_for_report( $from_hour, $to_hour, $limit = 20 ) {
		$out = array();
		foreach ( array_slice( self::range( $from_hour, $to_hour ), 0, $limit, true ) as $action => $row ) {
			if ( $row['total'] <= 0 ) {
				continue;
			}
			$out[] = array(
				'action' => (string) $action,
				'hits'   => $row['total'],
				'get'    => $row['m:GET'],
				'post'   => $row['m:POST'],
				'user'   => $row['c:user'],
				'bot'    => $row['c:bot'],
				'other'  => $row['c:other'],
			);
		}
		return $out;
	}
}
