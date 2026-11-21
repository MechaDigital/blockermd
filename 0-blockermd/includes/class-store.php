<?php
/**
 * Short-lived counters and flags (scores, bans, rate limits).
 *
 * Uses the persistent object cache (Redis via Object Cache Pro on Cloudways)
 * when present, then APCu, then transients as a last resort.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Store {

	const GROUP = 'blockermd';

	/** @var string|null */
	private static $backend = null;

	public static function backend() {
		if ( null === self::$backend ) {
			if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
				self::$backend = 'cache';
			} elseif ( function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
				self::$backend = 'apcu';
			} else {
				self::$backend = 'transient';
			}
		}
		return self::$backend;
	}

	private static function key( $key ) {
		// Keep keys short and safe for every backend; scope APCu by site.
		return 'bmd_' . substr( md5( $key . '|' . ( defined( 'DB_NAME' ) ? DB_NAME : '' ) ), 0, 20 );
	}

	public static function get( $key ) {
		$k = self::key( $key );
		switch ( self::backend() ) {
			case 'cache':
				$v = wp_cache_get( $k, self::GROUP );
				return false === $v ? null : $v;
			case 'apcu':
				$ok = false;
				$v  = apcu_fetch( $k, $ok );
				return $ok ? $v : null;
			default:
				$v = get_transient( $k );
				return false === $v ? null : $v;
		}
	}

	public static function set( $key, $value, $ttl ) {
		$k   = self::key( $key );
		$ttl = max( 1, (int) $ttl );
		switch ( self::backend() ) {
			case 'cache':
				wp_cache_set( $k, $value, self::GROUP, $ttl );
				break;
			case 'apcu':
				apcu_store( $k, $value, $ttl );
				break;
			default:
				set_transient( $k, $value, $ttl );
		}
	}

	/** Set only if missing. Returns true when this call created the key. */
	public static function add( $key, $value, $ttl ) {
		$k   = self::key( $key );
		$ttl = max( 1, (int) $ttl );
		switch ( self::backend() ) {
			case 'cache':
				return (bool) wp_cache_add( $k, $value, self::GROUP, $ttl );
			case 'apcu':
				return (bool) apcu_add( $k, $value, $ttl );
			default:
				if ( false !== get_transient( $k ) ) {
					return false;
				}
				set_transient( $k, $value, $ttl );
				return true;
		}
	}

	/**
	 * Add $by to a fixed-window counter that expires $ttl seconds after it was
	 * first created. Returns the new total.
	 */
	public static function incr( $key, $by, $ttl ) {
		$by = (int) $by;
		if ( self::add( $key, $by, $ttl ) ) {
			return $by;
		}
		$k = self::key( $key );
		switch ( self::backend() ) {
			case 'cache':
				$v = wp_cache_incr( $k, $by, self::GROUP );
				if ( false === $v ) {
					wp_cache_set( $k, $by, self::GROUP, $ttl );
					return $by;
				}
				return (int) $v;
			case 'apcu':
				$ok = false;
				$v  = apcu_inc( $k, $by, $ok, $ttl );
				return $ok ? (int) $v : $by;
			default:
				// Transients have no atomic increment; good enough for abuse counting.
				$v = (int) get_transient( $k ) + $by;
				set_transient( $k, $v, $ttl );
				return $v;
		}
	}

	/**
	 * Fetch many keys at once (one round trip on Redis / APCu).
	 * Returns key => value for the keys that exist.
	 */
	public static function get_multi( array $keys ) {
		$out = array();
		if ( ! $keys ) {
			return $out;
		}
		$map = array();
		foreach ( $keys as $key ) {
			$map[ self::key( $key ) ] = $key;
		}
		switch ( self::backend() ) {
			case 'cache':
				if ( function_exists( 'wp_cache_get_multiple' ) ) {
					foreach ( (array) wp_cache_get_multiple( array_keys( $map ), self::GROUP ) as $k => $v ) {
						if ( false !== $v && isset( $map[ $k ] ) ) {
							$out[ $map[ $k ] ] = $v;
						}
					}
					return $out;
				}
				break;
			case 'apcu':
				foreach ( (array) apcu_fetch( array_keys( $map ) ) as $k => $v ) {
					if ( isset( $map[ $k ] ) ) {
						$out[ $map[ $k ] ] = $v;
					}
				}
				return $out;
		}
		foreach ( $keys as $key ) {
			$v = self::get( $key );
			if ( null !== $v ) {
				$out[ $key ] = $v;
			}
		}
		return $out;
	}

	public static function delete( $key ) {
		$k = self::key( $key );
		switch ( self::backend() ) {
			case 'cache':
				wp_cache_delete( $k, self::GROUP );
				break;
			case 'apcu':
				apcu_delete( $k );
				break;
			default:
				delete_transient( $k );
		}
	}
}
