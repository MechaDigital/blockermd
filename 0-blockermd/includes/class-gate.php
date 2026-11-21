<?php
/**
 * The front door. Runs while the plugin file is loading (before the theme and
 * most plugins), so a turned-away request costs very little.
 *
 * Rules, in order:
 *   0. admin-ajax           -> no action: WP's own 400 "0" early; else count (both modes)
 *   1. allow list           -> skip everything
 *   2. active ban           -> 403
 *   3. scanner probe path   -> 403 + score
 *   4. login brute force    -> 429 while locked out
 *   5. crawler controls     -> 403 (block list / bot oEmbed) or 429 (rate limit)
 *   6. odd query strings    -> score only
 * Later in the request: 404s add score, failed logins count toward lockout.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Gate {

	const GENERIC_BOT = '/bot|crawl|spider|slurp|scrapy|python-requests|curl\/|wget|go-http-client|httpclient|libwww|okhttp|headless/i';

	// Link-preview services that legitimately use oEmbed (Slack/Discord unfurls etc.).
	const OEMBED_FRIENDS = '/slackbot|discordbot|twitterbot|facebookexternalhit|linkedinbot|whatsapp|telegrambot|iframely|embedly|skypeuripreview|pinterestbot|redditbot|mastodon/i';

	/** @var string|null */
	private static $ip = null;

	public static function run() {
		if ( self::should_skip() ) {
			return;
		}

		$ip     = self::client_ip();
		$path   = self::request_path();
		$query  = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) : 'GET';
		$ua     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

		// 0. admin-ajax: answer action-less requests early, count the rest.
		// Runs for everyone (allow-listed too) and in both modes; never blocks.
		BlockerMD_Ajax::handle_request( $ip, $ua );

		if ( '' === $ip || self::is_allowed_ip( $ip ) ) {
			return;
		}

		// 2. Active ban. The login page stays reachable so a banned admin can
		// log in, which trusts their IP and lifts the ban (see on_admin_login).
		// Brute force on the login page is still handled by rule 4.
		if ( BlockerMD_Store::get( 'ban:' . $ip ) && 'wp-login.php' !== strtolower( basename( $path ) ) ) {
			self::deny( 403, 'banned', $ip, $path, $ua );
		}

		// 3. Scanner probes.
		if ( self::is_probe( $path ) ) {
			self::add_score( $ip, (int) BlockerMD_Settings::get( 'probe_points' ), 'probe', $path, $ua );
			self::deny( 403, 'probe', $ip, $path, $ua );
		}

		// 4. Login brute force.
		$is_login = self::is_login_endpoint( $path );
		if ( $is_login ) {
			if ( BlockerMD_Store::get( 'lock:' . $ip ) ) {
				self::deny( 429, 'login_locked', $ip, $path, $ua, (int) BlockerMD_Settings::get( 'login_lockout_minutes' ) * 60 );
			}
			if ( 'POST' === $method ) {
				$window = (int) BlockerMD_Settings::get( 'login_post_window' );
				$posts  = BlockerMD_Store::incr( 'lpost:' . $ip, 1, $window );
				if ( $posts > (int) BlockerMD_Settings::get( 'login_max_posts' ) ) {
					self::lock_login( $ip );
					self::deny( 429, 'login_flood', $ip, $path, $ua, (int) BlockerMD_Settings::get( 'login_lockout_minutes' ) * 60 );
				}
			}
		}

		// 5. Crawlers.
		if ( '' !== $ua ) {
			$blocked = self::match_ua( $ua, BlockerMD_Settings::lines( 'bot_block_list' ) );
			if ( null !== $blocked ) {
				self::deny( 403, 'bot_blocked', $ip, $path, $ua );
			}

			if ( BlockerMD_Settings::get( 'block_bot_oembed' ) && self::is_oembed( $path, $query ) && preg_match( self::GENERIC_BOT, $ua ) && ! preg_match( self::OEMBED_FRIENDS, $ua ) ) {
				self::deny( 403, 'bot_oembed', $ip, $path, $ua );
			}

			$limited = self::match_ua( $ua, BlockerMD_Settings::lines( 'bot_limit_list' ) );
			if ( null !== $limited ) {
				$bucket = 'bot:' . strtolower( $limited ) . ':' . (int) floor( time() / 60 );
				$hits   = BlockerMD_Store::incr( $bucket, 1, 70 );
				if ( $hits > (int) BlockerMD_Settings::get( 'bot_limit_per_minute' ) ) {
					self::deny( 429, 'bot_rate', $ip, $path, $ua, 60 );
				}
			}
		}

		// 6. Odd cache-busting query strings (e.g. "?1eaae7=84115") on non-content URLs.
		if ( '' !== $query && self::is_odd_query( $path, $query ) ) {
			self::add_score( $ip, (int) BlockerMD_Settings::get( 'odd_query_points' ), 'odd_query', $path, $ua );
		}
	}

	public static function register_late_hooks() {
		add_action( 'template_redirect', array( __CLASS__, 'on_template_redirect' ), 0 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ) );
		add_action( 'xmlrpc_login_error', array( __CLASS__, 'on_login_failed' ) );
		add_action( 'wp_login', array( __CLASS__, 'on_admin_login' ), 10, 2 );
	}

	/** 404s add to the client's score. */
	public static function on_template_redirect() {
		if ( ! is_404() || self::should_skip() || is_user_logged_in() ) {
			return;
		}
		$ip = self::client_ip();
		if ( '' === $ip || self::is_allowed_ip( $ip ) ) {
			return;
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		self::add_score( $ip, (int) BlockerMD_Settings::get( 'not_found_points' ), 'not_found', self::request_path(), $ua );
	}

	public static function on_login_failed() {
		$ip = self::client_ip();
		if ( '' === $ip || self::is_allowed_ip( $ip ) ) {
			return;
		}
		$fails = BlockerMD_Store::incr( 'lfail:' . $ip, 1, (int) BlockerMD_Settings::get( 'login_failure_window' ) );
		if ( $fails >= (int) BlockerMD_Settings::get( 'login_max_failures' ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
			if ( BlockerMD_Settings::enforcing() ) {
				self::lock_login( $ip );
			}
			BlockerMD_Log::write( $ip, 'login_failures', BlockerMD_Settings::enforcing() ? 'lock' : 'log', self::request_path(), $ua );
		}
	}

	/* ------------------------------------------------------------------ */

	private static function should_skip() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		if ( 'cli' === PHP_SAPI ) {
			return true;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}
		return false;
	}

	private static function lock_login( $ip ) {
		BlockerMD_Store::set( 'lock:' . $ip, 1, (int) BlockerMD_Settings::get( 'login_lockout_minutes' ) * 60 );
	}

	private static function add_score( $ip, $points, $rule, $path, $ua ) {
		if ( $points <= 0 ) {
			return;
		}
		$score = BlockerMD_Store::incr( 'score:' . $ip, $points, (int) BlockerMD_Settings::get( 'score_window' ) );
		if ( $score >= (int) BlockerMD_Settings::get( 'score_threshold' ) ) {
			if ( BlockerMD_Settings::enforcing() ) {
				$ttl = (int) BlockerMD_Settings::get( 'ban_minutes' ) * 60;
				if ( BlockerMD_Store::add( 'ban:' . $ip, 1, $ttl ) ) {
					BlockerMD_Log::write( $ip, 'ban:' . $rule, 'ban', $path, $ua );
				}
			} elseif ( BlockerMD_Store::add( 'wouldban:' . $ip, 1, (int) BlockerMD_Settings::get( 'score_window' ) ) ) {
				BlockerMD_Log::write( $ip, 'ban:' . $rule, 'log', $path, $ua );
			}
		}
	}

	/**
	 * Turn the request away (or, in log-only mode, just record it).
	 */
	private static function deny( $code, $rule, $ip, $path, $ua, $retry_after = 0 ) {
		$enforce = BlockerMD_Settings::enforcing();
		BlockerMD_Log::write( $ip, $rule, $enforce ? ( 429 === $code ? 'limit' : 'block' ) : 'log', $path, $ua );

		if ( ! $enforce ) {
			return;
		}

		if ( ! headers_sent() ) {
			http_response_code( $code );
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Cache-Control: no-store, max-age=0' );
			header( 'X-Robots-Tag: noindex' );
			if ( $retry_after > 0 ) {
				header( 'Retry-After: ' . (int) $retry_after );
			}
		}
		echo 429 === $code ? 'Too Many Requests' : 'Forbidden';
		exit;
	}

	/* ------------------------------------------------------------------ */

	public static function client_ip() {
		if ( null !== self::$ip ) {
			return self::$ip;
		}
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
		$ip     = $remote;

		// Only trust forwarding headers when the direct peer is a local proxy
		// (Cloudways puts Nginx/Varnish in front of PHP on the same box).
		if ( '' === $remote || self::is_private_ip( $remote ) ) {
			foreach ( array( 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' ) as $h ) {
				if ( empty( $_SERVER[ $h ] ) ) {
					continue;
				}
				foreach ( explode( ',', (string) $_SERVER[ $h ] ) as $cand ) {
					$cand = trim( $cand );
					if ( filter_var( $cand, FILTER_VALIDATE_IP ) && ! self::is_private_ip( $cand ) ) {
						$ip = $cand;
						break 2;
					}
				}
			}
		}

		self::$ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
		return self::$ip;
	}

	private static function is_private_ip( $ip ) {
		return ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * An administrator just logged in: trust this IP for a while and wipe any
	 * ban, lockout or score it had. Covers admins whose IP changes often.
	 */
	public static function on_admin_login( $user_login, $user ) {
		if ( ! BlockerMD_Settings::get( 'trust_on_login' ) || ! $user instanceof WP_User || ! user_can( $user, 'manage_options' ) ) {
			return;
		}
		$ip = self::client_ip();
		if ( '' === $ip || self::is_private_ip( $ip ) ) {
			return;
		}
		$trusted        = self::trusted_ips();
		$trusted[ $ip ] = time() + (int) BlockerMD_Settings::get( 'trust_days' ) * DAY_IN_SECONDS;
		arsort( $trusted );
		$trusted = array_slice( $trusted, 0, 20, true ); // Keep the 20 most recent.
		update_option( 'blockermd_trusted', $trusted, true );

		foreach ( array( 'ban:', 'lock:', 'score:', 'lfail:', 'lpost:', 'wouldban:' ) as $prefix ) {
			BlockerMD_Store::delete( $prefix . $ip );
		}
		BlockerMD_Log::write( $ip, 'trusted_login', 'trust', self::request_path(), isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '' );
	}

	/** Trusted IPs that have not expired, as ip => expiry timestamp. */
	public static function trusted_ips() {
		$list = get_option( 'blockermd_trusted', array() );
		if ( ! is_array( $list ) ) {
			return array();
		}
		$now = time();
		foreach ( $list as $ip => $expires ) {
			if ( (int) $expires < $now ) {
				unset( $list[ $ip ] );
			}
		}
		return $list;
	}

	private static function is_allowed_ip( $ip ) {
		if ( self::is_private_ip( $ip ) ) {
			return true; // Loopback health checks, server-side cron, etc.
		}
		if ( BlockerMD_Settings::get( 'trust_on_login' ) && isset( self::trusted_ips()[ $ip ] ) ) {
			return true;
		}
		foreach ( BlockerMD_Settings::lines( 'allow_ips' ) as $allowed ) {
			if ( $allowed === $ip || self::ip_in_cidr( $ip, $allowed ) ) {
				return true;
			}
		}
		return false;
	}

	private static function ip_in_cidr( $ip, $cidr ) {
		if ( false === strpos( $cidr, '/' ) ) {
			return false;
		}
		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$ip_bin  = @inet_pton( $ip );
		$sub_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $sub_bin || strlen( $ip_bin ) !== strlen( $sub_bin ) ) {
			return false;
		}
		$bits  = (int) $bits;
		$bytes = intdiv( $bits, 8 );
		$rem   = $bits % 8;
		if ( substr( $ip_bin, 0, $bytes ) !== substr( $sub_bin, 0, $bytes ) ) {
			return false;
		}
		if ( 0 === $rem ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rem ) ) & 0xff );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $sub_bin[ $bytes ] & $mask );
	}

	public static function request_path() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$path = (string) parse_url( $uri, PHP_URL_PATH );
		$path = rawurldecode( $path );
		return '' === $path ? '/' : $path;
	}

	public static function is_probe( $path ) {
		static $regex = null;
		if ( null === $regex ) {
			$parts = array();
			foreach ( BlockerMD_Settings::lines( 'probe_paths' ) as $p ) {
				$p = trim( $p, '/' );
				if ( '' !== $p ) {
					$parts[] = preg_quote( $p, '#' );
				}
			}
			// Whole path segment: start of path or "/" before, end or "/", "." or "~" after.
			$regex = $parts ? '#(?:^|/)(?:' . implode( '|', $parts ) . ')(?:$|[/.~])#i' : '';
		}
		return '' !== $regex && (bool) preg_match( $regex, $path );
	}

	private static function is_login_endpoint( $path ) {
		$base = strtolower( basename( $path ) );
		return 'wp-login.php' === $base || 'xmlrpc.php' === $base;
	}

	private static function is_oembed( $path, $query ) {
		if ( false !== stripos( $path, '/wp-json/oembed/' ) ) {
			return true;
		}
		if ( '' === $query ) {
			return false;
		}
		parse_str( $query, $q );
		if ( isset( $q['rest_route'] ) && 0 === stripos( (string) $q['rest_route'], '/oembed/' ) ) {
			return true;
		}
		// Legacy-style "?url=...&format=xml|json" requests.
		return isset( $q['url'], $q['format'] ) && in_array( strtolower( (string) $q['format'] ), array( 'xml', 'json' ), true );
	}

	private static function is_odd_query( $path, $query ) {
		// One parameter, random hex-looking name, numeric value: "?1eaae7=84115".
		if ( ! preg_match( '/^[a-f0-9]{5,8}=\d{1,8}$/i', $query ) ) {
			return false;
		}
		// Only count it on URLs that are not normal content pages.
		$base = strtolower( basename( $path ) );
		return in_array( $base, array( 'admin-ajax.php', 'wp-load.php', 'wp-cron.php', 'index.php', 'xmlrpc.php' ), true )
			|| (bool) preg_match( '/\.(php|env|sql|bak|zip|key|ini|log)$/i', $path );
	}

	/** Returns the matching needle, or null. */
	private static function match_ua( $ua, array $needles ) {
		foreach ( $needles as $needle ) {
			if ( '' !== $needle && false !== stripos( $ua, $needle ) ) {
				return $needle;
			}
		}
		return null;
	}
}
