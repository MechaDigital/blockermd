<?php
/**
 * Client side of hub reporting.
 *
 * Each site makes its own Ed25519 key pair the first time it reports. It
 * introduces itself to the hub with the public key ("enroll"), waits until
 * someone approves it on the hub dashboard, then sends a signed summary every
 * hour. The private key never leaves this site, and nobody has to copy
 * tokens around.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Reporter {

	const OPTION    = 'blockermd_identity';
	const CRON_HOOK = 'blockermd_report';
	const MAX_SPAN  = 7 * DAY_IN_SECONDS;

	public static function register_hooks() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
		add_action( 'admin_post_blockermd_report_now', array( __CLASS__, 'handle_report_now' ) );
	}

	public static function ensure_schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + wp_rand( 60, 900 ), 'hourly', self::CRON_HOOK );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/** Hub base URL, or '' if reporting is off. */
	public static function hub_url() {
		if ( ! BlockerMD_Settings::get( 'report_to_hub' ) ) {
			return '';
		}
		$url = (string) BlockerMD_Settings::get( 'hub_url' );
		if ( '' === $url ) {
			$url = defined( 'BLOCKERMD_HUB_URL' ) ? (string) BLOCKERMD_HUB_URL : BLOCKERMD_DEFAULT_HUB;
		}
		return untrailingslashit( $url );
	}

	/** True when the hub is this same site (nothing to send). */
	public static function hub_is_self() {
		$hub = wp_parse_url( self::hub_url(), PHP_URL_HOST );
		$me  = wp_parse_url( home_url(), PHP_URL_HOST );
		$port_hub = wp_parse_url( self::hub_url(), PHP_URL_PORT );
		$port_me  = wp_parse_url( home_url(), PHP_URL_PORT );
		return $hub && $me && strtolower( $hub ) === strtolower( $me ) && $port_hub === $port_me;
	}

	public static function identity() {
		$id = get_option( self::OPTION );
		return is_array( $id ) ? $id : array();
	}

	private static function save_identity( array $id ) {
		update_option( self::OPTION, $id, false );
	}

	private static function ensure_identity() {
		$id = self::identity();
		if ( empty( $id['site_id'] ) || empty( $id['sk'] ) || empty( $id['pk'] ) ) {
			$pair = sodium_crypto_sign_keypair();
			$id   = array(
				'site_id' => wp_generate_uuid4(),
				'sk'      => base64_encode( sodium_crypto_sign_secretkey( $pair ) ),
				'pk'      => base64_encode( sodium_crypto_sign_publickey( $pair ) ),
				'status'  => '',
				'since'   => 0,
			);
			self::save_identity( $id );
		}
		return $id;
	}

	/** Throw away this site's identity so it enrolls again from scratch. */
	public static function reset_identity() {
		delete_option( self::OPTION );
	}

	public static function handle_report_now() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'blockermd_report_now' );
		if ( ! empty( $_POST['reset_identity'] ) ) {
			self::reset_identity();
		}
		self::run();
		wp_safe_redirect( admin_url( 'options-general.php?page=blockermd&tab=settings&reported=1' ) );
		exit;
	}

	/* ------------------------------------------------------------------ */

	public static function run() {
		$hub = self::hub_url();
		if ( '' === $hub || self::hub_is_self() ) {
			return;
		}
		$id = self::ensure_identity();

		if ( ! self::url_allowed( $hub ) ) {
			self::note( array( 'last_error' => 'Hub URL must use https.' ) );
			return;
		}

		if ( 'approved' !== ( isset( $id['status'] ) ? $id['status'] : '' ) ) {
			$status = self::enroll( $hub, $id );
			if ( 'approved' !== $status ) {
				return;
			}
			$id = self::identity();
		}

		self::report( $hub, $id );
	}

	private static function url_allowed( $url ) {
		$scheme = wp_parse_url( $url, PHP_URL_SCHEME );
		if ( 'https' === $scheme ) {
			return true;
		}
		return 'http' === $scheme && defined( 'BLOCKERMD_HUB_ALLOW_HTTP' ) && BLOCKERMD_HUB_ALLOW_HTTP;
	}

	private static function enroll( $hub, array $id ) {
		$payload = array(
			'site_id'    => $id['site_id'],
			'public_key' => $id['pk'],
			'home_url'   => home_url(),
			'name'       => get_bloginfo( 'name' ),
			'version'    => BLOCKERMD_VERSION,
			'ts'         => time(),
		);
		$res = self::send( $hub . '/wp-json/blockermd-hub/v1/enroll', $payload, $id );
		if ( is_wp_error( $res ) ) {
			self::note( array( 'last_error' => 'Enroll: ' . $res->get_error_message() ) );
			return '';
		}
		$status = isset( $res['body']['status'] ) ? sanitize_key( $res['body']['status'] ) : '';
		if ( in_array( $status, array( 'pending', 'approved', 'rejected' ), true ) ) {
			self::note( array( 'status' => $status, 'last_error' => '', 'last_contact' => time() ) );
			return $status;
		}
		$msg = isset( $res['body']['message'] ) ? (string) $res['body']['message'] : 'HTTP ' . $res['code'];
		self::note( array( 'last_error' => 'Enroll: ' . $msg ) );
		return '';
	}

	private static function report( $hub, array $id ) {
		$now   = time();
		$since = ! empty( $id['since'] ) ? (int) $id['since'] : $now - HOUR_IN_SECONDS;
		$since = max( $since, $now - self::MAX_SPAN );

		$payload = array_merge(
			array(
				'site_id'      => $id['site_id'],
				'ts'           => $now,
				'version'      => BLOCKERMD_VERSION,
				'mode'         => BlockerMD_Settings::get( 'mode' ),
				'home_url'     => home_url(),
				'name'         => get_bloginfo( 'name' ),
				'period_start' => $since,
				'period_end'   => $now,
			),
			BlockerMD_Log::summary( $since, $now )
		);

		// admin-ajax counters are kept per finished UTC hour; send the hours
		// not sent yet (at most 7 days' worth).
		BlockerMD_Ajax::rollup();
		$cur_hour = BlockerMD_Ajax::hour( $now );
		$ax_to    = $cur_hour - 1;
		$ax_from  = ! empty( $id['ax_hour'] ) ? (int) $id['ax_hour'] + 1 : $ax_to;
		$ax_from  = max( $ax_from, $cur_hour - 168 );
		$payload['ajax_actions'] = array();
		if ( $ax_from <= $ax_to ) {
			$payload['ajax_actions'] = BlockerMD_Ajax::top_for_report( $ax_from, $ax_to, 20 );
			$na                      = BlockerMD_Ajax::noaction_count( $ax_from, $ax_to );
			if ( $na > 0 ) {
				$payload['totals'][] = array( 'rule' => 'ajax_noaction', 'action' => 'shortcut', 'hits' => $na, 'ips' => 0 );
			}
		}

		$res = self::send( $hub . '/wp-json/blockermd-hub/v1/report', $payload, $id );
		if ( is_wp_error( $res ) ) {
			self::note( array( 'last_error' => 'Report: ' . $res->get_error_message() ) );
			return;
		}
		if ( 200 === $res['code'] ) {
			self::note( array( 'status' => 'approved', 'since' => $now, 'ax_hour' => max( $ax_to, $ax_from - 1 ), 'last_ok' => $now, 'last_contact' => $now, 'last_error' => '' ) );
			return;
		}
		$status = isset( $res['body']['status'] ) ? sanitize_key( $res['body']['status'] ) : '';
		if ( 404 === $res['code'] ) {
			// The hub no longer knows this site (removed on the dashboard): enroll again next run.
			self::note( array( 'status' => '', 'last_error' => 'Hub does not know this site; it will ask to join again.' ) );
			return;
		}
		$msg = isset( $res['body']['message'] ) ? (string) $res['body']['message'] : 'HTTP ' . $res['code'];
		self::note( array( 'status' => $status ? $status : ( isset( $id['status'] ) ? $id['status'] : '' ), 'last_error' => 'Report: ' . $msg ) );
	}

	/** Sign and POST a JSON payload. Returns array(code, body) or WP_Error. */
	private static function send( $url, array $payload, array $id, $hops = 0 ) {
		$body = wp_json_encode( $payload );
		$sig  = base64_encode( sodium_crypto_sign_detached( $body, base64_decode( $id['sk'] ) ) );

		$response = self::post( $url, $body, $sig );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// The hub may redirect (e.g. mecha-digital.com -> www.mecha-digital.com).
		// Redirects turn POSTs into GETs, so re-send to the new address ourselves,
		// but only within the same domain.
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $hops < 2 && in_array( $code, array( 301, 302, 307, 308 ), true ) ) {
			$location = (string) wp_remote_retrieve_header( $response, 'location' );
			if ( '' !== $location && self::same_domain( $url, $location ) && self::url_allowed( $location ) ) {
				return self::send( $location, $payload, $id, $hops + 1 );
			}
		}

		$decoded = json_decode( wp_remote_retrieve_body( $response ), true );
		return array(
			'code' => $code,
			'body' => is_array( $decoded ) ? $decoded : array(),
		);
	}

	private static function same_domain( $a, $b ) {
		$ha = preg_replace( '/^www\./', '', strtolower( (string) wp_parse_url( $a, PHP_URL_HOST ) ) );
		$hb = preg_replace( '/^www\./', '', strtolower( (string) wp_parse_url( $b, PHP_URL_HOST ) ) );
		return '' !== $ha && $ha === $hb;
	}

	private static function post( $url, $body, $sig ) {
		return wp_remote_post(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'headers'     => array(
					'Content-Type'          => 'application/json',
					'X-BlockerMD-Signature' => $sig,
					'User-Agent'            => 'BlockerMD/' . BLOCKERMD_VERSION . '; ' . home_url(),
				),
				'body'        => $body,
			)
		);
	}

	private static function note( array $changes ) {
		$id = self::identity();
		if ( ! $id ) {
			return;
		}
		$changes['last_attempt'] = time();
		self::save_identity( array_merge( $id, $changes ) );
	}
}
