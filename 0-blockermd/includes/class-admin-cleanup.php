<?php
/**
 * Admin cleanup (F3) and the admin bar badge (F4).
 *
 * Performance settings only: nothing here blocks traffic or counts toward
 * stats. Each part has its own per-site toggle.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Admin_Cleanup {

	/**
	 * WooCommerce admin features that only fetch marketing, inbox or
	 * suggestion content. Orders, payments and Analytics are not listed.
	 * Unknown names are ignored by WooCommerce, so the list is safe across versions.
	 */
	const WC_FEATURES_OFF = array(
		'marketing',
		'remote-inbox-notifications',
		'remote-free-extensions',
		'payment-gateway-suggestions',
		'wc-pay-promotion',
		'wc-pay-welcome-page',
		'mobile-app-banner',
		'woo-mobile-welcome',
		'shipping-label-banner',
	);

	public static function register_hooks() {
		// Dashboard widgets: after everything else has registered its widgets.
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'remove_dashboard_widgets' ), PHP_INT_MAX );

		// Heartbeat.
		add_action( 'admin_init', array( __CLASS__, 'heartbeat_dashboard' ) );
		add_filter( 'heartbeat_settings', array( __CLASS__, 'heartbeat_settings' ), 99 );

		// WooCommerce trimming.
		if ( BlockerMD_Settings::get( 'wc_admin_trim' ) ) {
			add_filter( 'woocommerce_admin_features', array( __CLASS__, 'wc_features' ), 99 );
			add_filter( 'woocommerce_allow_marketplace_suggestions', '__return_false', 99 );
			add_filter( 'pre_option_woocommerce_show_marketplace_suggestions', array( __CLASS__, 'option_no' ), 99 );
		}

		// Badge.
		add_action( 'admin_bar_menu', array( __CLASS__, 'badge' ), 999 );
		add_action( 'admin_head', array( __CLASS__, 'badge_style' ) );
		add_action( 'wp_head', array( __CLASS__, 'badge_style' ) );
	}

	/* ---------- F3a: dashboard widgets ---------- */

	public static function remove_dashboard_widgets() {
		if ( ! BlockerMD_Settings::get( 'dash_remove_all' ) ) {
			return;
		}
		$keep = BlockerMD_Settings::lines( 'dash_keep_widgets' );

		global $wp_meta_boxes;
		if ( ! empty( $wp_meta_boxes['dashboard'] ) && is_array( $wp_meta_boxes['dashboard'] ) ) {
			foreach ( $wp_meta_boxes['dashboard'] as $context => $priorities ) {
				foreach ( (array) $priorities as $priority => $boxes ) {
					foreach ( (array) $boxes as $id => $box ) {
						if ( false !== $box && ! in_array( (string) $id, $keep, true ) ) {
							remove_meta_box( $id, 'dashboard', $context );
						}
					}
				}
			}
		}
		remove_action( 'welcome_panel', 'wp_welcome_panel' );
	}

	/* ---------- F3b: Heartbeat ---------- */

	/** Dashboard: stop Heartbeat (and the login-expired popup that pulls it in). */
	public static function heartbeat_dashboard() {
		global $pagenow;
		if ( ! BlockerMD_Settings::get( 'heartbeat_control' ) || wp_doing_ajax() || 'index.php' !== $pagenow ) {
			return;
		}
		remove_action( 'admin_enqueue_scripts', 'wp_auth_check_load' );
		add_action(
			'admin_enqueue_scripts',
			function () {
				// Dequeue rather than deregister: if another plugin's script
				// needs Heartbeat it still loads, and nothing throws a notice.
				wp_dequeue_script( 'heartbeat' );
			},
			PHP_INT_MAX
		);
	}

	/** Elsewhere in wp-admin: 120 s. Post/page editors and the front end: untouched. */
	public static function heartbeat_settings( $settings ) {
		global $pagenow;
		if ( ! BlockerMD_Settings::get( 'heartbeat_control' ) || ! is_admin() ) {
			return $settings;
		}
		if ( in_array( $pagenow, array( 'post.php', 'post-new.php' ), true ) ) {
			return $settings; // Autosave and edit locks.
		}
		$settings             = is_array( $settings ) ? $settings : array();
		$settings['interval'] = 120;
		return $settings;
	}

	/* ---------- F3c: WooCommerce ---------- */

	public static function wc_features( $features ) {
		return is_array( $features ) ? array_values( array_diff( $features, self::WC_FEATURES_OFF ) ) : $features;
	}

	public static function option_no() {
		return 'no';
	}

	/* ---------- F4: admin bar badge ---------- */

	private static function badge_visible() {
		return BlockerMD_Settings::get( 'admin_badge' ) && is_admin_bar_showing() && current_user_can( 'manage_options' );
	}

	public static function badge_state() {
		$mode = (string) BlockerMD_Settings::get( 'mode' );
		if ( 'block' === $mode ) {
			return array( 'label' => 'BlockerMD ON', 'class' => 'on' );
		}
		if ( 'log' === $mode ) {
			return array( 'label' => 'BlockerMD LOG', 'class' => 'log' );
		}
		return array( 'label' => 'BlockerMD OFF', 'class' => 'off' );
	}

	public static function badge( $bar ) {
		if ( ! self::badge_visible() || ! is_object( $bar ) ) {
			return;
		}
		$state = self::badge_state();
		$bar->add_node(
			array(
				'id'    => 'blockermd-badge',
				'title' => esc_html( $state['label'] ),
				'href'  => admin_url( 'options-general.php?page=blockermd' ),
				'meta'  => array(
					'class' => 'blockermd-badge blockermd-' . $state['class'],
					'title' => 'BlockerMD settings',
				),
			)
		);
	}

	public static function badge_style() {
		if ( ! self::badge_visible() ) {
			return;
		}
		echo '<style id="blockermd-badge-css">'
			. '#wpadminbar .blockermd-badge>.ab-item{font-weight:600;color:#fff!important}'
			. '#wpadminbar .blockermd-on>.ab-item,#wpadminbar .blockermd-on:hover>.ab-item{background:#d63638!important}'
			. '#wpadminbar .blockermd-log>.ab-item,#wpadminbar .blockermd-log:hover>.ab-item{background:#dba617!important;color:#1d2327!important}'
			. '#wpadminbar .blockermd-off>.ab-item,#wpadminbar .blockermd-off:hover>.ab-item{background:#000!important}'
			. '</style>';
	}
}
