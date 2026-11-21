<?php
/**
 * Plugin Name:       BlockerMD
 * Plugin URI:        https://mecha-digital.com/
 * Description:       Performance-first security for MD sites: stops scanner probes, abusive bots and login brute force before WordPress does heavy work, and logs every decision.
 * Version:           0.3.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Mecha Digital
 * License:           GPL-2.0-or-later
 * Text Domain:       blockermd
 *
 * The folder is named "0-blockermd" on purpose: WordPress loads active plugins
 * in alphabetical order, so this one runs before the theme and other plugins
 * and can turn bad requests away cheaply.
 */

defined( 'ABSPATH' ) || exit;

define( 'BLOCKERMD_VERSION', '0.3.0' );
define( 'BLOCKERMD_FILE', __FILE__ );
define( 'BLOCKERMD_DIR', __DIR__ );
define( 'BLOCKERMD_DB_VERSION', 1 );

// Where client sites send their hourly summaries unless a site overrides it.
define( 'BLOCKERMD_DEFAULT_HUB', 'https://mecha-digital.com' );

require_once BLOCKERMD_DIR . '/includes/class-settings.php';
require_once BLOCKERMD_DIR . '/includes/class-store.php';
require_once BLOCKERMD_DIR . '/includes/class-log.php';
require_once BLOCKERMD_DIR . '/includes/class-ajax.php';
require_once BLOCKERMD_DIR . '/includes/class-gate.php';
require_once BLOCKERMD_DIR . '/includes/class-admin.php';
require_once BLOCKERMD_DIR . '/includes/class-admin-cleanup.php';
require_once BLOCKERMD_DIR . '/includes/class-updater.php';
require_once BLOCKERMD_DIR . '/includes/class-reporter.php';
require_once BLOCKERMD_DIR . '/includes/class-hub.php';
require_once BLOCKERMD_DIR . '/includes/class-hub-admin.php';

// 1. Front door: runs right now, while the plugin file loads.
BlockerMD_Gate::run();

// 2. Hooks that need more of WordPress.
BlockerMD_Gate::register_late_hooks();
BlockerMD_Log::register_hooks();
BlockerMD_Admin::register_hooks();
BlockerMD_Admin_Cleanup::register_hooks();
BlockerMD_Ajax::register_hooks();
BlockerMD_Updater::register_hooks();
BlockerMD_Reporter::register_hooks();
BlockerMD_Hub::register_hooks();
BlockerMD_Hub_Admin::register_hooks();

register_activation_hook( __FILE__, array( 'BlockerMD_Log', 'install' ) );
register_deactivation_hook(
	__FILE__,
	function () {
		BlockerMD_Log::unschedule();
		BlockerMD_Reporter::unschedule();
		BlockerMD_Ajax::unschedule();
	}
);
