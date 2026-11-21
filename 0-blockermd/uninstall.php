<?php
/**
 * Runs when BlockerMD is deleted from the Plugins screen.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;
foreach ( array( 'blockermd_log', 'blockermd_hub_sites', 'blockermd_hub_reports', 'blockermd_hub_ips' ) as $blockermd_table ) {
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . $blockermd_table ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
}

delete_option( 'blockermd_settings' );
delete_option( 'blockermd_db_version' );
delete_option( 'blockermd_hub_db_version' );
delete_option( 'blockermd_identity' );
delete_option( 'blockermd_trusted' );
delete_option( 'blockermd_defaults_version' );
delete_site_transient( 'blockermd_release' );
wp_clear_scheduled_hook( 'blockermd_prune' );
wp_clear_scheduled_hook( 'blockermd_report' );
wp_clear_scheduled_hook( 'blockermd_ajax_rollup' );

// Counters (scores, bans, admin-ajax stats). They all expire on their own
// within 8 days; this clears them now. All keys start with "bmd_".
if ( function_exists( 'wp_cache_supports' ) && wp_cache_supports( 'flush_group' ) ) {
	wp_cache_flush_group( 'blockermd' );
}
if ( function_exists( 'apcu_enabled' ) && apcu_enabled() && class_exists( 'APCUIterator' ) ) {
	apcu_delete( new APCUIterator( '/^bmd_/' ) );
}
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_bmd\\_%' OR option_name LIKE '\\_transient\\_timeout\\_bmd\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
