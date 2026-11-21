<?php
/**
 * Admin: Settings > BlockerMD page, and dashboard noise control.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Admin {

	const SLUG = 'blockermd';

	public static function register_hooks() {
		if ( ! is_admin() ) {
			return;
		}
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_blockermd_save', array( __CLASS__, 'handle_save' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'hide_cache_widgets' ), PHP_INT_MAX );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( BLOCKERMD_FILE ), array( __CLASS__, 'action_links' ) );
	}

	/**
	 * Remove Object Cache Pro / Redis dashboard widgets. They poll for stats
	 * about once a minute while a dashboard is open, which adds up when a
	 * client leaves wp-admin sitting there all day. The cache keeps running.
	 */
	public static function hide_cache_widgets() {
		if ( ! BlockerMD_Settings::get( 'hide_ocp_widget' ) ) {
			return;
		}
		global $wp_meta_boxes;
		if ( empty( $wp_meta_boxes['dashboard'] ) || ! is_array( $wp_meta_boxes['dashboard'] ) ) {
			return;
		}
		foreach ( $wp_meta_boxes['dashboard'] as $context => $priorities ) {
			foreach ( (array) $priorities as $priority => $boxes ) {
				foreach ( (array) $boxes as $id => $box ) {
					if ( false !== stripos( (string) $id, 'objectcache' ) || false !== stripos( (string) $id, 'redis' ) ) {
						remove_meta_box( $id, 'dashboard', $context );
					}
				}
			}
		}
	}

	public static function menu() {
		add_options_page( 'BlockerMD', 'BlockerMD', 'manage_options', self::SLUG, array( __CLASS__, 'render' ) );
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=' . self::SLUG ) ) . '">Settings</a>' );
		return $links;
	}

	public static function notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( blockermd_plugin_active( '0-md-ai-bot-blocker/md-ai-bot-blocker.php' ) ) {
			echo '<div class="notice notice-warning"><p><strong>BlockerMD:</strong> the older "MD AI Bot Blocker" plugin is still active. BlockerMD replaces it; deactivate the old one once you have checked its rules are covered.</p></div>';
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && 'settings_page_' . self::SLUG === $screen->id && ! empty( $_GET['saved'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>';
		}
	}

	public static function handle_save() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'blockermd_save' );
		$input = isset( $_POST['blockermd'] ) && is_array( $_POST['blockermd'] ) ? $_POST['blockermd'] : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- sanitized in save().
		BlockerMD_Settings::save( $input );
		wp_safe_redirect( admin_url( 'options-general.php?page=' . self::SLUG . '&tab=settings&saved=1' ) );
		exit;
	}

	/* ------------------------------------------------------------------ */

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s        = BlockerMD_Settings::all();
		$tab      = isset( $_GET['tab'] ) && 'settings' === $_GET['tab'] ? 'settings' : 'activity';
		$base_url = admin_url( 'options-general.php?page=' . self::SLUG );
		?>
		<div class="wrap">
			<h1>BlockerMD <span style="font-size:13px;color:#646970;">v<?php echo esc_html( BLOCKERMD_VERSION ); ?></span></h1>

			<p>
				Mode:
				<?php if ( BlockerMD_Settings::enforcing() ) : ?>
					<strong style="color:#008a20;">Blocking</strong>, rules are enforced.
				<?php else : ?>
					<strong style="color:#996800;">Log only</strong>, nothing is blocked; the log shows what would have been. Switch to Blocking in Settings when the log looks right.
				<?php endif; ?>
				&nbsp;·&nbsp; Counter storage: <code><?php echo esc_html( BlockerMD_Store::backend() ); ?></code>
			</p>

			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( $base_url ); ?>" class="nav-tab <?php echo 'activity' === $tab ? 'nav-tab-active' : ''; ?>">Activity</a>
				<a href="<?php echo esc_url( $base_url . '&tab=settings' ); ?>" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>">Settings</a>
			</nav>

			<?php
			if ( 'settings' === $tab ) {
				self::render_settings( $s );
			} else {
				self::render_activity( $s );
			}
			?>
		</div>
		<?php
	}

	private static function render_activity( $s ) {
		$totals    = BlockerMD_Log::totals( 24 );
		$top_ips   = BlockerMD_Log::top( 'ip', 24, 10 );
		$top_paths = BlockerMD_Log::top( 'path', 24, 10 );
		$offenders = BlockerMD_Log::offenders( (int) $s['offender_min_hits'] );
		$recent    = BlockerMD_Log::recent( 50 );
		?>
		<h2>Last 24 hours</h2>
		<?php if ( empty( $totals ) ) : ?>
			<p>Nothing logged in the last 24 hours.</p>
		<?php else : ?>
			<table class="widefat striped" style="max-width:720px">
				<thead><tr><th>Rule</th><th>Action</th><th>Requests</th><th>IPs</th></tr></thead>
				<tbody>
				<?php foreach ( $totals as $row ) : ?>
					<tr>
						<td><code><?php echo esc_html( $row->rule ); ?></code></td>
						<td><?php echo esc_html( $row->action ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) $row->hits ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) $row->ips ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:16px">
				<?php self::small_table( 'Top IPs', $top_ips ); ?>
				<?php self::small_table( 'Top paths', $top_paths ); ?>
			</div>
		<?php endif; ?>

		<?php self::render_ajax( $s ); ?>

		<h2>Repeat offenders (24h,<?php echo (int) $s['offender_min_hits']; ?>+ requests)</h2>
		<p>Candidates for the Cloudways server firewall. Copy the list and send it for approval.</p>
		<?php if ( empty( $offenders ) ) : ?>
			<p>None.</p>
		<?php else : ?>
			<textarea readonly rows="<?php echo (int) min( 12, count( $offenders ) + 1 ); ?>" style="width:100%;max-width:720px;font-family:monospace"><?php
			foreach ( $offenders as $o ) {
				echo esc_textarea( $o->ip . "\t" . (int) $o->total . "\t" . str_replace( ',', ', ', (string) $o->rules ) ) . "\n";
			}
			?></textarea>
		<?php endif; ?>

		<h2>Recent log</h2>
		<?php if ( empty( $recent ) ) : ?>
			<p>Empty.</p>
		<?php else : ?>
			<table class="widefat striped">
				<thead><tr><th>Time (UTC)</th><th>IP</th><th>Rule</th><th>Action</th><th>Hits</th><th>Path</th><th>User agent</th></tr></thead>
				<tbody>
				<?php foreach ( $recent as $r ) : ?>
					<tr>
						<td><?php echo esc_html( $r->ts ); ?></td>
						<td><?php echo esc_html( $r->ip ); ?></td>
						<td><code><?php echo esc_html( $r->rule ); ?></code></td>
						<td><?php echo esc_html( $r->action ); ?></td>
						<td><?php echo (int) $r->hits; ?></td>
						<td style="word-break:break-all"><?php echo esc_html( $r->path ); ?></td>
						<td style="word-break:break-all;color:#646970"><?php echo esc_html( $r->ua ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
	}

	private static function render_ajax( $s ) {
		$now = BlockerMD_Ajax::hour();
		BlockerMD_Ajax::rollup(); // Cheap; makes sure finished hours are folded in.
		$na24 = BlockerMD_Ajax::noaction_count( $now - 23, $now );
		$na7  = BlockerMD_Ajax::noaction_count( $now - 167, $now );
		?>
		<h2>admin-ajax</h2>
		<p>
			Empty requests (no action) answered early:
			<strong><?php echo esc_html( number_format_i18n( $na24 ) ); ?></strong> in 24h,
			<strong><?php echo esc_html( number_format_i18n( $na7 ) ); ?></strong> in 7 days
			<?php echo empty( $s['ajax_noaction'] ) ? '<span style="color:#996800">(turned off)</span>' : ''; ?>
			<br><span class="description">Rule <code>ajax_noaction</code>. Each one would otherwise boot WordPress and every plugin just to answer "0".</span>
		</p>
		<?php
		if ( empty( $s['ajax_log'] ) ) {
			echo '<p>Action counting is turned off in Settings.</p>';
			return;
		}
		$day  = BlockerMD_Ajax::last_hours( 24 );
		$week = BlockerMD_Ajax::last_hours( 168 );
		if ( ! $week ) {
			echo '<p>No admin-ajax requests with an action counted yet.</p>';
			return;
		}
		?>
		<h3>Top actions</h3>
		<table class="widefat striped">
			<thead><tr>
				<th>Action</th><th style="text-align:right">24h</th><th style="text-align:right">7d</th>
				<th style="text-align:right">GET</th><th style="text-align:right">POST</th>
				<th style="text-align:right">Logged in</th><th style="text-align:right">Crawler</th><th style="text-align:right">Other</th>
				<th style="text-align:right">4xx/5xx</th><th>Top IPs (24h)</th>
			</tr></thead>
			<tbody>
			<?php
			foreach ( array_slice( $week, 0, 50, true ) as $action => $w ) :
				$d = isset( $day[ $action ] ) ? $day[ $action ] : null;
				$r = $d ? $d : $w; // Splits show 24h when there is 24h data, else 7d.
				$ips = array();
				foreach ( array_slice( $d ? $d['ips'] : array(), 0, 3, true ) as $ip => $n ) {
					$ips[] = $ip . ' (' . (int) $n . ')';
				}
				?>
				<tr>
					<td><code><?php echo esc_html( $action ); ?></code></td>
					<td style="text-align:right"><?php echo esc_html( number_format_i18n( $d ? $d['total'] : 0 ) ); ?></td>
					<td style="text-align:right"><?php echo esc_html( number_format_i18n( $w['total'] ) ); ?></td>
					<td style="text-align:right"><?php echo (int) $r['m:GET']; ?></td>
					<td style="text-align:right"><?php echo (int) $r['m:POST']; ?></td>
					<td style="text-align:right"><?php echo (int) $r['c:user']; ?></td>
					<td style="text-align:right"><?php echo (int) $r['c:bot']; ?></td>
					<td style="text-align:right"><?php echo (int) $r['c:other']; ?></td>
					<td style="text-align:right"><?php echo (int) ( $r['s:4xx'] + $r['s:5xx'] ); ?></td>
					<td style="color:#646970;font-size:12px"><?php echo esc_html( implode( ', ', $ips ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="description">Method, client and status columns show the last 24h (7 days if the action had no requests in 24h). "Logged in" means a WordPress login cookie was sent. Up to 200 action names are tracked; the rest count as <code>other</code>. IP lists are approximate.</p>
		<?php
	}

	private static function small_table( $title, $rows ) {
		?>
		<div style="flex:1;min-width:280px;max-width:480px">
			<h3><?php echo esc_html( $title ); ?></h3>
			<table class="widefat striped">
				<tbody>
				<?php foreach ( (array) $rows as $row ) : ?>
					<tr><td style="word-break:break-all"><?php echo esc_html( $row->label ); ?></td><td style="text-align:right"><?php echo esc_html( number_format_i18n( (int) $row->hits ) ); ?></td></tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	private static function render_settings( $s ) {
		$num = function ( $key, $label, $help = '' ) use ( $s ) {
			printf(
				'<tr><th scope="row"><label for="bmd-%1$s">%2$s</label></th><td><input type="number" class="small-text" id="bmd-%1$s" name="blockermd[%1$s]" value="%3$d">%4$s</td></tr>',
				esc_attr( $key ),
				esc_html( $label ),
				(int) $s[ $key ],
				$help ? ' <span class="description">' . esc_html( $help ) . '</span>' : ''
			);
		};
		$area = function ( $key, $label, $help = '' ) use ( $s ) {
			printf(
				'<tr><th scope="row"><label for="bmd-%1$s">%2$s</label></th><td><textarea class="large-text code" rows="6" id="bmd-%1$s" name="blockermd[%1$s]">%3$s</textarea>%4$s</td></tr>',
				esc_attr( $key ),
				esc_html( $label ),
				esc_textarea( $s[ $key ] ),
				$help ? '<p class="description">' . esc_html( $help ) . '</p>' : ''
			);
		};
		$check = function ( $key, $label ) use ( $s ) {
			printf(
				'<tr><th scope="row">%2$s</th><td><label><input type="checkbox" name="blockermd[%1$s]" value="1" %3$s> On</label></td></tr>',
				esc_attr( $key ),
				esc_html( $label ),
				checked( ! empty( $s[ $key ] ), true, false )
			);
		};
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="blockermd_save">
			<?php wp_nonce_field( 'blockermd_save' ); ?>

			<h2>General</h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">Mode</th>
					<td>
						<label><input type="radio" name="blockermd[mode]" value="log" <?php checked( $s['mode'], 'log' ); ?>> Log only</label><br>
						<label><input type="radio" name="blockermd[mode]" value="block" <?php checked( $s['mode'], 'block' ); ?>> Blocking</label>
					</td>
				</tr>
				<?php $area( 'allow_ips', 'Allow list (IPs / CIDR)', 'Never blocked or counted. One per line. For fixed IPs such as an office or uptime monitor. Admins with changing IPs are covered by the setting below.' ); ?>
				<?php $check( 'trust_on_login', 'Trust admins automatically when they log in' ); ?>
				<?php $num( 'trust_days', 'Trust an admin login IP for (days)' ); ?>
				<tr>
					<th scope="row">Trusted right now</th>
					<td>
						<?php
						$trusted = BlockerMD_Gate::trusted_ips();
						if ( ! $trusted ) {
							echo '<span class="description">None yet. Your IP is added the next time you log in as an administrator.</span>';
						} else {
							echo '<ul style="margin:0">';
							foreach ( $trusted as $tip => $until ) {
								echo '<li><code>' . esc_html( $tip ) . '</code> <span class="description">until ' . esc_html( wp_date( get_option( 'date_format' ), (int) $until ) ) . '</span></li>';
							}
							echo '</ul>';
						}
						?>
					</td>
				</tr>
				<?php $check( 'hide_ocp_widget', 'Hide Object Cache / Redis dashboard widgets' ); ?>
				<?php $check( 'admin_badge', 'Status badge in the admin bar (admins only)' ); ?>
			</table>

			<h2>Admin cleanup</h2>
			<p>Stops idle wp-admin tabs from loading the server. These only change wp-admin; they never block anything.</p>
			<table class="form-table" role="presentation">
				<?php $check( 'dash_remove_all', 'Remove all dashboard widgets and the Welcome panel (every user)' ); ?>
				<?php $area( 'dash_keep_widgets', 'Widgets to keep (IDs)', 'One widget ID per line, e.g. dashboard_activity. Leave empty to remove them all.' ); ?>
				<?php $check( 'heartbeat_control', 'Heartbeat: off on the Dashboard, every 120 s elsewhere in wp-admin, default in the post/page editor' ); ?>
				<?php $check( 'wc_admin_trim', 'WooCommerce: turn off marketing, inbox/remote notifications and marketplace suggestions' ); ?>
				<tr><th></th><td><p class="description">Orders, payments and Analytics are not touched. Test once on a store (place a test order, open Analytics) before turning this on everywhere.</p></td></tr>
			</table>

			<h2>admin-ajax</h2>
			<p>Both run in Log only and Blocking modes.</p>
			<table class="form-table" role="presentation">
				<?php $check( 'ajax_noaction', 'Answer empty admin-ajax requests (no action) before WordPress loads' ); ?>
				<tr><th></th><td><p class="description">Sends the same reply WordPress would (400, body "0"), without booting WordPress and every plugin. Turn off only if something breaks.</p></td></tr>
				<?php $check( 'ajax_log', 'Count admin-ajax requests by action (Activity tab)' ); ?>
			</table>

			<h2>Scanner probes</h2>
			<table class="form-table" role="presentation">
				<?php $area( 'probe_paths', 'Probe paths', 'Matched against whole path segments, anywhere in the path. One per line; lines starting with # are ignored.' ); ?>
			</table>

			<h2>Behaviour score</h2>
			<p>Each client earns points for suspicious requests; reaching the threshold inside the window bans it.</p>
			<table class="form-table" role="presentation">
				<?php $num( 'score_threshold', 'Ban threshold' ); ?>
				<?php $num( 'score_window', 'Window (seconds)' ); ?>
				<?php $num( 'probe_points', 'Points per probe' ); ?>
				<?php $num( 'not_found_points', 'Points per 404', 'Logged-in users are never scored.' ); ?>
				<?php $num( 'odd_query_points', 'Points per random cache-buster query' ); ?>
				<?php $num( 'ban_minutes', 'Ban length (minutes)' ); ?>
			</table>

			<h2>Login protection</h2>
			<table class="form-table" role="presentation">
				<?php $num( 'login_max_failures', 'Failed logins before lockout' ); ?>
				<?php $num( 'login_failure_window', 'Failure window (seconds)' ); ?>
				<?php $num( 'login_max_posts', 'Max login/XML-RPC POSTs per window' ); ?>
				<?php $num( 'login_post_window', 'POST window (seconds)' ); ?>
				<?php $num( 'login_lockout_minutes', 'Lockout length (minutes)' ); ?>
			</table>

			<h2>Crawlers</h2>
			<table class="form-table" role="presentation">
				<?php $area( 'bot_block_list', 'Always block (user-agent contains)', 'One per line, e.g. Baiduspider on US-only sites.' ); ?>
				<?php $area( 'bot_limit_list', 'Rate-limit (user-agent contains)', 'One per line. Each bot gets its own per-minute allowance across all of its IPs.' ); ?>
				<?php $num( 'bot_limit_per_minute', 'Requests per minute per bot' ); ?>
				<?php $check( 'block_bot_oembed', 'Block bots on oEmbed endpoints' ); ?>
				<?php $check( 'block_user_enum', 'Block user enumeration (/wp-json/wp/v2/users, ?author=N) for visitors who are not logged in' ); ?>
			</table>

			<h2>Hub reporting</h2>
			<p>Sends an hourly summary (counts, top IPs and paths, mode, version) to the BlockerMD hub. Each site signs its reports with its own key; nothing has to be copied between sites.</p>
			<table class="form-table" role="presentation">
				<?php $check( 'report_to_hub', 'Report to the hub' ); ?>
				<tr>
					<th scope="row"><label for="bmd-hub_url">Hub address</label></th>
					<td><input type="url" class="regular-text code" id="bmd-hub_url" name="blockermd[hub_url]" value="<?php echo esc_attr( $s['hub_url'] ); ?>" placeholder="<?php echo esc_attr( defined( 'BLOCKERMD_HUB_URL' ) ? BLOCKERMD_HUB_URL : BLOCKERMD_DEFAULT_HUB ); ?>">
					<p class="description">Leave empty to use the default shown.</p></td>
				</tr>
				<tr>
					<th scope="row">Status</th>
					<td><?php self::hub_status(); ?></td>
				</tr>
				<?php $check( 'hub_enabled', 'This site is the hub' ); ?>
			</table>

			<h2>Housekeeping</h2>
			<table class="form-table" role="presentation">
				<?php $num( 'log_retention_days', 'Keep log (days)' ); ?>
				<?php $num( 'offender_min_hits', 'Repeat-offender threshold (requests in 24h)' ); ?>
				<tr>
					<th scope="row"><label for="bmd-update_repo">Update source (GitHub owner/repo)</label></th>
					<td><input type="text" class="regular-text code" id="bmd-update_repo" name="blockermd[update_repo]" value="<?php echo esc_attr( $s['update_repo'] ); ?>" placeholder="MechaDigital/blockermd">
					<p class="description">New releases show up as normal plugin updates. Can also be set with <code>define( 'BLOCKERMD_UPDATE_REPO', 'owner/repo' );</code> in wp-config.php. Left blank, it uses MechaDigital/blockermd.</p></td>
				</tr>
				<?php $check( 'auto_update', 'Install new BlockerMD releases automatically' ); ?>
			</table>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<?php if ( '' !== BlockerMD_Reporter::hub_url() && ! BlockerMD_Reporter::hub_is_self() ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="blockermd_report_now">
				<?php wp_nonce_field( 'blockermd_report_now' ); ?>
				<?php submit_button( 'Send report to hub now', 'secondary', 'submit', false ); ?>
			</form>
		<?php endif; ?>
		<?php
	}

	private static function hub_status() {
		$hub = BlockerMD_Reporter::hub_url();
		if ( '' === $hub ) {
			echo 'Reporting is off.';
			return;
		}
		if ( BlockerMD_Reporter::hub_is_self() ) {
			echo 'This site is the hub address, so it does not report to itself.';
			return;
		}
		$id     = BlockerMD_Reporter::identity();
		$status = isset( $id['status'] ) ? $id['status'] : '';
		$labels = array(
			''         => 'Not connected yet (first report goes out within the hour).',
			'pending'  => 'Waiting for approval on the hub.',
			'approved' => 'Connected.',
			'rejected' => 'Rejected by the hub.',
		);
		echo '<strong>' . esc_html( isset( $labels[ $status ] ) ? $labels[ $status ] : $status ) . '</strong>';
		if ( ! empty( $id['last_ok'] ) ) {
			echo '<br>Last report: ' . esc_html( human_time_diff( (int) $id['last_ok'], time() ) ) . ' ago';
		}
		if ( ! empty( $id['last_error'] ) ) {
			echo '<br><span style="color:#b32d2e">' . esc_html( $id['last_error'] ) . '</span>';
		}
		if ( ! empty( $id['site_id'] ) ) {
			echo '<br><span style="color:#646970">Site ID: <code>' . esc_html( $id['site_id'] ) . '</code></span>';
		}
	}
}

/**
 * is_plugin_active() lives in wp-admin/includes/plugin.php, which is not
 * always loaded on admin_notices for every screen.
 */
function blockermd_plugin_active( $plugin ) {
	$active = (array) get_option( 'active_plugins', array() );
	return in_array( $plugin, $active, true );
}
