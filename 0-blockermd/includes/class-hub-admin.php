<?php
/**
 * Hub dashboard: one wp-admin page listing every reporting site.
 * Read-only toward client sites; the only actions are approve / reject /
 * remove, which change the hub's own list.
 */

defined( 'ABSPATH' ) || exit;

class BlockerMD_Hub_Admin {

	const SLUG = 'blockermd-hub';

	public static function register_hooks() {
		if ( ! is_admin() || ! BlockerMD_Hub::enabled() ) {
			return;
		}
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_blockermd_hub_site', array( __CLASS__, 'handle_site_action' ) );
	}

	public static function menu() {
		add_menu_page( 'BlockerMD Hub', 'BlockerMD Hub', 'manage_options', self::SLUG, array( __CLASS__, 'render' ), 'dashicons-shield', 3 );
	}

	public static function handle_site_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Not allowed.' );
		}
		check_admin_referer( 'blockermd_hub_site' );
		$site_id = isset( $_POST['site_id'] ) ? sanitize_text_field( wp_unslash( $_POST['site_id'] ) ) : '';
		$op      = isset( $_POST['op'] ) ? sanitize_key( $_POST['op'] ) : '';
		if ( $site_id ) {
			if ( 'approve' === $op ) {
				BlockerMD_Hub::set_status( $site_id, 'approved' );
			} elseif ( 'reject' === $op ) {
				BlockerMD_Hub::set_status( $site_id, 'rejected' );
			} elseif ( 'remove' === $op ) {
				BlockerMD_Hub::remove_site( $site_id );
			}
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SLUG . '&done=' . rawurlencode( $op ) ) );
		exit;
	}

	private static function button( $site_id, $op, $label, $class = 'button', $confirm = '' ) {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" <?php echo $confirm ? 'onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ')"' : ''; ?>>
			<input type="hidden" name="action" value="blockermd_hub_site">
			<input type="hidden" name="site_id" value="<?php echo esc_attr( $site_id ); ?>">
			<input type="hidden" name="op" value="<?php echo esc_attr( $op ); ?>">
			<?php wp_nonce_field( 'blockermd_hub_site' ); ?>
			<button type="submit" class="<?php echo esc_attr( $class ); ?>"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	private static function ago( $ts ) {
		$ts = (int) $ts;
		return $ts ? human_time_diff( $ts, time() ) . ' ago' : 'never';
	}

	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$sites    = (array) BlockerMD_Hub::sites();
		$pending  = array_filter( $sites, function ( $s ) { return 'pending' === $s->status; } );
		$approved = array_filter( $sites, function ( $s ) { return 'approved' === $s->status; } );
		$rejected = array_filter( $sites, function ( $s ) { return 'rejected' === $s->status; } );
		$names    = array();
		foreach ( $sites as $s ) {
			$names[ $s->site_uuid ] = $s->name ? $s->name : wp_parse_url( $s->home_url, PHP_URL_HOST );
		}

		$total_24 = 0;
		$total_7d = 0;
		$stale    = 0;
		$logonly  = 0;
		foreach ( $approved as $s ) {
			$total_24 += (int) $s->blocks_24h;
			$total_7d += (int) $s->blocks_7d;
			if ( time() - (int) $s->last_report > 3 * HOUR_IN_SECONDS ) {
				$stale++;
			}
			if ( 'block' !== $s->mode ) {
				$logonly++;
			}
		}
		$rules = BlockerMD_Hub::rule_totals( 24 );
		$ips   = BlockerMD_Hub::cross_site_ips( 24, 50 );
		?>
		<div class="wrap">
			<h1>BlockerMD Hub</h1>
			<p style="color:#646970">Hourly summaries from every site running BlockerMD. Nothing here can change a client site.</p>

			<div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0">
				<?php
				self::tile( 'Sites reporting', count( $approved ) - $stale . ' / ' . count( $approved ) );
				self::tile( 'Blocked, 24h', number_format_i18n( $total_24 ) );
				self::tile( 'Blocked, 7 days', number_format_i18n( $total_7d ) );
				self::tile( 'Still in log-only', (string) $logonly );
				self::tile( 'Waiting for approval', (string) count( $pending ), count( $pending ) ? '#996800' : '' );
				?>
			</div>

			<?php if ( $pending ) : ?>
				<h2>Waiting for approval</h2>
				<p>Approve only sites you recognise. A site you don't recognise can be rejected; it can't do anything either way.</p>
				<table class="widefat striped" style="max-width:1000px">
					<thead><tr><th>Site</th><th>URL</th><th>Asked</th><th>From IP</th><th>Version</th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $pending as $s ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $s->name ); ?></strong></td>
							<td><?php echo esc_html( $s->home_url ); ?></td>
							<td><?php echo esc_html( self::ago( $s->created ) ); ?></td>
							<td><?php echo esc_html( $s->last_ip ); ?></td>
							<td><?php echo esc_html( $s->version ); ?></td>
							<td style="white-space:nowrap">
								<?php self::button( $s->site_uuid, 'approve', 'Approve', 'button button-primary' ); ?>
								<?php self::button( $s->site_uuid, 'reject', 'Reject' ); ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2>Sites</h2>
			<?php if ( ! $approved ) : ?>
				<p>No approved sites yet. Sites appear under "Waiting for approval" within an hour of installing BlockerMD.</p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th>Site</th><th>Mode</th><th>Version</th><th>Last report</th><th style="text-align:right">Blocked 24h</th><th style="text-align:right">Blocked 7d</th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $approved as $s ) : ?>
						<?php $late = time() - (int) $s->last_report > 3 * HOUR_IN_SECONDS; ?>
						<tr>
							<td><strong><?php echo esc_html( $s->name ); ?></strong><br><span style="color:#646970"><?php echo esc_html( $s->home_url ); ?></span></td>
							<td><?php echo 'block' === $s->mode ? '<span style="color:#008a20">Blocking</span>' : '<span style="color:#996800">Log only</span>'; ?></td>
							<td><?php echo esc_html( $s->version ); ?><?php echo version_compare( (string) $s->version, BLOCKERMD_VERSION, '<' ) ? ' <span style="color:#996800">(behind)</span>' : ''; ?></td>
							<td style="<?php echo $late ? 'color:#b32d2e;font-weight:600' : ''; ?>"><?php echo esc_html( self::ago( $s->last_report ) ); ?></td>
							<td style="text-align:right"><?php echo esc_html( number_format_i18n( (int) $s->blocks_24h ) ); ?></td>
							<td style="text-align:right"><?php echo esc_html( number_format_i18n( (int) $s->blocks_7d ) ); ?></td>
							<td><?php self::button( $s->site_uuid, 'remove', 'Remove', 'button-link', 'Remove this site and its history? It will ask to join again on its next report.' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<div style="display:flex;gap:24px;flex-wrap:wrap;margin-top:8px">
				<div style="flex:1;min-width:300px;max-width:520px">
					<h2>Rules, all sites, 24h</h2>
					<?php if ( ! $rules ) : ?>
						<p>Nothing yet.</p>
					<?php else : ?>
						<table class="widefat striped">
							<thead><tr><th>Rule</th><th>Action</th><th style="text-align:right">Requests</th></tr></thead>
							<tbody>
							<?php foreach ( $rules as $r ) : ?>
								<tr><td><code><?php echo esc_html( $r['rule'] ); ?></code></td><td><?php echo esc_html( $r['action'] ); ?></td><td style="text-align:right"><?php echo esc_html( number_format_i18n( $r['hits'] ) ); ?></td></tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>

				<div style="flex:1;min-width:300px;max-width:640px">
					<h2>Offenders across sites, 24h</h2>
					<?php if ( ! $ips ) : ?>
						<p>Nothing yet.</p>
					<?php else : ?>
						<table class="widefat striped">
							<thead><tr><th>IP</th><th style="text-align:right">Sites</th><th style="text-align:right">Requests</th><th>Where</th></tr></thead>
							<tbody>
							<?php foreach ( $ips as $row ) : ?>
								<?php
								$where = array();
								foreach ( array_slice( explode( ',', (string) $row->site_ids ), 0, 5 ) as $sid ) {
									$where[] = isset( $names[ $sid ] ) ? $names[ $sid ] : '?';
								}
								?>
								<tr>
									<td><code><?php echo esc_html( $row->ip ); ?></code></td>
									<td style="text-align:right;<?php echo (int) $row->sites > 1 ? 'font-weight:600' : ''; ?>"><?php echo (int) $row->sites; ?></td>
									<td style="text-align:right"><?php echo esc_html( number_format_i18n( (int) $row->hits ) ); ?></td>
									<td style="color:#646970"><?php echo esc_html( implode( ', ', $where ) . ( (int) $row->sites > 5 ? ', …' : '' ) ); ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<p class="description">IPs seen on several sites are the best candidates for the Cloudways server firewall.</p>
					<?php endif; ?>
				</div>
			</div>

			<?php
			$ajax = BlockerMD_Hub::ajax_actions( 24 );
			?>
			<h2>admin-ajax actions, 24h</h2>
			<?php if ( ! $ajax['all'] ) : ?>
				<p>Nothing yet. Sites send this from v0.3.0 on.</p>
			<?php else : ?>
				<div style="display:flex;gap:24px;flex-wrap:wrap">
					<div style="flex:1;min-width:300px;max-width:760px">
						<h3>All sites</h3>
						<table class="widefat striped">
							<thead><tr><th>Action</th><th style="text-align:right">Requests</th><th style="text-align:right">Sites</th><th style="text-align:right">GET</th><th style="text-align:right">POST</th><th style="text-align:right">Logged in</th><th style="text-align:right">Crawler</th><th style="text-align:right">Other</th></tr></thead>
							<tbody>
							<?php foreach ( array_slice( $ajax['all'], 0, 30, true ) as $action => $a ) : ?>
								<tr>
									<td><code><?php echo esc_html( $action ); ?></code></td>
									<td style="text-align:right"><?php echo esc_html( number_format_i18n( $a['hits'] ) ); ?></td>
									<td style="text-align:right"><?php echo (int) $a['sites']; ?></td>
									<td style="text-align:right"><?php echo (int) $a['get']; ?></td>
									<td style="text-align:right"><?php echo (int) $a['post']; ?></td>
									<td style="text-align:right"><?php echo (int) $a['user']; ?></td>
									<td style="text-align:right"><?php echo (int) $a['bot']; ?></td>
									<td style="text-align:right"><?php echo (int) $a['other']; ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
					<div style="flex:1;min-width:300px;max-width:520px">
						<h3>Per site (top 5)</h3>
						<table class="widefat striped">
							<thead><tr><th>Site</th><th>Actions</th></tr></thead>
							<tbody>
							<?php foreach ( $ajax['sites'] as $sid => $list ) : ?>
								<?php
								$bits = array();
								foreach ( array_slice( $list, 0, 5, true ) as $action => $n ) {
									$bits[] = $action . ' ' . number_format_i18n( $n );
								}
								?>
								<tr>
									<td><?php echo esc_html( isset( $names[ $sid ] ) ? $names[ $sid ] : $sid ); ?></td>
									<td style="font-family:monospace;font-size:12px"><?php echo esc_html( implode( ' · ', $bits ) ); ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				</div>
			<?php endif; ?>

			<?php if ( $rejected ) : ?>
				<h2>Rejected</h2>
				<table class="widefat striped" style="max-width:1000px">
					<tbody>
					<?php foreach ( $rejected as $s ) : ?>
						<tr>
							<td><?php echo esc_html( $s->name ); ?></td>
							<td><?php echo esc_html( $s->home_url ); ?></td>
							<td><?php echo esc_html( $s->last_ip ); ?></td>
							<td style="white-space:nowrap"><?php self::button( $s->site_uuid, 'approve', 'Approve after all' ); ?> <?php self::button( $s->site_uuid, 'remove', 'Forget', 'button-link' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function tile( $label, $value, $color = '' ) {
		?>
		<div style="background:#fff;border:1px solid #dcdcde;border-radius:4px;padding:12px 16px;min-width:150px">
			<div style="font-size:12px;color:#646970"><?php echo esc_html( $label ); ?></div>
			<div style="font-size:22px;font-weight:600;<?php echo $color ? 'color:' . esc_attr( $color ) : ''; ?>"><?php echo esc_html( $value ); ?></div>
		</div>
		<?php
	}
}
