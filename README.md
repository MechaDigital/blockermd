# BlockerMD

Lightweight WordPress security and performance plugin: scanner-probe blocking, behavior scoring, login protection, crawler controls, admin-ajax shortcuts, admin cleanup, and an optional hub that collects signed stats from every site.

Starts in **Log only** mode. Settings → BlockerMD.

## Install
Download `blockermd.zip` from the latest release and upload it in Plugins → Add New → Upload. The folder is `0-blockermd` so it loads before other plugins.

## Updates
In Settings → BlockerMD → Settings, set **Update source** to this repo (`owner/blockermd`), or add to wp-config.php:

```php
define( 'BLOCKERMD_UPDATE_REPO', 'owner/blockermd' );
```

Updates then show in wp-admin like any other plugin. Since v0.4.1, sites install new releases automatically (WordPress's twice-daily update check); turn this off per site under Settings → Housekeeping.

## Releasing
1. Bump `Version:` and `BLOCKERMD_VERSION` in `0-blockermd/blockermd.php` and commit.
2. On GitHub: Releases → Draft a new release → new tag `vX.Y.Z` → Publish (or push the tag from git).
3. The Release workflow checks the tag matches the version, lints the PHP, builds `blockermd.zip` and attaches it to the release.

## License
GPL-2.0-or-later.
