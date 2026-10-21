# php2shell-patch

Interim hardening script for the **PHP2Shell** PHP vulnerabilities
(CVE-2026-109618 / CVE-2026-109619), for people who run several Linux web servers.

> **This is a stop-gap, not a fix.** It switches off two PHP session features to
> reduce exposure until you can install the fixed PHP release from php.net or
> your vendor. PHP versions with no upstream fix (end-of-life) only get this.
> Provided as-is, no warranty. Test on one low-risk server first.

## What it does

For one server at a time (over SSH), it adds a single new file,
`zz-php2shell.ini`, to every PHP configuration scan directory it finds:

```ini
session.upload_progress.enabled = Off
session.use_strict_mode = On
```

Then it reloads the running PHP services **gracefully** (no hard restart), waits
for each one to come back, and compares service and HTTP state before and after.

It never edits an existing `php.ini`, and never touches files in customers'
home directories.

## Usage

```bash
./php2shell-patch.sh <host|ip> --dry-run     # always start here: shows what would be written
./php2shell-patch.sh <host|ip>               # write + graceful reload + health check
./php2shell-patch.sh <host|ip> --rollback    # remove the drop-ins again
```

| Option | Meaning |
|---|---|
| `--dry-run` | Show what would be written. Changes nothing, restarts nothing. |
| `--no-restart` | Write the files only; reload things yourself later. |
| `--hard-restart` | `restart` instead of `reload` (brief downtime). |
| `--restart-lsws` | Also restart LiteSpeed (off by default, see below). |
| `--force` | Re-write and re-reload even if already applied. |
| `--rollback` | Remove the drop-ins this script wrote and reload. |
| `--user NAME` | SSH user (default `root`). |

Environment variables:

* `SSH_OPTS` — extra ssh options, e.g. for very old servers:
  `SSH_OPTS="-o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa"`
* `SUDO=1` — run the remote part with `sudo -n` (log in as a non-root user with passwordless sudo).
* `LOGDIR` — where per-run logs go (default `./php2shell-logs`).

You need working key-based SSH to the target (the script uses `BatchMode`,
so it fails instead of asking for a password).

## What it detects

cPanel / EasyApache, CloudLinux alt-php, DirectAdmin CustomBuild, Plesk,
Debian / Ubuntu (including old `/etc/php5`), RHEL / Alma / Rocky / CentOS,
Remi / SCL, LiteSpeed `lsphp`, and generic source builds. If a PHP binary points
at a configuration scan directory that does not exist yet (PHP silently ignores a
missing one), the script creates it, but only under a known PHP prefix.

## Reading the output

| Line | Meaning |
|---|---|
| `wrote ...` / `already applied ...` | Drop-in written / already identical. |
| `STATE ALREADY-APPLIED` | Nothing to do on this host; nothing was restarted. |
| `BACK-UP <service>` / `NOT-BACK <service>` | The reloaded service is active again / is not (after 30 s). |
| `BIN ... upload_progress=Off strict_mode=On` | What each PHP binary now reports. |
| `*** UNPROTECTED ... ***` | That binary still has the feature on. Needs attention. |
| `WARN-no-strict-mode-before-5.5.2` | That PHP is too old to have the setting. |
| `HEALTH OK` / `HEALTH PROBLEM:...` | Service set, PHP-FPM master count and HTTP status before vs after. |
| `NO_PHP_INI_DIR_FOUND` | No PHP scan directory found; nothing was changed. |

## Limitations — please read

* **PHP too old:** `upload_progress` needs PHP 5.4+, `use_strict_mode` needs 5.5.2+.
  Older builds are flagged; this script cannot protect them.
* **No scan directory:** a PHP built with no scan directory
  (`Scan for additional .ini files in: (none)`) cannot take a drop-in. It would need
  `php.ini` edited, which this script deliberately does not do.
* **Per-site overrides:** a site's own `.user.ini`, `.htaccess`, or Plesk's per-domain
  *PHP Settings* can switch these values back on. They are not checked.
* **Login loops:** `use_strict_mode` can break legacy apps that invent their own
  session IDs. Per-site fix: `session.use_strict_mode = 0` in that site's `.user.ini`.
  Test a real login after rolling out.
* **LiteSpeed:** `lsphp` workers keep the old settings until LiteSpeed restarts or the
  workers are replaced. The script reports this and does **not** restart LiteSpeed unless
  you pass `--restart-lsws` (a restart re-checks the licence, which matters on
  IP-locked licences).
* **Pools that can't be reloaded:** if a PHP-FPM pool's own configuration is broken, a
  reload is refused and that pool keeps its old settings. The script reports
  `RELOAD-FAILED`; do **not** hard-restart such a pool without fixing its config first.
* **Not a patch:** upgrade PHP as soon as a fixed release is available for your branch.

## Suggested rollout

1. `--dry-run` on one server and read the output.
2. Apply to one low-risk server, check `HEALTH OK`, and test a real page and login.
3. Roll out in small batches. Keep the logs in `LOGDIR`.
4. Re-run with `--dry-run` later: `STATE ALREADY-APPLIED` confirms a host is done.

## Rolling back

`./php2shell-patch.sh <host|ip> --rollback` deletes only the `zz-php2shell.ini` files
this script wrote and reloads the services.
