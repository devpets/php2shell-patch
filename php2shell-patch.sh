#!/bin/bash
# =============================================================================
# php2shell-patch.sh — interim PHP hardening for the "PHP2Shell" vulnerabilities
#                      (CVE-2026-109618 / CVE-2026-109619)
#
# WHAT THIS IS
#   A stop-gap, NOT a fix. It disables two PHP session features that reduce the
#   exposed attack surface until you can install the fixed PHP release:
#       session.upload_progress.enabled = Off
#       session.use_strict_mode         = On
#   The real remedy is upgrading PHP to the patched version from php.net / your
#   vendor. PHP versions without an upstream fix (end-of-life) only get this.
#
# HOW IT WORKS
#   Run it from an admin machine. It SSHes to ONE server, finds every PHP
#   configuration "scan directory" (php.d / conf.d) that exists there, and drops
#   a single new file `zz-php2shell.ini` into each. The "zz" prefix makes it load
#   last. It never edits an existing php.ini or any file in a customer's home.
#   Then it reloads the running PHP services GRACEFULLY, waits for them to come
#   back, and compares service/HTTP state before vs after.
#
# USAGE
#   php2shell-patch.sh <host|ip> [options]
#
#   --dry-run        Show what would be written. Changes nothing, restarts nothing.
#   --no-restart     Write the files only; do not reload anything yourself.
#   --hard-restart   Use `restart` instead of a graceful `reload` (brief downtime).
#   --restart-lsws   Also hard-restart the LiteSpeed server itself (re-checks its
#                    licence). Rarely needed: lsphp is recycled automatically.
#   --force          Re-write and re-reload even if everything is already applied.
#   --rollback       Remove the drop-ins this script wrote and reload.
#   --user NAME      SSH user (default: root).
#
# ENVIRONMENT
#   SSH_OPTS   Extra ssh options, e.g. for very old servers:
#                SSH_OPTS="-o KexAlgorithms=+diffie-hellman-group1-sha1 \
#                          -o HostKeyAlgorithms=+ssh-rsa"
#   SUDO=1     Run the remote part through `sudo -n` (use with --user for hosts
#              where you log in as a non-root user with passwordless sudo).
#   LOGDIR     Where per-run logs are written (default: ./php2shell-logs).
#
# EXIT STATUS
#   0  all good (or already applied / dry run).
#   1  a human must look: an unprotected PHP binary, HEALTH PROBLEM, or a failed
#      reload / lsphp recycle.  2  no PHP scan directory found (nothing changed).
#   Other non-zero values come from ssh itself (e.g. 255 = connection failed).
#
# PLATFORMS DETECTED (drop-in locations)
#   cPanel/EasyApache, CloudLinux alt-php, DirectAdmin CustomBuild, Plesk,
#   Debian/Ubuntu (/etc/php/*/*/conf.d and legacy /etc/php5), RHEL/Alma/Rocky/
#   CentOS (/etc/php.d), Remi/SCL, LiteSpeed lsphp, generic source builds.
#   If a PHP binary's configured scan dir does not exist yet (PHP silently
#   ignores it), the script creates it — but only under a known PHP prefix.
#
# LIMITATIONS — read before use
#   * Needs PHP >= 5.4 for upload_progress and >= 5.5.2 for strict mode. Older
#     builds are flagged in the output; this script cannot protect them.
#   * Builds with NO scan directory ("Scan for additional .ini files: (none)")
#     cannot take a drop-in; they would need php.ini edited, which this script
#     deliberately never does.
#   * A site can override these values with its own .user.ini / .htaccess /
#     Plesk per-domain "PHP Settings". Those are not touched or checked.
#   * session.use_strict_mode can cause login loops in legacy apps that invent
#     their own session IDs. Fix per site: session.use_strict_mode=0 in its
#     .user.ini. Test a real login after rolling out.
#   * LiteSpeed: lsphp workers are recycled by touching
#     <lsws>/admin/tmp/.lsphp_restart.txt (no server restart, no licence
#     re-check). LiteSpeed notices the file within seconds; workers busy with a
#     request should finish it first. Confirm with the BIN lines / a live check.
#
# NOTES
#   * Idempotent: re-running on an already-patched host prints
#     "STATE ALREADY-APPLIED" and changes nothing.
#   * ALWAYS run --dry-run first, then try one low-risk host before the fleet.
#   * Provided as-is, with no warranty. You are responsible for testing it in
#     your environment.
# =============================================================================
set -u -o pipefail

# --- argument parsing --------------------------------------------------------
HOST="${1:-}"; [ -n "$HOST" ] || { sed -n '2,3p;22,40p' "$0"; exit 1; }; shift
DRY=0; NORESTART=0; LSWS=0; ROLLBACK=0; HARD=0; FORCE=0; USER_=root
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1;; --no-restart) NORESTART=1;; --restart-lsws) LSWS=1;; --rollback) ROLLBACK=1;; --hard-restart) HARD=1;; --force) FORCE=1;;
    --user) shift; USER_="$1";; *) echo "unknown option $1"; exit 1;;
  esac; shift
done

# --- local logging -----------------------------------------------------------
LOGDIR="${LOGDIR:-./php2shell-logs}"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/patch-$HOST-$(date +%Y%m%d-%H%M%S).log"

# --- run the remote part over ssh ---------------------------------------------
# Everything between <<'REMOTE' and REMOTE is executed on the target server by
# `bash -s`. Options are passed as environment variables. BatchMode makes ssh
# fail instead of prompting, so the script never hangs on a password.
# shellcheck disable=SC2086
ssh -o BatchMode=yes -o ConnectTimeout=15 ${SSH_OPTS:-} "$USER_@$HOST" "${SUDO:+sudo -n }env DRY=$DRY NORESTART=$NORESTART LSWS=$LSWS ROLLBACK=$ROLLBACK HARD=$HARD FORCE=$FORCE bash -s" <<'REMOTE' 2>&1 | tee "$LOG"
set -u
RC=0   # remote exit status: 1 = a human must look at this host

# The drop-in content. Compared byte-for-byte later to detect "already applied".
INI='; php2shell interim mitigation 2026-10-21 (CVE-2026-109618/109619) - keep after patching
session.upload_progress.enabled = Off
session.use_strict_mode = On'

# --- identify the host/platform ----------------------------------------------
h=$(hostname -f 2>/dev/null || hostname)
plat=bare
[ -d /usr/local/cpanel ] && plat=cpanel
[ -d /usr/local/directadmin ] && plat=directadmin
{ [ -d /usr/local/psa ] || [ -d /opt/psa ]; } && plat=plesk
[ -f /etc/cloudlinux-release ] && plat="$plat+cloudlinux"
[ -d /usr/local/lsws ] && plat="$plat+litespeed"
echo "HOST $h platform=$plat dry=$DRY norestart=$NORESTART restart_lsws=$LSWS rollback=$ROLLBACK hard=$HARD"

# --- "before" snapshot, compared with "after" in the health check at the end ---
svc_snapshot() { systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(.*php.*fpm.*|httpd|apache2|nginx|lsws|litespeed|lshttpd)\.service$' | sort; }
hcode() { curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1/ 2>/dev/null; }
nmasters() { ps -eo args | grep -c '[p]hp-fpm: master'; }
SVC_B=$(svc_snapshot); H_B=$(hcode); M_B=$(nmasters)
[ -f /etc/os-release ] && . /etc/os-release 2>/dev/null && echo "OS ${PRETTY_NAME:-unknown}"
[ -f /etc/redhat-release ] && cat /etc/redhat-release

# --- find every existing PHP scan directory ------------------------------------
DIRS=""
for d in /opt/cpanel/ea-php*/root/etc/php.d /opt/alt/php*/etc/php.d \
         /usr/local/php*/lib/php.conf.d \
         /opt/plesk/php/*/etc/php.d \
         /etc/php/*/*/conf.d /etc/php5/*/conf.d \
         /etc/php.d /etc/opt/remi/php*/php.d /etc/opt/rh/*/php.d \
         /usr/local/lsws/lsphp*/etc/php.d \
         /usr/local/etc/php/conf.d /usr/local/lib/php.conf.d; do
  [ -d "$d" ] && DIRS="$DIRS $d"
done

# Also honour each binary's configured scan dir even if it does not exist yet (PHP silently ignores a missing one).
# Only paths under a known PHP prefix are created, and only when the parent dir exists.
NEWDIRS=""
for b in /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /usr/local/php*/bin/php \
         /opt/plesk/php/*/bin/php /opt/remi/php*/root/usr/bin/php /usr/local/lsws/lsphp*/bin/php \
         /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php; do
  [ -x "$b" ] || continue
  sd=$("$b" --ini 2>/dev/null | sed -n 's/^Scan for additional .ini files in: *//p' | head -1)
  case "$sd" in ""|"(none)") continue;; esac
  if [ -d "$sd" ]; then case " $DIRS " in *" $sd "*) ;; *) DIRS="$DIRS $sd"; echo "NOTE extra scan dir from $b: $sd";; esac; continue; fi
  case " $DIRS $NEWDIRS " in *" $sd "*) continue;; esac
  case "$sd" in /usr/local/php*|/opt/cpanel/*|/opt/alt/*|/opt/plesk/*|/opt/remi/*|/etc/opt/remi/*|/etc/php*|/usr/local/lsws/*|/usr/local/lib/*|/usr/local/etc/php*) ;; *) echo "SKIP scan dir outside known prefixes: $sd ($b)"; continue;; esac
  [ -d "$(dirname "$sd")" ] || { echo "SKIP scan dir parent missing: $sd ($b)"; continue; }
  NEWDIRS="$NEWDIRS $sd"
done
DIRS="$DIRS $NEWDIRS"

# Nothing found: stop without changing anything (e.g. DB/NAS/Redis boxes, or a custom PHP prefix).
[ -n "$(echo $DIRS)" ] || { echo "RESULT NO_PHP_INI_DIR_FOUND - non-standard PHP prefix; check 'php --ini'. Nothing changed."; exit 2; }

# --- write (or remove, for --rollback) the drop-in in each directory -----------
ALREADY_ALL=1; [ "$ROLLBACK" = 1 ] && ALREADY_ALL=0; [ "${FORCE:-0}" = 1 ] && ALREADY_ALL=0; NDIRS=0
for d in $DIRS; do
  f="$d/zz-php2shell.ini"
  if [ "$ROLLBACK" = 1 ]; then
    if [ "$DRY" = 1 ]; then echo "WOULD REMOVE $f"; else rm -f "$f" && echo "removed $f"; fi
  else
    NDIRS=$((NDIRS+1))
    # already identical? then skip (idempotent)
    if [ -f "$f" ] && [ "$(cat "$f" 2>/dev/null)" = "$INI" ]; then echo "already applied $f"; continue; fi
    ALREADY_ALL=0
    miss=""; [ -d "$d" ] || miss=" (creating missing scan dir)"
    if [ "$DRY" = 1 ]; then echo "WOULD WRITE $f$miss"; else { [ -d "$d" ] || { mkdir -p "$d" && chmod 755 "$d"; }; } && printf '%s\n' "$INI" > "$f" && chmod 644 "$f" && echo "wrote $f$miss"; fi
  fi
done
[ "$ALREADY_ALL" = 1 ] && echo "STATE ALREADY-APPLIED (all $NDIRS drop-ins present and identical; nothing written, nothing restarted)"
[ "$DRY" = 1 ] && exit 0

# --- reload PHP services so running workers pick up the new settings -----------
# PHP reads ini files only when a process starts, so already-running workers keep
# the old values until reloaded. Default is a GRACEFUL reload (no dropped requests).
running() { ps -e -o comm= 2>/dev/null | grep -qx "$1"; }
have_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }
VERB=reload; [ "$HARD" = 1 ] && VERB=restart
RELOAD_FAIL=0
RELOADED=""        # every service we touched; checked again below
svc_do() {
  n="$1"; RELOADED="$RELOADED $n"
  if have_systemd; then systemctl $VERB "$n" >/dev/null 2>&1 && echo "${VERB}ed $n" || { echo "RELOAD-FAILED $n"; RELOAD_FAIL=1; }
  elif [ -x "/etc/init.d/$n" ]; then "/etc/init.d/$n" $VERB >/dev/null 2>&1 && echo "${VERB}ed $n (init.d)" || { echo "RELOAD-FAILED $n"; RELOAD_FAIL=1; }
  else service "$n" $VERB >/dev/null 2>&1 && echo "${VERB}ed $n (service)" || { echo "RELOAD-FAILED $n"; RELOAD_FAIL=1; }; fi
}
web_graceful() {   # Apache (also covers mod_php): graceful restart keeps in-flight requests
  w="$1"; RELOADED="$RELOADED $w"
  if [ "$HARD" = 1 ]; then svc_do "$w"; return; fi
  { apachectl graceful >/dev/null 2>&1 || svc_do "$w"; } && echo "graceful $w"
}
fpm_services() {   # only services that are RUNNING; never start a stopped/broken one
  if have_systemd; then
    systemctl list-units --type=service --state=active --no-legend '*php*fpm*' 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /\.service$/){sub(/\.service$/,"",$i); print $i; break}}'
  else
    for s in $(ls /etc/init.d 2>/dev/null | grep -E 'php.*fpm'); do service "$s" status >/dev/null 2>&1 && echo "$s"; done
  fi
}
if [ "$NORESTART" = 0 ] && [ "$ALREADY_ALL" = 0 ]; then
  for s in $(fpm_services); do svc_do "$s"; done
  running apache2 && web_graceful apache2
  running httpd   && web_graceful httpd
  if [ -d /usr/local/lsws ]; then
    # LiteSpeed-documented way to recycle every lsphp process without restarting the web server (no licence re-check)
    if touch /usr/local/lsws/admin/tmp/.lsphp_restart.txt 2>/dev/null; then echo "lsphp workers marked for restart (.lsphp_restart.txt)"; else echo "RELOAD-FAILED lsphp (could not touch .lsphp_restart.txt)"; RELOAD_FAIL=1; fi
    if [ "$LSWS" = 1 ]; then for s in lsws litespeed lshttpd; do { have_systemd && systemctl cat "$s" >/dev/null 2>&1; } || [ -x "/etc/init.d/$s" ] && { VERB=restart; svc_do "$s"; break; }; done; fi
  fi
  sleep 3
fi

# --- verify every reloaded service is active again (up to 30 s each) -----------
if [ "$DRY" = 0 ] && [ -n "$(echo $RELOADED)" ]; then
  echo "--- waiting for reloaded services to be active again ---"
  for n in $(echo $RELOADED | tr ' ' '\n' | sort -u); do
    ok=0
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      if have_systemd; then systemctl is-active --quiet "$n" && ok=1; else service "$n" status >/dev/null 2>&1 && ok=1; fi
      [ "$ok" = 1 ] && break; sleep 2
    done
    if [ "$ok" = 1 ]; then echo "BACK-UP $n"; else echo "NOT-BACK $n (not active after 30s)"; RELOAD_FAIL=1; fi
  done
fi

# --- report effective settings per PHP binary ----------------------------------
# Asks each real PHP binary for its resulting values. Wrapper scripts (e.g. a
# cPanel /usr/bin/php Perl wrapper) are skipped because they print nothing useful.
vernum() { echo "$1" | awk -F. '{printf "%d", $1*10000+$2*100+$3}'; }
echo "--- effective settings ---"
for b in /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /opt/alt/php*/usr/bin/php /usr/local/php*/sbin/php-fpm /usr/local/php*/bin/php \
         /opt/plesk/php/*/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/rh/*/root/usr/sbin/php-fpm \
         /usr/sbin/php-fpm* /usr/sbin/php5-fpm /opt/remi/php*/root/usr/sbin/php-fpm /usr/local/lsws/lsphp*/bin/php \
         /usr/local/sbin/php-fpm /usr/bin/php /usr/local/bin/php; do
  [ -x "$b" ] || continue
  [ "$(head -c4 "$b" 2>/dev/null | tr -d '\000')" = "$(printf '\177ELF')" ] || { echo "SKIP $b (wrapper script, not a PHP binary)"; continue; }
  i=$("$b" -i 2>/dev/null)
  ver=$("$b" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1)
  up=$(printf '%s\n' "$i" | awk -F' => ' '/^session.upload_progress.enabled/ {print $2; exit}')
  sm=$(printf '%s\n' "$i" | awk -F' => ' '/^session.use_strict_mode/ {print $2; exit}')
  w=""
  if [ -n "$ver" ]; then
    n=$(vernum "$ver")
    [ "$n" -lt 50500 ] && w="$w WARN-no-strict-mode-before-5.5.2"
    [ "$n" -lt 50400 ] && w="$w WARN-no-upload-progress-before-5.4"
    [ "$n" -lt 80200 ] && w="$w EOL-no-upstream-fix"
  fi
  if [ "$ROLLBACK" = 0 ]; then
    case "$up" in Off|off|0) ;; *) w="$w *** UNPROTECTED-upload_progress-still-on ***";; esac
    case "$sm" in On|on|1) ;; *) case "$w" in *WARN-no-strict*) ;; *) w="$w *** strict_mode-not-on ***";; esac;; esac
  fi
  case "$w" in *'***'*) RC=1;; esac
  echo "BIN $b php=${ver:-?} upload_progress=${up:-?} strict_mode=${sm:-?}$w"
done
echo "WORKERS fpm_masters=$(ps -eo args | grep -c '[p]hp-fpm: master') httpd=$(ps -e -o comm= | grep -cx httpd) apache2=$(ps -e -o comm= | grep -cx apache2) lsphp=$(ps -e -o comm= | grep -c lsphp)"
[ "$plat" != "${plat#plesk}" ] && echo "NOTE Plesk: per-domain 'PHP Settings' in the panel override this file; check domains that set these values themselves."

# --- health check: compare "after" with the "before" snapshot -------------------
if [ "$DRY" = 0 ]; then
  SVC_A=$(svc_snapshot); H_A=$(hcode); M_A=$(nmasters); prob=""
  gone=$(comm -23 <(echo "$SVC_B") <(echo "$SVC_A") | tr '\n' ' ')
  [ -n "$gone" ] && prob="$prob services-no-longer-active:[$gone]"
  [ "$M_A" -lt "$M_B" ] && prob="$prob fpm-masters:$M_B->$M_A"
  [ "$H_B" != "$H_A" ] && prob="$prob http:$H_B->$H_A"
  [ "$RELOAD_FAIL" = 1 ] && prob="$prob reload-failed"
  if [ -z "$prob" ]; then echo "HEALTH OK services=$(echo "$SVC_A" | grep -c .) fpm_masters=$M_A http=$H_A (same as before)"; else echo "HEALTH PROBLEM:$prob"; RC=1; fi
fi
echo "RESULT done. Login loop on a legacy site => session.use_strict_mode=0 in that site's .user.ini"
exit $RC
REMOTE
rc=$?
echo "log: $LOG (exit $rc)"
exit $rc
