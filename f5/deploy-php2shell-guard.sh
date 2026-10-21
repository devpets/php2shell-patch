#!/bin/bash
# =============================================================================
# deploy-php2shell-guard.sh - install / attach / switch / remove the php2shell_guard
# iRule on a BIG-IP LTM, safely and reversibly.
#
#   deploy-php2shell-guard.sh <f5-mgmt-host> <action> [args] [options]
#
# ACTIONS
#   status                  Read-only: failover/sync state, rule + mode, data group,
#                           virtual servers using it, recent hit summary.
#   list-vs                 Read-only: every virtual server with whether it has an HTTP profile
#                           and which iRules it already runs.
#   install                 UCS backup, create data group, load the iRule in LOG-ONLY mode.
#                           Attaches to NOTHING.
#   attach <virtual>        Add the iRule to one HTTP virtual server (appended last).
#   detach <virtual>        Remove it from that virtual server.
#   log-only | enforce      Switch mode (static::p2s_enforce 0 / 1) by reloading the rule.
#   big-host <hostname>     Allow larger uploads for a host (adds it to p2s_big_upload_hosts).
#   logs [N]                Last N (default 40) php2shell_guard log lines.
#   uninstall               Detach from all virtual servers, delete the rule and data group.
#
# OPTIONS
#   --yes             Actually make the change. WITHOUT it, every changing action only prints
#                     the plan and exits (nothing is sent to the F5).
#   --block-chunked   With install/log-only/enforce: set static::p2s_block_chunked 1
#                     (reject multipart sent with Transfer-Encoding; recommended).
#   --no-backup       Skip the UCS backup on install (not recommended).
#   --force           Allow running on a standby unit / non-HTTP virtual server.
#   --irule FILE      iRule source (default: php2shell_guard.irule.tcl next to this script).
#
# CONNECTION
#   Uses ssh to the F5 and runs tmsh there. Defaults to key auth as root:
#     F5_USER=root   F5_SSH="ssh -o BatchMode=yes"
#   For keyboard-interactive password auth (export SSHPASS first):
#     F5_SSH="sshpass -e ssh -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no"
#
# SAFETY
#   * Always start in log-only mode, attach to ONE low-risk virtual server, watch logs + CPU
#     for 30-60 minutes (`logs`, `status`), then widen, then `enforce`.
#   * Changes go to the ACTIVE unit and are saved; if config-sync is enabled they replicate.
#     This script never forces a failover.
#   * The iRule file is validated by tmsh (`verify`) before it is loaded.
# =============================================================================
set -u

F5_HOST="${1:-}"; ACTION="${2:-}"
[ -n "$F5_HOST" ] && [ -n "$ACTION" ] || { sed -n '2,38p' "$0"; exit 1; }
shift 2
ARG=""; case "$ACTION" in attach|detach|big-host|logs) ARG="${1:-}"; [ $# -gt 0 ] && shift;; esac
YES=0; BLOCK_CHUNKED=""; BACKUP=1; FORCE=0
IRULE_FILE="$(cd "$(dirname "$0")" && pwd)/php2shell_guard.irule.tcl"
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1;; --block-chunked) BLOCK_CHUNKED=1;; --no-backup) BACKUP=0;; --force) FORCE=1;;
    --irule) shift; IRULE_FILE="$1";; *) echo "unknown option: $1"; exit 1;;
  esac; shift
done

F5_USER="${F5_USER:-root}"
F5_SSH="${F5_SSH:-ssh -o BatchMode=yes}"
RULE=php2shell_guard
DG=p2s_big_upload_hosts
TS=$(date +%Y%m%d-%H%M%S)

# --- helpers ------------------------------------------------------------------
# r: run a command on the F5 (always real; used for reads and, after --yes, for changes)
r() { $F5_SSH -o ConnectTimeout=15 "$F5_USER@$F5_HOST" "$@" </dev/null; }
r_in() { $F5_SSH -o ConnectTimeout=15 "$F5_USER@$F5_HOST" "$@"; }   # reads stdin (file upload only)
die() { echo "ERROR: $*" >&2; exit 1; }
# plan/do: print the step; execute only with --yes
plan() { echo "  PLAN: $*"; }
do_r() { local desc="$1"; shift; if [ "$YES" = 1 ]; then echo "  DO:   $desc"; r "$@" || die "failed: $desc"; else plan "$desc"; fi; }

need_active() {
  local st; st=$(r "tmsh show cm failover-status 2>/dev/null | grep -i '^Status'" 2>/dev/null)
  echo "  failover: ${st:-unknown}"
  echo "$st" | grep -qi "ACTIVE" || { [ "$FORCE" = 1 ] || die "this unit is not ACTIVE; run against the active unit (or --force)"; }
}
sync_state() { r "tmsh show cm sync-status 2>/dev/null | grep -iE '^Status|Mode|Summary'" 2>/dev/null | sed 's/^/  sync: /'; }
rule_exists() { r "tmsh list ltm rule $RULE >/dev/null 2>&1 && echo yes || echo no"; }
is_http_vs() {  # true if any profile on the virtual is an HTTP profile
  local vs="$1" p
  for p in $(r "tmsh list ltm virtual $vs profiles 2>/dev/null | awk '/^ *\\/?[A-Za-z0-9_.\\/-]+ *\\{/ {gsub(/[{ ]/,\"\"); print}'"); do
    r "tmsh list ltm profile http $p >/dev/null 2>&1" && return 0
  done; return 1
}


# Build the "rules ..." clause for a virtual server WITHOUT our rule, keeping the others in order.
# (tmsh here rejects `rules add` / `rules delete`, so the whole list is always set.)
rules_clause_without() {
  local vs="$1" cur list
  cur=$(r "tmsh list ltm virtual $vs rules 2>/dev/null" | tr -s ' \n' ' ' | sed -E 's/^.*[[:space:]]rules[[:space:]]+//')
  if echo "$cur" | grep -q '^none'; then echo "rules none"; return; fi
  list=$(echo "$cur" | sed -E 's/^\{[[:space:]]*//; s/[[:space:]]*\}[[:space:]]*\}[[:space:]]*$//; s/[[:space:]]*\}[[:space:]]*$//')
  list=$(echo " $list " | sed -E "s/ $RULE / /g; s/^ +//; s/ +$//")
  if [ -z "$list" ]; then echo "rules none"; else echo "rules { $list }"; fi
}
# Build the rule definition (tmsh config-file format) with the requested mode/limits.
build_conf() {  # $1 = enforce 0/1, $2 = block_chunked 0/1
  [ -f "$IRULE_FILE" ] || die "iRule file not found: $IRULE_FILE"
  { echo "ltm rule $RULE {"
    sed -E "s/^([[:space:]]*set static::p2s_enforce[[:space:]]+)[01]/\\1$1/; s/^([[:space:]]*set static::p2s_block_chunked[[:space:]]+)[01]/\\1$2/" "$IRULE_FILE"
    echo "}"; } > "$3"
}
current_flag() {  # read a static flag from the rule currently on the F5
  r "tmsh list ltm rule $RULE 2>/dev/null | grep -m1 -E '^[[:space:]]*set static::$1[[:space:]]'" 2>/dev/null | awk '{print $3}'
}
load_rule() {  # $1 enforce, $2 block_chunked
  local conf; conf=$(mktemp); build_conf "$1" "$2" "$conf"
  echo "  rule definition built: mode enforce=$1 block_chunked=$2 ($(wc -l < "$conf") lines)"
  if [ "$YES" = 1 ]; then
    r_in "cat > /var/tmp/$RULE.$TS.conf" < "$conf" || die "upload failed"
    echo "  DO:   verify rule file with tmsh (no change yet)"
    r "tmsh load sys config merge file /var/tmp/$RULE.$TS.conf verify" || die "tmsh verify FAILED - nothing was loaded"
    echo "  DO:   load rule"
    r "tmsh load sys config merge file /var/tmp/$RULE.$TS.conf" || die "load failed"
    r "tmsh save sys config" >/dev/null && echo "  saved config"
    r "rm -f /var/tmp/$RULE.$TS.conf"
  else
    plan "upload rule file, 'tmsh load sys config merge file ... verify', then load, then 'tmsh save sys config'"
  fi
  rm -f "$conf"
}

# --- actions --------------------------------------------------------------------
echo "F5: $F5_USER@$F5_HOST   action: $ACTION $ARG   $( [ "$YES" = 1 ] && echo '[APPLYING]' || echo '[plan only - add --yes to apply]')"
case "$ACTION" in
  status)
    need_active; sync_state
    echo "  rule present: $(rule_exists)   mode enforce=$(current_flag p2s_enforce)  block_chunked=$(current_flag p2s_block_chunked)"
    echo "  data group:"; r "tmsh list ltm data-group internal $DG 2>&1 | head -8" | sed 's/^/    /'
    echo "  virtual servers running the rule:"
    r "tmsh list ltm virtual one-line 2>/dev/null | grep -F ' $RULE ' | awk '{print \$3}'" | sed 's/^/    /'
    echo "  hits in /var/log/ltm (by reason):"
    r "grep php2shell_guard /var/log/ltm 2>/dev/null | sed -n 's/.* \\(log-only\\|block\\) .*reason=\\([a-z-]*\\).*/\\1 \\2/p' | sort | uniq -c | sort -rn | head" | sed 's/^/    /'
    echo "  TMM CPU now: $(r "tmsh show sys cpu 2>/dev/null | grep -iE 'Utilization|Average' | head -2 | tr -s ' ' | tr '\\n' ' '")" ;;
  list-vs)
    r "tmsh list ltm virtual one-line 2>/dev/null" | awk '{n=$3; d=""; rl=""; for(i=1;i<=NF;i++){ if($i=="destination")d=$(i+1); if($i=="rules"){rl=$(i+1)$(i+2)$(i+3)$(i+4)} } printf "%-45s %-26s rules:%s\n", n, d, rl}' ;;
  install)
    need_active
    [ "$(rule_exists)" = yes ] && echo "  NOTE: rule already exists; this will reload it (mode kept at log-only unless you pass otherwise)"
    if [ "$BACKUP" = 1 ]; then do_r "UCS backup /var/local/ucs/php2shell-pre-$TS.ucs" "tmsh save sys ucs /var/local/ucs/php2shell-pre-$TS.ucs"; fi
    r "tmsh list ltm data-group internal $DG >/dev/null 2>&1" && echo "  data group $DG exists" || do_r "create data group $DG" "tmsh create ltm data-group internal $DG type string"
    load_rule 0 "${BLOCK_CHUNKED:-0}"
    echo "  Next: '$0 $F5_HOST list-vs' then '$0 $F5_HOST attach <low-risk-virtual> --yes' and watch 'logs'/'status'."
    sync_state ;;
  attach)
    [ -n "$ARG" ] || die "usage: attach <virtual-server>"
    need_active
    [ "$(rule_exists)" = yes ] || die "rule not installed; run 'install' first"
    r "tmsh list ltm virtual $ARG >/dev/null 2>&1" || die "virtual server not found: $ARG"
    if ! is_http_vs "$ARG"; then [ "$FORCE" = 1 ] || die "$ARG has no HTTP profile; the rule needs one (use --force to try anyway)"; fi
    echo "  current rules on $ARG: $(r "tmsh list ltm virtual $ARG rules 2>/dev/null | tr -s ' \\n' ' '")"
    # an empty list ("rules none") cannot take `add`; set it directly in that case
    # tmsh here does not accept `rules add`; set the whole list instead: existing rules in their order, ours last
    CUR=$(r "tmsh list ltm virtual $ARG rules 2>/dev/null" | tr -s ' \n' ' ' | sed -E 's/^.*[[:space:]]rules[[:space:]]+//')
    if echo "$CUR" | grep -q '^none'; then RMOD="rules { $RULE }"
    else
      LIST=$(echo "$CUR" | sed -E 's/^\{[[:space:]]*//; s/[[:space:]]*\}[[:space:]]*\}[[:space:]]*$//; s/[[:space:]]*\}[[:space:]]*$//')
      case " $LIST " in *" $RULE "*) echo "  already attached to $ARG - nothing to do"; sync_state; exit 0;; esac
      RMOD="rules { $LIST $RULE }"
    fi
    echo "  new rule list: $RMOD"
    do_r "attach $RULE to $ARG ($RMOD)" "tmsh modify ltm virtual $ARG $RMOD && tmsh save sys config"
    echo "  mode now: enforce=$(current_flag p2s_enforce). Watch: $0 $F5_HOST logs   |   Undo: $0 $F5_HOST detach $ARG --yes"
    sync_state ;;
  detach)
    [ -n "$ARG" ] || die "usage: detach <virtual-server>"
    need_active
    RMOD=$(rules_clause_without "$ARG"); echo "  new rule list: $RMOD"
    do_r "detach $RULE from $ARG ($RMOD)" "tmsh modify ltm virtual $ARG $RMOD && tmsh save sys config"
    sync_state ;;
  log-only|enforce)
    need_active
    [ "$(rule_exists)" = yes ] || die "rule not installed"
    E=0; [ "$ACTION" = enforce ] && E=1
    CH="${BLOCK_CHUNKED:-$(current_flag p2s_block_chunked)}"; CH="${CH:-0}"
    if [ "$E" = 1 ]; then echo "  Before enforcing: confirm 'status' shows only expected hits (no legitimate uploads) after 30-60 min of log-only."; fi
    load_rule "$E" "$CH"; sync_state ;;
  big-host)
    [ -n "$ARG" ] || die "usage: big-host <hostname>"
    H=$(echo "$ARG" | tr 'A-Z' 'a-z')
    do_r "allow big uploads for $H" "tmsh modify ltm data-group internal $DG records add { $H { } } && tmsh save sys config" ;;
  logs)
    r "grep php2shell_guard /var/log/ltm 2>/dev/null | tail -n ${ARG:-40}" ;;
  uninstall)
    need_active
    for v in $(r "tmsh list ltm virtual one-line 2>/dev/null | grep -F ' $RULE ' | awk '{print \$3}'"); do
      RMOD=$(rules_clause_without "$v"); do_r "detach from $v ($RMOD)" "tmsh modify ltm virtual $v $RMOD"
    done
    do_r "delete rule $RULE" "tmsh delete ltm rule $RULE"
    do_r "delete data group $DG" "tmsh delete ltm data-group internal $DG"
    do_r "save config" "tmsh save sys config"
    sync_state ;;
  *) die "unknown action '$ACTION' (status|list-vs|install|attach|detach|log-only|enforce|big-host|logs|uninstall)";;
esac
