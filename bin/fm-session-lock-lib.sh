#!/usr/bin/env bash
# Shared session-lock harness identity.
#
# ONE owner of the "which verified-harness process holds this home's session
# lock, and does the current process descend from that same harness?" decision.
# bin/fm-lock.sh uses it to acquire and inspect state/.lock;
# bin/fm-claude-stop-autoarm.sh uses it to prove a Stop hook fires inside the
# lock-owning primary session before it may arm or rewake.
# This file is sourced by scripts and has no side effects on source.

# Known harness command names; extend when a new adapter is verified.
FM_HARNESS_RE='claude|codex|opencode|grok|kimi|^pi$|^pi-signed$'

# --- Windows / Git Bash (MSYS) harness ancestry ------------------------------
# On Git Bash/MSYS/Cygwin the harness (e.g. claude.exe) is a NATIVE Windows
# process, and the POSIX emulation layer maps a native parent to init: both the
# Cygwin `ps` PPID column and /proc/<pid>/stat report the tool-call shell's
# parent as pid 1, so the shell-side ancestry walk can never reach the harness.
# Additionally that `ps` rejects the `-o`/`-p` fields the POSIX walk uses.
#
# The native Windows parent chain (Win32_Process.ParentProcessId, readable
# WITHOUT admin via CIM and keyed on Windows PIDs / WINPIDs) is only reliable
# from the TOP-LEVEL tool-call shell: MSYS emulates fork() by spawning throwaway
# Windows processes, so a script the shell spawns (e.g. bin/fm-lock.sh) has a
# ParentProcessId pointing at a fork stub that has already exited, severing the
# chain before it reaches the harness. The robust anchor is the harness PID the
# harness itself exports into the environment (CLAUDE_PID), inherited by every
# descendant and therefore immune to that boundary; the CIM walk stays as a
# best-effort fallback for harnesses that do not export one.
#
# So on Windows the lock identity is the harness WINPID. Every helper fails
# CLOSED (non-zero / no output) when the toolchain is missing or the harness
# cannot be resolved, keeping the session read-only rather than ever falsely
# claiming ownership.
_FM_LOCK_UNAME=$(uname -s 2>/dev/null || echo unknown)

_fm_is_windows() {
  case "$_FM_LOCK_UNAME" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
    *) return 1 ;;
  esac
}

# Walk the native Windows ancestry from FM_START_WINPID up to the outermost
# harness process. Mirrors fm_harness_ancestry_pid's shape: for a claude-named
# match, keep walking through consecutive claude ancestors (the bg-spare hook
# worker chain) and stop the instant a non-match follows; any other harness
# match wins at its innermost pid.
_FM_PS_ANCESTRY='
$ErrorActionPreference="SilentlyContinue"; $ProgressPreference="SilentlyContinue"
$id=[int]$env:FM_START_WINPID
$h="(claude|codex|opencode|grok|kimi|pi|pi-signed)"
$best=0; $ext=$false
for($i=0;$i -lt 24;$i++){
  $p=Get-CimInstance Win32_Process -Filter "ProcessId=$id"
  if(-not $p){break}
  $n=$p.Name; $hit=$false; $isc=$false
  if($n -match "^$h(\.exe)?$"){ $hit=$true; if($n -match "^claude"){$isc=$true} }
  elseif($n -match "^(node|python|python3)(\.exe)?$" -and $p.CommandLine -match $h){ $hit=$true; if($p.CommandLine -match "claude"){$isc=$true} }
  if($hit){ $best=$p.ProcessId; if($isc){$ext=$true} else {break} }
  elseif($ext){ break }
  $id=[int]$p.ParentProcessId
  if($id -le 0){break}
}
if($best -gt 0){ [Console]::Out.Write($best); exit 0 }
exit 1
'

# True (exit 0) when FM_CHECK_WINPID is a live process whose image looks like a
# verified harness.
_FM_PS_ALIVE='
$ErrorActionPreference="SilentlyContinue"; $ProgressPreference="SilentlyContinue"
$id=[int]$env:FM_CHECK_WINPID
$h="(claude|codex|opencode|grok|kimi|pi|pi-signed)"
$p=Get-CimInstance Win32_Process -Filter "ProcessId=$id"
if(-not $p){exit 1}
$n=$p.Name
if($n -match "^$h(\.exe)?$"){exit 0}
if($n -match "^(node|python|python3)(\.exe)?$" -and $p.CommandLine -match $h){exit 0}
exit 1
'

# Run an inline PowerShell script ($1) via -EncodedCommand: no quoting, no temp
# file. Caller-set env vars are visible to the script. Returns PowerShell's exit
# code, or 127 (fail closed) if the encode/run toolchain is unavailable.
_fm_pwsh() {
  local script=$1 enc
  command -v powershell >/dev/null 2>&1 || return 127
  command -v iconv >/dev/null 2>&1 || return 127
  command -v base64 >/dev/null 2>&1 || return 127
  enc=$(printf '%s' "$script" | iconv -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null) || return 127
  [ -n "$enc" ] || return 127
  powershell -NoProfile -NonInteractive -EncodedCommand "$enc" 2>/dev/null
}

# WINPID of the current (sourcing) shell, via the MSYS-exposed /proc file.
_fm_win_self_winpid() {
  local wp
  wp=$(cat "/proc/$$/winpid" 2>/dev/null) || return 1
  case "$wp" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$wp"
}

# Print this session's harness WINPID.
# Preferred source: the harness-exported PID env var, which every descendant
# inherits (extend FM_HARNESS_PID_ENVS as new adapters are verified). It is
# validated as a live harness so a stale value inherited across a re-exec can
# never be published as ownership. Falls back to the CIM ancestry walk.
FM_HARNESS_PID_ENVS='CLAUDE_PID'
_fm_win_harness_winpid() {
  local var val start out
  for var in $FM_HARNESS_PID_ENVS; do
    eval "val=\${$var:-}"
    case "$val" in
      ''|*[!0-9]*) continue ;;
    esac
    if _fm_win_winpid_is_harness "$val"; then
      printf '%s\n' "$val"
      return 0
    fi
  done
  start=$(_fm_win_self_winpid) || return 1
  out=$(FM_START_WINPID="$start" _fm_pwsh "$_FM_PS_ANCESTRY") || return 1
  out=$(printf '%s' "$out" | tr -cd '0-9')
  [ -n "$out" ] || return 1
  printf '%s\n' "$out"
}

# True when WINPID $1 is a live harness process.
_fm_win_winpid_is_harness() {
  local wp=$1
  case "$wp" in ''|*[!0-9]*) return 1 ;; esac
  FM_CHECK_WINPID="$wp" _fm_pwsh "$_FM_PS_ALIVE" >/dev/null
}

# Walk the current process ancestry (up to 16 hops) and print a harness pid.
# For every harness except Claude, the first match wins (innermost pid), which
# is where e.g. Pi's shared signed-wrapper ancestry actually holds the session:
# a "pi-signed" launcher can be the direct parent of the inner "pi" engine
# pid that owns the lock, and the wrapper pid above it is not that owner.
# Claude Code's bg-spare hook worker chain is the opposite shape: it nests
# several claude-named processes directly parent-child with no non-harness
# process between them, and the lock is held by the outermost pid of that
# run. So once a claude-named match is found, this keeps walking past it
# looking for a still-more-ancestral claude-named match, and stops the
# instant a non-match follows - never walking past that gap to an unrelated
# claude-named process further up the real process tree (e.g. the live
# session that launched a test as its own subprocess). The harness pid lives
# as long as the session, unlike the transient subshell pid of any one tool
# call.
fm_harness_ancestry_pid() {
  if _fm_is_windows; then
    _fm_win_harness_winpid
    return
  fi
  local pid=$$ comm args best='' bc extending=0 hit=0 is_claude=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    comm=$(ps -o comm= -p "$pid" 2>/dev/null) || break
    args=$(ps -o args= -p "$pid" 2>/dev/null)
    bc=$(basename -- "$comm")
    hit=0; is_claude=0
    if printf '%s' "$bc" | grep -qE "$FM_HARNESS_RE"; then
      hit=1
      case "$bc" in *claude*) is_claude=1 ;; esac
    else
      # Bare interpreter (e.g. node): match the harness name in its script path.
      case "$comm" in
        *node*|*python*)
          if printf '%s' "$args" | grep -qE "$FM_HARNESS_RE"; then
            hit=1
            case "$args" in *claude*) is_claude=1 ;; esac
          fi
          ;;
      esac
    fi
    if [ "$hit" -eq 1 ]; then
      best="$pid"
      if [ "$is_claude" -eq 1 ]; then
        extending=1
      else
        break
      fi
    elif [ "$extending" -eq 1 ]; then
      break
    fi
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$pid" ] && [ "$pid" -gt 1 ] || break
  done
  [ -n "$best" ] && { echo "$best"; return 0; }
  return 1
}

# True if $1 is a live process that looks like a verified harness.
fm_harness_pid_alive() {
  local pid=$1 comm args
  if _fm_is_windows; then
    _fm_win_winpid_is_harness "$pid"
    return
  fi
  kill -0 "$pid" 2>/dev/null || return 1
  comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
  if printf '%s' "$(basename -- "$comm")" | grep -qE "$FM_HARNESS_RE"; then
    return 0
  fi
  case "$comm" in
    *node*|*python*)
      args=$(ps -o args= -p "$pid" 2>/dev/null)
      printf '%s' "$args" | grep -qE "$FM_HARNESS_RE"
      ;;
    *) return 1 ;;
  esac
}

# True when state dir $1 holds a session lock whose pid is the harness ancestor
# of the current process: this script runs inside the session that owns the
# home's fleet lock. A missing lock, a lock held by another live harness, or an
# ancestry that cannot be resolved all fail closed.
fm_session_lock_owned_by_self() {
  local state=$1 lock_pid my_pid
  lock_pid=$(cat "$state/.lock" 2>/dev/null || true)
  case "$lock_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  my_pid=$(fm_harness_ancestry_pid) || return 1
  [ "$my_pid" = "$lock_pid" ]
}
