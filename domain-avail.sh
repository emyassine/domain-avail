#!/usr/bin/env bash
# domain-avail — authoritative domain availability checker for ANY TLD,
# with name suggestions (local generator or AI agent CLI).
#
# Backends are discovered dynamically, nothing is hardcoded per TLD:
#   1. RDAP   — server from the IANA bootstrap registry (data.iana.org/rdap/dns.json)
#   2. WHOIS  — server from IANA (whois.iana.org "whois:" field), raw TCP/43
#   3. DNS    — NS lookup, last resort (never reports AVAILABLE: unverified)
#
# Requires: bash >= 4.4, curl, jq.  Optional: timeout|gtimeout, dig|host, idn2.

if [ -z "${BASH_VERSION:-}" ]; then
  echo "domain-avail: bash is required" >&2
  exit 2
fi
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  echo "domain-avail: bash >= 4.4 required (found $BASH_VERSION). macOS: brew install bash" >&2
  exit 2
fi

set -uo pipefail
shopt -s extglob

# =============================================================================
# Constants
# =============================================================================
declare -r VERSION="2.0.0"
declare -r PROG="${0##*/}"
declare -r SEP=$'\x1f'                      # record field separator (non-whitespace IFS)
declare -r UA="domain-avail/${VERSION}"
declare -r URL_RDAP_BOOTSTRAP="https://data.iana.org/rdap/dns.json"
declare -r URL_TLD_LIST="https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
declare -r WHOIS_IANA="whois.iana.org"
declare -ri WHOIS_PORT=43
declare -ri DATA_TTL=86400                  # IANA data cache lifetime
declare -ri WHOIS_SRV_TTL=2592000           # whois server discovery cache (30d)

declare -ri EX_OK=0 EX_TAKEN=1 EX_USAGE=2 EX_UNKNOWN=3

declare -r RE_LABEL='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
declare -r RE_TLD='[a-z]([a-z0-9-]{0,61}[a-z0-9])?'
declare -r RE_DOMAIN="^(${RE_LABEL}\\.)+${RE_TLD}\$"
declare -r RE_WHOIS_AVAIL='no match for|not found|no object found|no entries found|no data found|nothing found|no such domain|status:[[:space:]]*(free|available)|is free[[:space:]]*$|available for registration'
declare -r RE_WHOIS_RESERVED='prohibited string|reserved by|reserved name|reserved domain|not available for registration|status:[[:space:]]*reserved'
declare -r RE_WHOIS_RATELIMIT='rate limit|quota exceeded|too many (queries|requests)|try again later|temporarily unavailable'

_resolve_self() {
  local p=${BASH_SOURCE[0]}
  readlink -f -- "$p" 2>/dev/null || printf '%s\n' "$p"
}
SCRIPT_PATH="$(_resolve_self)"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
declare -r SCRIPT_PATH SCRIPT_DIR

# =============================================================================
# Typed state / configuration
# =============================================================================
declare -l MODE="" FORMAT="auto" METHOD="auto" COLOR_MODE="auto" ONLY="all"
declare -l AGENT="${DOMAIN_AVAIL_AGENT:-auto}" LANG_HINT="en" STYLE="brandable"
declare -- INPUT_FILE="" OUT_FILE="" TLDS_RAW="${DOMAIN_AVAIL_TLDS:-com,ma}"
declare -- AGENT_CMD="" CONTEXT_TEXT=""
declare -- OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/output}"
declare -- CACHE_DIR="${DOMAIN_AVAIL_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME:-${TMPDIR:-/tmp}}/.cache}/domain-avail}"
declare -- DELAY="0.5"                      # decimal string (seconds)
declare -- TIMEOUT_BIN=""
declare -- WORK=""
declare -i TIMEOUT=15 RETRIES=2 JOBS=1
declare -i TTL=604800 TTL_AVAILABLE=3600
declare -i COUNT=20 AGENT_TIMEOUT=120
declare -i VERBOSITY=1                      # 0 quiet · 1 normal · 2 verbose · 3 debug
declare -i REFRESH=0 NO_CACHE=0 NO_HEADER=0 NO_CHECK=0 NO_SAVE=0
declare -i SHOW_ALL=0 ONLY_SET=0 EXIT_STATUS=0 PRINT_PROMPT=0
declare -i TOTAL=0 N_AVAIL=0 N_TAKEN=0 N_UNKNOWN=0
declare -i OUT_TTY=0 ERR_TTY=0 IN_TTY=0
[[ -t 1 ]] && OUT_TTY=1
[[ -t 2 ]] && ERR_TTY=1
[[ -t 0 ]] && IN_TTY=1

declare -a POSITIONAL=() TOKENS=() DOMAINS=() TLD_ARRAY=() ROWS_ALL=() ROWS=() KEYWORDS=() CANDIDATES=()
declare -A SGR_OUT=() SGR_ERR=()
declare -A TLD_CHAIN=()                     # root TLD -> "rdap:URL whois:HOST dns"
declare -A RDAP_SERVER=() WHOIS_SERVER=()   # user overrides (root TLD -> value)
declare -A DELAY_TLD=([ma]="1.2")           # per-TLD politeness delays (overridable)
declare -A SEEN=() CAND_SEEN=()
WHOIS_SERVER[ma]="whois.registre.ma"        # fallback default; IANA is consulted otherwise

# =============================================================================
# Generic helpers
# =============================================================================
is_uint()    { [[ ${1:-} =~ ^[0-9]+$ ]]; }
is_posint()  { [[ ${1:-} =~ ^[1-9][0-9]*$ ]]; }
is_decimal() { [[ ${1:-} =~ ^[0-9]+([.][0-9]+)?$ ]]; }

trim() {
  local v=$1
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  printf '%s' "$v"
}

now_utc()    { date -u +%Y-%m-%dT%H:%M:%SZ; }
file_mtime() {
  local m
  m=$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0)
  is_uint "$m" || m=0
  printf '%s' "$m"
}

# Build one record: fields are sanitised (no tab/CR/LF/SEP) and joined by SEP.
emit() {
  local out='' f first=1
  for f in "$@"; do
    f=${f//[$'\t\r\n']/ }
    f=${f//"$SEP"/ }
    if ((first)); then first=0; else out+=$SEP; fi
    out+=$f
  done
  printf '%s\n' "$out"
}

# =============================================================================
# Colors & formatting
# =============================================================================
setup_colors() {
  local -i out=0 err=0
  case $COLOR_MODE in
    always) out=1; err=1 ;;
    never)  ;;
    *)
      if [[ -z ${NO_COLOR:-} && ${TERM:-} != dumb ]]; then
        ((OUT_TTY)) && out=1
        ((ERR_TTY)) && err=1
      fi
      if [[ -n ${CLICOLOR_FORCE:-} && ${CLICOLOR_FORCE} != 0 ]]; then out=1; err=1; fi
      ;;
  esac
  local -A codes=(
    [reset]=0 [bold]=1 [dim]=2 [under]=4
    [red]=31 [green]=32 [yellow]=33 [blue]=34 [magenta]=35 [cyan]=36 [gray]=90
  )
  local k
  SGR_OUT=(); SGR_ERR=()
  for k in "${!codes[@]}"; do
    if ((out)); then SGR_OUT[$k]=$'\e['"${codes[$k]}"m; else SGR_OUT[$k]=''; fi
    if ((err)); then SGR_ERR[$k]=$'\e['"${codes[$k]}"m; else SGR_ERR[$k]=''; fi
  done
}

# paint OUT|ERR "style[+style]" text...   (prints, no newline)
paint() {
  local stream=$1 styles=$2
  shift 2
  local text="$*"
  local -n _paint_map="SGR_${stream}"
  local prefix='' s
  local IFS='+'
  for s in $styles; do prefix+="${_paint_map[$s]:-}"; done
  if [[ -z $prefix ]]; then
    printf '%s' "$text"
  else
    printf '%s%s%s' "$prefix" "$text" "${_paint_map[reset]:-}"
  fi
}

status_style() {
  case $1 in
    AVAILABLE)  printf 'bold+green' ;;
    REGISTERED) printf 'red' ;;
    RESERVED)   printf 'yellow' ;;
    INVALID)    printf 'bold+red' ;;
    *)          printf 'gray' ;;
  esac
}

# Left-pad THEN colour (so ANSI codes never break column alignment).
cell() {
  local text=$1 width=$2 style=${3:-} padded
  printf -v padded '%-*s' "$width" "$text"
  if [[ -n $style ]]; then paint OUT "$style" "$padded"; else printf '%s' "$padded"; fi
}

trunc() { # trunc text width -> REPLY
  local t=$1 w=$2
  if ((${#t} > w && w > 3)); then REPLY="${t:0:w-3}..."; else REPLY=$t; fi
}

hline() { # hline width -> REPLY (dashes)
  local s
  printf -v s '%*s' "$1" ''
  REPLY=${s// /-}
}

# =============================================================================
# Logging (stderr only; stdout stays machine-clean)
# =============================================================================
log_err()   { printf '%s %s\n' "$(paint ERR bold+red '[ERROR]')" "$*" >&2; }
log_warn()  { ((VERBOSITY >= 1)) && printf '%s %s\n' "$(paint ERR bold+yellow '[WARN]')" "$*" >&2; return 0; }
log_info()  { ((VERBOSITY >= 2)) && printf '%s %s\n' "$(paint ERR bold+cyan '[INFO]')" "$*" >&2; return 0; }
log_debug() { ((VERBOSITY >= 3)) && printf '%s %s\n' "$(paint ERR gray '[DBG]')" "$*" >&2; return 0; }
log_ok()    { ((VERBOSITY >= 1)) && printf '%s %s\n' "$(paint ERR bold+green '[OK]')" "$*" >&2; return 0; }
log_step()  { ((VERBOSITY >= 1)) && printf '\n%s %s\n' "$(paint ERR bold+blue '==>')" "$(paint ERR bold "$*")" >&2; return 0; }
die()       { log_err "$*"; exit "$EX_USAGE"; }

progress() { # idx domain status
  if ((VERBOSITY >= 2 || (VERBOSITY == 1 && ERR_TTY))); then
    printf '  %s %s %s\n' "$(paint ERR dim "[$1/$TOTAL]")" "$2" \
      "$(paint ERR "$(status_style "$3")" "$3")" >&2
  fi
}

# =============================================================================
# Usage
# =============================================================================
usage() {
  local b=${SGR_OUT[bold]:-} d=${SGR_OUT[dim]:-} r=${SGR_OUT[reset]:-} g=${SGR_OUT[green]:-}
  local c=${SGR_OUT[cyan]:-} m=${SGR_OUT[magenta]:-} y=${SGR_OUT[yellow]:-} R=${SGR_OUT[red]:-}
  cat <<EOF
${b}${m}${PROG} ${VERSION}${r} — domain availability for ${b}any${r} TLD (RDAP → WHOIS → DNS), plus name suggestions

${b}${c}USAGE${r}
  ${b}${PROG}${r}                                   interactive menu (TTY) / batch from stdin
  ${b}${PROG}${r} [opts] domain.tld [domain.tld ...]  check domains (any TLD: .com .ma .fr .rs .co.uk ...)
  ${b}${PROG}${r} [opts] name [name ...]              check names on every TLD in --tlds
  ${b}${PROG}${r} check   [opts] ...                  like above; exit code reflects availability
  ${b}${PROG}${r} batch   [opts] -f names.txt         like above; auto-saves CSV on a TTY
  ${b}${PROG}${r} suggest [opts] keyword [keyword ...] generate names, then verify them
  ${b}${PROG}${r} tlds [--all]                        list RDAP-capable TLDs (or all IANA TLDs)
  ${b}${PROG}${r} update                              refresh IANA data and WHOIS server cache
  cat names.txt | ${b}${PROG}${r} batch -F jsonl

${b}${c}INPUT${r}
  ${g}-f, --file FILE${r}        read names/domains from FILE ('-' = stdin); commas/spaces/newlines split
  ${g}    --tlds LIST${r}        TLDs applied to bare names, e.g. com,ma,fr,rs,co.uk   (default: ${TLDS_RAW})

${b}${c}OUTPUT${r}
  ${g}-F, --format FMT${r}       table | csv | tsv | json | jsonl | bool | names   (default: table on TTY, csv otherwise;
                          'bool' = one true/false per line; 'names' = available domains only)
  ${g}-o, --output FILE${r}      also write results to FILE (format inferred from .csv .tsv .json .jsonl .txt)
  ${g}-b, --boolean${r}          shortcut for --format bool
  ${g}-a, --available${r}        show only AVAILABLE rows       ${g}--only STATUS${r}  available|taken|unknown|all
  ${g}    --no-header${r}        omit header (csv/tsv)
  ${g}    --color WHEN${r}       auto | always | never  (NO_COLOR and CLICOLOR_FORCE are honoured)

${b}${c}ENGINE${r}
  ${g}    --method M${r}         auto | rdap | whois | dns  (auto = fallback chain)
  ${g}-j, --jobs N${r}           parallel checks (default 1; per-TLD delays are not enforced across jobs)
  ${g}    --delay SEC${r}        politeness delay after each network check (default ${DELAY})
  ${g}    --delay-tld T=SEC${r}  per-TLD delay (repeatable), e.g. --delay-tld ma=2
  ${g}    --timeout SEC${r}      network timeout (default ${TIMEOUT})
  ${g}    --retries N${r}        retries on 429/5xx/network errors (default ${RETRIES})
  ${g}    --rdap-server T=URL${r}   override RDAP base URL for a TLD (repeatable)
  ${g}    --whois-server T=HOST${r} override WHOIS host for a TLD (repeatable)
  ${g}    --ttl SEC${r}          cache lifetime for taken domains (default ${TTL}); available: ${TTL_AVAILABLE}
  ${g}    --refresh${r}          ignore cache and re-download IANA data      ${g}--no-cache${r}  disable cache read/write

${b}${c}SUGGEST${r}
  ${g}    --agent NAME${r}       auto | none | claude | codex | opencode | grok | gemini   (default: auto)
  ${g}    --agent-cmd CMD${r}    custom command; prompt on stdin, names on stdout (run via bash -c)
  ${g}-n, --count N${r}          number of candidates (default ${COUNT})
  ${g}    --style S${r}          brandable | short | descriptive | playful | ...  (free text for agents)
  ${g}    --lang CODE${r}        fr | en | ...  (language/affix hint)
  ${g}    --context TEXT${r}     describe the project to the agent
  ${g}    --all${r}              show unavailable candidates too (default: available only)
  ${g}    --no-check${r}         print candidate names without checking domains
  ${g}    --print-prompt${r}     print the agent prompt and exit
  ${g}    --agent-timeout SEC${r} agent time limit (default ${AGENT_TIMEOUT})

${b}${c}MISC${r}
  ${g}-q, --quiet${r}  ${g}-v, --verbose${r}  ${g}--debug${r}   ${g}-h, --help${r}  ${g}-V, --version${r}

${b}${c}STATUS VALUES${r}  ${g}AVAILABLE${r} ${R}REGISTERED${r} ${y}RESERVED${r} ${R}INVALID${r} UNKNOWN

${b}${c}EXIT CODES${r}
  ${g}0${r} ok (check: every domain AVAILABLE) · ${y}1${r} check/--exit-status: at least one taken/invalid
  ${y}3${r} check/--exit-status: none taken but some UNKNOWN · ${R}2${r} usage / dependency / I/O error

${b}${c}ENVIRONMENT${r}
  NO_COLOR, CLICOLOR_FORCE, OUTPUT_DIR, DOMAIN_AVAIL_CACHE_DIR, DOMAIN_AVAIL_TLDS, DOMAIN_AVAIL_AGENT

${b}${c}EXAMPLES${r}
  ${d}# one domain → true/false; exit status 0 only if available${r}
  ${PROG} check -b immortels.ma && echo "free!"
  ${d}# any TLD, mixed${r}
  ${PROG} nova.rs atelier.fr studio.co.uk
  ${d}# CI / foreach${r}
  ${PROG} -F jsonl --tlds com,io,fr -f names.txt | jq -r 'select(.available) | .domain'
  for n in alpha beta; do ${PROG} check -b "\$n.com" >/dev/null && echo "\$n ok"; done
  ${d}# suggestions from keywords (uses an installed agent CLI, else a local generator)${r}
  ${PROG} suggest --tlds com,ma,fr --lang fr -n 30 atlas immortel
  ${PROG} suggest --agent none --style short zen cafe
EOF
}

# =============================================================================
# Argument parsing
# =============================================================================
need_arg() { (($# >= 2)) || die "option $1 requires an argument"; }

parse_kv() { # "T=V" -> KV_K (lowercase, no dot) KV_V
  [[ ${1:-} == *=* ]] || die "expected TLD=VALUE, got: ${1:-<empty>}"
  KV_K=${1%%=*}; KV_V=${1#*=}
  KV_K=${KV_K,,}; KV_K=${KV_K#.}
  [[ -n $KV_K && -n $KV_V ]] || die "expected TLD=VALUE, got: $1"
}

parse_args() {
  local arg
  while (($#)); do
    arg=$1
    case $arg in
      --*=*) set -- "${arg%%=*}" "${arg#*=}" "${@:2}"; arg=$1 ;;
    esac
    case $arg in
      -f|--file|-i)   need_arg "$@"; INPUT_FILE=$2; shift 2 ;;
      -o|--output)    need_arg "$@"; OUT_FILE=$2; shift 2 ;;
      -F|--format)    need_arg "$@"; FORMAT=$2; shift 2 ;;
      --tlds)         need_arg "$@"; TLDS_RAW=$2; shift 2 ;;
      --method)       need_arg "$@"; METHOD=$2; shift 2 ;;
      --color)        need_arg "$@"; COLOR_MODE=$2; shift 2 ;;
      --only)         need_arg "$@"; ONLY=$2; ONLY_SET=1; shift 2 ;;
      --delay)        need_arg "$@"; is_decimal "$2" || die "--delay must be a non-negative number"; DELAY=$2; shift 2 ;;
      --delay-tld)    need_arg "$@"; parse_kv "$2"; is_decimal "$KV_V" || die "--delay-tld needs a number"; DELAY_TLD[$KV_K]=$KV_V; shift 2 ;;
      --rdap-server)  need_arg "$@"; parse_kv "$2"; RDAP_SERVER[$KV_K]=$KV_V; shift 2 ;;
      --whois-server) need_arg "$@"; parse_kv "$2"; WHOIS_SERVER[$KV_K]=$KV_V; shift 2 ;;
      --timeout)      need_arg "$@"; is_posint "$2" || die "--timeout must be a positive integer"; TIMEOUT=$2; shift 2 ;;
      --retries)      need_arg "$@"; is_uint "$2" || die "--retries must be an integer >= 0"; RETRIES=$2; shift 2 ;;
      -j|--jobs)      need_arg "$@"; is_posint "$2" || die "--jobs must be a positive integer"; JOBS=$2; shift 2 ;;
      --ttl)          need_arg "$@"; is_uint "$2" || die "--ttl must be an integer"; TTL=$2; shift 2 ;;
      -n|--count)     need_arg "$@"; is_posint "$2" || die "--count must be a positive integer"; COUNT=$2; shift 2 ;;
      --agent)        need_arg "$@"; AGENT=$2; shift 2 ;;
      --agent-cmd)    need_arg "$@"; AGENT_CMD=$2; shift 2 ;;
      --agent-timeout) need_arg "$@"; is_posint "$2" || die "--agent-timeout must be a positive integer"; AGENT_TIMEOUT=$2; shift 2 ;;
      --style)        need_arg "$@"; STYLE=$2; shift 2 ;;
      --lang)         need_arg "$@"; LANG_HINT=$2; shift 2 ;;
      --context)      need_arg "$@"; CONTEXT_TEXT=$2; shift 2 ;;
      -b|--boolean)   FORMAT=bool; shift ;;
      -a|--available) ONLY=available; ONLY_SET=1; shift ;;
      --all)          SHOW_ALL=1; shift ;;
      --exit-status)  EXIT_STATUS=1; shift ;;
      --no-header)    NO_HEADER=1; shift ;;
      --no-check)     NO_CHECK=1; shift ;;
      --no-save)      NO_SAVE=1; shift ;;
      --no-cache)     NO_CACHE=1; shift ;;
      --refresh)      REFRESH=1; shift ;;
      --print-prompt) PRINT_PROMPT=1; shift ;;
      --plain)        FORMAT=bool; shift ;;
      -q|--quiet)     VERBOSITY=0; shift ;;
      -v|--verbose)   VERBOSITY=2; shift ;;
      --debug)        VERBOSITY=3; shift ;;
      -h|--help)      MODE=help; shift ;;
      -V|--version)   MODE=version; shift ;;
      --)             shift; POSITIONAL+=("$@"); break ;;
      -?*)            die "unknown option: $arg (see --help)" ;;
      *)              POSITIONAL+=("$arg"); shift ;;
    esac
  done

  if [[ -z $MODE && ${#POSITIONAL[@]} -gt 0 ]]; then
    case ${POSITIONAL[0],,} in
      check|batch|suggest|tlds|update|menu|help|version)
        MODE=${POSITIONAL[0],,}
        POSITIONAL=("${POSITIONAL[@]:1}")
        ;;
    esac
  fi
  [[ $MODE == help || $MODE == version ]] || validate_options
}

validate_options() {
  case $FORMAT  in auto|table|csv|tsv|json|jsonl|bool|names) ;; *) die "invalid --format: $FORMAT" ;; esac
  case $METHOD  in auto|rdap|whois|dns) ;; *) die "invalid --method: $METHOD" ;; esac
  case $COLOR_MODE in auto|always|never) ;; *) die "invalid --color: $COLOR_MODE" ;; esac
  case $ONLY    in all|available|taken|unknown) ;; *) die "invalid --only: $ONLY" ;; esac
  ((SHOW_ALL)) && ONLY=all
  normalize_tlds
}

normalize_tlds() {
  local item t norm=''
  local -a items
  IFS=', ' read -r -a items <<< "$TLDS_RAW"
  TLD_ARRAY=()
  for item in "${items[@]}"; do
    t=${item,,}; t=${t#.}
    [[ -n $t ]] || continue
    [[ $t =~ ^[a-z0-9-]+(\.[a-z0-9-]+)*$ ]] || die "invalid TLD: $item"
    case " $norm " in *" $t "*) continue ;; esac
    norm+="${norm:+ }$t"
    TLD_ARRAY+=("$t")
  done
  ((${#TLD_ARRAY[@]} > 0)) || die "--tlds cannot be empty"
}

# =============================================================================
# Dependencies & cleanup
# =============================================================================
check_deps() {
  local missing=() c
  for c in curl jq; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  ((${#missing[@]} == 0)) || die "missing dependencies: ${missing[*]}"
  if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN=timeout
  elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN=gtimeout
  fi
  [[ -n $TIMEOUT_BIN ]] || log_debug "no timeout/gtimeout: WHOIS and agent backends disabled"
  mkdir -p "$CACHE_DIR/results" "$CACHE_DIR/whois-servers" 2>/dev/null \
    || die "cannot create cache directory: $CACHE_DIR"
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/domain-avail.XXXXXX") || die "mktemp failed"
}

cleanup() {
  local pids
  pids=$(jobs -p 2>/dev/null)
  [[ -z $pids ]] || kill $pids 2>/dev/null
  [[ -n $WORK && -d $WORK ]] && rm -rf -- "$WORK"
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# =============================================================================
# IANA data (bootstrap, TLD list, WHOIS server discovery)
# =============================================================================
declare -- BOOTSTRAP_FILE="" TLD_LIST_FILE=""

fetch_cached() { # url file max_age_seconds
  local url=$1 file=$2 max=$3 now mt tmp
  printf -v now '%(%s)T' -1
  if [[ -s $file ]] && ((!REFRESH)); then
    mt=$(file_mtime "$file")
    ((now - mt < max)) && return 0
  fi
  tmp="$file.tmp.$$"
  if curl -fsSL --max-time "$TIMEOUT" -A "$UA" -o "$tmp" "$url" 2>/dev/null && [[ -s $tmp ]]; then
    mv -f "$tmp" "$file"
    log_debug "downloaded $url"
    return 0
  fi
  rm -f "$tmp"
  if [[ -s $file ]]; then
    log_debug "download failed, using stale $file"
    return 0
  fi
  log_warn "cannot download $url (offline?)"
  return 1
}

ensure_data() {
  BOOTSTRAP_FILE="$CACHE_DIR/iana-rdap-dns.json"
  TLD_LIST_FILE="$CACHE_DIR/iana-tlds.txt"
  fetch_cached "$URL_TLD_LIST" "$TLD_LIST_FILE" "$DATA_TTL" || true
  case $METHOD in
    auto|rdap) fetch_cached "$URL_RDAP_BOOTSTRAP" "$BOOTSTRAP_FILE" "$DATA_TTL" || true ;;
  esac
  if [[ -s $BOOTSTRAP_FILE ]] && ! jq -e '.services' "$BOOTSTRAP_FILE" >/dev/null 2>&1; then
    log_warn "corrupt RDAP bootstrap, discarding"
    rm -f "$BOOTSTRAP_FILE"
  fi
}

tld_exists() { # root TLD known to IANA? (unknown list => assume yes)
  [[ -s $TLD_LIST_FILE ]] || return 0
  grep -qixF -- "$1" "$TLD_LIST_FILE"
}

rdap_base_for() {
  local tld=$1
  if [[ -n ${RDAP_SERVER[$tld]+x} ]]; then printf '%s' "${RDAP_SERVER[$tld]}"; return 0; fi
  [[ -s $BOOTSTRAP_FILE ]] || return 0
  jq -r --arg t "$tld" '
    [ .services[] | select(.[0] | index($t))
      | (([.[1][] | select(startswith("https"))][0]) // .[1][0]) ][0] // empty
  ' "$BOOTSTRAP_FILE" 2>/dev/null
}

whois_raw() { # host query -> raw response on stdout
  [[ -n $TIMEOUT_BIN ]] || return 127
  "$TIMEOUT_BIN" "$((TIMEOUT + 2))" bash -c '
    exec 3<>"/dev/tcp/$1/$2" || exit 9
    printf "%s\r\n" "$3" >&3
    cat <&3
  ' _ "$1" "$WHOIS_PORT" "$2" 2>/dev/null
}

whois_host_for() {
  local tld=$1 f="$CACHE_DIR/whois-servers/$tld" now mt host=''
  if [[ -n ${WHOIS_SERVER[$tld]+x} ]]; then printf '%s' "${WHOIS_SERVER[$tld]}"; return 0; fi
  printf -v now '%(%s)T' -1
  if [[ -s $f ]] && ((!REFRESH)); then
    mt=$(file_mtime "$f")
    if ((now - mt < WHOIS_SRV_TTL)); then
      host=$(<"$f")
      [[ $host == - ]] || printf '%s' "$host"
      return 0
    fi
  fi
  host=$(whois_raw "$WHOIS_IANA" "$tld" \
    | awk 'tolower($1)=="whois:" {print $2; exit}' | tr -d '\r')
  if [[ $host =~ ^[A-Za-z0-9.-]+$ ]]; then
    printf '%s\n' "$host" > "$f"
    printf '%s' "$host"
  else
    printf '%s\n' '-' > "$f"
  fi
}

prepare_backends() { # resolve fallback chain per distinct root TLD (done before forking jobs)
  local d root url host chain
  for d in "${DOMAINS[@]}"; do
    [[ $d =~ $RE_DOMAIN ]] || continue
    root=${d##*.}
    [[ -n ${TLD_CHAIN[$root]+x} ]] && continue
    chain=''
    case $METHOD in auto|rdap)
      url=$(rdap_base_for "$root"); [[ -n $url ]] && chain+=" rdap:$url" ;;
    esac
    case $METHOD in auto|whois)
      if [[ -n $TIMEOUT_BIN ]]; then
        host=$(whois_host_for "$root"); [[ -n $host ]] && chain+=" whois:$host"
      fi ;;
    esac
    case $METHOD in auto|dns) chain+=" dns" ;; esac
    TLD_CHAIN[$root]=${chain# }
    log_debug "backends .$root: ${TLD_CHAIN[$root]:-none}"
  done
}

# =============================================================================
# Cache
# =============================================================================
cache_get() { # domain -> REPLY=record (status..detail)
  local f="$CACHE_DIR/results/$1" line ts rest st ttl now
  ((NO_CACHE || REFRESH)) && return 1
  [[ -r $f ]] || return 1
  IFS= read -r line < "$f" || return 1
  ts=${line%%"$SEP"*}; rest=${line#*"$SEP"}
  is_uint "$ts" || return 1
  st=${rest%%"$SEP"*}
  ttl=$TTL
  [[ $st == AVAILABLE ]] && ((TTL_AVAILABLE < ttl)) && ttl=$TTL_AVAILABLE
  printf -v now '%(%s)T' -1
  ((now - ts <= ttl)) || return 1
  REPLY=$rest
}

cache_put() { # domain record
  local f="$CACHE_DIR/results/$1" now
  ((NO_CACHE)) && return 0
  printf -v now '%(%s)T' -1
  printf '%s%s%s\n' "$now" "$SEP" "$2" > "$f.tmp.$$" && mv -f "$f.tmp.$$" "$f"
}

# =============================================================================
# Probes — each prints one record: status|method|created|expires|registrar|detail
# =============================================================================
short_date() { local v=${1%%[T ]*}; printf '%s' "$v"; }

probe_rdap() { # domain base_url
  local domain=$1 base=${2%/} body="$WORK/body.$BASHPID" http parsed
  local -i attempt
  local st created expires registrar
  for ((attempt = 0; attempt <= RETRIES; attempt++)); do
    http=$(curl -sS -L --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" -A "$UA" \
      -H 'Accept: application/rdap+json, application/json' \
      -o "$body" -w '%{http_code}' "$base/domain/$domain" 2>/dev/null) || true
    [[ $http =~ ^[0-9]{3}$ ]] || http=000
    case $http in
      200)
        if ! parsed=$(jq -r '[
            ((.status // []) | join(",")),
            (((.events // []) | map(select(.eventAction=="registration") | .eventDate) | .[0] // "") | .[0:10]),
            (((.events // []) | map(select(.eventAction=="expiration")   | .eventDate) | .[0] // "") | .[0:10]),
            ([.entities[]? | select((.roles // []) | index("registrar"))
              | (.vcardArray[1][]? | select(.[0]=="fn") | .[3])] | .[0] // "")
          ] | join("\u001f")' "$body" 2>/dev/null); then
          rm -f "$body"; emit UNKNOWN rdap '' '' '' "http=200 but invalid JSON"; return 0
        fi
        rm -f "$body"
        IFS=$SEP read -r st created expires registrar <<< "$parsed"
        if [[ ,${st,,}, == *reserved* ]]; then
          emit RESERVED rdap "$created" "$expires" "$registrar" "rdap status=$st"
        else
          emit REGISTERED rdap "$created" "$expires" "$registrar" "rdap status=${st:-active}"
        fi
        return 0 ;;
      404)
        rm -f "$body"; emit AVAILABLE rdap '' '' '' "rdap 404 (${base#https://})"; return 0 ;;
      429|500|502|503|504|000)
        ((attempt < RETRIES)) && { sleep $(((attempt + 1) * 3)); continue; }
        rm -f "$body"; emit UNKNOWN rdap '' '' '' "http=$http after $((RETRIES + 1)) attempt(s)"; return 0 ;;
      *)
        rm -f "$body"; emit UNKNOWN rdap '' '' '' "http=$http"; return 0 ;;
    esac
  done
}

whois_field() { # file ERE(lowercase key) -> first non-empty value
  awk -F: -v re="$2" 'tolower($1) ~ re {
      sub(/^[^:]*:[ \t]*/, ""); sub(/[ \t\r]+$/, "");
      if (length($0)) { print; exit } }' "$1"
}

probe_whois() { # domain host
  local domain=$1 host=$2 raw="$WORK/whois.$BASHPID" rc created expires registrar
  whois_raw "$host" "$domain" > "$raw"; rc=$?
  if [[ ! -s $raw ]]; then
    rm -f "$raw"; emit UNKNOWN whois '' '' '' "whois $host: no response (rc=$rc)"; return 0
  fi
  if grep -qiE "$RE_WHOIS_AVAIL" "$raw"; then
    rm -f "$raw"; emit AVAILABLE whois '' '' '' "whois $host: not found"; return 0
  fi
  if grep -qiE "$RE_WHOIS_RESERVED" "$raw"; then
    rm -f "$raw"; emit RESERVED whois '' '' '' "whois $host: reserved/prohibited"; return 0
  fi
  if grep -qiE '^[[:space:]]*domain( name)?:' "$raw"; then
    created=$(short_date "$(whois_field "$raw" '^[ \t]*(creation date|created( on)?|registered( on)?|registration (date|time)|domain registered)[ \t]*$')")
    expires=$(short_date "$(whois_field "$raw" '^[ \t]*(registry expiry date|registrar registration expiration date|expir(y|ation|es)( date| on)?|paid-till|renewal date)[ \t]*$')")
    registrar=$(whois_field "$raw" '^[ \t]*(sponsoring )?registrar[ \t]*$')
    rm -f "$raw"
    emit REGISTERED whois "$created" "$expires" "$registrar" "whois $host"
    return 0
  fi
  if grep -qiE "$RE_WHOIS_RATELIMIT" "$raw"; then
    rm -f "$raw"; emit UNKNOWN whois '' '' '' "whois $host: rate limited"; return 0
  fi
  rm -f "$raw"
  emit UNKNOWN whois '' '' '' "whois $host: unrecognised response"
}

probe_dns() { # domain — can prove "registered", can never prove "available"
  local d=$1 out
  if command -v dig >/dev/null 2>&1; then
    out=$(dig +noall +answer +comments +time="$TIMEOUT" +tries=1 NS "$d" 2>/dev/null) || true
    if grep -q 'status: NOERROR' <<< "$out" && grep -qE '[[:space:]]NS[[:space:]]' <<< "$out"; then
      emit REGISTERED dns '' '' '' 'NS records present'
    elif grep -q 'status: NXDOMAIN' <<< "$out"; then
      emit UNKNOWN dns '' '' '' 'NXDOMAIN (unverified: may still be registered)'
    else
      emit UNKNOWN dns '' '' '' 'dns inconclusive'
    fi
  elif command -v host >/dev/null 2>&1; then
    out=$(host -W "$TIMEOUT" -t NS "$d" 2>&1) || true
    if grep -qi 'name server' <<< "$out"; then emit REGISTERED dns '' '' '' 'NS records present'
    elif grep -qi 'NXDOMAIN' <<< "$out"; then emit UNKNOWN dns '' '' '' 'NXDOMAIN (unverified)'
    else emit UNKNOWN dns '' '' '' 'dns inconclusive'; fi
  else
    emit UNKNOWN dns '' '' '' 'no dig/host available'
  fi
}

# =============================================================================
# Input handling
# =============================================================================
ingest_line() { # split a line into tokens (no globbing, comments stripped)
  local -
  set -f
  local line=${1%%#*} w
  line=${line//[,;]/ }
  for w in $line; do TOKENS+=("$w"); done
}

collect_tokens() {
  local line a
  if [[ -n $INPUT_FILE ]]; then
    if [[ $INPUT_FILE == - ]]; then
      while IFS= read -r line || [[ -n $line ]]; do ingest_line "$line"; done
    else
      [[ -r $INPUT_FILE ]] || die "cannot read $INPUT_FILE"
      while IFS= read -r line || [[ -n $line ]]; do ingest_line "$line"; done < "$INPUT_FILE"
    fi
  fi
  for a in "${POSITIONAL[@]}"; do ingest_line "$a"; done
  if ((${#TOKENS[@]} == 0 && !IN_TTY)) && [[ $INPUT_FILE != - ]]; then
    while IFS= read -r line || [[ -n $line ]]; do ingest_line "$line"; done
  fi
}

normalize_token() { # -> REPLY
  local t=${1,,} conv
  t=${t#*://}; t=${t%%[/?#]*}; t=${t##*@}; t=${t%%:*}
  [[ $t == www.*.* ]] && t=${t#www.}
  t=${t%.}; t=${t#.}
  if [[ ! $t =~ ^[a-z0-9.-]+$ ]]; then
    if command -v idn2 >/dev/null 2>&1 && conv=$(idn2 "$t" 2>/dev/null) && [[ -n $conv ]]; then
      t=$conv
    elif command -v idn >/dev/null 2>&1 && conv=$(idn --quiet "$t" 2>/dev/null) && [[ -n $conv ]]; then
      t=$conv
    fi
  fi
  REPLY=$t
}

add_domain() {
  [[ -n ${SEEN[$1]+x} ]] && return 0
  SEEN[$1]=1
  DOMAINS+=("$1")
}

build_domain_list() {
  local tok tld
  DOMAINS=(); SEEN=()
  for tok in "${TOKENS[@]}"; do
    normalize_token "$tok"
    [[ -n $REPLY ]] || continue
    if [[ $REPLY == *.* ]]; then
      add_domain "$REPLY"
    else
      for tld in "${TLD_ARRAY[@]}"; do add_domain "$REPLY.$tld"; done
    fi
  done
}

# =============================================================================
# Core check
# =============================================================================
check_one() { # idx domain -> writes $WORK/res.idx
  local -i idx=$1 cached=0
  local domain=$2
  local name=${domain%%.*} tld=${domain#*.} root=${domain##*.}
  local rec='' st='' me='' cr='' ex='' rg='' de='' step kind arg res notes='' ts dl
  ts=$(now_utc)

  if ((${#domain} > 253)) || [[ ! $domain =~ $RE_DOMAIN ]]; then
    rec=$(emit INVALID syntax '' '' '' 'invalid domain syntax')
  elif ! tld_exists "$root"; then
    rec=$(emit INVALID iana '' '' '' "unknown TLD .$root")
  elif cache_get "$domain"; then
    rec=$REPLY; cached=1
  else
    local chain=${TLD_CHAIN[$root]:-}
    rec=$(emit UNKNOWN none '' '' '' "no backend available for .$root")
    for step in $chain; do
      kind=${step%%:*}; arg=${step#*:}
      case $kind in
        rdap)  res=$(probe_rdap "$domain" "$arg") ;;
        whois) res=$(probe_whois "$domain" "$arg") ;;
        dns)   res=$(probe_dns "$domain") ;;
        *)     continue ;;
      esac
      IFS=$SEP read -r st me cr ex rg de <<< "$res"
      if [[ $st != UNKNOWN ]]; then rec=$res; notes=''; break; fi
      notes+="${notes:+ | }$de"
      rec=$(emit UNKNOWN "$me" '' '' '' "$notes")
      dl=${DELAY_TLD[$root]:-$DELAY}
      [[ $kind == dns ]] || sleep "$dl"
    done
    IFS=$SEP read -r st me cr ex rg de <<< "$rec"
    if [[ $st != UNKNOWN && $st != INVALID ]]; then
      cache_put "$domain" "$rec"
      dl=${DELAY_TLD[$root]:-$DELAY}
      sleep "$dl"
    fi
  fi

  IFS=$SEP read -r st me cr ex rg de <<< "$rec"
  emit "$domain" "$name" "$tld" "$st" "$me" "$cr" "$ex" "$rg" "$de" "$ts" "$cached" > "$WORK/res.$idx"
  progress "$idx" "$domain" "$st"
}

run_pipeline() {
  ((${#DOMAINS[@]} > 0)) || die "no domains supplied"
  local d row line
  local -i i=0 running=0
  TOTAL=${#DOMAINS[@]}
  ensure_data
  prepare_backends

  for d in "${DOMAINS[@]}"; do
    i+=1
    if ((JOBS > 1)); then
      check_one "$i" "$d" &
      running+=1
      if ((running >= JOBS)); then wait -n 2>/dev/null; running=$((running - 1)); fi
    else
      check_one "$i" "$d"
    fi
  done
  wait

  ROWS_ALL=()
  for ((i = 1; i <= TOTAL; i++)); do
    if [[ -s $WORK/res.$i ]]; then
      IFS= read -r line < "$WORK/res.$i"
      ROWS_ALL+=("$line")
    else
      ROWS_ALL+=("$(emit "${DOMAINS[i-1]}" '' '' UNKNOWN none '' '' '' 'check did not complete' "$(now_utc)" 0)")
    fi
  done
  count_rows
}

row_status() { local _a _b _c; IFS=$SEP read -r _a _b _c REPLY _ <<< "$1"; }

count_rows() {
  local row
  N_AVAIL=0; N_TAKEN=0; N_UNKNOWN=0
  for row in "${ROWS_ALL[@]}"; do
    row_status "$row"
    case $REPLY in
      AVAILABLE) N_AVAIL+=1 ;;
      REGISTERED|RESERVED|INVALID) N_TAKEN+=1 ;;
      *) N_UNKNOWN+=1 ;;
    esac
  done
}

filter_rows() {
  local row
  ROWS=()
  for row in "${ROWS_ALL[@]}"; do
    row_status "$row"
    case $ONLY in
      all) ;;
      available) [[ $REPLY == AVAILABLE ]] || continue ;;
      taken)     [[ $REPLY == REGISTERED || $REPLY == RESERVED || $REPLY == INVALID ]] || continue ;;
      unknown)   [[ $REPLY == UNKNOWN ]] || continue ;;
    esac
    ROWS+=("$row")
  done
}

# =============================================================================
# Renderers (read ROWS, write stdout)
# =============================================================================
csv_q() { local v=${1//\"/\"\"}; printf '"%s"' "$v"; }

render_csv() {
  local row d n t st me cr ex rg de ca ck
  ((NO_HEADER)) || printf 'domain,name,tld,status,method,created,expires,registrar,detail,checked_at\n'
  for row in "${ROWS[@]}"; do
    IFS=$SEP read -r d n t st me cr ex rg de ca ck <<< "$row"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$(csv_q "$d")" "$(csv_q "$n")" "$(csv_q "$t")" "$st" "$me" "$cr" "$ex" \
      "$(csv_q "$rg")" "$(csv_q "$de")" "$ca"
  done
}

render_tsv() {
  local row d n t st me cr ex rg de ca ck
  ((NO_HEADER)) || printf 'domain\tname\ttld\tstatus\tmethod\tcreated\texpires\tregistrar\tdetail\tchecked_at\n'
  for row in "${ROWS[@]}"; do
    IFS=$SEP read -r d n t st me cr ex rg de ca ck <<< "$row"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$d" "$n" "$t" "$st" "$me" "$cr" "$ex" "$rg" "$de" "$ca"
  done
}

declare -r JQ_REC='split($sep) | {
  domain: .[0], name: .[1], tld: .[2], status: .[3], available: (.[3] == "AVAILABLE"),
  method: .[4], created: .[5], expires: .[6], registrar: .[7], detail: .[8],
  checked_at: .[9], cached: (.[10] == "1")
} | with_entries(if .value == "" then .value = null else . end)'

render_json() {
  if ((${#ROWS[@]} == 0)); then printf '[]\n'; return; fi
  printf '%s\n' "${ROWS[@]}" | jq -Rn --arg sep "$SEP" "[inputs | $JQ_REC]"
}

render_jsonl() {
  ((${#ROWS[@]} == 0)) && return 0
  printf '%s\n' "${ROWS[@]}" | jq -Rnc --arg sep "$SEP" "inputs | $JQ_REC"
}

render_bool() {
  local row st
  for row in "${ROWS[@]}"; do
    row_status "$row"
    [[ $REPLY == AVAILABLE ]] && printf 'true\n' || printf 'false\n'
  done
}

render_names() {
  local row d
  for row in "${ROWS[@]}"; do
    row_status "$row"
    [[ $REPLY == AVAILABLE ]] || continue
    IFS=$SEP read -r d _ <<< "$row"
    printf '%s\n' "$d"
  done
}

term_width() {
  local w=${COLUMNS:-0}
  if ((w <= 0)) && ((OUT_TTY)); then w=$(tput cols 2>/dev/null || echo 0); fi
  is_posint "$w" || w=120
  printf '%s' "$w"
}

render_table() {
  local row d n t st me cr ex rg de ca ck i
  local -a A_d=() A_st=() A_me=() A_cr=() A_ex=() A_in=()
  local -i wd=6 wi tw
  for row in "${ROWS[@]}"; do
    IFS=$SEP read -r d n t st me cr ex rg de ca ck <<< "$row"
    [[ -n $rg ]] && de="registrar=$rg${de:+; $de}"
    ((ck == 1)) && me="$me*"
    A_d+=("$d"); A_st+=("$st"); A_me+=("${me:--}"); A_cr+=("${cr:--}"); A_ex+=("${ex:--}"); A_in+=("$de")
    ((${#d} > wd)) && wd=${#d}
  done
  tw=$(term_width)
  wi=$((tw - wd - 55)); ((wi < 20)) && wi=20

  local b1 b2 b3 b4 b5 b6
  hline $((wd + 2));  b1=$REPLY
  hline 12; b2=$REPLY; hline 12; b3=$REPLY; hline 12; b4=$REPLY
  hline 8;  b5=$REPLY; hline $((wi + 2)); b6=$REPLY
  local border="+$b1+$b2+$b3+$b4+$b5+$b6+"

  paint OUT dim "$border"; printf '\n'
  printf '| '; cell DOMAIN "$wd" bold; printf ' | '; cell STATUS 10 bold
  printf ' | '; cell CREATED 10 bold; printf ' | '; cell EXPIRES 10 bold
  printf ' | '; cell METHOD 6 bold; printf ' | '; cell INFO "$wi" bold; printf ' |\n'
  paint OUT dim "$border"; printf '\n'
  for ((i = 0; i < ${#A_d[@]}; i++)); do
    trunc "${A_in[i]}" "$wi"
    printf '| '; cell "${A_d[i]}" "$wd"
    printf ' | '; cell "${A_st[i]}" 10 "$(status_style "${A_st[i]}")"
    printf ' | '; cell "${A_cr[i]}" 10
    printf ' | '; cell "${A_ex[i]}" 10
    printf ' | '; cell "${A_me[i]}" 6 dim
    printf ' | '; cell "$REPLY" "$wi" dim
    printf ' |\n'
  done
  paint OUT dim "$border"; printf '\n'
  render_summary
}

render_summary() {
  ((VERBOSITY >= 1)) || return 0
  printf '%s  %s available · %s taken · %s unknown  (%s checked)\n' \
    "$(paint OUT bold Summary:)" \
    "$(paint OUT bold+green "$N_AVAIL")" "$(paint OUT red "$N_TAKEN")" \
    "$(paint OUT gray "$N_UNKNOWN")" "$TOTAL"
  ((${#TLD_ARRAY[@]} > 1)) || return 0
  local row d n t st k line=''
  local -A tot=() av=()
  local -a order=()
  for row in "${ROWS_ALL[@]}"; do
    IFS=$SEP read -r d n t st _ <<< "$row"
    [[ -n ${tot[$n]+x} ]] || order+=("$n")
    tot[$n]=$((${tot[$n]:-0} + 1))
    [[ $st == AVAILABLE ]] && av[$n]=$((${av[$n]:-0} + 1))
  done
  for k in "${order[@]}"; do
    ((${tot[$k]} > 1 && ${av[$k]:-0} == ${tot[$k]})) && line+="${line:+, }$k"
  done
  [[ -z $line ]] || printf '%s %s\n' "$(paint OUT bold+green 'Available on every TLD:')" "$line"
}

infer_format() { # file -> REPLY
  case ${1##*.} in
    csv) REPLY=csv ;; tsv) REPLY=tsv ;; json) REPLY=json ;;
    jsonl|ndjson) REPLY=jsonl ;; txt|lst) REPLY=names ;;
    *) REPLY=csv ;;
  esac
}

render() { "render_$1"; }

present() {
  filter_rows
  local fmt=$FORMAT
  if [[ -n $OUT_FILE ]]; then
    [[ $fmt != auto ]] || { infer_format "$OUT_FILE"; fmt=$REPLY; }
    mkdir -p "$(dirname -- "$OUT_FILE")" 2>/dev/null || die "cannot create directory for $OUT_FILE"
    ( SGR_OUT=(); render "$fmt" ) > "$OUT_FILE" || die "cannot write $OUT_FILE"
    log_ok "saved: $OUT_FILE"
    if ((OUT_TTY)); then render table; fi
    return 0
  fi
  if [[ $fmt == auto ]]; then
    if [[ $MODE == check && ${#ROWS_ALL[@]} -eq 1 ]]; then fmt=bool
    elif ((OUT_TTY)); then fmt=table
    else fmt=csv; fi
  fi
  render "$fmt"
}

final_exit_code() {
  if [[ $MODE == check ]] || ((EXIT_STATUS)); then
    ((N_TAKEN > 0)) && return "$EX_TAKEN"
    ((N_UNKNOWN > 0)) && return "$EX_UNKNOWN"
  fi
  return "$EX_OK"
}

# =============================================================================
# Suggestions
# =============================================================================
slugify() { # -> REPLY (ascii lowercase [a-z0-9])
  local s
  s=$(iconv -f UTF-8 -t ASCII//TRANSLIT 2>/dev/null <<< "$1" || printf '%s' "$1")
  s=${s,,}
  REPLY=${s//[^a-z0-9]/}
}

add_candidate() {
  local c=${1:-}
  [[ -n $c ]] || return 0
  ((${#CANDIDATES[@]} >= COUNT)) && return 0
  ((${#c} >= 2 && ${#c} <= 63)) || return 0
  [[ $STYLE == short ]] && ((${#c} > 8)) && return 0
  [[ -n ${CAND_SEEN[$c]+x} ]] && return 0
  CAND_SEEN[$c]=1
  CANDIDATES+=("$c")
}

suggest_local() {
  local -a kws=() pre=() suf=() b_plain=() b_pair=() b_suf=() b_pre=() b_blend=()
  local k a b p s h1 h2 i
  local -i m=0
  for k in "${KEYWORDS[@]}"; do slugify "$k"; [[ -n $REPLY ]] && kws+=("$REPLY"); done
  ((${#kws[@]} > 0)) || return 0
  case $LANG_HINT in
    fr*) pre=(le la mon ma mes un) ; suf=(ia pro web lab hub club maison atelier ly) ;;
    es*) pre=(el la mi mis un)     ; suf=(ia pro web lab hub club casa ly) ;;
    *)   pre=(get try go my the use hey); suf=(hub lab ly ify hq box base kit zone works studio app) ;;
  esac
  for k in "${kws[@]}"; do
    b_plain+=("$k")
    for s in "${suf[@]}"; do b_suf+=("$k$s"); done
    for p in "${pre[@]}"; do b_pre+=("$p$k"); done
  done
  for a in "${kws[@]}"; do
    for b in "${kws[@]}"; do
      [[ $a == "$b" ]] && continue
      b_pair+=("$a$b")
      h1=${a:0:(${#a} + 1) / 2}; h2=${b:${#b} / 2}
      b_blend+=("$h1$h2")
    done
  done
  for a in ${#b_plain[@]} ${#b_pair[@]} ${#b_suf[@]} ${#b_pre[@]} ${#b_blend[@]}; do ((a > m)) && m=$a; done
  for ((i = 0; i < m && ${#CANDIDATES[@]} < COUNT; i++)); do
    add_candidate "${b_plain[i]:-}"
    add_candidate "${b_pair[i]:-}"
    add_candidate "${b_blend[i]:-}"
    add_candidate "${b_suf[i]:-}"
    add_candidate "${b_pre[i]:-}"
  done
}

agent_prompt() {
  local kw="${KEYWORDS[*]}"
  cat <<EOF
You are a naming expert. Suggest ${COUNT} domain-friendly brand names for this project.
Keywords: ${kw}
${CONTEXT_TEXT:+Project description: ${CONTEXT_TEXT}
}Style: ${STYLE}
Language/culture hint: ${LANG_HINT}

Rules:
- Output ONLY the names, one per line. No numbering, no bullets, no explanations, no TLD.
- Lowercase ASCII letters, digits and hyphens only; 3 to 15 characters; easy to pronounce and spell.
- Avoid existing well-known brands and trademarks.
EOF
}

detect_agent() { # -> REPLY (agent name or empty)
  local a
  REPLY=''
  [[ -n $TIMEOUT_BIN ]] || return 0
  if [[ -n $AGENT_CMD ]]; then REPLY=custom; return 0; fi
  case $AGENT in
    none) return 0 ;;
    auto) for a in claude codex opencode grok gemini; do
            command -v "$a" >/dev/null 2>&1 && { REPLY=$a; return 0; }
          done ;;
    claude|codex|opencode|grok|gemini)
          command -v "$AGENT" >/dev/null 2>&1 && REPLY=$AGENT \
            || log_warn "agent '$AGENT' not found in PATH" ;;
    *)    die "unknown agent: $AGENT (claude|codex|opencode|grok|gemini|none|auto, or --agent-cmd)" ;;
  esac
}

run_agent() { # agent prompt -> stdout
  local agent=$1 prompt=$2
  local -a tb=("$TIMEOUT_BIN" "$AGENT_TIMEOUT")
  case $agent in
    custom)   printf '%s' "$prompt" | "${tb[@]}" bash -c "$AGENT_CMD" ;;
    claude)   "${tb[@]}" claude -p "$prompt" </dev/null ;;
    codex)    "${tb[@]}" codex exec "$prompt" </dev/null ;;
    opencode) "${tb[@]}" opencode run "$prompt" </dev/null ;;
    grok)     "${tb[@]}" grok -p "$prompt" </dev/null ;;
    gemini)   "${tb[@]}" gemini -p "$prompt" </dev/null ;;
  esac
}

parse_agent_names() { # stdin: agent output -> CANDIDATES
  local line
  local re='^[[:space:]]*([-*+0-9.)]+[[:space:]]+)?[`"*_]*([a-z0-9][a-z0-9-]*[a-z0-9]|[a-z0-9])(\.[a-z0-9.-]+)?[`"*_]*[[:space:]]*(([-:(]|[[:space:]]-).*)?$'
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line,,}; line=${line//$'\r'/}
    if [[ $line =~ $re ]]; then add_candidate "${BASH_REMATCH[2]}"; fi
  done
}

cmd_suggest() {
  local agent out
  KEYWORDS=("${POSITIONAL[@]}")
  if [[ -n $INPUT_FILE && $INPUT_FILE != - && -r $INPUT_FILE ]]; then
    local line; while IFS= read -r line; do ingest_line "$line"; done < "$INPUT_FILE"
    KEYWORDS+=("${TOKENS[@]}"); TOKENS=()
  fi
  ((${#KEYWORDS[@]} > 0)) || die "suggest needs at least one keyword"
  if ((PRINT_PROMPT)); then agent_prompt; return 0; fi

  CANDIDATES=(); CAND_SEEN=()
  detect_agent; agent=$REPLY
  if [[ -n $agent ]]; then
    log_step "asking agent: $agent"
    out=$(run_agent "$agent" "$(agent_prompt)" 2>/dev/null) || log_warn "agent '$agent' failed or timed out"
    parse_agent_names <<< "$out"
    log_info "agent returned ${#CANDIDATES[@]} usable name(s)"
  fi
  if ((${#CANDIDATES[@]} == 0)); then
    [[ -z $agent ]] || log_warn "no usable names from agent, falling back to local generator"
    suggest_local
  fi
  ((${#CANDIDATES[@]} > 0)) || die "could not generate any candidate"

  if ((NO_CHECK)); then printf '%s\n' "${CANDIDATES[@]}"; return 0; fi

  TOKENS=("${CANDIDATES[@]}")
  ((ONLY_SET || SHOW_ALL)) || ONLY=available
  run_and_present
}

# =============================================================================
# Commands
# =============================================================================
run_and_present() {
  build_domain_list
  run_pipeline
  if [[ $MODE == batch && -z $OUT_FILE && $NO_SAVE -eq 0 && $OUT_TTY -eq 1 && $FORMAT == auto ]]; then
    mkdir -p "$OUTPUT_DIR" 2>/dev/null || die "cannot create $OUTPUT_DIR"
    printf -v OUT_FILE '%s/domain-avail-%(%Y%m%dT%H%M%S)T.csv' "$OUTPUT_DIR" -1
  fi
  present
  final_exit_code
}

cmd_check() {
  collect_tokens
  ((${#TOKENS[@]} > 0)) || die "no domains supplied"
  run_and_present
}

cmd_tlds() {
  ensure_data
  if ((SHOW_ALL)); then
    [[ -s $TLD_LIST_FILE ]] || die "IANA TLD list unavailable"
    grep -v '^#' "$TLD_LIST_FILE" | tr 'A-Z' 'a-z'
  else
    [[ -s $BOOTSTRAP_FILE ]] || die "RDAP bootstrap unavailable"
    jq -r '.services[][0][]' "$BOOTSTRAP_FILE" | sort -u
  fi
}

cmd_update() {
  REFRESH=1
  rm -f "$CACHE_DIR"/whois-servers/* 2>/dev/null
  METHOD=auto
  ensure_data && log_ok "IANA data refreshed in $CACHE_DIR"
}

# ---------------------------- interactive menu -------------------------------
menu_ask() { local v; printf '  %s ' "$1" >&2; IFS= read -r v || v=''; printf '%s' "$v"; }

interactive_menu() {
  local choice val
  printf '\n%s\n' "$(paint ERR bold+magenta "+-- $PROG $VERSION : domain availability --+")" >&2
  while true; do
    {
      printf '\n  %s Check domain(s)        (any TLD)\n' "$(paint ERR bold+green '1)')"
      printf '  %s Check names on TLDs    (%s)\n' "$(paint ERR bold+green '2)')" "$TLDS_RAW"
      printf '  %s Suggest names from keywords\n' "$(paint ERR bold+green '3)')"
      printf '  %s Check a file\n' "$(paint ERR bold+green '4)')"
      printf '  %s Help\n' "$(paint ERR bold+green '5)')"
      printf '  %s Quit\n' "$(paint ERR bold+green 'q)')"
    } >&2
    choice=$(menu_ask 'Choice [1-5/q]:') || return 0
    case $choice in
      1) val=$(menu_ask 'Domain(s):'); [[ -n $val ]] && "$SCRIPT_PATH" check $val ;;
      2) val=$(menu_ask 'Name(s):');   [[ -n $val ]] && "$SCRIPT_PATH" batch --tlds "$TLDS_RAW" $val ;;
      3) val=$(menu_ask 'Keyword(s):'); [[ -n $val ]] && "$SCRIPT_PATH" suggest --tlds "$TLDS_RAW" $val ;;
      4) val=$(menu_ask 'File:');      [[ -n $val ]] && "$SCRIPT_PATH" batch -f "$val" ;;
      5) "$SCRIPT_PATH" --help ;;
      q|Q|quit|exit) return 0 ;;
      *) log_warn "invalid choice: $choice" ;;
    esac
  done
}

# =============================================================================
# Main
# =============================================================================
main() {
  parse_args "$@"
  setup_colors
  case $MODE in
    help|"") if [[ $MODE == help ]]; then usage; return 0; fi ;;
    version) printf '%s %s\n' "$PROG" "$VERSION"; return 0 ;;
  esac
  check_deps

  if [[ -z $MODE ]]; then
    if ((${#POSITIONAL[@]} == 0 && IN_TTY && OUT_TTY)) && [[ -z $INPUT_FILE ]]; then
      interactive_menu; return $?
    fi
    MODE=batch
    local a all_domains=1
    if ((${#POSITIONAL[@]} > 0)); then
      for a in "${POSITIONAL[@]}"; do [[ $a == *.* ]] || all_domains=0; done
      ((all_domains)) && MODE=check
    fi
  fi

  case $MODE in
    check|batch) cmd_check ;;
    suggest)     cmd_suggest ;;
    tlds)        cmd_tlds ;;
    update)      cmd_update ;;
    menu)        interactive_menu ;;
    *)           die "invalid mode: $MODE" ;;
  esac
}

main "$@"
exit $?
