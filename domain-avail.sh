#!/usr/bin/env bash
# domain-avail: authoritative availability checker for .com and .ma
set -uo pipefail

VERSION="1.3.0"
PROG="${0##*/}"
SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/domain-avail"
TTL=$((7*24*3600))
MODE="auto"                 # auto | batch | check
MODE_EXPLICIT=0
AUTO_TABLE=0
INPUT=""
OUT=""
TLDS="com,ma"
TLDS_SET=0
DELAY_COM="0.5"
DELAY_MA="1.2"
TIMEOUT="15"
REFRESH=0
QUIET=0
PLAIN_OUTPUT=0
WHOIS_HOST="whois.registre.ma"
WHOIS_PORT=43
POSITIONAL=()

# ----------------------------- Colors -----------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RESET=$'\033[0m'; BOLD=$'\033[1m'; DIM=$'\033[2m'
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
  BLUE=$'\033[34m'; MAGENTA=$'\033[35m'; CYAN=$'\033[36m'
else
  RESET=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''
  BLUE=''; MAGENTA=''; CYAN=''
fi

step() { printf '\n%s==>%s %s%s%s\n' "$BOLD$BLUE" "$RESET" "$BOLD" "$*" "$RESET"; }
ok()   { printf '  %s[OK]%s %s\n' "$GREEN$BOLD" "$RESET" "$*"; }
info() { printf '  %s[i]%s  %s\n' "$CYAN$BOLD" "$RESET" "$*"; }
warn() { printf '  %s[!]%s  %s\n' "$YELLOW$BOLD" "$RESET" "$*" >&2; }
err()  { printf '  %s[ERROR]%s %s\n' "$RED$BOLD" "$RESET" "$*" >&2; }
dim()  { printf '      %s%s%s\n' "$DIM" "$*" "$RESET"; }

usage() {
  cat <<EOF
${BOLD}${MAGENTA}$PROG $VERSION${RESET} - authoritative domain availability for .com and .ma

${BOLD}${CYAN}Usage:${RESET}
  ${BOLD}$PROG${RESET}                      Interactive menu (TTY only)
  ${BOLD}$PROG${RESET} [options] name [name ...]
  ${BOLD}$PROG${RESET} [options] domain.tld [domain.tld ...]
  ${BOLD}$PROG${RESET} check [options] domain.tld [domain.tld ...]
  ${BOLD}$PROG${RESET} batch [options] -f names.txt [-o results.csv]
  cat names.txt | ${BOLD}$PROG${RESET} batch [options] -o results.csv

${BOLD}${CYAN}Modes:${RESET}
  ${GREEN}auto${RESET}    One domain -> boolean; multiple domains -> ASCII table; bare names -> batch.
  ${GREEN}check${RESET}   Print true/false (one per line); exit 0 only if all are available.
  ${GREEN}batch${RESET}   Print CSV/table; accepts bare names or domains.
  ${GREEN}menu${RESET}    Run without arguments in a terminal for the interactive menu.

${BOLD}${CYAN}Options:${RESET}
  ${BOLD}${GREEN}-f, --file FILE${RESET}       Read names/domains from FILE.
  ${BOLD}${GREEN}-o, --output FILE${RESET}     CSV output file (batch mode only).
                        Default: output/domain-avail-<timestamp>.csv
  ${BOLD}${GREEN}    --tlds LIST${RESET}       Comma-separated TLDs: com,ma (default: com,ma).
  ${BOLD}${GREEN}    --delay-com SEC${RESET}   Delay between .com checks (default: 0.5).
  ${BOLD}${GREEN}    --delay-ma SEC${RESET}    Delay between .ma checks (default: 1.2).
  ${BOLD}${GREEN}    --timeout SEC${RESET}     Network timeout in seconds (default: 15).
  ${BOLD}${GREEN}    --refresh${RESET}         Ignore cache.
  ${BOLD}${GREEN}-b, --boolean${RESET}         Force boolean mode (true/false lines).
  ${BOLD}${GREEN}    --plain${RESET}           One true/false per line, even for many domains.
  ${BOLD}${GREEN}-q, --quiet${RESET}           Suppress per-line progress in batch mode.
  ${BOLD}${GREEN}-h, --help${RESET}            Show this help.
  ${BOLD}${GREEN}-V, --version${RESET}         Show version.

${BOLD}${CYAN}Environment:${RESET}
  ${BOLD}${GREEN}NO_COLOR=1${RESET}            Disable colors.
  ${BOLD}${GREEN}OUTPUT_DIR=DIR${RESET}        Override the default output directory.

${BOLD}${CYAN}Output:${RESET}
  check: ${GREEN}true${RESET} | ${RED}false${RESET}
  batch: CSV columns name,tld,status,method,detail,checked_at

${BOLD}${CYAN}Exit codes:${RESET}
  ${GREEN}0${RESET}  success; in check mode, every domain is available
  ${YELLOW}1${RESET}  check mode: at least one domain is unavailable or unknown
  ${RED}2${RESET}  usage, input, dependency, or output error

${BOLD}${CYAN}Examples:${RESET}
  ${DIM}# boolean mode${RESET}
  ${BOLD}$PROG${RESET} immortels.ma
  ${BOLD}$PROG${RESET} check immortels.ma placidite.com
  ${DIM}# batch mode${RESET}
  ${BOLD}$PROG${RESET} -f names.txt
  ${BOLD}$PROG${RESET} -f names.txt -o results.csv
  cat names.txt | ${BOLD}$PROG${RESET} batch
EOF
}

die() {
  err "$*"
  exit 2
}

is_number() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

is_uint() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

normalize_domain() {
  printf '%s' "$1" \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's#^https?://##; s#/.*$##; s/\.$//'
}

is_domain_arg() {
  local value
  value="$(normalize_domain "$1")"
  case "$value" in
    *.com|*.ma) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_tlds() {
  local item t normalized=""
  local -a items
  [ -n "$TLDS" ] || die "--tlds cannot be empty"
  IFS=',' read -r -a items <<< "$TLDS"
  for item in "${items[@]}"; do
    t="$(printf '%s' "$item" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    t="${t#.}"
    case "$t" in
      com|ma) ;;
      *) die "unsupported TLD: ${item:-<empty>} (supported: com, ma)" ;;
    esac
    case ",$normalized," in
      *",$t,"*) ;;
      *) normalized="${normalized:+$normalized,}$t" ;;
    esac
  done
  [ -n "$normalized" ] || die "--tlds cannot be empty"
  TLDS="$normalized"
  IFS=',' read -r -a TLD_ARRAY <<< "$TLDS"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -f|--file|-i)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      INPUT="$2"; shift 2 ;;
    -o|--output)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      OUT="$2"; shift 2 ;;
    --tlds)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      TLDS="$2"; TLDS_SET=1; shift 2 ;;
    --delay-com)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      DELAY_COM="$2"; shift 2 ;;
    --delay-ma)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      DELAY_MA="$2"; shift 2 ;;
    --timeout)
      [ $# -ge 2 ] || die "option $1 requires an argument"
      TIMEOUT="$2"; shift 2 ;;
    -b|--boolean)
      MODE="check"; MODE_EXPLICIT=1; PLAIN_OUTPUT=1; shift ;;
    --plain)
      PLAIN_OUTPUT=1; shift ;;
    --refresh) REFRESH=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) echo "$PROG $VERSION"; exit 0 ;;
    --) shift; POSITIONAL+=("$@"); break ;;
    -*) die "unknown option: $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

# Optional subcommands: check (boolean) and batch (CSV/table).
if [ ${#POSITIONAL[@]} -gt 0 ]; then
  case "${POSITIONAL[0]}" in
    check|batch)
      MODE="${POSITIONAL[0]}"
      MODE_EXPLICIT=1
      POSITIONAL=("${POSITIONAL[@]:1}")
      ;;
  esac
fi

is_number "$DELAY_COM" || die "--delay-com must be a non-negative number"
is_number "$DELAY_MA"  || die "--delay-ma must be a non-negative number"
is_uint "$TIMEOUT"     || die "--timeout must be a positive integer"
normalize_tlds

if [ "$MODE" = "auto" ]; then
  MODE="batch"
  if [ ${#POSITIONAL[@]} -gt 0 ]; then
    all_domains=1
    for arg in "${POSITIONAL[@]}"; do
      is_domain_arg "$arg" || all_domains=0
    done
    if [ "$all_domains" -eq 1 ]; then
      MODE="check"
      [ ${#POSITIONAL[@]} -gt 1 ] && AUTO_TABLE=1
    fi
  fi
fi

case "$MODE" in
  batch|check) ;;
  *) die "invalid mode: $MODE" ;;
esac

if [ "$MODE" = "check" ] && [ -n "$OUT" ]; then
  die "-o/--output is only valid in batch mode"
fi
if [ "$MODE" = "check" ] && [ "$TLDS_SET" -eq 1 ]; then
  die "--tlds is only valid in batch mode; put the TLD in each domain"
fi

command -v curl >/dev/null || die "curl is required"
command -v jq   >/dev/null || die "jq is required"
mkdir -p "$CACHE_DIR" || die "cannot create cache directory: $CACHE_DIR"

TMP_NAMES="$(mktemp)" || die "mktemp failed"
TMP_ROWS="$(mktemp)"  || die "mktemp failed"
TMP_CHECK_ROWS="$(mktemp)" || die "mktemp failed"
TMP_PROBE="$(mktemp)" || die "mktemp failed"
trap 'rm -f "$TMP_NAMES" "$TMP_ROWS" "$TMP_CHECK_ROWS" "$TMP_PROBE" "$TMP_NAMES.norm" "$TMP_ROWS.tmp"' EXIT

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

check_table_border() {
  printf '+-'
  printf '%*s' "$CHECK_DOMAIN_WIDTH" '' | tr ' ' '-'
  printf '%s' '-+-'
  printf '%*s' 10 '' | tr ' ' '-'
  printf '%s' '-+-'
  printf '%*s' 54 '' | tr ' ' '-'
  printf '%s\n' '-+'
}

check_table_row() { # domain, status, detail
  local domain="$1" status="$2" detail="$3"
  [ "${#detail}" -le 54 ] || detail="${detail:0:51}..."
  printf '| %-*s | %-10s | %-54s |\n' \
    "$CHECK_DOMAIN_WIDTH" "$domain" "$status" "$detail"
}

check_table_start() {
  CHECK_DOMAIN_WIDTH=$(awk 'length($0)>m {m=length($0)} END {if(m<6)m=6; print m}' "$TMP_NAMES")
  check_table_border
  check_table_row DOMAIN STATUS DETAIL
  check_table_border
}

run_probe() { # probe function, domain label
  local probe="$1" name="$2" pid elapsed=0 notice=0
  if [ "$AUTO_TABLE" -ne 1 ] || [ ! -t 2 ]; then
    "$probe" "$name"
    return
  fi

  : > "$TMP_PROBE"
  "$probe" "$name" > "$TMP_PROBE" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 0.2
    elapsed=$((elapsed+1))
    if [ "$elapsed" -ge 50 ] && [ $(((elapsed-50) % 50)) -eq 0 ]; then
      printf '\rToujours en cours : %s (%ss)' "$name" "$((elapsed/5))" >&2
      notice=1
    fi
  done
  wait "$pid" || true
  if [ "$notice" -eq 1 ]; then
    printf '\r\033[K' >&2
  fi
  cat "$TMP_PROBE"
}

cache_get() { # $1=name $2=tld -> prints status or nothing
  local f="$CACHE_DIR/${1,,}.${2,,}"
  [ "$REFRESH" -eq 0 ] && [ -f "$f" ] || return 1
  local ts; ts=$(sed -n '1p' "$f" 2>/dev/null)
  case "$ts" in ''|*[!0-9]*) return 1 ;; esac
  [ $(( $(date +%s) - ts )) -le "$TTL" ] || return 1
  sed -n '2p' "$f"
}

cache_put() { # $1=name $2=tld $3=status|detail
  local f="$CACHE_DIR/${1,,}.${2,,}"
  printf '%s\n%s\n' "$(date +%s)" "$3" > "$f.tmp" && mv "$f.tmp" "$f"
}

check_com() { # echoes STATUS|detail
  local name="${1,,}" body http attempt
  # one- and two-character .com labels are registry-reserved
  case ${#name} in 1|2) echo "RESERVED|single/two-character label"; return ;; esac
  for attempt in 1 2 3; do
    body=$(mktemp)
    http=$(curl -sS -m "$TIMEOUT" -H 'Accept: application/rdap+json' \
      -o "$body" -w '%{http_code}' \
      "https://rdap.verisign.com/com/v1/domain/${name}.com" 2>/dev/null)
    # Verisign may abort TLS right after a valid 404; trust the status code
    [ -n "$http" ] || http="000"
    case "$http" in
      200)
        local st
        st=$(jq -r '(.status // []) | join(",")' "$body" 2>/dev/null)
        rm -f "$body"
        case "$st" in
          *reserved*) echo "RESERVED|rdap status=$st" ;;
          *) echo "REGISTERED|rdap status=${st:-active}" ;;
        esac
        return ;;
      404)
        rm -f "$body"
        echo "AVAILABLE|verisign rdap 404"; return ;;
      429|503|000)
        rm -f "$body"
        [ "$attempt" -lt 3 ] && sleep $((attempt*5)) && continue
        echo "UNKNOWN|http=$http after 3 attempts"; return ;;
      *)
        rm -f "$body"
        echo "UNKNOWN|http=$http"; return ;;
    esac
  done
}

check_ma() { # echoes STATUS|detail
  local name="$1" raw rc
  raw=$(mktemp)
  timeout $((TIMEOUT+5)) bash -c '
    exec 3<>/dev/tcp/'"$WHOIS_HOST"'/'"$WHOIS_PORT"' || exit 9
    printf "%s\r\n" "$1" >&3
    cat <&3
  ' _ "${name}.ma" > "$raw" 2>/dev/null
  rc=$?
  if [ "$rc" -ne 0 ] || [ ! -s "$raw" ]; then
    rm -f "$raw"; echo "UNKNOWN|whois connection/timeout rc=$rc"; return
  fi
  if grep -qiE 'No Object Found|not found|no matching record|no entries found' "$raw"; then
    rm -f "$raw"; echo "AVAILABLE|anrt whois: no object found"; return
  fi
  if grep -qiE 'Prohibited String|reserved|not available for registration|restricted' "$raw"; then
    rm -f "$raw"; echo "RESERVED|anrt whois: prohibited/reserved"; return
  fi
  if grep -qiE '^Domain Name:[[:space:]]*' "$raw"; then
    local reg; reg=$(grep -iE '^Registrar:' "$raw" | head -1 | sed 's/^[^:]*:[[:space:]]*//')
    rm -f "$raw"; echo "REGISTERED|anrt whois registrar=${reg:-unknown}"; return
  fi
  if grep -qiE 'rate limit|quota|too many|try again later|temporarily' "$raw"; then
    rm -f "$raw"; echo "UNKNOWN|anrt whois rate limited"; return
  fi
  rm -f "$raw"; echo "UNKNOWN|unrecognised whois response"
}

collect_input() {
  if [ -n "$INPUT" ]; then
    [ -r "$INPUT" ] || die "cannot read $INPUT"
    cat "$INPUT" >> "$TMP_NAMES"
  fi
  if [ ${#POSITIONAL[@]} -gt 0 ]; then
    printf '%s\n' "${POSITIONAL[@]}" >> "$TMP_NAMES"
  fi
  if [ ! -s "$TMP_NAMES" ] && [ ! -t 0 ]; then
    cat >> "$TMP_NAMES"
  fi
}

run_check() {
  local line domain name tld st res cached all_ok=1 seen=0
  : > "$TMP_CHECK_ROWS"
  collect_input
  if [ "$AUTO_TABLE" -eq 1 ]; then
    check_table_start
  fi
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    seen=$((seen+1))
    domain="$(normalize_domain "$line")"

    if [[ ! "$domain" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?)\.(com|ma)$ ]]; then
      if [ "$AUTO_TABLE" -eq 1 ]; then
        check_table_row "$line" INVALID "invalid domain"
      else
        printf 'false\n'
      fi
      printf '%s: invalid domain: %s\n' "$PROG" "$line" >&2
      all_ok=0
      continue
    fi

    name="${BASH_REMATCH[1]}"
    tld="${BASH_REMATCH[3]}"
    if cached="$(cache_get "$name" "$tld")" && [ -n "$cached" ]; then
      res="$cached"
      st="${cached%%|*}"
    else
      case "$tld" in
        com) res="$(run_probe check_com "$name")"; sleep "$DELAY_COM" ;;
        ma)  res="$(run_probe check_ma  "$name")"; sleep "$DELAY_MA"  ;;
        *)   printf 'false\n'; printf '%s: unsupported TLD: %s\n' "$PROG" "$tld" >&2; all_ok=0; continue ;;
      esac
      st="${res%%|*}"
      cache_put "$name" "$tld" "$res"
    fi

    if [ "$st" = "AVAILABLE" ]; then
      if [ "$AUTO_TABLE" -eq 1 ]; then
        check_table_row "$domain" "$st" "${res#*|}"
      else
        printf 'true\n'
      fi
    else
      if [ "$AUTO_TABLE" -eq 1 ]; then
        check_table_row "$domain" "$st" "${res#*|}"
      else
        printf 'false\n'
      fi
      all_ok=0
    fi
  done < "$TMP_NAMES"

  [ "$seen" -gt 0 ] || die "no domains supplied"
  if [ "$AUTO_TABLE" -eq 1 ]; then
    check_table_border
  fi
  [ "$all_ok" -eq 1 ]
}

run_batch() {
  collect_input

  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$TMP_NAMES" \
    | grep -v '^#' \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's#^https?://##; s#/.*$##; s/\.$//; s/\.(com|ma)$//' \
    | grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' \
    | awk '!seen[$0]++' > "$TMP_NAMES.norm" || true
  mv "$TMP_NAMES.norm" "$TMP_NAMES"

  local count
  count=$(wc -l < "$TMP_NAMES" | tr -d ' ')
  [ "$count" -gt 0 ] || die "no valid names supplied"

  if [ -z "$OUT" ]; then
    mkdir -p "$OUTPUT_DIR" || die "cannot create output directory: $OUTPUT_DIR"
    OUT="$OUTPUT_DIR/domain-avail-$(date -u +%Y%m%dT%H%M%SZ).csv"
  else
    mkdir -p "$(dirname "$OUT")" || die "cannot create output directory: $(dirname "$OUT")"
  fi

  printf 'name,tld,status,method,detail,checked_at\n' > "$TMP_ROWS.tmp"
  : > "$TMP_ROWS"

  local name tld st detail cached res color
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    for tld in "${TLD_ARRAY[@]}"; do
      st=""; detail=""
      if cached=$(cache_get "$name" "$tld") && [ -n "$cached" ]; then
        st="${cached%%|*}"; detail="${cached#*|}"
      else
        case "$tld" in
          com) res=$(check_com "$name"); sleep "$DELAY_COM" ;;
          ma)  res=$(check_ma  "$name"); sleep "$DELAY_MA"  ;;
        esac
        st="${res%%|*}"; detail="${res#*|}"
        cache_put "$name" "$tld" "$res"
      fi
      printf '%s,%s,%s,%s,%s,%s\n' "$name" "$tld" "$st" \
        "$([ "$tld" = com ] && echo 'verisign-rdap' || echo 'anrt-whois')" \
        "\"${detail//\"/\"\"}\"" "$(now_utc)" >> "$TMP_ROWS"
      if [ "$QUIET" -eq 0 ]; then
        case "$st" in
          AVAILABLE)  color="$GREEN"  ;;
          REGISTERED) color="$RED"    ;;
          RESERVED)   color="$YELLOW" ;;
          *)          color="$DIM"    ;;
        esac
        printf '  %-14s .%-3s %s%s%s\n' "$name" "$tld" "$color" "$st" "$RESET"
      fi
    done
  done < "$TMP_NAMES"

  { head -1 "$TMP_ROWS.tmp"; cat "$TMP_ROWS"; } > "$OUT"
  rm -f "$TMP_ROWS.tmp"

  echo
  echo "== SUMMARY (names available on every checked TLD) =="
  awk -F, '{n[$1]++; if($3=="AVAILABLE") a[$1]++; s[$1]=s[$1]" "$2":"$3}
           END{for(k in n) if(a[k]==n[k]) printf "%-16s %s\n", k, s[k]}' "$TMP_ROWS" | sort
  echo
  echo "CSV: $OUT  ($(date -u +%Y-%m-%d) UTC)"
}

interactive_check_one() {
  local domain
  printf '  Domain (e.g. immortels.ma): '
  IFS= read -r domain || return 0
  [ -n "$domain" ] || { warn "No domain entered."; return 0; }
  step "Checking $domain"
  if "$SCRIPT_PATH" check "$domain"; then
    ok "$domain is available"
  else
    warn "$domain is not available"
  fi
}

interactive_batch_file() {
  local file
  printf '  Input file: '
  IFS= read -r file || return 0
  [ -n "$file" ] || { warn "No file entered."; return 0; }
  [ -r "$file" ] || { err "Cannot read $file"; return 0; }
  step "Batch check"
  "$SCRIPT_PATH" batch -f "$file"
}

interactive_names() {
  local tmp name
  tmp=$(mktemp) || { err "mktemp failed"; return 0; }
  step "Type names (one per line, blank to finish)"
  while true; do
    printf '  name: '
    IFS= read -r name || break
    [ -z "$name" ] && break
    printf '%s\n' "$name" >> "$tmp"
  done
  if [ ! -s "$tmp" ]; then
    warn "No names entered."
    rm -f "$tmp"
    return 0
  fi
  "$SCRIPT_PATH" batch -f "$tmp"
  rm -f "$tmp"
}

show_latest() {
  local latest
  latest=$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.csv' \
    -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
  if [ -z "$latest" ]; then
    warn "No CSV results in $OUTPUT_DIR yet."
    return 0
  fi
  step "Latest result"
  info "$latest"
  if command -v column >/dev/null 2>&1; then
    column -s, -t < "$latest" | head -25
  else
    head -25 "$latest"
  fi
}

interactive_menu() {
  local choice
  printf '\n%s+-- %s : domain availability --+%s\n' "$BOLD$MAGENTA" "$PROG" "$RESET"
  while true; do
    printf '\n  %s1)%s Check one domain (true/false)\n' "$BOLD$GREEN" "$RESET"
    printf '  %s2)%s Check a list from a file (CSV)\n' "$BOLD$GREEN" "$RESET"
    printf '  %s3)%s Type names interactively (CSV)\n' "$BOLD$GREEN" "$RESET"
    printf '  %s4)%s Show latest results\n' "$BOLD$GREEN" "$RESET"
    printf '  %s5)%s Help\n' "$BOLD$GREEN" "$RESET"
    printf '  %sq)%s Quit\n' "$BOLD$GREEN" "$RESET"
    printf '\n  %sChoice%s [1-5/q]: ' "$BOLD" "$RESET"
    IFS= read -r choice || { printf '\n'; return 0; }
    case "$choice" in
      1) interactive_check_one ;;
      2) interactive_batch_file ;;
      3) interactive_names ;;
      4) show_latest ;;
      5) "$SCRIPT_PATH" --help ;;
      q|Q|quit|exit) printf '\n'; ok "Bye."; return 0 ;;
      *) warn "Invalid choice: $choice" ;;
    esac
  done
}

if [ "$MODE" = "batch" ] && [ "$MODE_EXPLICIT" -eq 0 ] \
  && [ -z "$INPUT" ] && [ ${#POSITIONAL[@]} -eq 0 ] \
  && [ -t 0 ] && [ -t 1 ]; then
  interactive_menu
  exit $?
fi

if [ "$MODE" = "check" ]; then
  run_check
  exit $?
else
  run_batch
fi
