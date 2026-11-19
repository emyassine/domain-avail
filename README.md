# yas-domain

Authoritative availability checker for `.com` and `.ma`, with an interactive
menu, colored output, and scripting-friendly `true`/`false` mode.

- `.com`: Verisign RDAP (`https://rdap.verisign.com/com/v1/domain/<name>`).
  200 = REGISTERED, 404 = AVAILABLE, `reserved` status = RESERVED.
- `.ma`: ANRT registry WHOIS (`whois.registre.ma:43`).
  "No Object Found" = AVAILABLE, "Domain Name:" = REGISTERED,
  "Prohibited String" = RESERVED/PROHIBITED.
- No DNS guessing. Results cached for 7 days (use `--refresh` to re-check).

## Install

The source lives at `~/bash-tools/domain-avail/domain-avail.sh`.
The `yas-domain` command is a symlink in `~/.local/bin`:

```bash
ln -sf ~/bash-tools/domain-avail/domain-avail.sh ~/.local/bin/yas-domain
```

## Interactive mode

Run `yas-domain` with no arguments in a terminal:

```bash
yas-domain
```

Menu:

```text
1) Check one domain (true/false)
2) Check a list from a file (CSV)
3) Type names interactively (CSV)
4) Show latest results
5) Help
q) Quit
```

Colors are enabled when stdout is a TTY. Disable them with `NO_COLOR=1`.

## Scripting mode

```bash
# Boolean: true/false, exit 0 only if available
yas-domain immortels.ma
yas-domain check immortels.ma placidite.com
yas-domain -b google.com

# Batch: CSV + summary
yas-domain -f names.txt
yas-domain -f names.txt -o results.csv
yas-domain quiete riposo sosta
cat names.txt | yas-domain batch
```

Batch output defaults to `output/domain-avail-<timestamp>.csv` next to the
script. Use `-o FILE` only when you need a specific path.

## Modes

| Mode | Trigger | Output |
|------|---------|--------|
| `check` | `check` subcommand, `-b`, or one domain argument | `true` / `false` per domain |
| `table` | Multiple domain arguments without a subcommand | Live ASCII table with domain, status, and detail |
| `batch` | `batch` subcommand, bare names, `-f`, or stdin | CSV rows + summary |
| `menu` | no arguments in a TTY | interactive menu |

Auto-detection: one positional domain (`name.com` or `name.ma`) uses boolean
mode. Multiple positional domains print an ASCII status table as each check
finishes. If one network query takes more than 10 seconds, a temporary wait
message appears and clears when the result arrives. Use the explicit `check`
subcommand or `-b` to force scripting-friendly boolean output. Bare names use
`batch` mode.

All input domains, names, and TLDs are lowercased before cache lookup and
before any network check.

## Options

```text
-f, --file FILE       Read names/domains from FILE
-o, --output FILE     CSV output file (batch mode only)
                      Default: output/domain-avail-<timestamp>.csv
    --tlds LIST       Comma-separated TLDs: com,ma (default: com,ma)
    --delay-com SEC   Delay between .com checks (default: 0.5)
    --delay-ma SEC    Delay between .ma checks (default: 1.2)
    --timeout SEC     Network timeout in seconds (default: 15)
    --refresh         Ignore cache
-b, --boolean         Force boolean mode (same as "check")
-q, --quiet           Suppress per-line progress in batch mode
-h, --help            Show help
-V, --version         Show version
```

Environment: `NO_COLOR=1`, `OUTPUT_DIR=DIR`.

## Directory layout

```text
domain-avail/
├── domain-avail.sh                  # the tool
├── README.md
├── output/                          # new batch CSVs go here
└── archive/
    ├── 2026-11-19-research.tar.gz   # old research lists/CSVs
    └── README.md
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success; in `check` mode, every domain is available |
| `1` | `check` mode: at least one domain is unavailable or unknown |
| `2` | Usage, input, dependency, or output error |

## Scripting examples

```bash
if yas-domain "$domain" >/dev/null; then
  echo "$domain is free"
fi

while IFS= read -r domain; do
  status=$(yas-domain "$domain")
  printf '%s,%s\n' "$domain" "$status"
done < domains.txt
```

## Output statuses

`AVAILABLE`, `REGISTERED`, `RESERVED`, `UNKNOWN`.

## Caveats

Verisign RDAP is authoritative for *registration* state. A 404 does not
expose Verisign's private reserved-string inventory; one- and two-character
`.com` names are treated as RESERVED per registry rules. `.ma` WHOIS is the
registry's own availability service. Always confirm at a registrar before
purchase. Cache entries can hide a recent registration; use `--refresh` for
a fresh check.
# domain-avail
