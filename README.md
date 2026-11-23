# ClaudeNetworkCost

I asked Claude Code a one-line question: "how to install". It sent 175 KB to answer it. The reply came back in 41 KB.

I wanted to know what every query and every response costs on the wire, per session, without storing anything I wouldn't want to publish. So this is a small tool that sits in Claude Code's hooks and counts.

## What I found on day one

Nine turns of one session, 23 November 2026:

```
 #  calls  input  cache rd  cache wr  output  ctx/call     query  response  B/out
 1      1      4     83313         5     532     83322  175.0 KB   40.9 KB     77
 2      3      8    252071      1062    1313     84380  240.0 KB   33.0 KB     25
 3      2      6    171031       881    1851     85959  215.5 KB   43.7 KB     24
 4      3      8    264312      2181    2399     88833  278.3 KB   70.2 KB     29
 5      1      4     90569        16     347     90589  183.3 KB   23.4 KB     67
 6      1      4     90934        34     609     90972  175.5 KB   19.2 KB     32
 7      2      6    183212       440     597     91829  174.5 KB   18.5 KB     31
 9     10     22    994672     10870    9106    100556    1.8 MB  148.0 KB     16

tokens: input 64, cache read 2'222'413, cache write 15'899, output 17'128
```

(Turn 8 is left out: it was logged before a timing bug in the token count was fixed.)

Three things jump out.

**Every call sends the whole conversation again.** Prompt caching saves Anthropic compute, not my bandwidth. At about 100k tokens of context, each API call costs roughly 180 KB going up. Uploads ran at about nine times the downloads.

**It goes up and up.** The cost of a call grows in a straight line with the conversation. You pay it again on every call, so the session total grows faster than the conversation does. Each tool Claude uses is another full upload. Turn 9 made ten calls and sent 1.8 MB. `/compact` and fresh sessions reset the meter.

**Some of it goes to Datadog.** Claude Code ships logs to `http-intake.logs.us5.datadoghq.com`. In one turn that was 47 KB, against 193 KB for everything else. Cute. Over the first 13 turns it came to 115 KB in four bursts, 1.9% of the upload.

## What gets measured

Every turn (prompt in, finished answer out) logs:

- **query bytes**: what went up (my prompt, the conversation, tool results)
- **response bytes**: what came back (the answer, thinking, tool calls)
- an estimate of the bytes **on the wire**, including IP/TCP headers
- a split by destination: `anthropic` (API and claude.ai remote control share one IP), `anthropic-updates`, `datadog`, `github`, `lan`, `loopback`, `other`
- whether **telemetry was disabled** for that turn (`DISABLE_TELEMETRY` or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`)
- **tokens** from the session transcript: fresh input, cache read, cache write, output, number of API calls, model
- a **pseudonymous session name** such as `nimble-merlin-e34e`, plus the turn number

## Datadog

If telemetry isn't disabled, Claude Code ships logs to Datadog. The report gives it its own column and a summary, split by whether telemetry was off for each turn. ("Setting not recorded" covers turns logged before the tool started recording it; on day one telemetry was on.)

```
Datadog (Claude Code log/telemetry shipping):
  setting not recorded    13 turns: 114.9 KB up / 11.5 KB down (1.9% of upload), in 4 of 13 turns
```

Datadog moves its IPs around, so the tool doesn't pin addresses. It resolves the intake hostnames found in the Claude Code binary (`http-intake.logs.*`, `browser-intake-*`, for US1, US3, US5 and EU), caches the answers for six hours and keeps every address it has ever seen, so older turns keep their label. Answers that come back as `0.0.0.0` or `::` (a DNS block list doing its job) are ignored. If Datadog traffic still shows up in turns with telemetry disabled, the report says so.

Add your own names in `~/.config/claude-netcost/hosts.json`: `{"intake.example.com": "label"}`.

## How it works

Three hooks call `netcost.py`:

| hook | what happens |
|---|---|
| `UserPromptSubmit` | find the `claude` process, read the kernel's TCP counters (`bytes_sent`, `bytes_received` from `tcp_info`) for every socket it and its children hold, start a background sampler |
| sampler | re-reads the counters once a second, so connections that open and close mid-turn still count |
| `Stop` / `SessionEnd` | final reading, stop the sampler; a short background step waits for the transcript to settle, adds the tokens and appends one line to the log |

No root, no packet capture, no proxy, standard-library Python only. A hook that fails never breaks Claude Code; errors go to `~/.local/state/claude-netcost/errors.log`.

### What it costs to run

Nothing between turns. During a turn, a reading takes about 15 ms of CPU, roughly 1.5% of one core at one reading a second, and about 17 MB of RAM. The log grows by around 1 KB a turn.

### Where it's blind

- It counts **TCP payload**: the TLS records, not the plain text inside them. `*_wire` adds 52 bytes of header per segment as an estimate.
- A connection that opens and closes between two readings is missed. That certainly applies to a quick `curl` from a Bash tool, and I suspect some short API connections too, which would make several of the day-one turns low. A firewall counter is the honest cross-check.
- Everything the Claude process tree does during the turn is counted: model calls, remote control, telemetry, MCP servers. The destination split tells them apart where the IP allows.
- A turn cancelled with Esc gets no `Stop` hook. It's logged as `interrupted` when the next prompt arrives (Claude Code leaves a `[Request interrupted by user]` line in the transcript, which is how the tool tells it apart).
- A message typed while Claude is still working fires the prompt hook too, but Claude Code folds it into the running turn. The tool does the same: one turn, shown as `ok (+1 mid-turn msg)`. Turns split by older versions can be put back together with `merge`, which backs up the log first and renumbers the later turns.
- Subagent tokens live in their own transcripts and aren't in the token columns yet. Their bytes are counted.

## Privacy

I want to publish these numbers, so the tool stores nothing I wouldn't.

**Never stored:** prompt or response text, headers, API keys, OAuth tokens, or the real Claude session ID.

The session ID becomes `HMAC-SHA256(salt, session_id)`. The salt is a random key made on first run, kept in `~/.local/state/claude-netcost/salt` (mode 600) and never committed. The pseudonym stays stable, but nobody without that file can link it back to a session. On my own machine, `netcost.py whois <session-id>` does the lookup.

The private log does keep remote IP:port, process names, the project folder's name and prompt length in characters. The public export drops all of those.

## Install

Linux, `python3` and `ss` (part of iproute2, almost always installed already).

```sh
git clone https://github.com/SecuriLee/ClaudeNetworkCost.git ~/ClaudeNetworkCost
cd ~/ClaudeNetworkCost
./install.sh              # adds the hooks to ~/.claude/settings.json, backs it up first
./install.sh --uninstall  # takes them out again
```

New sessions pick the hooks up. Running ones may need a restart.

## Use

```sh
./netcost.py report                        # last 20 turns, bytes, totals per destination
./netcost.py report --tokens               # tokens next to bytes
./netcost.py report --by day               # tokens and bytes per day (or --by hour)
./netcost.py history                       # tokens per day from ALL transcripts on this host
./netcost.py history --by project          # ... or --by hour | session | model
./netcost.py report --session nimble       # one session
./netcost.py report --json --last 5        # raw rows
./netcost.py export [PATH] [--days 90] [--names]  # publish-safe JSON for a website
./netcost.py whois <claude-session-id>     # which pseudonym is this session?
./netcost.py name                          # list your session names
./netcost.py name nimble-merlin "CNC build"  # give a session a name you'll recognise
./netcost.py name nimble-merlin --clear    # take it off again
./netcost.py merge "CNC build" 21          # fold turn 22 into turn 21 (a wrongly split turn)
```

### Going back in time

The network side only starts when you install the hooks, but Claude Code has been saving token counts in its transcripts all along. `history` reads every transcript under `~/.claude/projects` (subagents included), counts each reply once even when a resumed session copied it into a new file, and gives tokens per day, hour, project (the folder Claude was working in), session or model. On my machine that went back six weeks and came to 1.16 billion tokens, 99% of them cache reads.

Claude Code deletes transcripts after 30 days unless you set `cleanupPeriodDays` higher in `~/.claude/settings.json`, so history only reaches as far back as what's still on disk.

### Naming sessions

Pseudonyms are fine for publishing and useless for remembering. `name` pins your own label on a session. You can point at it by pseudonym (or a unique prefix), by the 12-character `sid`, or by the real Claude session ID, which is hashed on the spot and never stored. The report then shows your label, and `--session` matches it.

Names live in `~/.local/state/claude-netcost/aliases.json` (mode 600), beside the salt. `export` leaves them out, because "Q4 layoffs planning" is exactly the kind of name you don't want on a website. Add `--names` when you do want them in.

Set `CLAUDE_NETCOST_EXPORT=/path/file.json` in the hook environment to re-export after every turn.

## Files

| what | where |
|---|---|
| private log, one JSON line per turn | `~/.local/share/claude-netcost/turns.jsonl` |
| public export | `~/.local/share/claude-netcost/public/claude-netcost.json` |
| in-flight state, salt, session names, turn counters, DNS label cache, errors | `~/.local/state/claude-netcost/` |

`CLAUDE_NETCOST_DATA` and `CLAUDE_NETCOST_STATE` move them. `CLAUDE_NETCOST_INTERVAL` changes the sampling interval (default `1.0` seconds).

### Export format (schema 1)

```json
{
  "generated": "...", "schema": 1, "window_days": 90,
  "totals":   { "turns": 0, "query_bytes": 0, "response_bytes": 0,
                "datadog_query_bytes": 0, "datadog_response_bytes": 0 },
  "sessions": [ { "sid", "session_name", "alias" (only with --names), "first", "last", "turns", "query_bytes", "response_bytes" } ],
  "turns":    [ { "started", "duration_s", "status", "sid", "session_name", "turn",
                  "query_bytes", "response_bytes", "query_wire", "response_wire",
                  "by_label": { "anthropic": { "query", "response" } },
                  "api_requests", "input_tokens", "cache_read_tokens", "cache_write_tokens",
                  "output_tokens", "models", "telemetry_disabled" } ]
}
```

### Your own labels

`~/.config/claude-netcost/labels.json`:

```json
{ "140.82.112.0/20": "github" }
```

## Licence

MIT, see [LICENSE](LICENSE).
