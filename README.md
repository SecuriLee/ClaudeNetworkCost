# ClaudeNetworkCost

I asked Claude Code a one-line question: "how to install". It sent 175 KB to answer it. The reply came back in 41 KB.

I wanted to know what every query and every response costs on the wire, per session, without storing anything I wouldn't want to publish. So this is a small tool that sits in Claude Code's hooks and counts.

## What I found on day one

Monday 23 November 2026, the first day with the hooks in: two sessions on one box, 48 turns between 15:08 and 18:00, and **104 MB up, 4.1 MB down**. Session names are swapped for Session1 and Session2 here; the tool itself shows pseudonyms or names you give them.

**Per hour** (`report --by hour`):

```
hour             sess turns calls  input  cache rd cache wr  output    total         up      down
2026-11-23 15:00    1    14    46    116     4.73M      40k     37k    4.81M     8.8 MB  743.7 KB
2026-11-23 16:00    2    18    68    172     8.40M     120k     48k    8.57M    19.0 MB  884.5 KB
2026-11-23 17:00    2    16    98    240    23.53M     166k    103k   23.80M    75.9 MB    2.4 MB
total                    48   212    528    36.66M     326k    188k   37.17M   103.7 MB    4.1 MB
```

**A selection of turns** (`report`):

```
started (local)  session                  #   dur     query  response    anth q    anth r   datadog reqs out tok  tel status
11-23 15:08:22   Session1                 1    7s  175.0 KB   40.9 KB  175.0 KB   40.9 KB       0 B    1     532  ?   ok
11-23 15:19:21   Session1                 9  105s    1.8 MB  148.0 KB    1.8 MB  145.5 KB       0 B   10    9106  ?   ok
11-23 15:59:05   Session1                14  147s    2.7 MB  188.0 KB    2.7 MB  178.0 KB       0 B   12   12717  ?   ok
11-23 16:13:01   Session2                 1   19s  316.5 KB   44.6 KB  316.5 KB   44.6 KB       0 B    3    1385  off ok
11-23 16:14:42   Session1                20    5s  459.9 KB   11.0 KB  459.9 KB   11.0 KB       0 B    1     248  off ok
11-23 16:19:35   Session2                 4   98s    1.6 MB  128.9 KB    1.6 MB  128.9 KB       0 B   12    8028  off ok (+1 mid-turn msg)
11-23 16:21:15   Session1                21  110s    2.4 MB  138.2 KB    2.4 MB  138.2 KB       0 B    9    8540  off ok (+1 mid-turn msg)
11-23 17:10:45   Session2                 8   37s    5.1 MB   77.4 KB    5.0 MB   41.8 KB       0 B    5    1940  off ok
11-23 17:31:16   Session1                37  575s   29.6 MB    1.4 MB   29.6 MB  745.7 KB       0 B   37   49788  off ok (+2 mid-turn msg)
11-23 17:43:11   Session1                38  108s   16.0 MB  140.9 KB   15.9 MB  117.7 KB       0 B   10    5775  off ok
```

**The same turns, tokens next to bytes** (`report --tokens`):

```
started (local)  session                  # calls  input  cache rd cache wr  output ctx/call     query  response  B/out
11-23 15:08:22   Session1                 1     1      4     83313        5     532    83322  175.0 KB   40.9 KB     77
11-23 15:19:21   Session1                 9    10     22    994672    10870    9106   100556    1.8 MB  148.0 KB     16
11-23 16:13:01   Session2                 1     3      6    177572    42907    1385    73495  316.5 KB   44.6 KB     32
11-23 16:14:42   Session1                20     1      4    144735       17     248   144756  459.9 KB   11.0 KB     44
11-23 17:10:45   Session2                 8     5     12    578997     3990    1940   116599    5.1 MB   77.4 KB     40
11-23 17:31:16   Session1                37    37     84  10875374    97296   49788   296560   29.6 MB    1.4 MB     27
11-23 17:43:11   Session1                38    10     22   3364058    10264    5775   337434   16.0 MB  140.9 KB     24
```

What jumps out:

**Every call sends the whole conversation again.** Prompt caching saves Anthropic compute, not my bandwidth. Session1's first turn sent 175 KB for a three-word question. Uploads ran at about 25 times the downloads.

**It goes up and up.** The size of each call grows with the conversation (`ctx/call`): Session1 went from 83k tokens per call at 15:08 to 337k by 17:43. A single call that cost 175 KB at the start cost 460 KB two hours later. Each tool Claude uses is another full upload, so the heavy turns are the ones with many calls: turn 37 was a blog post written in one go, 37 calls in ten minutes, **29.6 MB up**.

**Pasting big things hurts twice.** Turn 38 received a 14 KB base64 blob from another session. It sits in the conversation now, and every call after it carries it again.

**Screenshots are the worst per token.** Session2 had hundreds of browser screenshots in its history: about 8 bytes per token, against 2&ndash;3 for text. Its turn 8 sent 5.1 MB for 1'940 output tokens.

**Answers are cheap.** Around 15&ndash;30 bytes per output token (`B/out`), most of it the streaming wrapper around each token.

**Some of it goes to Datadog.** Claude Code ships logs to `http-intake.logs.us5.datadoghq.com`: 115 KB in four bursts over the first 14 turns. With `DISABLE_TELEMETRY=1` set, it dropped to zero for the 34 turns since.

Going back through the transcripts (`history`), the month before came to 1.24 billion tokens across two machines, 97% of them cache reads.

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
./netcost.py digest                        # the Telegram digest, printed (rolling 7/30 days; or --period day|week|month|auto)
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

### A daily digest on Telegram

`digest` sends one message each morning: the **last 7 days** and the **last 30 days** side by side, to the end of yesterday, each against the window before it (where transcripts reach that far back). Then a 30-day strip of output per day, the last 7 days as bars, projects for both windows, and the network side where the hooks were running.

```
Claude on dozer · rolling 7 and 30 days
to the end of Sun 22 Nov 2026

7 days: 252.37M tokens  ▲73%
30 days: 898.29M tokens
                 7 days  30 days
output             997k    3.78M
  per active day   142k     126k
cache read      247.12M  873.94M
cache write       4.25M   20.55M
API calls          1261     4988
sessions              1        4
active days         7/7    30/30
Output ▲47% on the 7 days before.

30 days (output per day)
▂▇▄▁▂▁▂▁▁▃▆▁▂▁▇▂▃▁▃▁▃▂▁▅▂█▂▁▁▁
24 Oct                  22 Nov
Last 7 days
Mon 16   243k ██████
Tue 17   120k ███
Wed 18   412k ██████████
Thu 19   107k ███
Fri 20    48k █
Sat 21    41k █
Sun 22    27k █

Projects (output tokens)
              7d    30d
Websites    326k  1.47M
lee         164k   818k
MIREC3      185k   631k
reporting   151k   252k
MFRWeb         -   212k
templates   106k   110k
```

Calendar periods are still there with `--period day|week|month`, and `auto` gives yesterday plus last week on Mondays and last month on the 1st.

In Telegram the title is bold and the tables are monospace, so the columns and bars line up (`--html` prints the raw message). With `--telegram` it posts instead of printing. The bot token and chat come from the environment only: `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CNC_CHAT_ID` or else `TELEGRAM_CHAT_ID`. `deploy/` has a systemd service and timer (07:30 daily) that load them from a root-only `/etc/telegram-notify.env` and run as your user:

```sh
sudo cp deploy/claude-netcost-digest.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start claude-netcost-digest.service     # send one now, to test
sudo systemctl enable --now claude-netcost-digest.timer
```

Edit `User=` and the paths in the service if you're not `lee` or cloned somewhere else.

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
