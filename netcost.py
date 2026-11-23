#!/usr/bin/env python3
"""ClaudeNetworkCost - measure the network traffic of each Claude Code turn.

How it works
------------
* A UserPromptSubmit hook finds the Claude Code process that fired it,
  snapshots the TCP counters (bytes_sent / bytes_received from the kernel's
  tcp_info, read via `ss -tinpe`) of every socket owned by that process and its
  descendants, and starts a small background sampler.
* The sampler re-reads the counters every INTERVAL seconds, so connections that
  open and close during the turn are still counted (up to their last sample).
* A Stop hook takes a final sample, stops the sampler and appends one JSON line
  per turn to the log: bytes up/down per remote, segment counts, an estimate of
  on-the-wire bytes, and the token usage / API request count from the transcript.

Nothing secret is stored: no prompt text, no response text, no headers, no
tokens or keys. Only byte counters, remote IP:port, process names, timings,
token counts and the session id.

No root needed. Stdlib only.
"""

import hashlib
import hmac
import ipaddress
import secrets
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

STATE_DIR = os.environ.get(
    "CLAUDE_NETCOST_STATE",
    os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")), "claude-netcost"),
)
DATA_DIR = os.environ.get(
    "CLAUDE_NETCOST_DATA",
    os.path.join(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")), "claude-netcost"),
)
LOG_FILE = os.path.join(DATA_DIR, "turns.jsonl")
INTERVAL = float(os.environ.get("CLAUDE_NETCOST_INTERVAL", "1.0"))
MAX_TURN_SECONDS = 6 * 3600

# IPv4/IPv6 + TCP header with timestamps option, per segment. Used for a rough
# on-the-wire estimate (payload counters exclude headers; TLS framing is
# already inside the payload).
HDR_V4 = 20 + 32
HDR_V6 = 40 + 32

# Known ranges, so the report can split API traffic from everything else.
# Extend in ~/.config/claude-netcost/labels.json: {"1.2.3.0/24": "name"}.
# api.anthropic.com and claude.ai (incl. remote-control relay) share these, so
# model calls and remote-control sync can't be told apart by address.
LABELS = {
    "160.79.104.0/23": "anthropic",
    "2607:6bc0::/48": "anthropic",
}

# Hostnames resolved (cached, see DNS_TTL) and labelled by the addresses they
# return. The Datadog names are the log/telemetry intakes built into the
# Claude Code binary; Datadog moves IPs around, so names beat pinned ranges.
# Extend in ~/.config/claude-netcost/hosts.json: {"host.example": "label"}.
HOST_LABELS = {
    "api.anthropic.com": "anthropic",
    "claude.ai": "anthropic",
    "downloads.claude.ai": "anthropic-updates",
    "github.com": "github",
    "api.github.com": "github",
    "http-intake.logs.us5.datadoghq.com": "datadog",
    "browser-intake-us5-datadoghq.com": "datadog",
    "http-intake.logs.datadoghq.com": "datadog",
    "browser-intake-datadoghq.com": "datadog",
    "http-intake.logs.datadoghq.eu": "datadog",
    "browser-intake-datadoghq.eu": "datadog",
    "http-intake.logs.us3.datadoghq.com": "datadog",
    "browser-intake-us3-datadoghq.com": "datadog",
}
DNS_TTL = 6 * 3600
# labels used by older versions of this tool, mapped to current ones
LEGACY_LABELS = {"anthropic-api": "anthropic", "datadog-telemetry": "datadog"}


ADJ = ("amber", "brisk", "calm", "dusky", "eager", "fern", "gilded", "hazel", "ivory", "jade",
       "keen", "lunar", "misty", "nimble", "ochre", "pale", "quiet", "russet", "slate", "tawny",
       "umber", "vivid", "woolly", "young", "zesty", "coral", "frosty", "mossy", "stormy", "sunny",
       "rusty", "silver")
NOUN = ("heron", "otter", "badger", "falcon", "marten", "lynx", "wren", "ibex", "stoat", "plover",
        "newt", "hare", "kestrel", "puffin", "beaver", "osprey", "vole", "curlew", "dormouse", "egret",
        "fox", "gannet", "hedgehog", "jay", "kite", "lark", "merlin", "nightjar", "owl", "pika",
        "raven", "swift")


# ---------------------------------------------------------------- helpers

def salt():
    """Per-machine secret used to pseudonymise session ids. Never leaves STATE_DIR."""
    path = os.path.join(STATE_DIR, "salt")
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        os.makedirs(STATE_DIR, exist_ok=True)
        key = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key


def pseudonym(session_id):
    """Stable, non-reversible id + friendly name for a Claude session."""
    h = hmac.new(salt(), session_id.encode(), hashlib.sha256).digest()
    sid = h[:6].hex()
    name = f"{ADJ[h[6] % len(ADJ)]}-{NOUN[h[7] % len(NOUN)]}-{sid[:4]}"
    return sid, name


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def read_hook_input():
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def proc_comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return None


def proc_ppid(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # comm may contain spaces/parens; fields after the last ')'
        return int(data[data.rindex(")") + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def find_claude_pid():
    """Walk up from the hook process to the Claude Code process."""
    pid = os.getppid()
    seen = 0
    while pid and pid > 1 and seen < 20:
        comm = proc_comm(pid) or ""
        if comm == "claude" or comm.startswith("claude"):
            return pid
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv0 = f.read().split(b"\0")[0].decode(errors="replace")
            if os.path.basename(argv0) == "claude":
                return pid
        except OSError:
            pass
        pid = proc_ppid(pid)
        seen += 1
    return None


def _children(pid):
    """Child pids via /proc/<pid>/task/*/children (cheap); None if unsupported."""
    kids = []
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return []
    for t in tasks:
        try:
            with open(f"/proc/{pid}/task/{t}/children") as f:
                kids.extend(int(x) for x in f.read().split())
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            pass
    return kids


def _children_map():
    children = defaultdict(list)
    for name in os.listdir("/proc"):
        if name.isdigit():
            ppid = proc_ppid(int(name))
            if ppid is not None:
                children[ppid].append(int(name))
    return children


def process_tree(root):
    """root plus all descendants, as {pid: comm}."""
    cmap = None
    tree = {}
    stack = [root]
    while stack:
        p = stack.pop()
        if p in tree:
            continue
        c = proc_comm(p)
        if c is None:
            continue
        tree[p] = c
        kids = _children(p)
        if kids is None:  # kernel without CONFIG_PROC_CHILDREN: full scan once
            if cmap is None:
                cmap = _children_map()
            kids = cmap.get(p, ())
        stack.extend(kids)
    return tree


def socket_inodes(pids):
    """{inode: pid} for sockets held open by the given pids."""
    inodes = {}
    for pid in pids:
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                inodes.setdefault(link[8:-1], pid)
    return inodes


def sample_sockets(pids):
    """Return {inode: {...counters}} for TCP sockets owned by any pid in pids.

    Ownership comes from /proc/<pid>/fd (only our tree), so `ss` runs without
    -p and doesn't have to scan every process on the machine.
    """
    owned = socket_inodes(pids)
    if not owned:
        return {}
    try:
        out = subprocess.run(
            ["ss", "-tineH", "state", "connected"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return {}
    socks = {}
    lines = out.splitlines()
    i = 0
    while i < len(lines):
        head = lines[i]
        info = lines[i + 1] if i + 1 < len(lines) and lines[i + 1][:1] in ("\t", " ") else ""
        i += 2 if info else 1
        parts = head.split()
        ino = None
        for tok in parts:
            if tok.startswith("ino:"):
                ino = tok[4:]
                break
        if ino not in owned or len(parts) < 5:
            continue
        rec = {
            "state": parts[0],
            "local": parts[3],
            "remote": parts[4],
            "pid": owned[ino],
            "sent": 0, "recv": 0, "segs_out": 0, "segs_in": 0, "retrans": 0,
        }
        for tok in info.split():
            k, _, v = tok.partition(":")
            try:
                if k == "bytes_sent":
                    rec["sent"] = int(v)
                elif k == "bytes_received":
                    rec["recv"] = int(v)
                elif k == "segs_out":
                    rec["segs_out"] = int(v)
                elif k == "segs_in":
                    rec["segs_in"] = int(v)
                elif k == "retrans":
                    rec["retrans"] = int(v.split("/")[-1])
            except ValueError:
                pass
        socks[ino] = rec
    return socks


def merge(acc, sample, tree):
    """Fold a sample into the accumulator: keep the highest counters seen."""
    for ino, rec in sample.items():
        cur = acc.get(ino)
        rec = dict(rec, comm=tree.get(rec["pid"], "?"))
        if cur is None:
            rec["base"] = None  # set by caller for the baseline sample
            acc[ino] = rec
        else:
            for k in ("sent", "recv", "segs_out", "segs_in", "retrans"):
                cur[k] = max(cur[k], rec[k])
            cur["state"] = rec["state"]


def state_path(session):
    safe = "".join(c for c in session if c.isalnum() or c in "-_") or "unknown"
    return os.path.join(STATE_DIR, f"{safe}.json")


def write_json_atomic(path, obj):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def dns_labels(refresh=True):
    """{ip: label} for HOST_LABELS. Cached in STATE_DIR; IPs once seen are kept,
    so traffic logged before a DNS change still gets its label."""
    path = os.path.join(STATE_DIR, "dns-cache.json")
    cache = load_json(path) or {}
    ips = {k: v for k, v in cache.get("ips", {}).items() if k not in ("0.0.0.0", "::")}
    if refresh and time.time() - cache.get("resolved", 0) > DNS_TTL:
        hosts = dict(HOST_LABELS)
        extra = load_json(os.path.expanduser("~/.config/claude-netcost/hosts.json"))
        if isinstance(extra, dict):
            hosts.update(extra)
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        try:
            for host, lab in hosts.items():
                try:
                    for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                        a = info[4][0]
                        ip = ipaddress.ip_address(a.split("%")[0])
                        # skip sinkholed/blocked answers (0.0.0.0, ::, private)
                        if ip.is_unspecified or ip.is_loopback or ip.is_private:
                            continue
                        ips[a] = lab
                except OSError:
                    pass
        finally:
            socket.setdefaulttimeout(old)
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            write_json_atomic(path, {"resolved": time.time(), "ips": ips})
        except OSError:
            pass
    return ips


def load_labels(refresh=True):
    labels = dict(LABELS)
    for ip, lab in dns_labels(refresh).items():
        labels[ip] = lab
    extra = load_json(os.path.expanduser("~/.config/claude-netcost/labels.json"))
    if isinstance(extra, dict):
        labels.update(extra)
    nets = []
    for k, v in labels.items():
        try:
            nets.append((ipaddress.ip_network(k, strict=False), v))
        except ValueError:
            pass
    # most specific first, so a single-IP label beats a broad range
    nets.sort(key=lambda nv: -nv[0].prefixlen)
    return nets


def relabel(row, labels):
    """Recompute by_label from by_remote with the current labels."""
    out = defaultdict(lambda: defaultdict(int))
    for remote, r in (row.get("by_remote") or {}).items():
        host, _ = split_hostport(remote)
        lab = label_for(host, labels)
        for k in ("query", "response", "query_wire", "response_wire"):
            out[lab][k] += r.get(k, 0)
    if not out:  # very old rows without by_remote
        for k, v in (row.get("by_label") or {}).items():
            for kk, vv in v.items():
                out[LEGACY_LABELS.get(k, k)][kk] += vv
    return {k: dict(v) for k, v in out.items()}


def telemetry_disabled():
    truthy = lambda v: (v or "").strip().lower() not in ("", "0", "false", "no")
    return truthy(os.environ.get("DISABLE_TELEMETRY")) or \
        truthy(os.environ.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"))


def split_hostport(addr):
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    if "%" in host:
        host = host.split("%")[0]
    return host, port


def label_for(host, labels):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "other"
    if ip.is_loopback:
        return "loopback"
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    for net, name in labels:
        if ip.version == net.version and ip in net:
            return name
    if ip.is_private:
        return "lan"
    return "other"


def is_real_prompt(entry):
    """A typed prompt, as opposed to a tool_result fed back to the model."""
    if entry.get("isMeta") or entry.get("isSidechain"):
        return False
    c = (entry.get("message") or {}).get("content")
    if isinstance(c, str):
        return True
    if isinstance(c, list):
        return not any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c)
    return False


def wait_transcript_settled(path, quiet=1.5, limit=15.0):
    """Wait until the transcript hasn't grown for `quiet` seconds (max `limit`)."""
    last, since, t0 = file_size(path), time.time(), time.time()
    while time.time() - t0 < limit:
        time.sleep(0.25)
        cur = file_size(path)
        if cur != last:
            last, since = cur, time.time()
        elif time.time() - since >= quiet:
            return


def transcript_usage(path, offset):
    """Sum usage from transcript lines written after byte offset."""
    res = {"api_requests": 0, "input_tokens": 0, "output_tokens": 0,
           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
           "models": []}
    if not path:
        return res
    seen = set()
    models = set()
    prompts = 0
    try:
        with open(path, "rb") as f:
            f.seek(offset or 0)
            for raw in f:
                try:
                    d = json.loads(raw)
                except ValueError:
                    continue
                t = d.get("type")
                if t == "user" and is_real_prompt(d):
                    prompts += 1
                    if prompts > 1:
                        break  # the next turn's prompt: stop here
                if t == "api-request":
                    res["api_requests"] += 1
                elif t == "assistant":
                    m = d.get("message") or {}
                    mid = m.get("id")
                    u = m.get("usage")
                    if not u or mid in seen:
                        continue
                    seen.add(mid)
                    if m.get("model"):
                        models.add(m["model"])
                    for k in ("input_tokens", "output_tokens",
                              "cache_read_input_tokens", "cache_creation_input_tokens"):
                        res[k] += int(u.get(k) or 0)
    except OSError:
        pass
    res["models"] = sorted(models)
    return res


def file_size(path):
    try:
        return os.path.getsize(path)
    except (OSError, TypeError):
        return 0


# ---------------------------------------------------------------- turn logic

def mid_turn_message(prev):
    """True if the turn in `prev` is still running, i.e. this prompt was typed
    mid-generation rather than after an Esc / crash."""
    cpid = prev.get("claude_pid")
    if not cpid or proc_comm(cpid) is None or cpid != find_claude_pid():
        return False
    if time.time() - prev.get("t0", 0) > MAX_TURN_SECONDS:
        return False
    spid = prev.get("sampler_pid")
    if spid and proc_comm(spid) is None:
        return False  # sampler gave up: turn is stale
    path, off = prev.get("transcript_path"), prev.get("transcript_offset") or 0
    if not path:
        return False
    try:
        with open(path, "rb") as f:
            f.seek(off)
            for raw in f:
                if b"Request interrupted by user" not in raw:
                    continue
                try:
                    d = json.loads(raw)
                except ValueError:
                    continue
                if d.get("type") == "user":
                    return False  # Esc: the old turn is over
    except OSError:
        return False
    return True


def start_turn(hook):
    os.makedirs(STATE_DIR, exist_ok=True)
    session = hook.get("session_id") or "unknown"
    sp = state_path(session)
    if os.path.exists(sp):
        prev = load_json(sp) or {}
        if mid_turn_message(prev):
            # A message typed while Claude was still working (Claude Code
            # queues it into the running turn). Same turn: keep counting.
            prev["extra_messages"] = prev.get("extra_messages", 0) + 1
            prev["prompt_chars"] = (prev.get("prompt_chars") or 0) + len(hook.get("prompt") or "")
            write_json_atomic(sp, prev)
            return
        # previous turn never got a Stop: Esc, crash, Claude restarted
        finish_turn(hook, status="interrupted")

    cpid = find_claude_pid()
    if not cpid:
        return
    tree = process_tree(cpid)
    acc = {}
    merge(acc, sample_sockets(tree), tree)
    for rec in acc.values():
        rec["base"] = {k: rec[k] for k in ("sent", "recv", "segs_out", "segs_in", "retrans")}
    prompt = hook.get("prompt") or ""
    sid, sname = pseudonym(session)
    turn_no = bump_turn_counter(sid)
    state = {
        "turn": turn_no,
        "session_id": session,
        "sid": sid,
        "session_name": sname,
        "claude_pid": cpid,
        "started": now_iso(),
        "t0": time.time(),
        "cwd": hook.get("cwd"),
        "prompt_chars": len(prompt),
        "telemetry_disabled": telemetry_disabled(),
        "transcript_path": hook.get("transcript_path"),
        "transcript_offset": file_size(hook.get("transcript_path")),
        "sockets": acc,
        "sampler_pid": None,
    }
    write_json_atomic(sp, state)
    p = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "sampler", session],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )
    state["sampler_pid"] = p.pid
    write_json_atomic(sp, state)


def sampler(session):
    sp = state_path(session)
    stop = {"flag": False}

    def _term(*_):
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    state = load_json(sp)
    if not state:
        return
    cpid = state["claude_pid"]
    while not stop["flag"]:
        time.sleep(INTERVAL)
        if stop["flag"]:
            break
        if proc_comm(cpid) is None or time.time() - state["t0"] > MAX_TURN_SECONDS:
            break
        cur = load_json(sp)
        if not cur or cur.get("sampler_pid") not in (None, os.getpid()):
            return  # turn finished or replaced
        tree = process_tree(cpid)
        merge(cur["sockets"], sample_sockets(tree), tree)
        if stop["flag"]:
            break
        write_json_atomic(sp, cur)
        state = cur


def finish_turn(hook, status="ok"):
    session = hook.get("session_id") or "unknown"
    sp = state_path(session)
    state = load_json(sp)
    if not state:
        return
    spid = state.get("sampler_pid")
    if spid:
        try:
            os.kill(spid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(40):  # let it finish an in-flight write
            if proc_comm(spid) is None or proc_ppid(spid) is None:
                break
            time.sleep(0.05)
        state = load_json(sp) or state

    cpid = state["claude_pid"]
    if proc_comm(cpid) is not None:
        tree = process_tree(cpid)
        merge(state["sockets"], sample_sockets(tree), tree)

    labels = load_labels(refresh=False)  # no DNS in the Stop hook; finalize refreshes
    zero = {"sent": 0, "recv": 0, "segs_out": 0, "segs_in": 0, "retrans": 0}
    by_remote = {}
    tot = defaultdict(int)
    by_label = defaultdict(lambda: defaultdict(int))
    conns_new = 0
    for rec in state["sockets"].values():
        base = rec.get("base") or zero
        d = {k: max(0, rec[k] - base[k]) for k in zero}
        if not (d["sent"] or d["recv"]):
            continue
        if rec.get("base") is None:
            conns_new += 1
        host, _port = split_hostport(rec["remote"])
        hdr = HDR_V6 if ":" in host and not host.startswith("::ffff:") else HDR_V4
        vals = {
            "query": d["sent"],
            "response": d["recv"],
            "query_wire": d["sent"] + d["segs_out"] * hdr,
            "response_wire": d["recv"] + d["segs_in"] * hdr,
        }
        lab = label_for(host, labels)
        r = by_remote.setdefault(rec["remote"], {"label": lab, "procs": [], "conns": 0, "retrans": 0,
                                                  **{k: 0 for k in vals}})
        r["conns"] += 1
        r["retrans"] += d["retrans"]
        if rec.get("comm") and rec["comm"] not in r["procs"]:
            r["procs"].append(rec["comm"])
        for k, v in vals.items():
            r[k] += v
            tot[k] += v
            by_label[lab][k] += v
        tot["retrans"] += d["retrans"]

    sid = state.get("sid") or pseudonym(session)[0]
    sname = state.get("session_name") or pseudonym(session)[1]
    row = {
        "started": state["started"],
        "ended": now_iso(),
        "duration_s": round(time.time() - state["t0"], 2),
        "status": status,
        "sid": sid,
        "session_name": sname,
        "turn": state.get("turn") or next_turn_number(sid),
        "project": os.path.basename((state.get("cwd") or "").rstrip("/")) or None,
        "prompt_chars": state.get("prompt_chars"),
        "extra_messages": state.get("extra_messages", 0),
        "telemetry_disabled": state.get("telemetry_disabled"),
        "query_bytes": tot["query"],
        "response_bytes": tot["response"],
        "query_wire": tot["query_wire"],
        "response_wire": tot["response_wire"],
        "retrans_segs": tot["retrans"],
        "new_conns": conns_new,
        "by_label": {k: dict(v) for k, v in by_label.items()},
        "by_remote": by_remote,
        "usage": None,
        "interval_s": INTERVAL,
    }
    pending = os.path.join(STATE_DIR, f"pending-{sid}-{row['turn']}.json")
    write_json_atomic(pending, {"row": row, "transcript_path": state.get("transcript_path"),
                                "transcript_offset": state.get("transcript_offset")})
    try:
        os.remove(sp)
    except OSError:
        pass
    # Claude Code writes the final reply to the transcript after Stop fires, so
    # the token count is read by a detached step once the transcript settles.
    subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "finalize", pending],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True,
    )


def finalize(pending):
    job = load_json(pending)
    if not job:
        return
    wait_transcript_settled(job.get("transcript_path"))
    row = job["row"]
    row["by_label"] = relabel(row, load_labels(refresh=True))
    row["usage"] = transcript_usage(job.get("transcript_path"), job.get("transcript_offset"))
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
    try:
        os.remove(pending)
    except OSError:
        pass
    if os.environ.get("CLAUDE_NETCOST_EXPORT"):
        export([os.environ["CLAUDE_NETCOST_EXPORT"]])


def bump_turn_counter(sid):
    path = os.path.join(STATE_DIR, f"turns-{sid}")
    try:
        with open(path) as f:
            n = int(f.read().strip() or 0)
    except (OSError, ValueError):
        n = next_turn_number(sid) - 1
    n += 1
    write_text_atomic(path, str(n))
    return n


def write_text_atomic(path, text):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def next_turn_number(sid):
    n = 0
    for r in load_rows():
        if r.get("sid") == sid:
            n = max(n, r.get("turn") or 0)
    return n + 1


# ---------------------------------------------------------------- reading the log

def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1000 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000


def load_rows():
    rows = []
    try:
        with open(LOG_FILE) as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def parse_opts(args, **defaults):
    opts = dict(defaults)
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--") and a[2:] in opts and i + 1 < len(args) and not isinstance(opts[a[2:]], bool):
            opts[a[2:]] = type(opts[a[2:]])(args[i + 1]) if opts[a[2:]] is not None else args[i + 1]
            i += 2
        elif a.startswith("--") and isinstance(opts.get(a[2:]), bool):
            opts[a[2:]] = True
            i += 1
        else:
            rest.append(a)
            i += 1
    return opts, rest


def report(args):
    opts, _ = parse_opts(args, last=20, session=None, json=False, tokens=False)
    rows = load_rows()
    aliases = load_aliases()
    if opts["session"]:
        want = opts["session"].lower()
        rows = [r for r in rows if want in (r.get("sid"), r.get("session_name"))
                or r.get("session_name", "").startswith(want)
                or aliases.get(r.get("sid"), "").lower().startswith(want)]
    if not rows:
        print(f"No turns logged yet ({LOG_FILE}).")
        return
    labels = load_labels()
    for r in rows:
        r["by_label"] = relabel(r, labels)
    if opts["json"]:
        for r in rows[-opts["last"]:]:
            print(json.dumps(r))
        return

    if opts["tokens"]:
        print(f"{'started (local)':16} {'session':22} {'#':>3} {'calls':>5} {'input':>6} {'cache rd':>9} "
              f"{'cache wr':>8} {'output':>7} {'ctx/call':>8} {'query':>9} {'response':>9} {'B/out':>6}")
        tt = defaultdict(int)
        for r in rows[-opts["last"]:]:
            t = datetime.fromisoformat(r["started"]).astimezone().strftime("%m-%d %H:%M:%S")
            u = (r.get("usage") or {})
            calls = u.get("api_requests", 0)
            tin = sum(u.get(k, 0) for k in ("input_tokens", "cache_read_input_tokens",
                                             "cache_creation_input_tokens"))
            for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens"):
                tt[k] += u.get(k, 0)
            ot = u.get("output_tokens", 0)
            print(f"{t:16} {display_name(r, aliases):22} {r['turn']:>3} {calls:>5} {u.get('input_tokens', 0):>6} "
                  f"{u.get('cache_read_input_tokens', 0):>9} {u.get('cache_creation_input_tokens', 0):>8} "
                  f"{ot:>7} {tin // max(calls, 1):>8} {human(r['query_bytes']):>9} "
                  f"{human(r['response_bytes']):>9} {r['response_bytes'] / ot if ot else 0:>6.0f}")
        print()
        print(f"tokens: input {tt['input_tokens']}, cache read {tt['cache_read_input_tokens']}, "
              f"cache write {tt['cache_creation_input_tokens']}, output {tt['output_tokens']}")
        print("(main conversation only; ctx/call = tokens processed per API call; B/out = response bytes per output token)")
        return

    print(f"{'started (local)':16} {'session':22} {'#':>3} {'dur':>5} {'query':>9} {'response':>9} "
          f"{'anth q':>9} {'anth r':>9} {'datadog':>9} {'reqs':>4} {'out tok':>7}  {'tel':3} status")
    for r in rows[-opts["last"]:]:
        t = datetime.fromisoformat(r["started"]).astimezone().strftime("%m-%d %H:%M:%S")
        api = r["by_label"].get("anthropic", {})
        dd = r["by_label"].get("datadog", {})
        u = (r.get("usage") or {})
        tel = {True: "off", False: "on"}.get(r.get("telemetry_disabled"), "?")
        print(f"{t:16} {display_name(r, aliases):22} {r['turn']:>3} {r['duration_s']:>4.0f}s "
              f"{human(r['query_bytes']):>9} {human(r['response_bytes']):>9} "
              f"{human(api.get('query', 0)):>9} {human(api.get('response', 0)):>9} "
              f"{human(dd.get('query', 0) + dd.get('response', 0)):>9} "
              f"{u.get('api_requests', 0):>4} {u.get('output_tokens', 0):>7}  {tel:3} {r['status']}"
              + (f" (+{r['extra_messages']} mid-turn msg)" if r.get("extra_messages") else ""))

    q = sum(r["query_bytes"] for r in rows)
    rs = sum(r["response_bytes"] for r in rows)
    qw = sum(r["query_wire"] for r in rows)
    rw = sum(r["response_wire"] for r in rows)
    print()
    print(f"{len(rows)} turns: queries {human(q)}, responses {human(rs)} (payload); "
          f"~{human(qw)} / ~{human(rw)} on the wire")
    print(f"  per turn on average: query {human(q / len(rows))}, response {human(rs / len(rows))}")
    labs = defaultdict(lambda: [0, 0])
    for r in rows:
        for k, v in r["by_label"].items():
            labs[k][0] += v.get("query", 0)
            labs[k][1] += v.get("response", 0)
    for k, (a, b) in sorted(labs.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {k:16} query {human(a):>9}   response {human(b):>9}")
    datadog_report(rows)


def datadog_report(rows):
    """How much Claude Code shipped to Datadog, split by the telemetry setting."""
    groups = {"on": [], "off": [], "?": []}
    for r in rows:
        groups[{True: "off", False: "on"}.get(r.get("telemetry_disabled"), "?")].append(r)
    print()
    print("Datadog (Claude Code log/telemetry shipping):")
    for key, title in (("on", "telemetry on"), ("off", "telemetry disabled"), ("?", "setting not recorded")):
        g = groups[key]
        if not g:
            continue
        dd_up = sum(r["by_label"].get("datadog", {}).get("query", 0) for r in g)
        dd_dn = sum(r["by_label"].get("datadog", {}).get("response", 0) for r in g)
        up = sum(r["query_bytes"] for r in g)
        hit = sum(1 for r in g if r["by_label"].get("datadog"))
        share = f"{100 * dd_up / up:.1f}% of upload" if up else "-"
        print(f"  {title:21} {len(g):>4} turns: {human(dd_up)} up / {human(dd_dn)} down "
              f"({share}), in {hit} of {len(g)} turns")
    if groups["off"] and any(r["by_label"].get("datadog") for r in groups["off"]):
        print("  note: Datadog traffic seen even with telemetry disabled")


def export(args):
    """Write a publish-safe JSON summary for the websites.

    Contains no raw session ids, no paths, no IPs - only pseudonymous session
    ids/names, per-turn byte counts, per-label splits and token counts.
    """
    opts, rest = parse_opts(args, days=90, names=False)
    aliases = load_aliases() if opts["names"] else {}
    out = rest[0] if rest else os.path.join(DATA_DIR, "public", "claude-netcost.json")
    cutoff = time.time() - opts["days"] * 86400
    turns = []
    sessions = {}
    labels = load_labels()
    for r in load_rows():
        r["by_label"] = relabel(r, labels)
        try:
            ts = datetime.fromisoformat(r["started"]).timestamp()
        except (KeyError, ValueError):
            continue
        if ts < cutoff:
            continue
        u = (r.get("usage") or {})
        t = {
            "started": r["started"],
            "duration_s": r["duration_s"],
            "status": r["status"],
            "sid": r["sid"],
            "session_name": r["session_name"],
            **({"alias": aliases[r["sid"]]} if r["sid"] in aliases else {}),
            "turn": r["turn"],
            "query_bytes": r["query_bytes"],
            "response_bytes": r["response_bytes"],
            "query_wire": r["query_wire"],
            "response_wire": r["response_wire"],
            "by_label": {k: {"query": v.get("query", 0), "response": v.get("response", 0)}
                         for k, v in r["by_label"].items()},
            "api_requests": u.get("api_requests", 0),
            "input_tokens": u.get("input_tokens", 0),
            "cache_read_tokens": u.get("cache_read_input_tokens", 0),
            "cache_write_tokens": u.get("cache_creation_input_tokens", 0),
            "output_tokens": u.get("output_tokens", 0),
            "models": u.get("models", []),
            "telemetry_disabled": r.get("telemetry_disabled"),
        }
        turns.append(t)
        s = sessions.setdefault(r["sid"], {"sid": r["sid"], "session_name": r["session_name"],
                                           **({"alias": aliases[r["sid"]]} if r["sid"] in aliases else {}),
                                           "first": r["started"], "last": r["started"], "turns": 0,
                                           "query_bytes": 0, "response_bytes": 0})
        s["last"] = r["started"]
        s["turns"] += 1
        s["query_bytes"] += r["query_bytes"]
        s["response_bytes"] += r["response_bytes"]
    doc = {
        "generated": now_iso(),
        "schema": 1,
        "window_days": opts["days"],
        "notes": "Bytes are TCP payload (TLS included) counted from kernel tcp_info for the "
                 "Claude Code process tree; *_wire adds an IP+TCP header estimate per segment.",
        "totals": {
            "datadog_query_bytes": sum(t["by_label"].get("datadog", {}).get("query", 0) for t in turns),
            "datadog_response_bytes": sum(t["by_label"].get("datadog", {}).get("response", 0) for t in turns),
            "turns": len(turns),
            "query_bytes": sum(t["query_bytes"] for t in turns),
            "response_bytes": sum(t["response_bytes"] for t in turns),
        },
        "sessions": sorted(sessions.values(), key=lambda s: s["last"], reverse=True),
        "turns": turns,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    write_json_atomic(out, doc)
    if sys.stdout.isatty():
        print(f"wrote {out} ({len(turns)} turns, {len(sessions)} sessions)")


ALIAS_FILE = os.path.join(STATE_DIR, "aliases.json")


def load_aliases():
    a = load_json(ALIAS_FILE)
    return a if isinstance(a, dict) else {}


def display_name(row, aliases):
    alias = aliases.get(row.get("sid"))
    return alias[:22] if alias else row.get("session_name", "?")


def resolve_session(ref):
    """Accept a pseudonym (or prefix), a 12-hex sid, or a real Claude session id."""
    rows = load_rows()
    known = {}
    for r in rows:
        known[r["sid"]] = r["session_name"]
    if ref in known:
        return ref, known[ref]
    aliases = load_aliases()
    hits = {sid: name for sid, name in known.items() if name == ref or name.startswith(ref)}
    if not hits:
        low = ref.lower()
        exact = {sid: known.get(sid, a) for sid, a in aliases.items() if a.lower() == low}
        hits = exact or {sid: known.get(sid, a) for sid, a in aliases.items()
                         if a.lower().startswith(low)}
    if len(hits) == 1:
        return next(iter(hits.items()))
    if len(hits) > 1:
        raise SystemExit(f"'{ref}' matches several sessions: {', '.join(sorted(hits.values()))}")
    if len(ref) >= 32:  # looks like a real Claude session id: hash it
        return pseudonym(ref)
    raise SystemExit(f"no session matches '{ref}' (try a name from `report`, or the real session id)")


def name_cmd(args):
    """name                      list aliases
    name <session> <alias...>   set an alias (session = pseudonym, sid or real session id)
    name <session> --clear      remove it"""
    aliases = load_aliases()
    if not args:
        if not aliases:
            print("No aliases yet. Set one: netcost.py name <session> <alias>")
        known = {r["sid"]: r["session_name"] for r in load_rows()}
        for sid, alias in sorted(aliases.items(), key=lambda kv: kv[1].lower()):
            print(f"{alias:30} {known.get(sid, '(no turns logged)')}  ({sid})")
        return
    sid, pname = resolve_session(args[0])
    if args[1:] == ["--clear"]:
        aliases.pop(sid, None)
        msg = f"cleared alias for {pname}"
    elif len(args) >= 2:
        aliases[sid] = " ".join(args[1:]).strip()
        msg = f"{pname} ({sid}) -> {aliases[sid]}"
    else:
        print(f"{pname} ({sid}): {aliases.get(sid, 'no alias')}")
        return
    os.makedirs(STATE_DIR, exist_ok=True)
    write_json_atomic(ALIAS_FILE, aliases)
    os.chmod(ALIAS_FILE, 0o600)
    print(msg)


def merge_cmd(args):
    """merge <session> <turn>   fold turn N+1 into turn N (a turn wrongly split)"""
    if len(args) != 2 or not args[1].isdigit():
        raise SystemExit("usage: netcost.py merge <session> <turn>   (merges turn and turn+1)")
    sid, pname = resolve_session(args[0])
    n = int(args[1])
    rows = load_rows()
    idx = {r.get("turn"): i for i, r in enumerate(rows) if r.get("sid") == sid}
    if n not in idx or n + 1 not in idx:
        raise SystemExit(f"{pname}: need turns {n} and {n + 1} in the log")
    a, b = rows[idx[n]], rows[idx[n + 1]]
    m = dict(a)
    m["ended"] = b["ended"]
    m["duration_s"] = round(datetime.fromisoformat(b["ended"]).timestamp()
                            - datetime.fromisoformat(a["started"]).timestamp(), 2)
    m["status"] = b["status"]
    for k in ("query_bytes", "response_bytes", "query_wire", "response_wire",
              "retrans_segs", "new_conns", "prompt_chars"):
        m[k] = (a.get(k) or 0) + (b.get(k) or 0)
    m["extra_messages"] = (a.get("extra_messages") or 0) + (b.get("extra_messages") or 0) + 1
    br = json.loads(json.dumps(a.get("by_remote") or {}))
    for remote, rb in (b.get("by_remote") or {}).items():
        ra = br.setdefault(remote, {"label": rb.get("label"), "procs": [], "conns": 0, "retrans": 0})
        for k, v in rb.items():
            if isinstance(v, int):
                ra[k] = ra.get(k, 0) + v
        ra["procs"] = sorted(set(ra.get("procs", [])) | set(rb.get("procs", [])))
    m["by_remote"] = br
    m["by_label"] = relabel(m, load_labels(refresh=False))
    ua, ub = a.get("usage") or {}, b.get("usage") or {}
    m["usage"] = {k: (ua.get(k) or 0) + (ub.get(k) or 0) for k in
                  ("api_requests", "input_tokens", "output_tokens",
                   "cache_read_input_tokens", "cache_creation_input_tokens")}
    m["usage"]["models"] = sorted(set(ua.get("models", [])) | set(ub.get("models", [])))
    m["merged"] = True
    out = []
    for i, r in enumerate(rows):
        if i == idx[n + 1]:
            continue
        if i == idx[n]:
            r = m
        elif r.get("sid") == sid and (r.get("turn") or 0) > n + 1:
            r = dict(r, turn=r["turn"] - 1)  # close the gap
        out.append(r)
    backup = f"{LOG_FILE}.bak-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    with open(LOG_FILE) as src, open(backup, "w") as dst:
        dst.write(src.read())
    tmp = f"{LOG_FILE}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        for r in out:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    os.replace(tmp, LOG_FILE)
    for sp in os.listdir(STATE_DIR):  # a turn in flight for this session
        if sp.endswith(".json") and sp.count("-") >= 4:
            st = load_json(os.path.join(STATE_DIR, sp)) or {}
            if st.get("sid") == sid and (st.get("turn") or 0) > n + 1:
                st["turn"] -= 1
                write_json_atomic(os.path.join(STATE_DIR, sp), st)
    cpath = os.path.join(STATE_DIR, f"turns-{sid}")
    try:
        with open(cpath) as f:
            write_text_atomic(cpath, str(max(0, int(f.read().strip()) - 1)))
    except (OSError, ValueError):
        pass
    print(f"{pname}: merged turns {n} and {n + 1} (backup: {backup})")


def whois(args):
    """Map a real Claude session id to its pseudonym (local only, needs the salt)."""
    if not args:
        print("usage: netcost.py whois <claude-session-id>", file=sys.stderr)
        sys.exit(2)
    for a in args:
        sid, name = pseudonym(a)
        print(f"{a} -> {name} ({sid})")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    if cmd == "start":
        start_turn(read_hook_input())
    elif cmd == "stop":
        finish_turn(read_hook_input())
    elif cmd == "end":
        finish_turn(read_hook_input(), status="session-end")
    elif cmd == "sampler":
        sampler(sys.argv[2])
    elif cmd == "finalize":
        finalize(sys.argv[2])
    elif cmd == "report":
        report(sys.argv[2:])
    elif cmd == "export":
        export(sys.argv[2:])
    elif cmd == "whois":
        whois(sys.argv[2:])
    elif cmd == "name":
        name_cmd(sys.argv[2:])
    elif cmd == "merge":
        merge_cmd(sys.argv[2:])
    else:
        print("usage: netcost.py report [--last N] [--session NAME] [--json]\n"
              "       netcost.py export [PATH] [--days N]\n"
              "       netcost.py whois <claude-session-id>\n"
              "       netcost.py name [<session> <alias...> | <session> --clear]\n"
              "       netcost.py merge <session> <turn>   (fold turn+1 into turn)\n"
              "  (hooks: start | stop | end)", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never break Claude Code because of a hook
        if sys.argv[1:2] in (["start"], ["stop"], ["end"], ["sampler"], ["finalize"]):
            try:
                os.makedirs(STATE_DIR, exist_ok=True)
                with open(os.path.join(STATE_DIR, "errors.log"), "a") as f:
                    f.write(f"{now_iso()} {sys.argv[1]}: {e!r}\n")
            except OSError:
                pass
            sys.exit(0)
        raise
