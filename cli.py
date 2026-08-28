#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.9.0", "httpx>=0.27", "cryptography>=42", "secretstorage>=3.3"]
# ///
"""Setup and diagnostics for the Airflow MCP server: doctor, login, browser, setup."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import httpx

from auth import (
    cookies_for_host,
    get_token,
    jwt_expiry,
    load_env,
    load_registry,
    login,
    resolve_url,
    write_cache,
)
from client import USER_AGENT

HERE = Path(__file__).parent


def _envs(selected: str | None):
    registry, default = load_registry()
    if selected:
        if selected not in registry:
            raise SystemExit(f"unknown environment '{selected}', available: {', '.join(registry)}")
        return [registry[selected]], default
    return list(registry.values()), default


def cmd_doctor(args: argparse.Namespace) -> int:
    envs, default = _envs(args.env)
    failures = 0
    for env in envs:
        mark = " (default)" if env.name == default else ""
        print(f"\n[{env.name}]{mark}")
        try:
            url = resolve_url(env, force=args.refresh)
            print(f"  url        {url}")
        except Exception as exc:
            print(f"  url        UNREACHABLE: {exc}")
            failures += 1
            continue

        try:
            r = httpx.get(f"{url}/api/v2/version", timeout=10, follow_redirects=True)
            print(f"  version    {r.json().get('version')}")
        except Exception as exc:
            print(f"  version    unknown: {exc}")

        cookies = cookies_for_host(env.host)
        print(f"  cookies    {', '.join(sorted(cookies)) or 'none in local browsers'}")

        try:
            token, jar, source = get_token(env, force=args.refresh)
        except Exception as exc:
            print(f"  token      NO: {exc}")
            failures += 1
            continue
        exp = jwt_expiry(token)
        print(f"  token      via {source}" + (f", expires unix {int(exp)}" if exp else ""))

        try:
            r = httpx.get(
                f"{url}/api/v2/dags",
                params={"limit": 1},
                headers={"Authorization": f"Bearer {token}", "User-Agent": USER_AGENT},
                cookies=jar or None,
                timeout=env.timeout,
                follow_redirects=True,
            )
            if r.status_code == 200:
                print(f"  api        ok, {r.json().get('total_entries')} dags visible")
            else:
                print(f"  api        NO: {r.status_code} {r.text[:160]}")
                failures += 1
        except Exception as exc:
            print(f"  api        NO: {exc}")
            failures += 1

        print(f"  readonly   {env.readonly}")
    return 1 if failures else 0


def cmd_browser(args: argparse.Namespace) -> int:
    from auth import token_from_browser

    envs, _ = _envs(args.env)
    failures = 0
    for env in envs:
        try:
            token, cookies = token_from_browser(env, args.cookie)
            write_cache(env, token, "browser", cookies)
            exp = jwt_expiry(token)
            print(f"{env.name}: token imported" + (f", expires unix {int(exp)}" if exp else ""))
        except Exception as exc:
            print(f"{env.name}: {exc}")
            failures += 1
    return 1 if failures else 0


def cmd_login(args: argparse.Namespace) -> int:
    envs, _ = _envs(args.env or "local")
    env = envs[0]
    username = args.username or input(f"[{env.name}] username: ")
    password = args.password or getpass.getpass(f"[{env.name}] password: ")
    token = login(env, username, password)
    write_cache(env, token, "password")
    print(f"token stored in {env.cache_file}")
    if args.save:
        path = HERE / ".env"
        prefix = f"AIRFLOW_MCP_{env.name.upper()}_"
        lines = [l for l in (path.read_text().splitlines() if path.exists() else [])
                 if not l.startswith((f"{prefix}USERNAME=", f"{prefix}PASSWORD="))]
        lines += [f"{prefix}USERNAME={username}", f"{prefix}PASSWORD={password}"]
        path.write_text("\n".join(lines) + "\n")
        path.chmod(0o600)
        print(f"credentials saved to {path}, {env.name} refreshes itself from now on")
    return 0


def cmd_cookies(args: argparse.Namespace) -> int:
    """Where cookies come from and why they fail to decrypt. Prints names and sizes, never values."""
    from auth import _chromium_dbs, _chromium_keys, _firefox_dbs, _query_sqlite, _clean_cookie_bytes

    envs, _ = _envs(args.env)
    host = envs[0].host
    print(f"host: {host}\n")

    try:
        import secretstorage

        conn = secretstorage.dbus_init()
        labels = []
        for coll in secretstorage.get_all_collections(conn):
            state = "locked" if coll.is_locked() else "unlocked"
            labels.append(f"{coll.get_label()} [{state}]")
            if not coll.is_locked():
                for item in coll.get_all_items():
                    if "Safe Storage" in (item.get_label() or ""):
                        labels.append(f"  found item: {item.get_label()}")
        print("keyring collections:", labels or "none")
    except Exception as exc:
        print(f"keyring unavailable: {type(exc).__name__}: {exc}")

    keys = _chromium_keys()
    print(f"candidate keys: {len(keys)} (keyring first, 'peanuts' last)\n")

    for db in _firefox_dbs():
        rows = _query_sqlite(db, "SELECT name, value FROM moz_cookies WHERE host LIKE ?", (f"%{host}%",))
        print(f"firefox {db}: {[name for name, _ in rows] or 'no cookies'}")

    for db in _chromium_dbs():
        try:
            rows = _query_sqlite(
                db,
                "SELECT name, host_key, length(value), encrypted_value FROM cookies WHERE host_key LIKE ?",
                (f"%{host}%",),
            )
        except Exception as exc:
            print(f"chromium {db}: unreadable ({exc})")
            continue
        print(f"chromium {db}: {len(rows)} cookies")
        for name, host_key, plain_len, enc in rows:
            prefix = bytes(enc or b"")[:3]
            decrypted = _chromium_decrypt_report(enc, keys, _clean_cookie_bytes)
            print(f"  {name:<20} host={host_key:<28} prefix={prefix!r:<8} plain_len={plain_len} -> {decrypted}")
    return 0


def _chromium_decrypt_report(enc: bytes, keys: list, cleaner) -> str:
    """Try every key and report which one produced printable ascii, without exposing the value."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from auth import _unpad

    if not enc:
        return "no encrypted value"
    prefix, body = bytes(enc)[:3], bytes(enc)[3:]
    for index, key in enumerate(keys):
        try:
            if prefix in (b"v10", b"v11"):
                plain = _unpad(Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor().update(body))
            elif prefix == b"v20":
                plain = AESGCM(key).decrypt(body[:12], body[12:], None)
            else:
                return "unencrypted"
        except Exception as exc:
            return f"key#{index} error {type(exc).__name__}"
        text = cleaner(plain)
        if text:
            return f"OK with key#{index}, len={len(text)}, jwt={text.count('.') == 2}"
    return "no key produced printable ascii"


def cmd_deps(args: argparse.Namespace) -> int:
    """What the script environment actually resolved, for import troubleshooting."""
    import importlib
    import importlib.metadata as md
    import pkgutil

    for dist in ("mcp", "httpx", "cryptography", "secretstorage"):
        try:
            print(f"{dist}: {md.version(dist)}")
        except Exception as exc:
            print(f"{dist}: not installed ({exc})")

    try:
        import mcp

        print(f"mcp path: {mcp.__file__}")
        import mcp.server as server_pkg

        print("mcp.server submodules:", sorted(m.name for m in pkgutil.iter_modules(server_pkg.__path__)))
    except Exception as exc:
        print(f"mcp import failed: {exc}")
        return 1

    for candidate in ("mcp", "mcp.server", "mcp.server.mcpserver"):
        try:
            module = importlib.import_module(candidate)
            names = [n for n in dir(module) if n[0].isupper()]
            print(f"{candidate}: {names}")
        except Exception as exc:
            print(f"{candidate}: import error ({exc})")

    try:
        from mcp.server.mcpserver import MCPServer

        print("MCPServer methods:", [n for n in dir(MCPServer) if not n.startswith('_')])
    except Exception as exc:
        print(f"MCPServer probe failed: {exc}")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Boot the MCP server in-process, list its tools, call one against a real instance."""
    import asyncio

    import server as srv

    async def run() -> int:
        tools = await srv.mcp.list_tools()
        print(f"tools registered: {len(tools)}")
        for tool in tools:
            print(f"  {tool.name}")

        target = args.env or srv.REG.default
        print(f"\ncalling airflow_status(env={target})")
        try:
            result = await srv.mcp.call_tool("airflow_status", {"env": target})
        except Exception as exc:
            print(f"  FAILED: {exc}")
            return 1
        payload = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
        if payload is None:
            content = getattr(result, "content", result)
            if isinstance(content, list):
                payload = [getattr(block, "text", str(block)) for block in content]
            else:
                payload = content
        print(json.dumps(payload, indent=2, default=str)[:2000])
        return 0

    return asyncio.run(run())


def cmd_queue_load(args: argparse.Namespace) -> int:
    """How busy one Celery queue is: occupancy, peak parallelism, failures, idle gaps."""
    import asyncio
    from datetime import datetime, timedelta, timezone

    sys.path.insert(0, str(HERE))
    from client import Registry

    registry = Registry()
    client = registry.client(args.env)
    window_start = datetime.now(timezone.utc) - timedelta(hours=args.hours)

    def parse(stamp: str | None):
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None

    async def run() -> int:
        # The API ignores start_date filters for rows that never ran, so page through
        # everything on the queue and window it here.
        collected, offset, total = [], 0, None
        while total is None or offset < total:
            page = await client.get(
                "/api/v2/dags/~/dagRuns/~/taskInstances",
                params={"queue": args.queue, "limit": 100, "offset": offset, "order_by": "-start_date"},
            )
            items = page.get("task_instances", [])
            total = page.get("total_entries", 0)
            collected += items
            offset += len(items)
            if not items:
                break

        pending = [t for t in collected if t.get("state") in ("queued", "scheduled", "running")]
        ran = [t for t in collected if parse(t.get("start_date")) and parse(t["start_date"]) >= window_start]

        print(f"queue        {args.queue} on {client.env.name}")
        print(f"known tasks  {len(collected)} total on this queue, {len(pending)} queued or running now")
        if not ran:
            print(f"window       nothing executed in the last {args.hours}h")
            return 0

        states: dict[str, int] = {}
        hosts: set[str] = set()
        spans = []
        busy = 0.0
        for ti in ran:
            states[ti.get("state") or "none"] = states.get(ti.get("state") or "none", 0) + 1
            if ti.get("hostname"):
                hosts.add(ti["hostname"])
            start, end, duration = parse(ti.get("start_date")), parse(ti.get("end_date")), ti.get("duration")
            if start and end and duration:
                spans.append((start, end))
                busy += float(duration)

        events = sorted([(s, 1) for s, _ in spans] + [(e, -1) for _, e in spans])
        peak = running = 0
        for _, delta in events:
            running += delta
            peak = max(peak, running)

        window_seconds = args.hours * 3600
        print(f"window       last {args.hours}h")
        print(f"executed     {len(ran)} ({', '.join(f'{k}={v}' for k, v in sorted(states.items()))})")
        print(f"workers seen {len(hosts)}: {', '.join(sorted(hosts)) or 'none'}")
        print(f"busy time    {busy / 3600:.2f} worker-hours")
        print(f"occupancy    {busy / window_seconds:.2f} tasks running on average")
        print(f"peak         {peak} tasks in parallel")
        return 0

    return asyncio.run(run())


def cmd_setup(args: argparse.Namespace) -> int:
    target = Path(args.project).expanduser().resolve()
    path = target / ".mcp.json"
    data = json.loads(path.read_text()) if path.exists() else {}
    servers = data.setdefault("mcpServers", {})
    servers[args.name] = {
        "command": "uv",
        "args": ["run", "--quiet", "--script", str(HERE / "server.py")],
    }
    path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"registered '{args.name}' in {path}")
    return 0


def main() -> int:
    load_env()
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--env", default=argparse.SUPPRESS, help="limit to one environment: prod, stage, test, local"
    )

    parser = argparse.ArgumentParser(description=__doc__, parents=[common])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", parents=[common], help="check every environment: url, cookies, token, API")
    p.add_argument("--refresh", action="store_true", help="ignore caches and probe again")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("browser", parents=[common], help="import session tokens from local browser cookies")
    p.add_argument("--cookie", default="_token")
    p.set_defaults(func=cmd_browser)

    p = sub.add_parser("login", parents=[common], help="username and password login, for instances without SSO")
    p.add_argument("-u", "--username")
    p.add_argument("-p", "--password")
    p.add_argument("--save", action="store_true", help="store credentials in .env for auto refresh")
    p.set_defaults(func=cmd_login)

    sub.add_parser("deps", parents=[common], help="show resolved packages and FastMCP location").set_defaults(
        func=cmd_deps
    )

    sub.add_parser("cookies", parents=[common], help="diagnose browser cookie decryption").set_defaults(
        func=cmd_cookies
    )

    p = sub.add_parser("selftest", parents=[common], help="boot the MCP server and call a tool for real")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("queue-load", parents=[common], help="how busy a celery queue is")
    p.add_argument("--queue", default="ingest")
    p.add_argument("--hours", type=int, default=24)
    p.set_defaults(func=cmd_queue_load)

    p = sub.add_parser("setup", parents=[common], help="register the server in a project .mcp.json")
    p.add_argument("project", nargs="?", default=str(HERE.parent))
    p.add_argument("--name", default="airflow")
    p.set_defaults(func=cmd_setup)

    args = parser.parse_args()
    if not hasattr(args, "env"):
        args.env = None
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
