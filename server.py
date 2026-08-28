#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp>=1.9.0", "httpx>=0.27", "cryptography>=42", "secretstorage>=3.3"]
# ///
"""MCP server for Apache Airflow 3 (REST API v2) across every configured instance."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

try:
    from mcp.server.mcpserver import MCPServer  # SDK 2.x
except ImportError:  # SDK 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

from auth import load_env
from client import DAG_KEYS, RUN_KEYS, TI_KEYS, Registry, slim

load_env()
REG = Registry()
ENVS = ", ".join(REG.names())
mcp = MCPServer("airflow")


def api(env: str | None):
    return REG.client(env)


@mcp.tool()
async def airflow_environments() -> dict:
    """Which Airflow instances this server can reach and how each one is authenticated.

    Every other tool takes an `env` argument with one of these names.
    """
    out = {}
    for name in REG.names():
        env = REG.env(name)
        out[name] = {
            "url": env.url,
            "auth": env.auth,
            "readonly": env.readonly,
            "default": name == REG.default,
        }
    return {"default": REG.default, "environments": out}


@mcp.tool()
async def airflow_status(env: str | None = None) -> dict:
    """Health of one instance: version, components, import errors, DAGs whose last run failed.

    Call this first when something looks wrong. Use `airflow_environments` for the valid `env` names.
    """
    client = api(env)
    version = await client.get("/api/v2/version")
    health = await client.get("/api/v2/monitor/health")
    errors = await client.get("/api/v2/importErrors", params={"limit": 5})
    failing = await client.get("/api/v2/dags", params={"limit": 20, "last_dag_run_state": "failed", "paused": False})
    return {
        "env": client.env.name,
        "url": client.env.url,
        "token_source": client.token_source,
        "readonly": client.env.readonly,
        "version": version.get("version"),
        "health": {k: v.get("status") for k, v in health.items()},
        "import_error_count": errors.get("total_entries", 0),
        "import_errors": [slim(e, ["filename", "stack_trace"]) for e in errors.get("import_errors", [])],
        "dags_with_failed_last_run": [d["dag_id"] for d in failing.get("dags", [])],
    }


@mcp.tool()
async def list_dags(
    pattern: str | None = None,
    tags: list[str] | None = None,
    owners: list[str] | None = None,
    paused: bool | None = None,
    last_run_state: str | None = None,
    limit: int = 50,
    env: str | None = None,
) -> dict:
    """List DAGs. `pattern` matches part of the dag_id, `last_run_state` is queued/running/success/failed."""
    data = await api(env).get(
        "/api/v2/dags",
        params={
            "dag_id_pattern": pattern,
            "tags": tags,
            "owners": owners,
            "paused": paused,
            "last_dag_run_state": last_run_state,
            "limit": limit,
        },
    )
    return {"total": data.get("total_entries"), "dags": [slim(d, DAG_KEYS) for d in data.get("dags", [])]}


@mcp.tool()
async def get_dag(dag_id: str, runs: int = 5, env: str | None = None) -> dict:
    """DAG details, its tasks, and the most recent runs."""
    client = api(env)
    details = await client.get(f"/api/v2/dags/{dag_id}/details")
    tasks = await client.get(f"/api/v2/dags/{dag_id}/tasks")
    recent = await client.get(f"/api/v2/dags/{dag_id}/dagRuns", params={"limit": runs, "order_by": "-run_after"})
    return {
        "env": client.env.name,
        "dag": slim(details, DAG_KEYS + ["schedule_interval", "start_date", "catchup", "max_active_runs", "doc_md"]),
        "tasks": [slim(t, ["task_id", "operator_name", "trigger_rule", "retries", "downstream_task_ids"])
                  for t in tasks.get("tasks", [])],
        "recent_runs": [slim(r, RUN_KEYS) for r in recent.get("dag_runs", [])],
    }


@mcp.tool()
async def list_dag_runs(
    dag_id: str = "~",
    state: list[str] | None = None,
    run_after_gte: str | None = None,
    limit: int = 20,
    env: str | None = None,
) -> dict:
    """DAG runs, newest first. `dag_id="~"` covers every DAG. Dates are ISO 8601."""
    body: dict[str, Any] = {"page_limit": limit, "order_by": "-run_after"}
    if state:
        body["states"] = state
    if run_after_gte:
        body["run_after_gte"] = run_after_gte
    if dag_id != "~":
        body["dag_ids"] = [dag_id]
    data = await api(env).post("/api/v2/dags/~/dagRuns/list", json=body)
    return {"total": data.get("total_entries"), "runs": [slim(r, RUN_KEYS) for r in data.get("dag_runs", [])]}


@mcp.tool()
async def list_task_instances(
    dag_id: str = "~",
    dag_run_id: str = "~",
    state: list[str] | None = None,
    task_id: str | None = None,
    start_date_gte: str | None = None,
    limit: int = 50,
    env: str | None = None,
) -> dict:
    """Task instances across DAGs and runs. `state=["failed"]` shows what is broken right now."""
    data = await api(env).get(
        f"/api/v2/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances",
        params={
            "state": state,
            "task_id": task_id,
            "start_date_gte": start_date_gte,
            "limit": limit,
            "order_by": "-start_date",
        },
    )
    return {
        "total": data.get("total_entries"),
        "task_instances": [slim(t, TI_KEYS) for t in data.get("task_instances", [])],
    }


def _log_line(chunk: Any) -> str:
    if not isinstance(chunk, dict):
        return str(chunk)
    parts = [str(chunk[k]) for k in ("timestamp", "level") if chunk.get(k)]
    parts.append(str(chunk.get("event", "")))
    return " ".join(parts)


@mcp.tool()
async def get_task_log(
    dag_id: str,
    dag_run_id: str,
    task_id: str,
    try_number: int | None = None,
    map_index: int = -1,
    tail_chars: int = 8000,
    env: str | None = None,
) -> dict:
    """Log of one task try. Defaults to the latest try and returns the tail, where the error lives."""
    client = api(env)
    if try_number is None:
        ti = await client.get(
            f"/api/v2/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances/{task_id}",
            params={"map_index": map_index} if map_index >= 0 else None,
        )
        try_number = ti.get("try_number") or 1

    data = await client.get(
        f"/api/v2/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances/{task_id}/logs/{try_number}",
        params={"full_content": True, "map_index": map_index if map_index >= 0 else None},
    )
    content = data.get("content", data)
    if isinstance(content, list):
        text = "\n".join(_log_line(c) for c in content)
    else:
        text = content if isinstance(content, str) else json.dumps(content)

    truncated = len(text) > tail_chars
    return {
        "env": client.env.name,
        "dag_id": dag_id,
        "dag_run_id": dag_run_id,
        "task_id": task_id,
        "try_number": try_number,
        "truncated_head": truncated,
        "log": text[-tail_chars:] if truncated else text,
    }


@mcp.tool()
async def trigger_dag(
    dag_id: str,
    conf: dict | None = None,
    logical_date: str | None = None,
    dag_run_id: str | None = None,
    note: str | None = None,
    env: str | None = None,
) -> dict:
    """Trigger a DAG run. `logical_date` is ISO 8601; omit it for a plain manual run."""
    REG.guard_write(env)
    body: dict[str, Any] = {"logical_date": logical_date}
    for key, value in (("conf", conf), ("dag_run_id", dag_run_id), ("note", note)):
        if value is not None:
            body[key] = value
    client = api(env)
    run = await client.post(f"/api/v2/dags/{dag_id}/dagRuns", json=body)
    return {"env": client.env.name, **slim(run, RUN_KEYS)}


@mcp.tool()
async def set_dag_paused(dag_id: str, paused: bool, env: str | None = None) -> dict:
    """Pause or unpause a DAG."""
    REG.guard_write(env)
    dag = await api(env).patch(
        f"/api/v2/dags/{dag_id}", json={"is_paused": paused}, params={"update_mask": "is_paused"}
    )
    return slim(dag, DAG_KEYS)


@mcp.tool()
async def clear_tasks(
    dag_id: str,
    dag_run_id: str | None = None,
    task_ids: list[str] | None = None,
    only_failed: bool = True,
    include_downstream: bool = False,
    include_upstream: bool = False,
    reset_dag_runs: bool = True,
    dry_run: bool = True,
    env: str | None = None,
) -> dict:
    """Clear task instances so they rerun. Dry run by default: check the list, then pass dry_run=False."""
    if not dry_run:
        REG.guard_write(env)
    body: dict[str, Any] = {
        "dry_run": dry_run,
        "only_failed": only_failed,
        "reset_dag_runs": reset_dag_runs,
        "include_downstream": include_downstream,
        "include_upstream": include_upstream,
    }
    if dag_run_id:
        body["dag_run_id"] = dag_run_id
    if task_ids:
        body["task_ids"] = task_ids
    client = api(env)
    data = await client.post(f"/api/v2/dags/{dag_id}/clearTaskInstances", json=body)
    return {
        "env": client.env.name,
        "dry_run": dry_run,
        "affected": data.get("total_entries", len(data.get("task_instances", []))),
        "task_instances": [slim(t, ["dag_id", "dag_run_id", "task_id", "state", "try_number"])
                           for t in data.get("task_instances", [])],
    }


@mcp.tool()
async def set_task_state(
    dag_id: str,
    dag_run_id: str,
    task_id: str,
    new_state: str,
    map_index: int = -1,
    include_downstream: bool = False,
    note: str | None = None,
    env: str | None = None,
) -> dict:
    """Mark a task instance success/failed/skipped without rerunning it."""
    REG.guard_write(env)
    body: dict[str, Any] = {"new_state": new_state, "include_downstream": include_downstream}
    if note is not None:
        body["note"] = note
    path = f"/api/v2/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances/{task_id}"
    if map_index >= 0:
        path = f"{path}/{map_index}"
    data = await api(env).patch(path, json=body)
    return slim(data, TI_KEYS) if isinstance(data, dict) else {"result": data}


@mcp.tool()
async def list_import_errors(limit: int = 20, env: str | None = None) -> dict:
    """DAG files the scheduler failed to parse, with tracebacks."""
    data = await api(env).get("/api/v2/importErrors", params={"limit": limit})
    return {
        "total": data.get("total_entries"),
        "errors": [slim(e, ["filename", "stack_trace", "timestamp"]) for e in data.get("import_errors", [])],
    }


@mcp.tool()
async def get_dag_source(dag_id: str, env: str | None = None) -> dict:
    """Source code of a DAG as the scheduler on that instance currently sees it."""
    client = api(env)
    data = await client.get(f"/api/v2/dagSources/{dag_id}")
    return {"env": client.env.name, "dag_id": dag_id, "source": data.get("content", data.get("text", ""))}


@mcp.tool()
async def compare_dag_across_envs(dag_id: str, envs: list[str] | None = None) -> dict:
    """Same DAG side by side on several instances: paused, last run, parse time, source length.

    Answers "is prod running the same thing as stage".
    """
    out = {}
    for name in envs or REG.names():
        try:
            client = REG.client(name)
            details = await client.get(f"/api/v2/dags/{dag_id}/details")
            runs = await client.get(f"/api/v2/dags/{dag_id}/dagRuns", params={"limit": 1, "order_by": "-run_after"})
            source = await client.get(f"/api/v2/dagSources/{dag_id}")
            last = (runs.get("dag_runs") or [{}])[0]
            out[name] = {
                "url": client.env.url,
                "is_paused": details.get("is_paused"),
                "last_parsed_time": details.get("last_parsed_time"),
                "timetable_summary": details.get("timetable_summary"),
                "last_run": slim(last, ["dag_run_id", "state", "run_after", "duration"]),
                "source_chars": len(source.get("content", "") or ""),
            }
        except Exception as exc:
            out[name] = {"error": str(exc)}
    return {"dag_id": dag_id, "environments": out}


@mcp.tool()
async def list_variables(limit: int = 100, env: str | None = None) -> dict:
    """Airflow variables. Sensitive values come back masked by Airflow itself."""
    data = await api(env).get("/api/v2/variables", params={"limit": limit})
    return {
        "total": data.get("total_entries"),
        "variables": [slim(v, ["key", "value", "description"]) for v in data.get("variables", [])],
    }


@mcp.tool()
async def list_connections(limit: int = 100, env: str | None = None) -> dict:
    """Airflow connections without passwords: which systems this instance reaches."""
    data = await api(env).get("/api/v2/connections", params={"limit": limit})
    return {
        "total": data.get("total_entries"),
        "connections": [slim(c, ["connection_id", "conn_type", "host", "schema", "port", "login", "description"])
                        for c in data.get("connections", [])],
    }


@mcp.tool()
async def airflow_api(
    method: str, path: str, params: dict | None = None, body: dict | None = None, env: str | None = None
) -> Any:
    """Escape hatch for any REST API v2 endpoint not covered above, e.g. path="/api/v2/pools".

    Non-GET calls respect the read-only setting of the environment.
    """
    method = method.upper()
    if method != "GET":
        REG.guard_write(env)
    if not path.startswith("/api/v2"):
        path = "/api/v2/" + path.lstrip("/")
    return await api(env).request(method, path, params=params, **({"json": body} if body else {}))


if __name__ == "__main__":
    mcp.run()
