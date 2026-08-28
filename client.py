"""Async client over the Airflow 3 REST API v2, one per environment, with token refresh."""

from __future__ import annotations

import json
from typing import Any

import httpx

from auth import AuthError, Env, get_token, load_registry, resolve_url


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"


class AirflowError(RuntimeError):
    pass


class AirflowClient:
    def __init__(self, env: Env):
        self.env = env
        self._token: str | None = None
        self._cookies: dict[str, str] = {}
        self._source = "none"
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            url = resolve_url(self.env)
            self._client = httpx.AsyncClient(base_url=url, timeout=self.env.timeout, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    def _auth(self, force: bool = False) -> None:
        if force or not self._token:
            self._token, self._cookies, self._source = get_token(self.env, force=force)

    @property
    def token_source(self) -> str:
        return self._source

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        client = await self._http()
        params = {k: v for k, v in (kwargs.pop("params", None) or {}).items() if v is not None}

        async def send(force: bool) -> httpx.Response:
            try:
                self._auth(force=force)
            except AuthError as exc:
                raise AirflowError(str(exc)) from exc
            headers = {
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
            return await client.request(
                method, path, params=params, headers=headers, cookies=self._cookies or None, **kwargs
            )

        r = await send(False)
        if r.status_code in (401, 403):
            r = await send(True)

        if r.status_code >= 400:
            detail = r.text[:600]
            try:
                detail = json.dumps(r.json().get("detail", r.json()))[:600]
            except Exception:
                pass
            raise AirflowError(f"[{self.env.name}] {method} {path} -> {r.status_code}: {detail}")

        if not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            return {"text": r.text}

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw: Any) -> Any:
        return await self.request("POST", path, **kw)

    async def patch(self, path: str, **kw: Any) -> Any:
        return await self.request("PATCH", path, **kw)


class Registry:
    """Lazily built clients, one per environment."""

    def __init__(self) -> None:
        self.envs, self.default = load_registry()
        self._clients: dict[str, AirflowClient] = {}

    def names(self) -> list[str]:
        return list(self.envs)

    def env(self, name: str | None) -> Env:
        name = name or self.default
        if name not in self.envs:
            raise AirflowError(f"unknown environment '{name}', available: {', '.join(self.envs)}")
        return self.envs[name]

    def client(self, name: str | None = None) -> AirflowClient:
        env = self.env(name)
        if env.name not in self._clients:
            self._clients[env.name] = AirflowClient(env)
        return self._clients[env.name]

    def guard_write(self, name: str | None = None) -> None:
        env = self.env(name)
        if env.readonly:
            raise AirflowError(f"environment '{env.name}' is read-only (AIRFLOW_MCP_READONLY_ENVS)")


def slim(obj: dict, keys: list[str]) -> dict:
    """Keep the listed keys, drop empties, so tool output stays readable."""
    return {k: obj[k] for k in keys if obj.get(k) not in (None, [], {}, "")}


DAG_KEYS = [
    "dag_id", "is_paused", "is_stale", "owners", "tags", "timetable_summary", "description",
    "has_import_errors", "next_dagrun_run_after", "last_parsed_time", "relative_fileloc", "bundle_name",
]
RUN_KEYS = [
    "dag_id", "dag_run_id", "state", "run_type", "logical_date", "run_after",
    "start_date", "end_date", "duration", "note", "conf",
]
TI_KEYS = [
    "dag_id", "dag_run_id", "task_id", "map_index", "state", "try_number", "max_tries",
    "start_date", "end_date", "duration", "operator", "pool", "queue", "hostname", "note",
]
