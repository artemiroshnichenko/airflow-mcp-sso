# airflow-mcp-sso

MCP (Model Context Protocol) server for Apache Airflow 3, over its REST API v2, for Airflow
instances that sit behind SSO. There's no service account or API token to provision: the server
reuses the session cookie that's already sitting in your browser after you log in through SSO,
the same way your browser talks to Airflow. Multiple environments (prod, stage, a local instance)
are configured side by side and selected per tool call.

## Why cookie auth

Most Airflow MCP servers assume a static API token or basic auth. That falls apart the moment
Airflow sits behind SSO with no exposed service-account path -- which is the common case in a
corporate setup. This one reads the session cookie straight out of the local browser's cookie
store instead, so "being logged in to the Airflow UI" is the same thing as "the MCP server has
access." Works with Firefox and Chromium-family browsers (Chrome, Chromium, Brave, Edge, Vivaldi)
on Linux, macOS and Windows, and with Safari on macOS. See [`auth.py`](auth.py) for exactly how
each platform's cookie store is read.

An environment with a real API token, or a username/password (for a non-SSO instance like a
local dev Airflow), works too -- see Configuration below.

## Install

```bash
git clone <this-repo> airflow-mcp-sso
cd airflow-mcp-sso
cp instances.example.json instances.json   # fill in your Airflow URLs
cp .env.example .env                       # optional, only for overrides

uv run --script cli.py doctor                # every environment: url, cookies, token, API
uv run --script cli.py selftest --env prod   # start the MCP server, list tools, live call
uv run --script cli.py setup                 # register in ../.mcp.json, then restart your MCP host
```

`doctor` prints, per environment, which URL answered, which cookies were found, where the token
came from, and how many DAGs are visible. For an instance without SSO, if a password is needed:

```bash
uv run --script cli.py login --env local --save
```

## How the token is obtained

Per instance, top to bottom, first one that works wins:

1. `AIRFLOW_MCP_<ENV>_TOKEN`
2. the cache at `~/.cache/airflow-mcp/token-<env>.json`, if the JWT is still fresh
3. `POST /auth/token` with a username and password (only where there's no SSO)
4. the session cookie from the local browser

Every cookie present for the host is sent, not just the session cookie, so an SSO proxy in front
of Airflow gets what it needs too. The JWT goes both as an `Authorization: Bearer` header and as
a cookie. On a 401 or 403 the server re-reads the browser cookie and retries once, so an expired
session is fixed by a normal page reload in the browser, not by editing config.

## Tools

Every tool takes an `env` argument (whatever names you defined in `instances.json`), defaulting
to the registry's default environment.

| Tool | What it does |
| --- | --- |
| `airflow_environments` | list of instances, their URLs, and how each authenticates |
| `airflow_status` | version, health, parsing errors, DAGs whose last run failed |
| `list_dags` | filter by name, tags, owners, paused state, last-run status |
| `get_dag` | details, tasks, recent runs |
| `list_dag_runs` | runs, `dag_id="~"` for every DAG at once |
| `list_task_instances` | task instances, `state=["failed"]` for everything currently broken |
| `get_task_log` | a task attempt's log, defaults to the latest attempt, tail only |
| `trigger_dag` | trigger a run with a `conf` payload |
| `set_dag_paused` | pause or unpause |
| `clear_tasks` | rerun tasks, `dry_run=True` by default |
| `set_task_state` | mark success/failed/skipped |
| `list_import_errors` | files the scheduler couldn't parse |
| `get_dag_source` | the DAG's source as the scheduler sees it |
| `compare_dag_across_envs` | one DAG across every instance side by side: paused, last run, parse time |
| `list_variables`, `list_connections` | variables and connections; connection passwords are never returned |
| `airflow_api` | raw call to any `/api/v2` endpoint, an escape hatch |

## Configuration

`instances.json` (copy from `instances.example.json`) defines the environments: name, candidate
URLs, and auth methods (`browser`, `password`, or both). On first use the server probes every
candidate URL for an environment and remembers which one answered, in
`~/.cache/airflow-mcp/hosts.json`.

Environment variables (a `.env` file next to the code works too), all optional:

| Variable | Meaning |
| --- | --- |
| `AIRFLOW_MCP_DEFAULT_ENV` | override the default environment from `instances.json` |
| `AIRFLOW_MCP_READONLY_ENVS` | comma-separated list of environments where write calls are refused |
| `AIRFLOW_MCP_COOKIE_NAME` | the SSO session cookie's name (default `_token`) |
| `AIRFLOW_MCP_TIMEOUT` | HTTP timeout in seconds (default 30) |
| `AIRFLOW_MCP_<ENV>_URL` | override an environment's URL |
| `AIRFLOW_MCP_<ENV>_TOKEN` | a static token, skips cookie auth entirely for that environment |
| `AIRFLOW_MCP_<ENV>_USERNAME` / `_PASSWORD` | credentials for password-grant environments |
