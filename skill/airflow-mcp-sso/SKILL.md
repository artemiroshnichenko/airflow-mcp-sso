---
name: airflow-mcp-sso
description: Investigate and operate Apache Airflow 3 through the airflow-mcp-sso server, which logs in with the browser's existing SSO session instead of a service account and can reach several environments (prod, stage, local). Use when the user asks why a DAG or task failed, what is broken in Airflow right now, whether prod runs the same DAG as stage, or wants a DAG triggered, paused, cleared or a task marked; also when they paste an Airflow UI link. Requires the airflow-mcp-sso server (https://github.com/artemiroshnichenko/airflow-mcp-sso) registered as an MCP server named "airflow".
---

# Airflow via airflow-mcp-sso

The `airflow` MCP server talks to Airflow 3 over REST API v2, as the user who is logged in to the
Airflow UI in the local browser. It can see and do exactly what that user can, in every
environment listed in its `instances.json`.

## Setup check

If the `airflow_*` tools are missing, the server is not registered. Tell the user to run, from the
cloned repo:

```bash
uv run --script cli.py doctor     # every environment: url, cookies, token, API
uv run --script cli.py setup      # registers the server in ../.mcp.json
```

then restart the agent. Do not try to install it yourself.

## Pick the environment first

Call `airflow_environments` at the start. It lists the environment names, which one is the
default, and which are read-only. Every other tool takes `env`; omitting it means the default,
which is often `prod`. Name the environment in every answer, so "the DAG failed" is never
ambiguous between prod and stage.

If a call fails with an auth error, the SSO session in the browser has expired: ask the user to
open that Airflow UI and log in, then retry. Do not ask for a password or token.

## Which tool for which question

| Question | Start with |
| --- | --- |
| "Is anything broken?" | `airflow_status` (health, import errors, DAGs whose last run failed) |
| "Why did DAG X fail?" | `get_dag` (recent runs), then `list_task_instances` with `state=["failed"]`, then `get_task_log` |
| "A DAG disappeared / won't load" | `list_import_errors` |
| "Is prod running the same as stage?" | `compare_dag_across_envs`, then `get_dag_source` on both if they differ |
| "What does this DAG connect to?" | `list_connections` (no passwords), `list_variables` (sensitive values masked) |
| Anything else in REST API v2 (pools, XComs, assets) | `airflow_api` with a GET |

`get_task_log` returns the tail of the latest try by default, which is where the traceback is.
Raise `tail_chars` only if the cause is clearly earlier in the log.

## Write actions

These change the user's Airflow: `trigger_dag`, `set_dag_paused`, `clear_tasks` with
`dry_run=False`, `set_task_state`, and `airflow_api` with any method other than GET.

- Before each one, state the environment, the DAG and run, and what will change. Wait for an
  explicit yes. A yes for one action does not cover the next one, and a yes for stage does not
  cover prod.
- `clear_tasks` is a dry run by default. Run it as is, show the user the list of task instances
  it would clear, and only then repeat it with `dry_run=False`.
- An environment in `AIRFLOW_MCP_READONLY_ENVS` refuses writes by design. Report that; do not
  look for a way around it through `airflow_api` or another environment.

## Reporting

Quote what you actually saw: run ids, task states, the error line from the log. Say plainly when a
log was empty, a run had no failed tasks, or a call errored, rather than guessing the cause.
