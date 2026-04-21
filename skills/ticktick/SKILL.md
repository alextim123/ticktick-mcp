---
name: ticktick
description: Use when working with the user's TickTick tasks, projects, plans, next actions, daily agenda, weekly review, goal decomposition, or the local TickTick MCP server in /Users/alextim/Бот/ticktick-mcp.
---

# TickTick

Use TickTick as the user's operational task tracker for current plans, projects, next actions, and lightweight reviews.

## Local MCP

- Project path: `/Users/alextim/Бот/ticktick-mcp`
- MCP config: `/Users/alextim/Бот/ticktick-mcp/.mcp.json`
- Secrets and OAuth tokens live in `/Users/alextim/Бот/ticktick-mcp/.env`; never print, copy, or commit this file.
- Run auth, if needed:
  ```bash
  cd /Users/alextim/Бот/ticktick-mcp
  .venv/bin/python -m ticktick_mcp.cli auth
  ```
- Use read-only API calls freely for summaries. Ask for confirmation before bulk creation, deletion, completion, or broad updates.

## Remote MCP

- Keep `stdio` for local Codex use.
- Use `sse` for a remote ChatGPT-compatible MCP endpoint:
  ```bash
  cd /Users/alextim/Бот/ticktick-mcp
  .venv/bin/python -m ticktick_mcp.cli run --transport sse --host 0.0.0.0
  ```
- Public SSE endpoint is `/sse`; message endpoint is `/messages/`.
- Do not deploy a public remote endpoint without access control. The exposed tools can read and mutate TickTick tasks.
- Prefer setting `MCP_PUBLIC_URL`, `MCP_AUTH_TOKEN`, `MCP_ALLOWED_HOSTS`, and `MCP_ALLOWED_ORIGINS` for production deployments.

## Planning Rules

- Prefer TickTick for concrete current tasks and next actions.
- Keep goal decomposition practical: create a project only when the goal is multi-step; otherwise create tasks in the relevant existing project.
- Before creating many tasks, show the proposed project/task list and ask for approval.
- Do not delete projects or tasks unless the user explicitly asks and confirms the exact deletion.
- For reviews, separate overdue, today, tomorrow, this week, blocked, and next actions.

## Date Grouping

- Interpret task/event times in `Europe/Moscow` unless the user says otherwise.
- If a TickTick item has both `startDate` and `dueDate`, display it as an interval (`HH:MM-HH:MM`) rather than showing only `dueDate`.
- Convert `startDate` and `dueDate` using the item's `timeZone` when present; otherwise use `Europe/Moscow`.
- When grouping TickTick tasks/events by day, if an item has local time `00:00` and semantically represents the end of an interval, assign it to the previous day.
- Show such midnight-ending items as `00:00` at the end of the previous day's list.
- Example: an item shown locally as `2026-04-23 00:00` that represents the end of April 22 belongs in the April 22 agenda.
