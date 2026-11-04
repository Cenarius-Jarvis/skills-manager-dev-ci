# Devices: multi-device skill deployment (design)

Status: proposal for v1.43.x. This document describes the "Devices" feature:
managing AI-agent skills on *other machines* from the Skills Manager UI,
without merging those machines' skill libraries and without assuming a
persistent connection between them.

## Goals

- See, per device, which agents exist and which skills each agent has.
- Request a deployment (or removal) of one skill on one agent of one device.
- Distinguish, everywhere, between: library content, *desired* state
  (an instruction was written), and *actual* state (the device reported it).
- Work over an intermittent connection: both sides talk to a Git remote;
  no direct network link between devices is required.
- Never allow arbitrary command execution. The only remote operations are
  "deploy a skill directory" and "remove a previously deployed skill".

## Non-goals (v1)

- Merging two devices' libraries into one (Git Backup already covers the
  single-library, multi-device case).
- A resident daemon on the target device. The executor is an explicit
  one-shot CLI invocation (cron/systemd timer or manual).
- Real-time presence. "Online" means "reported recently", configured as a
  threshold, not a live socket.

## Architecture

Three cooperating parts, all already present in the codebase in some form:

1. **Control channel** — a dedicated Git remote + branch (independent from
   any skill backup repo by default) holding small JSON files. Both the
   managing app and each device's executor read and write it.
2. **Local projection** — SQLite tables mirroring the channel so the UI is
   instant and works offline. The channel is the source of truth; the DB is
   rebuilt from it on every refresh (same convention as `pending_conflicts`).
3. **Executor** — a CLI subcommand run on the device: pull instructions,
   execute allow-listed deploy/undeploy actions, publish receipts and a
   state report (heartbeat).

```
 managing app ──write──▶ instructions ──pull──▶ executor (device)
      ▲                                              │
      └────read── receipts + state.json ◀──write─────┘
                     (control channel branch)
```

### Control channel layout

```
protocol.json                                  {"schema": 1}
devices/<device_id>/device.json                identity (name, platform, executor version)
devices/<device_id>/state.json                 reported agents + deployed skills + timestamp
devices/<device_id>/instructions/<id>.json     desired deployments
devices/<device_id>/receipts/<id>.json         per-instruction outcome
```

`<device_id>` and `<id>` are restricted to `[A-Za-z0-9-]{1,64}`; the loader
also rejects path traversal before anything is parsed. Files that fail
validation are reported as warnings and skipped — one malformed file must
not blind the whole page.

### Instruction (v1 schema)

```json
{
  "schema": 1,
  "id": "inst-018f3a…",
  "device_id": "…",
  "action": "deploy",                       // "deploy" | "undeploy"
  "skill_url": "https://github.com/…",      // deploy only; https only
  "skill_branch": "main",
  "skill_subpath": "skills/my-skill",       // must contain SKILL.md after fetch
  "skill_name": "my-skill",                 // display + undeploy key
  "agent_key": "codex",
  "created_at": 1769000000,
  "expires_at": 1769086400,
  "created_by": "workstation"
}
```

Parsing uses `deny_unknown_fields`. Validation rejects: non-https URLs,
`..` in subpaths, unknown agent keys, expired instructions, and IDs outside
the safe charset. There is deliberately no "run command" action.

### Receipt (v1 schema)

```json
{
  "schema": 1,
  "instruction_id": "inst-…",
  "device_id": "…",
  "status": "success",                      // "success" | "failed" | "rejected"
  "reason": "none",                         // conflict | expired | unknown_agent | …
  "instruction_commit": "<sha>",            // commit in which the instruction file was published
  "detail": "…",
  "executor_version": "1.43.1",
  "finished_at": 1769000100
}
```

Receipts are validated against their instruction: IDs and device must match.
A receipt whose `instruction_commit` differs from the instruction's own
publish commit is displayed as **stale**, never as success — a stale
success must not be able to mask a newer unexecuted instruction. (The
publish commit is resolved with `git log --diff-filter=A`, so it stays
stable even though the channel advances whenever devices push receipts
and state.)

### Task states shown in the UI

| State | Meaning |
|---|---|
| Pending sync | Instruction published; device has not reported on it yet |
| Executing | Device's state report marks the instruction as in-flight |
| Success | Receipt `success` whose commit matches the instruction |
| Failed | Receipt `failed`/`rejected` for the current instruction commit |
| Device offline | No state report within the online threshold; nothing has executed |
| Stale / expired | Receipt belongs to an older instruction commit, or the TTL passed without a receipt |

"Success" is therefore *always* backed by the device's own report — the app
never renders "deployed" merely because an instruction was written or a
commit exists on the channel.

### Executor (device side)

`skills-manager-cli devices executor-run-once` — one shot, exits when done:

1. Fetch the control channel; load instructions addressed to this device.
2. Skip: expired, already journaled as completed (idempotency journal with
   `started`/`completed` records, surviving crashes mid-run), agent not in
   the operator's allow-list.
3. For a deploy: fetch `skill_url`, verify `SKILL.md` in `skill_subpath`,
   copy into the mapped agent directory. Refuse to overwrite any directory
   it did not deploy itself (no journal record ⇒ conflict receipt, nothing
   is modified).
4. For an undeploy: remove only paths recorded in its own journal.
5. Publish `state.json` (agents and skills it manages, timestamps) and all
   receipts; push once; exit non-zero only if nothing could be published.

The executor keeps its own config (agent → directory mapping), lock file and
journal under its own base directory, touches nothing else on the machine,
and only ever talks to the configured remote. Skipped/failed attempts are
reported as receipts so the UI can show *why* nothing happened.

## Data model (schema v9)

- `devices` — registry projection: id, name, platform, created_at,
  last_seen_at, last_state_commit.
- `device_skill_records` — what each device *reported*: (device, agent,
  skill, content_hash, deployed_at, reported_commit).
- `device_instructions` — instructions plus their projection: instruction
  commit, derived state, receipt fields.

Settings keys: `device_channel_url` (encrypted like other sensitive keys),
`device_channel_branch` (default `skills-manager-devices`),
`device_local_id`, `device_local_name`, `device_online_threshold_secs`.

## Security notes

- Deploy keys / tokens: the channel reuses the existing per-host credential
  storage; operators should prefer a *separate* repository with the
  narrowest usable token. (Branch-scoped write permissions are a known
  limitation of deploy keys; see README note.)
- Instructions are only honored for the device ID the executor was
  configured with, within their TTL, for allow-listed agents only.
- The executor never runs content from the channel as code; skills are data
  directories copied into agent skill folders.
