# SOC Agent

Go API skeleton for the defensive SOC agent. The initial slice provides health checks and local alert storage; agent orchestration, RAG, authentication, and the web UI are not implemented yet.

## Run with Docker Compose

Docker Compose starts the API, PostgreSQL/ParadeDB, and Redis. PostgreSQL migrations run automatically when the API starts. Host ports are bound to loopback by default.

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8080/healthz`. The development database password in `docker-compose.yml` is not suitable for deployment.

Create an alert:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8080/api/v1/alerts `
  -ContentType 'application/json' `
  -Body '{"source":"waf","raw":{"event":"blocked","path":"/login"}}'
```

List alerts:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/api/v1/alerts
```

Stop the services without deleting data:

```powershell
docker compose down
```

Delete local database and queue data only when intentionally resetting the development environment:

```powershell
docker compose down --volumes
```

## Run the Go API directly

Start PostgreSQL first, then set `SOC_PG_DSN` and run:

```powershell
$env:SOC_PG_DSN = 'postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable'
go run ./cmd/soc api
```

Useful checks from this directory:

```powershell
go test ./...
go vet ./...
go run ./cmd/soc version
```

Run migrations separately (the API also migrates on startup):

```powershell
go run ./cmd/soc migrate
```

Integration tests need a running PostgreSQL and are excluded from the default build:

```powershell
go test -tags=integration ./...
```

## Initial API

- `GET /healthz`: process liveness.
- `GET /readyz`: PostgreSQL readiness.
- `POST /api/v1/alerts`: persist one JSON alert; the initial local mode uses a fixed `local` tenant. Returns `201` when created and `200` for a duplicate.
- `GET /api/v1/alerts`: list up to 100 alerts for the local tenant.

## Commands

| Command | Purpose |
| --- | --- |
| `soc api` | HTTP API; applies migrations on startup |
| `soc worker` | Outbox relay + asynq consumer; recovers expired leases at startup |
| `soc migrate` | Apply embedded migrations only |
| `soc models check [--ping]` | Validate the model config; `--ping` makes one real call per role |
| `soc hunt` | **Let the model drive the tools** inside a fixed duty and budget |
| `soc probe` / `soc web` | Run one tool yourself, same gates, no model |
| `soc version` | Print the build version |

## Agent runs (`soc hunt`)

`soc probe` and `soc web` are one action per invocation: you decide the next step. `soc hunt` inverts that — the model decides, inside a bounded loop, and the loop stops for a recorded reason.

```bash
export DEEPSEEK_API_KEY=...          # the key, not the name
export SOC_MODELS_CONFIG=models.yaml
soc hunt --scope <id> --target <host> --duty recon \
  --goal "确认存活、技术栈、所有入口" --park-to parked.json
```

| Duty | Tools | Why |
| --- | --- | --- |
| `plan` | none | Planning produces no traffic |
| `recon` | dns_lookup, http_probe, web_fetch, port_scan, service_scan | Fingerprinting |
| `web` | http_request, http_intruder, web_fetch, http_probe | Repeater + Intruder |
| `exploit` | http_request, http_intruder, web_fetch | Verification only |
| `critic` | none | Judgement must not scan |
| `report` | none | Reporting must not scan |

Three duties hold no tools **on purpose**: giving the judge a scanner is how you get a critic that decides to poke the target itself.

**The whitelist is narrower than the catalog and is applied twice** — the loop refuses a call whose tool is not in `AgentSpec.Tools`, and the prompt only advertises those same tools. So the model cannot see a tool the runner would reject, and cannot call one the duty does not hold.

### Five stop reasons, always recorded

| Stop | Meaning | What happens next |
| --- | --- | --- |
| `verdict` | Model produced a final answer | Review it |
| `budget` | Step or token cap hit | Designed stop, not an error; grant more and resume |
| `stall` | Same tool + same arguments twice | Change approach, or escalate |
| `approval` | A human must approve one exact action | Parked; resume with `--approval` |
| `fatal` | Unknown tool repeatedly, or model transport failure | Do not retry the same run |

**Approval parks, it does not retry.** Returning `approval_required` to a model as a recoverable error produces a livelock: the model rewords the call, is refused again, and spends the whole budget generating identical audit rows. So the loop records the exact binding, writes a parked file, and exits. A human approves through the API, then:

```bash
soc hunt --resume parked.json --approval <id>
```

The approval id is held by the runtime for that one call only — the model never sees it, so it cannot reuse a granted approval for a different action.

### Worked example (CTFshow, authorized)

```
duty    recon   → found eval($_GET['c']) with a /flag/i filter in the source
duty    web     → baseline echo, scandir, then glob("fla*") to dodge the filter
stop    verdict → ctfshow{...}
```

The recon run called `dns_lookup` first and got `binary_missing` (no `dig` on the host), then adapted to HTTP without being told — which is the behaviour the error envelope exists to enable.

## Durable task flow

Posting an alert commits four things in one PostgreSQL transaction: the alert row, an `agent_tasks` row, a pending `task_intents` row, and a `queue_outbox` row. The worker's relay publishes the outbox row to Redis; the consumer claims the intent transactionally (`FOR UPDATE SKIP LOCKED` + lease), executes it, marks it complete, and appends a `task_events` row. When no open intents remain the task becomes `succeeded`.

On startup the worker also returns expired-lease intents to `pending` and closes running tasks with no open intents, so a crash between completion and closure does not strand work.

### Lease renewal

Every claimed intent runs under a heartbeat that renews the lease at one third of its duration. Without it an agent intent — which can span many model calls — outlives its lease, gets declared dead, and a second worker claims it: the same target attacked twice by two workers that cannot see each other.

| Rule | Reason |
| --- | --- |
| Renewal is one conditional `UPDATE ... RETURNING` | A read-then-write leaves a window where the reclaim and the renewal both believe they won |
| `lease_until > now()` is part of the condition | **Expiry is irreversible for the holder.** A process suspended for ten minutes must not veto the system's decision that it is gone and resume with stale assumptions |
| `claimed_by` and `task.lease_owner` must both match | Intent ownership and task ownership can diverge after a takeover |
| Terminal tasks are excluded | Renewing on a cancelled task resurrects work a human already stopped |
| A lost lease cancels the execution context | Continuing would send traffic to a target another worker owns |
| A lost lease writes nothing and returns `nil` | Completing the intent here would overwrite the new owner's result |
| A transient renewal error keeps retrying | A connection blip is not proof the lease was taken; aborting would abandon a healthy run |

`DiagnoseLease` reports why renewal failed — `intent_not_found`, `intent_not_claimed`, `claimed_by_other`, `expired`, `task_owner_changed`, `task_finished` — because "another worker legitimately took over" and "this worker lost the race for a bug-shaped reason" need different responses. `RecoverExpiredLeases` also clears the stale task lease and skips terminal tasks.

**Not implemented yet:** RAG, authentication, and the web UI.

## Triage

With `SOC_MODELS_CONFIG` set, each alert's `triage` intent is judged by the `triage` model role. The model must return structured JSON; the executor validates it before anything is stored:

| Check | Rejects |
| --- | --- |
| verdict enum | labels outside `true_positive`/`false_positive`/`benign`/`suspicious`/`unknown` |
| severity enum | `critical`/`high`/`medium`/`low`/`info` only |
| confidence range | outside `[0,1]` |
| rationale | empty |
| **evidence** | no entry with a non-empty `ref` — an ungrounded verdict is an opinion |

Malformed output gets **one** retry with an explanation of what was wrong; still unusable means human review, not another loop. A transport failure is a real error and triggers consultation.

Routing after a valid verdict:

- **auto-close** — confidence ≥ floor (default 0.75, override with `SOC_CONFIDENCE_FLOOR`) and severity is `low`/`medium`/`info`
- **waiting_review** — low confidence, `high`/`critical` severity, or verdict `unknown`

Parking a task for review releases its lease and stops the loop immediately, so the same alert is never re-judged while nobody can approve it. The verdict is stored in the task checkpoint and the `intent_completed` event records tokens for cost attribution.

### Local end-to-end without a vendor account

```powershell
go run ./cmd/mockllm -addr 127.0.0.1:8089 -confidence 0.42
# in another terminal, with models.local.yaml pointing at that endpoint:
$env:SOC_MODELS_CONFIG = "models.local.yaml"
go run ./cmd/soc worker
```

`-confidence 0.42` exercises the review path; `-confidence 0.95` exercises auto-close. `models.local.yaml` is gitignored.

## Models

Configuration is three layers: `providers` (endpoint, auth, transport), `profiles` (one model: type, limits, abilities, cost), and `roles` (which business use binds to which profile). Copy `models.example.yaml` and point `SOC_MODELS_CONFIG` at it.

```powershell
$env:SOC_MODELS_CONFIG = "models.yaml"
go run ./cmd/soc models check          # validate references and types, no network
go run ./cmd/soc models check --ping   # one minimal call per role (spends quota)
```

A model's `type` (`chat`, `vision`, `embedding`, `rerank`, `asr`) selects the protocol and adapter, so a role can never be bound to a mismatched model. A `vision` model satisfies a chat role because vision is chat plus image input; an embedding model never does. Embedding profiles require a `dimension` so an index is never built on an unknown width. Credentials are read only from the variable named by `api_key_env` and are never echoed in errors.

## Conditional consultation

Agents work independently by default. A consultation room opens only when an agent is genuinely stuck or a human interrupts.

| Trigger | Allowed when |
| --- | --- |
| `user` | always — a human deliberately interrupting |
| `stall` | at least one objective signal |
| `agent_request` | the agent asked **and** at least one objective signal corroborates it |

Objective signals are computed in code, never taken from the model's opinion: step budget exhausted, repeated tool calls, low confidence, missing evidence, contradictory evidence, deadline near, repeated tool errors. This prevents "I need help" from becoming a way to escape work.

A room costs `O(participants)`: one structured brief, one bounded turn per participant, one synthesis. Participants see the brief and their own duty — never each other's transcripts. A single failing agent is recorded as skipped rather than sinking the consultation, and an unstructured synthesis degrades to `escalate_human` instead of being silently accepted.

One open escalation per task is enforced by a partial unique index, so a retrying agent cannot open a second room for the same wall.

### Wiring

The worker enables consultation automatically when `SOC_MODELS_CONFIG` is set; without it, work still proceeds and no room is summoned. A failed intent is what triggers a summon, because the error is objective evidence that the agent is stuck. The outcome is recorded either way:

- `consultation_completed` — the room produced a decision
- `consultation_rejected` — no team, or a duplicate escalation

Each team member's `duty` selects the prompt (triage/hunting/intel/critic/reporter) and its `model_role` selects the model, so a critic can run on a stronger model than a triage agent. Consultation turns receive **no tools**, so an agent cannot start new work while consulting.

## Authorization scope and command execution

Red-team simulation needs real tooling, so the runner executes Kali binaries — but only inside a scope enforced **in code**, never by prompt. ARTEX removed its scope mechanism; this does not.

```go
scope := domain.TargetScope{
    ID:         "eng-2026-001",
    Domains:    []string{"client.example"},
    CIDRs:      []string{"203.0.113.0/24"},
    Ports:      []int{80, 443},
    MaxRisk:    domain.RiskActive,   // intrusive stays off
    TicketID:   "SEC-1042",
    ApprovedBy: "ciso",
    ExpiresAt:  time.Now().Add(72 * time.Hour),
}
```

Check order is fixed: **policy deny → scope (with DNS resolution) → approval → execute → audit**. Approval runs after scope on purpose — a human must never be asked to sign off on a target the engagement forbids.

| Gate | Behaviour |
| --- | --- |
| Command policy | Unknown binaries are **denied**; every tool is classified `passive`/`light`/`active`/`intrusive` |
| Destructive patterns | `rm -rf`, `mkfs`, `dd of=/dev/`, `shutdown`, fork bombs, `iptables -F`, `chmod 777 /`, `useradd`, `crontab -r`, `systemctl stop` are always denied — never part of authorized testing |
| Shell metacharacters | `\|`, `;`, `$(`, `>`, backticks rejected unless `Policy.Shell` is set explicitly |
| Scope | Domain suffix matching respects dot boundaries (`example.com` does not authorize `notexample.com`); ports and expiry are enforced |
| DNS rebinding | Hostnames are resolved and the resulting IPs checked; loopback, link-local (`169.254.169.254`), unspecified and multicast are rejected. Internal ranges are allowed **only** if declared as CIDRs |
| Output | 256 KiB per stream, truncated and flagged; timeout defaults to 120 s |
| Environment | Minimal env passed to the child, so worker credentials never reach a target-facing process |
| Audit | Every decision recorded with ticket id, risk, reason, exit code and duration |

The default catalog is `dns_lookup`, `http_probe`, `port_scan`, `service_scan`, `web_enum`, plus the two built-in HTTP tools described below. **No intrusive tool ships enabled** — adding `sqlmap`/`hydra` is a deliberate change, and it will still be blocked unless `MaxRisk` is raised to `intrusive`.

## Execution backends (local vs Kali toolbox)

Docker on Windows and macOS is already a Linux VM, so "run it in Kali" does not mean "run it on Linux" — it means **deciding where the scanners live**. The platform keeps that as a swappable backend, because policy, scope, approval, rate limiting and audit must be identical regardless of the destination.

| `SOC_EXEC_BACKEND` | Where binaries run | Use it for |
| --- | --- | --- |
| `local` (default) | Child process of `soc` | Development, CI, built-in HTTP tools |
| `docker` | `docker exec` into a long-lived Kali container | Real engagements, where scanners are not installed on the workstation |

```bash
docker compose up -d --build toolbox          # build the Kali image (core tools only)
export SOC_EXEC_BACKEND=docker
export SOC_TOOLBOX_CONTAINER=soc-toolbox
export SOC_TOOLBOX_WORKDIR=/work
```

The image is built in two tiers. `KALI_BULK=0` installs the small core set (`nmap`, `masscan`, `sqlmap`, `hydra`, `gobuster`, `nikto`, `whatweb`, `dirb`, plus the network basics) and finishes in a couple of minutes; the default `KALI_BULK=1` adds `ffuf`, `feroxbuster`, `nuclei` and `seclists`, which are hundreds of megabytes and dominate build time on a slow mirror. If the bulk tier fails, the build still succeeds and the missing tools report `binary_missing` — honest and visible, rather than an image that pretends to have them.

```bash
docker compose build --build-arg KALI_BULK=0 toolbox   # fast, reliable
docker compose build toolbox                            # full toolbox
```

Two consequences worth stating plainly:

- **Availability is checked in the right place.** With the docker backend, `binary_missing` is decided by `command -v` *inside* the container. A tool installed on the host but absent from the toolbox is still reported missing, and an approval is never spent on it.
- **The docker socket is root.** Mounting `/var/run/docker.sock` into a container is equivalent to root on the host. Run `soc` natively against the toolbox (as on Windows), or enable the socket only on a dedicated engagement host. The Compose file leaves it commented out on purpose.

Interpreters (`sh`, `python3`, `java`) work through either backend. Under `docker` they land in `/work` inside the container, so a script cannot touch the platform's own filesystem.

## Built-in web tools (Repeater / Intruder)

Two tools need no external binary, so web work is possible even where Kali is not installed. Both go through the same gates as a scanner: scope, approval, rate limit, audit.

| Tool | What it does | Risk |
| --- | --- | --- |
| `http_request` | Sends one exact request and returns status, headers, body, length and body SHA-256. Raw bodies and multipart uploads are supported, so a captured request can be replayed byte for byte | `light` for GET/HEAD, `active` for POST/PUT/PATCH/DELETE |
| `http_intruder` | Replays one request once per payload with a marker, after a no-payload control. Returns a comparable status/length/matched table; capped at 200 payloads per run | always `active` |

```bash
soc web --scope <id> --url https://host/path --method GET
soc web --scope <id> --url https://host/upload.php --method POST \
  --upload file=/tmp/probe.php --upload-name file=probe.php --approval <id>
soc web --scope <id> --tool http_intruder --json intruder.json --approval <id>
```

Design points that matter:

- **`approval_argv` is returned on refusal.** An approval binds to the exact action, so the tool reports the argv it wants authorized (`method`, URL, body digest, header names, reason). Without that, a caller would have to guess a body digest and the approval could never match.
- **The multipart boundary is content-derived, not random.** A random boundary makes every run of the same logical request produce a different body digest, so an approved request could never be retried.
- **Risk can be raised, never lowered.** A `GET /shell.php?cmd=id` is code execution, so the caller declares `"risk": "intrusive"` and the ceiling applies to that declaration. Declaring `"risk": "passive"` on a POST does not lower it below the state-changing floor.
- **Redirects are re-checked.** Every hop calls the same scope check, so a `302` cannot move the request out of scope mid-flight. Redirects are not followed by default.
- **A non-2xx status is success, not failure.** A `403` is evidence that a filter exists; only a transport failure is a tool error.

Authorization is still enforced in code. Running an intrusive action under an `active` ceiling returns `policy_denied`; issuing a scope with `max_risk: intrusive` is the human act that unlocks it, and the action then still needs its own approval.

## Sandbox and interpreters (sh / python / java)

Sandbox vocabulary follows deepseek-harness, with one correction that matters here.

**A sandbox bounds file effects, not network reach.** Upstream is explicit about this: network and process visibility are outside the sandbox vocabulary. So interpreters — which choose their own destinations at runtime — cannot be made scope-safe by a filesystem jail. Two independent axes are checked, and a script is only as contained as the weaker one.

| Axis | Types | Checked by |
| --- | --- | --- |
| Filesystem | `read-only`, `workspace-write`, `danger-full-access` | `sandbox.Policy`, per call |
| Network | `unconfined`, `egress-filtered`, `isolated` | `sandbox.Attestation`, per worker |

Design rules taken from upstream, plus what they mean here:

- **Per-call policy.** Confinement travels with the call, never pinned on a backend, so concurrent callers can run under different boundaries.
- **Honest enforcement.** `full` vs `partial` is reported. An interpreter requires `full`; a partially-enforcing backend is refused rather than silently treated as a boundary.
- **Fail closed.** If the requested mode cannot be enforced, the call fails. It never degrades to full access.
- **Closed escalation ladder.** `read-only → workspace-write → danger-full-access`, strictly wider only. Every widening needs a human and a justification, and applies to one call.
- **Writable roots validated each call.** Missing paths, non-directories and symlinks are rejected, because a legitimate directory can be replaced by a symlink between calls.
- **Attestation requires a name.** An unnamed claim about egress is not auditable, so it does not count. Recording `unconfined` is an explicit refusal, not a loophole.

Interpreters themselves are **always `ask`, never `allow`**, even when both axes pass: the code is opaque, so a human inspects each invocation. Two policy rules relax for them and only them — shell metacharacters are allowed (scripts legitimately contain `;` and `|`), and argv-target scope checking is skipped (there is no target on the command line). Destructive-pattern denial still applies, so `sh -c 'rm -rf /'` is refused.

Every interpreter call records the script payload — inline code or file path, plus a SHA256 and byte count — because the code, not the command line, is the real evidence.

This skeleton is intended for local development. It does not yet include authentication or multi-user tenant isolation; do not expose it to an untrusted network.