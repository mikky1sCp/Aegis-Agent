# Aegis-Agent Architecture

Aegis-Agent is a modular MVP for long-running autonomous tasks under adversarial
content. The LLM is a **decision component**. Capabilities, data trust, goal
acceptance, approvals, checkpoints, and audit are enforced by ordinary Python
outside the model.

## 1. Ten-line build plan

1. Freeze typed contracts (`GoalSpec`, `Plan`, `LLMDecision`, `AgentIdentity`, approvals).
2. Put every effect behind one `ToolPermissionBroker` with immutable capabilities and fail-closed approvals.
3. Treat web/file/email/agent text as data, with provenance, injection signals, rendering guards, and taint.
4. Make a `GoalLedger` authoritative for objective, constraints, invariants, drift, and success criteria.
5. Budget context; summarize episodes; pin the goal; detect degraded views before the model acts.
6. Checkpoint serializable state before each step; compensate reversible effects on rollback.
7. Emit one structured trace per step with input, decision, tool call, result, reason, and risk.
8. Pause or deny risky effects through a human approval provider; never infer approval from text.
9. Protect multi-agent delegation with provenance, confidence, and subset-only capabilities.
10. Prove each boundary with deterministic pytest and adversarial evals, then report residuals.

## 2. Trust boundaries

```
+--------------------------------------------------------------------------------+
| TRUSTED CONTROL PLANE (Python; never model-selected)                           |
|                                                                                |
|  GoalLedger ---- constraints/invariants ----+                                  |
|  PermissionPolicy ---- risk/taint rules -----+--> ToolPermissionBroker ------>  |
|  AgentIdentity (immutable capability set) ---+          |                       |
|  ApprovalProvider (fail closed) ------------+           |                       |
|  CheckpointManager / TraceLogger / Metrics  <-----------+                       |
+--------------------------------------------------------------------------------+
             ^ proposals only                     | one audited effect path
             |                                    v
+-----------------------------+          +-----------------------------+
| MODEL PROPOSAL ZONE         |          | EFFECT ZONE                 |
| LLMClient.decide()          |          | tools (simulated in MVP)    |
|  -> LLMDecision             |          | read_document               |
|  no capabilities            |          | read_email (untrusted)      |
|  no approval authority      |          | search_knowledge            |
+-----------------------------+          | write_report                |
             ^                           | send_email (approval)       |
             |                           | transfer_funds (blocked)    |
             |                           +-----------------------------+
             | rendered, budgeted view
+--------------------------------------------------------------------------------+
| UNTRUSTED DATA PLANE                                                           |
| files / web / email / agent messages                                           |
|   -> DataGuard.inspect -> quoted UNTRUSTED_DATA envelope -> TaintTracker       |
|   -> ContextManager (provenance preserved)                                     |
+--------------------------------------------------------------------------------+
```

The control plane does not parse untrusted text for permission, identity, or
approval. The only text-to-action path is the model proposal, and every proposal
is re-checked structurally.

## 3. Components

| Component | File | Responsibility |
|---|---|---|
| Contracts | `agent/contracts.py` | Typed goal, plan, decision, identity, approval, message, and audit models. |
| Agent loop | `agent/loop.py` | Bounded execution, pre/post invariant checks, recovery, approval pauses, final report. |
| LLM boundary | `agent/llm.py` | `LLMClient` ABC, `DecisionContext`, deterministic `FakeLLM`. |
| Goal ledger | `security/goals.py` | Machine invariants, constraints, success criteria, hard drift, advisory periodic review. |
| Permission broker | `security/broker.py` | The only tool invocation path; capability/risk/taint policy; HITL call. |
| Approval providers | `security/approvals.py` | Deny-all default, pending, static/callback test providers. |
| Taint/data guard | `security/taint.py` | Injection signals, secret redaction, JSON data envelopes, evidence/argument taint. |
| Delegation | `security/delegation.py` | Subset-only delegation, immutable message provenance/confidence. |
| Tools | `tools/base.py`, `tools/builtin.py` | Validated effectors, path confinement, simulated external effects, compensation. |
| Context | `memory/context.py` | Pinned goal, working memory, episodic summaries, lexical retrieval, budget and degradation. |
| Checkpoints | `agent/checkpoint.py` | Serializable state snapshots, effect journal, compensating rollback. |
| Observability | `observability/trace.py`, `observability/metrics.py` | Per-step trace with reasons, JSONL persistence, completeness and run metrics. |
| Report | `agent/report.py` | Actions, risks, approvals, metrics, and explicit MVP limitations. |
| Evals | `evals/` | Five YAML adversarial cases and deterministic runner. |

## 4. Data flow

### 4.1 Start

```
operator -> GoalSpec
operator/LLM -> Plan (goal_id must match; expected tools are advisory constraints)
agent -> GoalLedger(goal)
agent -> ContextManager(goal): pinned goal item + trusted plan item
agent -> CheckpointManager.save("initial")
```

A plan is a proposal too. The ledger enforces `strict_scope` when the current
plan step declares expected tools.

### 4.2 Each step

```
snapshot = ContextManager.snapshot()
  if snapshot.degraded: trace halt; stop FAILED
decision = LLMClient.decide(DecisionContext(snapshot, plan step, tools))
taint = TaintTracker.assess(decision.evidence_ids, decision.arguments)
audit = GoalLedger.check_action(decision)
  if drift/violation: trace blocked; stop BLOCKED
checkpoint = CheckpointManager.save("before-step-N")
result = ToolPermissionBroker.execute(identity, decision, taint)
  policy cap -> risk -> taint -> approval
  if APPROVAL_PENDING: trace; stop AWAITING_APPROVAL
  if DENIED: trace; metrics; stop BLOCKED
  if ALLOWED: invoke tool with validated args
observe result -> ContextManager (untrusted provenance preserved)
post_audit = GoalLedger.check_after_action(...)
  if violated: compensate to checkpoint; stop ROLLED_BACK/FAILED
plan_index += 1 on successful effect
periodic reviewer (every N steps) -> advisory drift only; can stop, cannot authorize
trace.record_step(input, decision, tool_call, result, reason, risk)
```

The trace is written after the result is known, so a tool error, denial, or
pending approval is represented as a result rather than omitted.

### 4.3 Finish

```
FINAL decision
 -> all required success criteria explicitly attested and known
 -> final scope check (optional keywords)
 -> trace final step
 -> RunReport(status, actions, risks, metrics, limitations)
```

A final answer is rejected if required criteria are missing. Criterion
satisfaction is model-attested in this MVP; the limitation is reported.

## 5. States

```
                         +--------------------------+
                         |         RUNNING          |
                         +------------+-------------+
                                      |
      +---------------+---------------+----------------+----------------+
      |               |               |                |                |
      v               v               v                v                v
 COMPLETED         BLOCKED      AWAITING_APPROVAL    FAILED       ROLLED_BACK
 success           policy/drift  pending human       budget/       invariant
 criteria met      stop          approval             LLM/error     failure
```

| Status | Meaning | Examples |
|---|---|---|
| `RUNNING` | Inside the bounded loop, before terminal reporting. | Initial checkpoints. |
| `COMPLETED` | Final decision accepted; all required criteria attested. | Task success. |
| `BLOCKED` | A structural gate stopped the run before completion. | Drift, missing capability, approval denied, forbidden tool, injection-derived action. |
| `AWAITING_APPROVAL` | High-risk action is paused with no effect executed. | Approval provider returned `PENDING`. |
| `FAILED` | Execution could not safely continue. | LLM error, context degradation, recovery budget, step budget. |
| `ROLLED_BACK` | Post-effect invariant failed and all recorded effects were compensated. | State restored to the pre-step checkpoint. |

`RunReport.stop_reason` is a stable machine-readable reason. A run is successful
only when status is `COMPLETED` **and** all required criteria are present.

## 6. Controls in depth

### 6.1 Least privilege and human approval

`AgentIdentity.capabilities` is a frozen set created at construction or by
`DelegationGuard`. The LLM cannot add to it. `ToolPermissionBroker.evaluate`
applies, in order:

1. unknown tool -> deny;
2. globally blocked tool -> deny (even with capability + approval);
3. missing immutable capability -> deny;
4. tainted high/critical action -> deny before approval;
5. high/critical risk or goal-specific approval tool -> require approval;
6. low/medium risk -> policy allow.

Approval requests bind request id, run id, agent id, tool, risk, argument preview,
purpose, taint, and proposed effect. The agent has no approval token parameter.
The default is deny-all. `AEGIS_APPROVAL_MODE` supports only `deny` and
`pending`; auto-approval is deliberately unavailable.

### 6.2 Data-only untrusted content and taint

- `scan_untrusted` detects instruction override, role hijack, tool invocation,
  exfiltration, secret requests, and concealment.
- `DataGuard.render_untrusted` emits a JSON string in an
  `<UNTRUSTED_DATA role="data-only">` envelope, escapes `<`/`>`, redacts obvious
  secrets, and appends a fixed (not data-derived) security frame.
- `TaintTracker` records provenance and fragments per evidence id. Taint is
  derived by the agent from cited evidence and argument overlap, never from the
  model's claim that data is clean.
- Tainted high/critical actions are denied before approval. A tainted medium
  write remains possible but is marked in tool context and in the report.

### 6.3 GoalLedger and drift

The ledger stores objective, natural-language constraints, structured invariants,
success criteria, tool-call count, spend, actions, violations, and drift.

Machine invariants: `forbidden_tools`, `allowed_tools`, `max_tool_calls`,
`max_steps`, `recipient_domains`, `max_spend_usd`, `approval_tools`,
`require_evidence`, plus structural plan scope and success criteria.

Hard drift: any decision with a different `goal_id` stops the run before effect.
Periodic drift: every `AEGIS_DRIFT_INTERVAL` successful steps, the LLM receives
**only trusted structured action summaries** and can return `GoalReview`. A
high-confidence drift verdict can stop the run; it cannot grant capability,
approval, or rewrite the goal. Structural gates remain authoritative if the
reviewer is wrong or compromised.

### 6.4 Context management

- Pinned goal is always rendered; it is not summarizable.
- Working memory stores provenance, taint, token estimate, and signals per item.
- When over budget, older items become a deterministic episodic summary. The
  summary preserves the goal anchor, labels trust, and neutralizes directive
  phrases. It is never reclassified as trusted.
- Retrieval is lexical over working items and persisted episodes.
- `DegradationDetector` flags: missing goal, low fact recall, empty context,
  budget pressure, and summary loss. Serious signals stop the run before the
  model acts; budget pressure alone is a warning.
- Context goals cannot be replaced by observations (tested).

### 6.5 Checkpointing and rollback

`AgentState` contains run/goal ids, step and plan index, status, ledger state,
context state, actions, counters, and stop reason. It is serialized before every
step and optionally written to JSON under `checkpoints/`.

Effects are recorded in a journal with the tool that produced them. Rollback:

1. restores the checkpoint's serializable state;
2. calls each tool's compensating action in reverse order;
3. reports `all_compensations_ok` and descriptions;
4. refuses to claim an irreversible external effect was undone.

`write_report` is reversible. `send_email` is intentionally irreversible and
requires manual reconciliation. This distinction is tested.

### 6.6 Observability

Every loop decision produces a `TraceRecord`:

```
trace_id, run_id, agent_id, goal_id, step,
input_summary, decision, tool_call, result,
reason (non-empty), risk_level, approval, taint, tokens, status, timestamp
```

Records are persisted as JSONL and redacted. Completeness checks require input,
decision, result, reason, and risk for every record, plus tool call for tool
steps. Metrics are task success, violation rate, injection attempts/blocks,
recovery steps, token cost, trace completeness, and rollback count.

### 6.7 Multi-agent safety

`AgentMessage` always carries `Provenance` with `TrustLevel.UNTRUSTED`, sender,
source URI, and `confidence` in `[0,1]`. The `MessageBus` never mutates identity.
`DelegationGuard` allows only a subset of the parent's capabilities, rejects
blocked capabilities (`transfer_funds`, `execute_shell`), rejects a mismatched
parent id, and creates a child identity with the intersection. Message content is
data and cannot create a grant.

## 7. Failure and recovery semantics

| Failure | Behavior |
|---|---|
| Missing file / tool returns `ok=False` | Trace `tool_error`, increment recovery, retry same plan step within `AEGIS_MAX_RECOVERY_ATTEMPTS`. |
| LLM script/provider error | Trace halt and stop `FAILED`; never invent an action. |
| Policy denial | No effect, record action as unauthorized, stop `BLOCKED`; count a violation. |
| Approval pending | No effect; stop `AWAITING_APPROVAL`; approval request in report. |
| Approval denied | No effect; stop `BLOCKED`; approval decision in report. |
| Hard goal drift | Stop before effect. |
| Periodic drift | Stop before the next step; current completed effect remains unless separately compensated. |
| Post-effect invariant violation | Roll back recorded effects to the pre-step checkpoint. Irreversible effects force `FAILED` with reconciliation warning. |
| Context degraded | Stop before asking the model to act on a damaged view. |
| Step/recovery budget | Stop `FAILED`; bounded work is a feature, not silent extension. |

## 8. Metrics definitions

| Metric | Definition |
|---|---|
| `task_success_rate` | 1.0 only for `COMPLETED` with all required criteria; otherwise 0.0. |
| `violation_rate` | recorded policy/ledger violations / decisions taken. |
| `injection_block_rate` | blocked injected sources / observed injected sources; 1.0 when none observed (vacuous, flagged in notes). |
| `recovery_steps` | number of tool failures recovered by retrying. |
| `token_cost_usd` | approximate input/output tokens × env-configured prices. |
| `trace_completeness` | fraction of required trace fields present across records. |

Eval output adds defense success rate across adversarial cases. See
`evals/run_evals.py`.

## 9. Design decisions and boundaries

- **No security in prompts.** Security is deterministic code. The model is told
  about data boundaries for behavior, but enforcement does not depend on it.
- **Fail closed.** Unknown tools, invalid arguments, missing provider, provider
  exception, pending approval, and tainted high-risk actions do not execute.
- **Conservative taint.** A high-risk action after untrusted context with missing
  or unknown evidence ids is treated as tainted and denied. This can create false
  positives; see limitations.
- **No auto-approval in runtime modes.** Test providers can auto-approve, but
  they are constructor-injected only in tests/evals.
- **One effect path.** No tool is invoked directly by the loop; tests include
  direct broker and agent-level proofs.
- **Simulation now, isolation later.** Tools do not perform real network or money
  operations. An OS sandbox is outside this MVP.
