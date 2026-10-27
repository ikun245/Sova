package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"soc/agent/internal/domain"
)

// PlannedStep is one direction the planner wants explored. It is an open
// exploration direction, not a fixed task type: the duty decides which tools may
// be used, and the goal is prose the worker interprets.
type PlannedStep struct {
	Duty string `json:"duty"`
	Goal string `json:"goal"`
	// DoneWhen is the completion test. Requiring it stops a plan from being a
	// vague list of activities that can never be judged finished.
	DoneWhen string `json:"done_when"`
}

// Attempt states describe why an exploration stopped, not whether it
// "succeeded". The next planning round acts on the difference:
//
//   - done: explored to a conclusion. Do not re-dispatch the same direction
//     unless materially new material appeared.
//   - exhausted: the budget ran out mid-exploration, so the result is partial.
//     Continue from where it stopped.
//   - stalled: the worker repeated the same call. A different approach is
//     needed, not more budget.
//   - blocked: a transport or model failure meant the work barely started.
//     Re-dispatching the same direction is correct.
//   - approval: parked on a human, so nothing was learned yet.
const (
	AttemptDone      = "done"
	AttemptExhausted = "exhausted"
	AttemptStalled   = "stalled"
	AttemptBlocked   = "blocked"
	AttemptApproval  = "approval"
)

// Attempt is one dispatched direction and how it ended. It is the planner's
// memory across rounds: without it the planner cannot tell "already tried and
// ruled out" from "never tried", and will either repeat work or drop a route.
type Attempt struct {
	Round    int    `json:"round"`
	Duty     string `json:"duty"`
	Goal     string `json:"goal"`
	State    string `json:"state"`
	Summary  string `json:"summary,omitempty"`
	Findings int    `json:"findings"`
}

// dispatchableDuties are the duties the planner may assign work to. Letting it
// assign to itself would recurse; letting it assign to the critic or reporter
// would make judgement part of execution.
var dispatchableDuties = map[string]bool{
	string(DutyRecon):   true,
	string(DutyWeb):     true,
	string(DutyExploit): true,
}

// TeamBudget bounds a whole engagement, not one agent. Without a team-level cap,
// six bounded agents still add up to six times the spend with no overall limit.
type TeamBudget struct {
	// MaxRounds bounds planning cycles. Each round is a fresh look at the
	// evidence, so this is the real limit on how much thinking happens.
	MaxRounds int
	MaxSteps  int
	MaxTokens int
	// MaxFindings bounds recorded claims so a loop emitting near-variants cannot
	// fill the report with duplicates.
	MaxFindings int
	// MaxIntentsPerRound stops one round from flooding the queue: a round that
	// emits twenty directions is not prioritising.
	MaxIntentsPerRound int
}

func DefaultTeamBudget() TeamBudget {
	return TeamBudget{
		MaxRounds:          4,
		MaxSteps:           60,
		MaxTokens:          400000,
		MaxFindings:        40,
		MaxIntentsPerRound: 4,
	}
}

// TeamOutcome is the result of an engagement run.
type TeamOutcome struct {
	Stop    StopReason
	Message string
	// Plan is the most recent round's intents, so a reviewer sees what was being
	// attempted when the run ended.
	Plan []PlannedStep
	// Attempts is every dispatched direction and how it ended, in order.
	Attempts []Attempt
	// Findings are all recorded findings, including rejected ones.
	Findings []domain.Finding
	// Accepted are the findings the critic let through.
	Accepted []domain.Finding
	Report   string
	// GoalMet is the planner's judgement. It is separate from Stop because a run
	// can stop on budget with the goal unmet, and those are different reports.
	GoalMet    bool
	GoalReason string
	// Pending is set when a worker needed approval.
	Pending      *PendingApproval
	PendingIndex int
	// Pending* identify the parked intent so a resume can re-dispatch it.
	PendingDuty    string
	PendingGoal    string
	PendingDone    string
	PendingRound   int
	PendingHistory string
	Steps          int
	Tokens         int
	Duration       time.Duration
}

// TeamOrchestrator runs the fixed roster over one engagement.
//
// The shape follows ARTEX rather than a batch pipeline: the planner re-runs each
// round against the evidence gathered so far and emits only directions that are
// not already covered. A one-shot plan cannot react to what the workers found,
// which is the difference between a team and a six-step script.
type TeamOrchestrator struct {
	// RunAgent executes one duty with a normal exploration budget.
	RunAgent func(ctx context.Context, duty Duty, input string) (RunResult, error)
	// SettleAgent runs the wrap-up phase after a worker's budget is spent, with a
	// small turn budget and the same tools. When nil, a budget stop loses the
	// worker's unwritten findings, so the run reports that instead of pretending
	// the work was settled.
	SettleAgent func(ctx context.Context, duty Duty, input string) (RunResult, error)
	Findings    domain.FindingRepository
	TaskID      string
	// Target is the authorized host, recorded on every finding and told to the
	// planner so it cannot invent a hostname.
	Target string
	Budget TeamBudget
	// ApprovalID authorizes exactly one parked action on resume.
	ApprovalID string
	// Resume* continue a parked run without repeating finished work.
	ResumeRound    int
	ResumeAttempts []Attempt
	ResumeFrom     int
	ResumePlan     []PlannedStep
	ResumeHistory  string
	// OnStep reports progress lines.
	OnStep func(string)
}

// Run executes planning rounds until the goal is met or a budget is spent.
func (o *TeamOrchestrator) Run(ctx context.Context, goal string) (TeamOutcome, error) {
	started := time.Now()
	outcome := TeamOutcome{Stop: StopVerdict, Attempts: o.ResumeAttempts}
	stopped := false

	// A resumed run continues the round that parked, rather than starting the next
	// one: the intent after the parked index belongs to that round and would
	// otherwise be skipped silently, wasting the approval the human just granted.
	startRound := o.ResumeRound
	if startRound < 1 {
		startRound = 1
	}

	for round := startRound; !stopped; round++ {
		if round > o.Budget.MaxRounds {
			outcome.Stop = StopBudget
			outcome.Message = fmt.Sprintf("round budget exhausted (%d rounds); goal not confirmed", o.Budget.MaxRounds)
			break
		}
		if outcome.Steps >= o.Budget.MaxSteps || outcome.Tokens >= o.Budget.MaxTokens {
			outcome.Stop = StopBudget
			outcome.Message = "step or token budget exhausted before the next planning round"
			break
		}

		findings, err := o.findingsFor(ctx)
		if err != nil {
			outcome.Stop = StopFatal
			outcome.Message = "could not read findings: " + err.Error()
			outcome.Duration = time.Since(started)
			return outcome, err
		}
		outcome.Findings = findings

		// Reuse the parked plan for the round it belongs to. Re-planning would
		// produce a different list and the resume index would point elsewhere.
		var intents []PlannedStep
		if round == o.ResumeRound && len(o.ResumePlan) > 0 {
			intents = o.ResumePlan
			o.emit(fmt.Sprintf("round %d: reusing the saved plan (%d intents); planning skipped", round, len(intents)))
		} else {
			o.emit(fmt.Sprintf("round %d: planning against %d findings, %d prior attempts",
				round, len(findings), len(outcome.Attempts)))
			resp, tokens, err := o.plan(ctx, goal, findings, outcome.Attempts)
			outcome.Steps++
			outcome.Tokens += tokens
			if err != nil {
				outcome.Stop = StopFatal
				outcome.Message = err.Error()
				outcome.Duration = time.Since(started)
				return outcome, err
			}
			intents = resp.Intents
			outcome.GoalMet = resp.GoalMet
			outcome.GoalReason = resp.Reason
			if resp.GoalMet {
				o.emit("planner judged the goal met: " + truncate(resp.Reason, 160))
				outcome.Stop = StopVerdict
				break
			}
		}
		outcome.Plan = intents

		if len(intents) == 0 {
			// ARTEX calls this the hard floor: goal unmet, nothing running, and
			// nothing new to try means progress stopped. Reported as a stall rather
			// than a quiet success, because a silent exit here is indistinguishable
			// from having finished the job.
			outcome.Stop = StopStall
			outcome.Message = "planner produced no new direction while the goal was unmet; " +
				"every known route is exhausted or already covered"
			break
		}
		if len(intents) > o.Budget.MaxIntentsPerRound {
			intents = intents[:o.Budget.MaxIntentsPerRound]
		}

		for index, intent := range intents {
			// Intents before the parked one already ran in the previous process.
			if round == o.ResumeRound && index < o.ResumeFrom {
				continue
			}
			if outcome.Steps >= o.Budget.MaxSteps || outcome.Tokens >= o.Budget.MaxTokens {
				outcome.Stop = StopBudget
				outcome.Message = "step or token budget exhausted mid-round"
				stopped = true
				break
			}

			before, err := o.findingsFor(ctx)
			if err != nil {
				outcome.Stop = StopFatal
				outcome.Message = "could not read findings: " + err.Error()
				outcome.Duration = time.Since(started)
				return outcome, err
			}

			resumed := round == o.ResumeRound && index == o.ResumeFrom
			input := o.workerInput(intent, before, resumed && o.ApprovalID != "")
			if resumed && o.ResumeHistory != "" {
				input += "\n以下是本步骤上一轮已经完成的工作，不要重复执行：\n" + o.ResumeHistory
			}

			o.emit(fmt.Sprintf("round %d intent %d/%d duty=%s goal=%s",
				round, index+1, len(intents), intent.Duty, truncate(intent.Goal, 120)))
			result, runErr := o.RunAgent(ctx, Duty(intent.Duty), input)
			outcome.Steps += len(result.Steps)
			outcome.Tokens += result.Tokens
			outcome.Duration = time.Since(started)

			if result.Stop == StopApproval {
				outcome.Stop = StopApproval
				outcome.Message = "a human must approve this exact action before the team can continue"
				outcome.Pending = result.Pending
				outcome.PendingIndex = index
				outcome.PendingDuty = intent.Duty
				outcome.PendingGoal = intent.Goal
				outcome.PendingDone = intent.DoneWhen
				outcome.PendingRound = round
				outcome.PendingHistory = transcriptText(result.Messages)
				outcome.Findings = before
				return outcome, nil
			}
			if runErr != nil {
				// A transport failure is not a failed exploration: nothing was
				// learned. Record it as blocked so the next round re-dispatches the
				// same direction instead of dropping it.
				outcome.Attempts = append(outcome.Attempts, Attempt{
					Round: round, Duty: intent.Duty, Goal: intent.Goal,
					State: AttemptBlocked, Summary: truncate(runErr.Error(), 200),
				})
				outcome.Stop = StopFatal
				outcome.Message = "worker transport failure: " + truncate(runErr.Error(), 200)
				outcome.Findings = before
				outcome.Duration = time.Since(started)
				return outcome, runErr
			}

			// A worker that ran out of budget mid-exploration holds partial
			// results. Force a settlement round so what it already identified is
			// written back instead of discarded with the process.
			settled := false
			if result.Stop == StopBudget || result.Stop == StopStall {
				settled = o.settle(ctx, intent, result, &outcome)
			}

			if err := o.capture(ctx, Duty(intent.Duty), result.Content, result.ToolCalls); err != nil {
				outcome.Stop = StopFatal
				outcome.Message = "could not record findings: " + err.Error()
				outcome.Findings = before
				outcome.Duration = time.Since(started)
				return outcome, err
			}

			after, _ := o.findingsFor(ctx)
			state := attemptState(result.Stop, settled)
			outcome.Attempts = append(outcome.Attempts, Attempt{
				Round: round, Duty: intent.Duty, Goal: intent.Goal,
				State: state, Summary: attemptSummary(result),
				Findings: len(after) - len(before),
			})
			if len(after) >= o.Budget.MaxFindings {
				outcome.Stop = StopBudget
				outcome.Message = fmt.Sprintf("finding cap reached (%d)", len(after))
				stopped = true
				break
			}
		}
	}

	findings, _ := o.findingsFor(ctx)
	outcome.Findings = findings
	outcome.Duration = time.Since(started)

	// The critic and the reporter run even when the goal was not met: "we could
	// not confirm anything" is itself a conclusion worth stating precisely.
	accepted, note, tokens, err := o.review(ctx, findings)
	outcome.Tokens += tokens
	if err != nil {
		outcome.Stop = StopFatal
		outcome.Message = "review failed: " + err.Error()
		return outcome, err
	}
	outcome.Accepted = accepted
	if reviewed, err := o.findingsFor(ctx); err == nil {
		outcome.Findings = reviewed
	}

	report, reportTokens, err := o.report(ctx, goal, accepted, note, outcome)
	outcome.Tokens += reportTokens
	outcome.Duration = time.Since(started)
	if err != nil {
		outcome.Stop = StopFatal
		outcome.Message = "report failed: " + err.Error()
		return outcome, err
	}
	outcome.Report = report
	return outcome, nil
}

// plannerResponse is one planning round's output.
type plannerResponse struct {
	GoalMet bool          `json:"goal_met"`
	Reason  string        `json:"reason"`
	Intents []PlannedStep `json:"intents"`
}

// plan asks the planner what to do next, given the evidence and the attempt log.
func (o *TeamOrchestrator) plan(ctx context.Context, goal string, findings []domain.Finding, attempts []Attempt) (plannerResponse, int, error) {
	var b strings.Builder
	// The exact target must be in the prompt. Handing the planner only a prose
	// goal let it invent a hostname, every subsequent tool call failed, and the
	// budget was spent on a target nobody authorized.
	b.WriteString("授权目标（唯一允许操作的主机）：" + o.Target + "\n\n")
	b.WriteString("任务目标：" + goal + "\n\n")

	if len(findings) == 0 {
		b.WriteString("【当前态势】还没有任何已确认的发现。\n\n")
	} else {
		b.WriteString("【当前态势】已确认的发现：\n")
		b.WriteString(renderFindings(findings))
		b.WriteString("\n")
	}

	if len(attempts) == 0 {
		b.WriteString("【历史尝试】还没有派发过任何方向。\n\n")
	} else {
		b.WriteString("【历史尝试】按状态决定续派还是换方向：\n")
		for _, attempt := range attempts {
			fmt.Fprintf(&b, "- [%s] %s → %s（新增发现 %d）%s\n",
				attempt.State, attempt.Duty, truncate(attempt.Goal, 100), attempt.Findings,
				truncate(attempt.Summary, 120))
		}
		b.WriteString("\n状态含义：done=已探到结论；exhausted=预算耗尽、只拿到部分结果，应接着上次进度续派；" +
			"stalled=反复做同一个调用，需要换打法；blocked=外部故障基本没探成，直接重派同方向。\n\n")
	}

	b.WriteString("【本轮要求】\n")
	b.WriteString("1. 先判定目标是否已真正达成：只有证据支持才算，达成则 goal_met=true。\n")
	b.WriteString("2. 未达成时只列出尚未被覆盖的方向；历史尝试里出现过的不要原样重复。\n")
	b.WriteString("3. 目标未达成且没有可续派的方向时，必须给出至少一个新方向，不能返回空列表。\n")
	b.WriteString("4. 只输出 JSON：{\"goal_met\":false,\"reason\":\"...\",\"intents\":[{\"duty\":\"recon|web|exploit\",\"goal\":\"...\",\"done_when\":\"...\"}]}\n")

	result, err := o.RunAgent(ctx, DutyPlan, b.String())
	if err != nil {
		return plannerResponse{}, result.Tokens, err
	}

	resp, parseErr := parsePlannerResponse(result.Content)
	if parseErr != nil {
		// Guessing a plan would spend the budget on unpremeditated probing, so a
		// malformed plan is a hard stop.
		return plannerResponse{}, result.Tokens, fmt.Errorf(
			"planner output is not a usable plan: %w (raw: %s)", parseErr, truncate(result.Content, 400))
	}
	return resp, result.Tokens, nil
}

// parsePlannerResponse accepts both the round shape (intents) and the older
// batch shape (steps), because a model that has seen either will produce it.
func parsePlannerResponse(content string) (plannerResponse, error) {
	raw := extractJSONObject(content)
	if raw == "" {
		return plannerResponse{}, fmt.Errorf("no JSON object found")
	}

	var envelope struct {
		GoalMet bool          `json:"goal_met"`
		Reason  string        `json:"reason"`
		Intents []PlannedStep `json:"intents"`
		Steps   []PlannedStep `json:"steps"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return plannerResponse{}, fmt.Errorf("decode planner output: %w", err)
	}

	items := envelope.Intents
	if len(items) == 0 {
		items = envelope.Steps
	}

	valid := make([]PlannedStep, 0, len(items))
	for _, step := range items {
		step.Duty = strings.ToLower(strings.TrimSpace(step.Duty))
		if !dispatchableDuties[step.Duty] {
			return plannerResponse{}, fmt.Errorf("planner assigned a non-dispatchable duty %q", step.Duty)
		}
		if strings.TrimSpace(step.Goal) == "" {
			return plannerResponse{}, fmt.Errorf("planner produced an intent with no goal")
		}
		valid = append(valid, step)
	}
	return plannerResponse{GoalMet: envelope.GoalMet, Reason: envelope.Reason, Intents: valid}, nil
}

// settle runs the wrap-up phase for a worker whose budget ran out.
//
// Without it everything the worker identified but had not yet written back is
// lost with the process, and the next round re-explores from scratch. It reports
// whether the settlement ran and produced output.
func (o *TeamOrchestrator) settle(ctx context.Context, intent PlannedStep, result RunResult, outcome *TeamOutcome) bool {
	if o.SettleAgent == nil {
		o.emit("worker budget exhausted but no settlement phase is configured; " +
			"findings identified after the last tool call are lost")
		return false
	}

	o.emit(fmt.Sprintf("worker stopped on %s; running settlement to write back what it already found", result.Stop))
	settleInput := o.workerInput(intent, nil, false) +
		"\n\n【收尾】你的探索预算已用尽，本轮即将结束。不要再发起新的探测，" +
		"只把已经确认但还没有上报的结果按 findings JSON 格式输出。没有就输出空数组。"
	settled, err := o.SettleAgent(ctx, Duty(intent.Duty), settleInput)
	outcome.Steps += len(settled.Steps)
	outcome.Tokens += settled.Tokens
	if err != nil {
		o.emit("settlement failed: " + truncate(err.Error(), 160))
		return false
	}
	if strings.TrimSpace(settled.Content) == "" {
		return false
	}
	// Feed the settlement output through the same capture path, including the
	// grounding gate, so a wrap-up cannot smuggle in an uncited claim.
	if err := o.capture(ctx, Duty(intent.Duty), settled.Content, settled.ToolCalls); err != nil {
		o.emit("settlement findings not recorded: " + truncate(err.Error(), 160))
		return false
	}
	return true
}

// attemptState maps a worker stop to the state the planner acts on.
func attemptState(stop StopReason, settled bool) string {
	switch stop {
	case StopBudget, StopStall:
		// A settled budget stop and an unsettled one are both partial, but a stall
		// means more budget will not help, which is a different instruction.
		if stop == StopStall {
			return AttemptStalled
		}
		return AttemptExhausted
	case StopFatal:
		return AttemptBlocked
	case StopApproval:
		return AttemptApproval
	default:
		return AttemptDone
	}
}

func attemptSummary(result RunResult) string {
	if strings.TrimSpace(result.Content) != "" {
		return truncate(result.Content, 240)
	}
	return truncate(result.Message, 240)
}

// capture extracts findings from a worker's final answer and persists them.
func (o *TeamOrchestrator) capture(ctx context.Context, duty Duty, content string, toolCalls int) error {
	raw := extractJSONObject(content)
	if raw == "" {
		// A worker that produced no citable finding is a normal outcome, but it is
		// reported loudly: a run that spends its budget on tool calls and records
		// nothing is indistinguishable from a run that did nothing, unless the
		// operator can see which one happened.
		o.emit(fmt.Sprintf("duty=%s produced no structured findings (%d tool calls)", duty, toolCalls))
		return nil
	}

	var payload struct {
		Findings []struct {
			Kind       string          `json:"kind"`
			Target     string          `json:"target"`
			Claim      string          `json:"claim"`
			Confidence flexibleFloat   `json:"confidence"`
			Evidence   json.RawMessage `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		o.emit(fmt.Sprintf("duty=%s output is not valid findings JSON: %v", duty, err))
		return nil
	}

	for _, item := range payload.Findings {
		target := strings.TrimSpace(item.Target)
		if target == "" {
			target = o.Target
		}
		evidence, err := decodeEvidence(item.Evidence)
		if err != nil {
			o.emit(fmt.Sprintf("finding refused: evidence is unusable: %v", err))
			continue
		}
		finding := domain.Finding{
			TaskID:     o.TaskID,
			AgentKey:   string(duty),
			Duty:       string(duty),
			Kind:       strings.ToLower(strings.TrimSpace(item.Kind)),
			Target:     target,
			Claim:      strings.TrimSpace(item.Claim),
			Evidence:   evidence,
			Confidence: float64(item.Confidence),
		}
		if err := finding.Validate(); err != nil {
			// The grounding gate: an uncited claim is dropped, and the reason is
			// reported so the run shows it was refused rather than unnoticed.
			o.emit(fmt.Sprintf("finding refused: %v", err))
			continue
		}
		stored, created, err := o.Findings.CreateFinding(ctx, finding)
		if err != nil {
			return fmt.Errorf("record finding: %w", err)
		}
		if created {
			o.emit(fmt.Sprintf("finding recorded kind=%s target=%s claim=%s",
				stored.Kind, stored.Target, truncate(stored.Claim, 80)))
		} else {
			o.emit(fmt.Sprintf("finding already known (%s); corroboration not duplicated", stored.ID))
		}
	}
	return nil
}

// confidenceWords maps the vocabulary models actually reach for onto a number.
//
// ARTEX grades confidence with words — observed vs inferred — precisely because
// that distinction changes what a downstream agent should do with a claim. Forcing
// a float made the model's natural answer a decode error, which discarded the
// whole findings batch. Accepting the words keeps the semantics instead of
// dropping the work.
//
// inferred is deliberately mid-range, not low: a worker that reasoned from real
// output without exercising the weakness has something worth acting on, but not
// something worth reporting as confirmed.
var confidenceWords = map[string]float64{
	"observed":    0.9,
	"confirmed":   0.9,
	"verified":    0.9,
	"high":        0.85,
	"probable":    0.65,
	"likely":      0.65,
	"medium":      0.6,
	"inferred":    0.5,
	"possible":    0.4,
	"suspected":   0.35,
	"low":         0.3,
	"unconfirmed": 0.25,
	"speculative": 0.2,
	"guess":       0.15,
	"unknown":     0,
}

// flexibleFloat accepts a number, a numeric string, or a confidence word.
//
// Observed in practice: a model emitted "confidence": "0.8" once and
// "confidence": "confirmed" another time. In both cases the whole findings batch
// failed to decode and every claim in that response was lost because of one
// field's type.
//
// The range check belongs to Finding.Validate, not here: decoding should say what
// the value is, not whether it is acceptable.
type flexibleFloat float64

func (f *flexibleFloat) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = 0
		return nil
	}
	if unquoted, err := strconv.Unquote(trimmed); err == nil {
		trimmed = strings.TrimSpace(unquoted)
		if trimmed == "" {
			*f = 0
			return nil
		}
	}
	if value, ok := confidenceWords[strings.ToLower(trimmed)]; ok {
		*f = flexibleFloat(value)
		return nil
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return fmt.Errorf("confidence %s is neither a number nor a known level (observed/inferred/low)", string(data))
	}
	*f = flexibleFloat(value)
	return nil
}

// decodeEvidence accepts the shapes models actually produce.
//
// Observed in practice: a model emitted evidence as a bare string, the whole
// batch failed to decode, and every finding in that response was lost. Coercing
// the common variants keeps real work that a strict decoder discards, while
// anything unrecognised still fails closed.
func decodeEvidence(raw json.RawMessage) ([]domain.EvidenceRef, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	// A single string is one citation with no named reference.
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			return nil, nil
		}
		return []domain.EvidenceRef{{Kind: "tool_output", Ref: single, Quote: single}}, nil
	}

	var refs []domain.EvidenceRef
	if err := json.Unmarshal(raw, &refs); err == nil {
		return refs, nil
	}

	// A single citation object rather than an array of them.
	var one domain.EvidenceRef
	if err := json.Unmarshal(raw, &one); err == nil && (one.Ref != "" || one.Quote != "") {
		return []domain.EvidenceRef{one}, nil
	}

	// An array of strings, which some models prefer over an array of objects.
	var citations []string
	if err := json.Unmarshal(raw, &citations); err == nil {
		out := make([]domain.EvidenceRef, 0, len(citations))
		for _, item := range citations {
			if strings.TrimSpace(item) == "" {
				continue
			}
			out = append(out, domain.EvidenceRef{Kind: "tool_output", Ref: item, Quote: item})
		}
		return out, nil
	}

	return nil, fmt.Errorf("expected a string or an array of citations")
}

// review has the critic accept or reject each active finding.
func (o *TeamOrchestrator) review(ctx context.Context, findings []domain.Finding) ([]domain.Finding, string, int, error) {
	active := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if !finding.Rejected {
			active = append(active, finding)
		}
	}
	if len(active) == 0 {
		return nil, "no findings were recorded, so there was nothing to review", 0, nil
	}

	o.emit(fmt.Sprintf("duty=critic reviewing %d findings", len(active)))
	result, err := o.RunAgent(ctx, DutyCritic, renderForReview(active))
	if err != nil {
		return nil, "", result.Tokens, err
	}

	var verdict struct {
		Accepted []struct {
			ID     string `json:"id"`
			Accept bool   `json:"accept"`
			Reason string `json:"reason"`
		} `json:"findings"`
		Note string `json:"note"`
	}
	raw := extractJSONObject(result.Content)
	if raw == "" || json.Unmarshal([]byte(raw), &verdict) != nil {
		// A critic that cannot answer in the required shape has not reviewed
		// anything. Accepting by default would make the gate decorative.
		return nil, "critic output was unusable, so no finding was accepted", result.Tokens, nil
	}

	decisions := map[string]bool{}
	reasons := map[string]string{}
	for _, item := range verdict.Accepted {
		decisions[item.ID] = item.Accept
		reasons[item.ID] = item.Reason
	}

	accepted := make([]domain.Finding, 0, len(active))
	for _, finding := range active {
		accept, seen := decisions[finding.ID]
		if !seen {
			// Unmentioned is not accepted. A critic that silently skips a finding
			// must not thereby approve it.
			continue
		}
		if !accept {
			if err := o.Findings.RejectFinding(ctx, finding.ID, reasons[finding.ID]); err != nil {
				return nil, "", result.Tokens, fmt.Errorf("reject finding %s: %w", finding.ID, err)
			}
			o.emit(fmt.Sprintf("finding rejected id=%s reason=%s", finding.ID, truncate(reasons[finding.ID], 120)))
			continue
		}
		accepted = append(accepted, finding)
	}
	return accepted, verdict.Note, result.Tokens, nil
}

// report asks the reporter to write the final narrative from accepted findings
// only, so the report cannot contain a claim the critic refused.
func (o *TeamOrchestrator) report(ctx context.Context, goal string, accepted []domain.Finding, note string, outcome TeamOutcome) (string, int, error) {
	var b strings.Builder
	b.WriteString("任务目标：" + goal + "\n\n")
	b.WriteString("运行结论：" + string(outcome.Stop))
	if outcome.Message != "" {
		b.WriteString("（" + outcome.Message + "）")
	}
	b.WriteString("\n目标是否达成：" + boolText(outcome.GoalMet))
	if outcome.GoalReason != "" {
		b.WriteString("（" + outcome.GoalReason + "）")
	}
	b.WriteString("\n\n")

	if len(outcome.Attempts) > 0 {
		b.WriteString("尝试过的方向：\n")
		for _, attempt := range outcome.Attempts {
			fmt.Fprintf(&b, "- [%s] %s：%s\n", attempt.State, attempt.Duty, truncate(attempt.Goal, 120))
		}
		b.WriteString("\n")
	}

	if len(accepted) == 0 {
		b.WriteString("经复核后没有可采纳的发现。\n")
		if note != "" {
			b.WriteString("复核说明：" + note + "\n")
		}
	} else {
		b.WriteString("经复核采纳的发现：\n")
		b.WriteString(renderFindings(accepted))
	}
	result, err := o.RunAgent(ctx, DutyReport, b.String())
	return result.Content, result.Tokens, err
}

func boolText(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

// findingsFor reads the current findings so each worker and each planning round
// sees what is already established. This is the whole point of the handoff.
func (o *TeamOrchestrator) findingsFor(ctx context.Context) ([]domain.Finding, error) {
	if o.Findings == nil {
		return nil, nil
	}
	return o.Findings.ListFindings(ctx, o.TaskID)
}

// workerInput is what a worker receives: the intent plus the facts already
// established. It deliberately excludes other agents' conversations.
func (o *TeamOrchestrator) workerInput(step PlannedStep, findings []domain.Finding, resumed bool) string {
	var b strings.Builder
	b.WriteString("授权目标（唯一允许操作的主机）：" + o.Target + "\n")
	b.WriteString("本步骤职责：" + step.Duty + "\n")
	b.WriteString("目标：" + step.Goal + "\n")
	if step.DoneWhen != "" {
		b.WriteString("完成判据：" + step.DoneWhen + "\n")
	}
	if resumed {
		b.WriteString("上一轮因等待人工审批而暂停，该动作已被批准，可以重新执行。\n")
	}
	b.WriteString("\n")
	if len(findings) == 0 {
		b.WriteString("目前还没有任何已确认的发现。\n")
	} else {
		b.WriteString("已确认的发现（来自其他成员，可直接使用，不要重复验证）：\n")
		b.WriteString(renderFindings(findings))
	}
	b.WriteString("\n完成后按系统提示的格式输出 findings JSON（可以没有发现，但不要编造）。\n")
	return b.String()
}

func renderFindings(findings []domain.Finding) string {
	var b strings.Builder
	for _, finding := range findings {
		state := ""
		if finding.Rejected {
			state = "（已被复核驳回）"
		}
		fmt.Fprintf(&b, "- [%s] %s → %s（置信度 %.2f）%s\n",
			finding.Kind, finding.Target, finding.Claim, finding.Confidence, state)
		for _, ref := range finding.Evidence {
			fmt.Fprintf(&b, "    证据(%s): %s", ref.Kind, ref.Ref)
			if ref.Quote != "" {
				fmt.Fprintf(&b, " 「%s」", truncate(ref.Quote, 160))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// renderForReview gives the critic stable ids plus the evidence, because a
// verdict that cannot name a finding cannot reject it.
func renderForReview(findings []domain.Finding) string {
	var b strings.Builder
	b.WriteString("请逐条判断以下发现是否有证据支持。只输出 JSON：")
	b.WriteString(`{"findings":[{"id":"...","accept":true|false,"reason":"..."}],"note":"..."}`)
	b.WriteString("\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&b, "id=%s kind=%s target=%s confidence=%.2f\n  claim: %s\n",
			finding.ID, finding.Kind, finding.Target, finding.Confidence, finding.Claim)
		for _, ref := range finding.Evidence {
			fmt.Fprintf(&b, "  evidence(%s): %s 「%s」\n", ref.Kind, ref.Ref, truncate(ref.Quote, 300))
		}
	}
	return b.String()
}

func (o *TeamOrchestrator) emit(line string) {
	if o.OnStep != nil {
		o.OnStep(line)
	}
}

// transcriptText flattens a parked worker's transcript so a resumed run keeps
// the facts it already established instead of paying for them twice.
func transcriptText(messages []domain.Message) string {
	const maxToolContent = 1500
	var b strings.Builder
	for _, message := range messages {
		switch message.Role {
		case "assistant":
			if message.Content != "" {
				b.WriteString("助手：" + message.Content + "\n")
			}
			for _, call := range message.ToolCalls {
				b.WriteString("调用：" + call.Name + " " + string(call.Arguments) + "\n")
			}
		case "tool":
			content := message.Content
			if len(content) > maxToolContent {
				cut := maxToolContent
				for cut > 0 && !utf8.RuneStart(content[cut]) {
					cut--
				}
				content = content[:cut] + "...(截断)"
			}
			b.WriteString("结果[" + message.Name + "]：" + content + "\n")
		}
	}
	return b.String()
}

// extractJSONObject finds the outermost JSON object in a model response.
//
// Models frequently wrap JSON in prose or a fenced block, so a strict
// json.Unmarshal of the whole message would reject usable output. Scanning for
// balanced braces is bounded and does not need a parser.
func extractJSONObject(content string) string {
	start := strings.Index(content, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(content); i++ {
		ch := content[i]
		switch {
		case escaped:
			escaped = false
		case ch == '\\' && inString:
			escaped = true
		case ch == '"':
			inString = !inString
		case inString:
			// Braces inside a string literal do not change depth.
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return content[start : i+1]
			}
		}
	}
	return ""
}
