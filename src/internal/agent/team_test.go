package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"soc/agent/internal/domain"
)

// fakeFindings is an in-memory FindingRepository with real dedupe semantics, so
// orchestrator tests exercise the same convergence rule the database enforces.
type fakeFindings struct {
	mu       sync.Mutex
	rows     []domain.Finding
	rejected map[string]string
	failNext error
}

func newFakeFindings() *fakeFindings {
	return &fakeFindings{rejected: map[string]string{}}
}

func (f *fakeFindings) CreateFinding(_ context.Context, finding domain.Finding) (domain.Finding, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return domain.Finding{}, false, err
	}
	if finding.ID == "" {
		finding.ID = "f" + itoa(len(f.rows)+1)
	}
	if finding.DedupKey == "" {
		finding.DedupKey = finding.NormalizedDedupKey()
	}
	for _, row := range f.rows {
		if row.DedupKey == finding.DedupKey && row.TaskID == finding.TaskID {
			return row, false, nil
		}
	}
	f.rows = append(f.rows, finding)
	return finding, true, nil
}

func (f *fakeFindings) ListFindings(_ context.Context, taskID string) ([]domain.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]domain.Finding, 0, len(f.rows))
	for _, row := range f.rows {
		if row.TaskID != taskID {
			continue
		}
		if note, ok := f.rejected[row.ID]; ok {
			row.Rejected = true
			row.RejectNote = note
		}
		out = append(out, row)
	}
	return out, nil
}

func (f *fakeFindings) RejectFinding(_ context.Context, findingID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected[findingID] = reason
	return nil
}

func (f *fakeFindings) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// scriptedAgent answers per duty from a queue, so a multi-round test can give the
// planner a different answer each round. The last queued response repeats, so a
// test does not fail merely because a duty was called more often than scripted.
type scriptedAgent struct {
	mu           sync.Mutex
	queues       map[Duty][]string
	settleQueues map[Duty][]string
	errors       map[Duty]error
	stops        map[Duty]StopReason
	inputs       map[Duty][]string
	calls        map[Duty]int
	settleCalls  int
}

func newScriptedAgent() *scriptedAgent {
	return &scriptedAgent{
		queues:       map[Duty][]string{},
		settleQueues: map[Duty][]string{},
		errors:       map[Duty]error{},
		stops:        map[Duty]StopReason{},
		inputs:       map[Duty][]string{},
		calls:        map[Duty]int{},
	}
}

func (s *scriptedAgent) push(duty Duty, responses ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queues[duty] = append(s.queues[duty], responses...)
}

func (s *scriptedAgent) pushSettle(duty Duty, responses ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settleQueues[duty] = append(s.settleQueues[duty], responses...)
}

func (s *scriptedAgent) setStop(duty Duty, stop StopReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops[duty] = stop
}

func (s *scriptedAgent) nextLocked(duty Duty) string {
	queue := s.queues[duty]
	index := s.calls[duty]
	s.calls[duty]++
	if len(queue) == 0 {
		return ""
	}
	if index >= len(queue) {
		return queue[len(queue)-1]
	}
	return queue[index]
}

func (s *scriptedAgent) run(_ context.Context, duty Duty, input string) (RunResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputs[duty] = append(s.inputs[duty], input)
	if err := s.errors[duty]; err != nil {
		return RunResult{Tokens: 10}, err
	}
	stop := s.stops[duty]
	if stop == "" {
		stop = StopVerdict
	}
	return RunResult{
		Stop:      stop,
		Content:   s.nextLocked(duty),
		Tokens:    100,
		ToolCalls: 1,
		Steps:     []Step{{Index: 1, Kind: "model"}},
	}, nil
}

func (s *scriptedAgent) settle(_ context.Context, duty Duty, _ string) (RunResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settleCalls++
	queue := s.settleQueues[duty]
	if len(queue) == 0 {
		return RunResult{Tokens: 5}, nil
	}
	content := queue[0]
	if len(queue) > 1 {
		s.settleQueues[duty] = queue[1:]
	}
	return RunResult{Content: content, Tokens: 5, Steps: []Step{{Index: 1, Kind: "model"}}}, nil
}

func (s *scriptedAgent) inputFor(duty Duty) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	inputs := s.inputs[duty]
	if len(inputs) == 0 {
		return ""
	}
	return inputs[len(inputs)-1]
}

func (s *scriptedAgent) callCount(duty Duty) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inputs[duty])
}

func (s *scriptedAgent) plannerInput(round int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	inputs := s.inputs[DutyPlan]
	if round >= len(inputs) {
		return ""
	}
	return inputs[round]
}

// roundJSON builds one planning round's output.
func roundJSON(goalMet bool, reason string, intents ...string) string {
	items := make([]string, 0, len(intents))
	for _, intent := range intents {
		items = append(items, `{"duty":"`+intent+`","goal":"do `+intent+`","done_when":"evidence collected"}`)
	}
	met := "false"
	if goalMet {
		met = "true"
	}
	return `{"goal_met":` + met + `,"reason":"` + reason + `","intents":[` + strings.Join(items, ",") + `]}`
}

func findingsJSON(items ...string) string {
	return `{"findings":[` + strings.Join(items, ",") + `]}`
}

func findingJSON(kind, claim, ref string) string {
	return `{"kind":"` + kind + `","target":"example.com","claim":"` + claim +
		`","confidence":0.8,"evidence":[{"kind":"tool_output","ref":"` + ref + `","quote":"observed"}]}`
}

func criticJSON(accept map[string]bool) string {
	var items []string
	for id, ok := range accept {
		state := "false"
		if ok {
			state = "true"
		}
		items = append(items, `{"id":"`+id+`","accept":`+state+`,"reason":"checked"}`)
	}
	return `{"findings":[` + strings.Join(items, ",") + `],"note":"reviewed"}`
}

func newOrchestrator(repo *fakeFindings, stub *scriptedAgent) *TeamOrchestrator {
	return &TeamOrchestrator{
		RunAgent:    stub.run,
		SettleAgent: stub.settle,
		Findings:    repo,
		TaskID:      "task-1",
		Target:      "example.com:443",
		Budget:      DefaultTeamBudget(),
	}
}

func TestTeamPlannerReplansEachRound(t *testing.T) {
	// The central property: the planner runs again after seeing what the workers
	// found. A one-shot plan would execute its whole list without ever reacting.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "start with recon", "recon"),
		roundJSON(true, "the exposure finding is enough"),
	)
	stub.push(DutyRecon, findingsJSON(findingJSON("exposure", "upload endpoint accepts php", "http_request POST /upload.php")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))
	stub.push(DutyReport, "报告")

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "get the flag")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if stub.callCount(DutyPlan) != 2 {
		t.Fatalf("planner ran %d times, want 2 (one per round)", stub.callCount(DutyPlan))
	}
	if !outcome.GoalMet {
		t.Fatal("GoalMet = false, want true from the second round")
	}
	if outcome.Stop != StopVerdict {
		t.Fatalf("stop = %s", outcome.Stop)
	}
	if len(outcome.Attempts) != 1 || outcome.Attempts[0].State != AttemptDone {
		t.Fatalf("attempts = %+v", outcome.Attempts)
	}
	if outcome.Report != "报告" {
		t.Fatalf("report = %q", outcome.Report)
	}
}

func TestTeamSecondRoundSeesTheAttemptLog(t *testing.T) {
	// Without the attempt log the planner either repeats finished work or drops a
	// viable route, because it cannot tell "tried and ruled out" from "untried".
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "first direction", "recon"),
		roundJSON(true, "enough"),
	)
	stub.push(DutyRecon, findingsJSON(findingJSON("recon", "nginx detected", "probe")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	second := stub.plannerInput(1)
	if second == "" {
		t.Fatal("the planner did not run a second round")
	}
	if !strings.Contains(second, "历史尝试") {
		t.Fatalf("second planning round had no attempt log:\n%s", second)
	}
	if !strings.Contains(second, AttemptDone) {
		t.Fatalf("the attempt state was not reported to the planner:\n%s", second)
	}
	if !strings.Contains(second, "nginx detected") {
		t.Fatalf("the second round did not see the finding:\n%s", second)
	}
}

func TestTeamWorkerSeesEarlierFindings(t *testing.T) {
	// The handoff is why a team beats one agent with a longer prompt: the second
	// worker starts from confirmed facts instead of re-discovering them.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "recon first", "recon"),
		roundJSON(false, "deeper", "web"),
		roundJSON(true, "done"),
	)
	stub.push(DutyRecon, findingsJSON(findingJSON("recon", "PHP 7.3.11 detected", "probe")))
	stub.push(DutyWeb, findingsJSON(findingJSON("exposure", "eval sink at c", "http_request GET /?c=1")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true, "f2": true}))

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	webInput := stub.inputFor(DutyWeb)
	if !strings.Contains(webInput, "PHP 7.3.11 detected") {
		t.Fatalf("the web worker did not receive the recon finding:\n%s", webInput)
	}
}

func TestTeamWorkerBudgetTriggersSettlement(t *testing.T) {
	// Regression: StopBudget returned immediately, so everything the worker had
	// identified but not yet written back was lost with the process.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "start", "recon"),
		roundJSON(true, "the settled finding is enough"),
	)
	stub.push(DutyRecon, "") // budget hit before writing anything back
	stub.pushSettle(DutyRecon, findingsJSON(findingJSON("recon", "found during settlement", "probe")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))
	stub.setStop(DutyRecon, StopBudget)

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if stub.settleCalls == 0 {
		t.Fatal("no settlement phase ran after the worker's budget was spent")
	}
	if repo.count() != 1 {
		t.Fatalf("findings recorded = %d, want the settled finding to survive", repo.count())
	}
}

func TestTeamReportsMissingSettlementInsteadOfPretending(t *testing.T) {
	// When no settlement is wired the run must say so, not behave as if the
	// partial work had been saved.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "start", "recon"), roundJSON(true, "stop"))
	stub.push(DutyRecon, "")
	stub.setStop(DutyRecon, StopBudget)
	stub.push(DutyCritic, `{"findings":[],"note":""}`)

	var lines []string
	orchestrator := newOrchestrator(repo, stub)
	orchestrator.SettleAgent = nil
	orchestrator.OnStep = func(line string) { lines = append(lines, line) }

	if _, err := orchestrator.Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "settlement") {
		t.Fatalf("the missing settlement was not reported:\n%s", strings.Join(lines, "\n"))
	}
}

func TestAttemptStateSeparatesBudgetFromFailure(t *testing.T) {
	// The next round's instruction depends on this distinction: exhausted means
	// "continue where it stopped", blocked means "nothing was learned, retry".
	tests := []struct {
		name string
		stop StopReason
		want string
	}{
		{name: "verdict", stop: StopVerdict, want: AttemptDone},
		{name: "budget", stop: StopBudget, want: AttemptExhausted},
		{name: "stall", stop: StopStall, want: AttemptStalled},
		{name: "fatal", stop: StopFatal, want: AttemptBlocked},
		{name: "approval", stop: StopApproval, want: AttemptApproval},
	}
	for _, tc := range tests {
		if got := attemptState(tc.stop, false); got != tc.want {
			t.Fatalf("%s: attemptState(%s) = %s, want %s", tc.name, tc.stop, got, tc.want)
		}
	}
}

func TestTeamStopsWhenPlannerHasNothingNew(t *testing.T) {
	// The hard floor: goal unmet plus no new direction means progress stopped. A
	// silent success here is indistinguishable from having finished the job.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "nothing left to try"))

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.Stop != StopStall {
		t.Fatalf("stop = %s, want stall", outcome.Stop)
	}
	if outcome.GoalMet {
		t.Fatal("GoalMet = true while the planner produced no direction")
	}
	if !strings.Contains(outcome.Message, "no new direction") {
		t.Fatalf("message = %q", outcome.Message)
	}
}

func TestTeamRejectsPlansThatDispatchJudgement(t *testing.T) {
	// A planner that schedules the critic, the reporter or itself is a plan the
	// orchestrator cannot honour; silently dropping it would hide the confusion.
	for _, duty := range []string{"critic", "report", "plan"} {
		repo := newFakeFindings()
		stub := newScriptedAgent()
		stub.push(DutyPlan, roundJSON(false, "misplan", duty))

		if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err == nil {
			t.Fatalf("a plan dispatching %q was accepted", duty)
		}
	}
}

func TestTeamFailsOnUnusablePlan(t *testing.T) {
	// Guessing a plan would spend the budget on unpremeditated probing.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, "我先看看目标吧")

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err == nil {
		t.Fatal("an unusable plan was accepted")
	}
	if outcome.Stop != StopFatal {
		t.Fatalf("stop = %s, want fatal", outcome.Stop)
	}
	if stub.callCount(DutyRecon) != 0 {
		t.Fatal("a worker ran without a plan")
	}
}

func TestTeamEnforcesTheRoundBudget(t *testing.T) {
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "more", "recon"))
	stub.push(DutyRecon, "")
	stub.push(DutyCritic, `{"findings":[],"note":""}`)

	orchestrator := newOrchestrator(repo, stub)
	orchestrator.Budget.MaxRounds = 2

	outcome, err := orchestrator.Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.Stop != StopBudget {
		t.Fatalf("stop = %s, want budget", outcome.Stop)
	}
	if stub.callCount(DutyPlan) != 2 {
		t.Fatalf("planner ran %d times, want exactly the 2 allowed rounds", stub.callCount(DutyPlan))
	}
}

func TestTeamEnforcesTheIntentCapPerRound(t *testing.T) {
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "flood", "recon", "web", "exploit", "recon", "web", "exploit"),
		roundJSON(true, "done"),
	)
	stub.push(DutyCritic, `{"findings":[],"note":""}`)

	orchestrator := newOrchestrator(repo, stub)
	orchestrator.Budget.MaxIntentsPerRound = 2

	if _, err := orchestrator.Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	total := stub.callCount(DutyRecon) + stub.callCount(DutyWeb) + stub.callCount(DutyExploit)
	if total != 2 {
		t.Fatalf("workers ran %d times, want the 2 allowed intents", total)
	}
}

func TestTeamEnforcesTheFindingCap(t *testing.T) {
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "start", "recon"), roundJSON(false, "web", "web"))
	stub.push(DutyRecon, findingsJSON(
		findingJSON("recon", "fact one", "probe a"),
		findingJSON("recon", "fact two", "probe b"),
	))
	stub.push(DutyCritic, `{"findings":[{"id":"f1","accept":true},{"id":"f2","accept":true}],"note":""}`)

	orchestrator := newOrchestrator(repo, stub)
	orchestrator.Budget.MaxFindings = 1

	outcome, err := orchestrator.Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.Stop != StopBudget {
		t.Fatalf("stop = %s, want budget when the finding cap is reached", outcome.Stop)
	}
}

func TestTeamParksEverythingWhenAWorkerNeedsApproval(t *testing.T) {
	// A parked worker stops the team: a later intent acting on evidence the
	// parked one never produced would build on a gap.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "go", "web", "exploit"))
	stub.setStop(DutyWeb, StopApproval)

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.Stop != StopApproval {
		t.Fatalf("stop = %s, want approval", outcome.Stop)
	}
	if outcome.PendingRound != 1 {
		t.Fatalf("pending round = %d, want 1", outcome.PendingRound)
	}
	if outcome.PendingDuty != "web" {
		t.Fatalf("pending duty = %q", outcome.PendingDuty)
	}
	if stub.callCount(DutyExploit) != 0 {
		t.Fatal("an intent after the parked one executed")
	}
}

func TestTeamResumeReusesPlanAndContinuesTheRound(t *testing.T) {
	// Regression: resume re-planned and started a new round, so the parked intent
	// was never re-dispatched and the approval was wasted.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyWeb, findingsJSON(findingJSON("exposure", "upload works", "http_request POST /upload")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	orchestrator := newOrchestrator(repo, stub)
	orchestrator.ResumeRound = 1
	orchestrator.ResumeFrom = 1
	orchestrator.ResumePlan = []PlannedStep{
		{Duty: "recon", Goal: "step one", DoneWhen: "done"},
		{Duty: "web", Goal: "step two", DoneWhen: "done"},
	}
	orchestrator.ApprovalID = "approval-1"
	orchestrator.ResumeAttempts = []Attempt{{Round: 1, Duty: "recon", Goal: "step one", State: AttemptDone}}
	orchestrator.ResumeHistory = "结果[http_probe]：HTTP/1.1 200 OK"
	// The resumed round finishes without re-planning; round 2 then plans normally.
	orchestrator.Budget.MaxRounds = 2
	stub.push(DutyPlan, roundJSON(true, "the exposure finding is enough"))

	outcome, err := orchestrator.Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Exactly one planning call: the resumed round reused its saved plan, and only
	// the following round planned. Planning the resumed round would produce a
	// different list and the resume index would point elsewhere.
	if stub.callCount(DutyPlan) != 1 {
		t.Fatalf("planner ran %d times, want 1 (only for the round after the resume)", stub.callCount(DutyPlan))
	}
	if stub.callCount(DutyRecon) != 0 {
		t.Fatal("the already-completed intent re-ran")
	}
	if stub.callCount(DutyWeb) != 1 {
		t.Fatalf("the parked intent ran %d times, want 1", stub.callCount(DutyWeb))
	}
	webInput := stub.inputFor(DutyWeb)
	if !strings.Contains(webInput, "批准") {
		t.Fatalf("the resumed worker was not told about the approval:\n%s", webInput)
	}
	if !strings.Contains(webInput, "HTTP/1.1 200 OK") {
		t.Fatalf("the resumed worker did not receive its transcript:\n%s", webInput)
	}
	// The prior attempt is preserved and the resumed intent adds its own, so a
	// later round still knows the recon direction was already done.
	if len(outcome.Attempts) != 2 {
		t.Fatalf("attempts = %d, want the prior attempt plus the resumed one", len(outcome.Attempts))
	}
	if outcome.Attempts[0].State != AttemptDone || outcome.Attempts[0].Duty != "recon" {
		t.Fatalf("the prior attempt was not preserved: %+v", outcome.Attempts[0])
	}
	if outcome.Stop != StopVerdict {
		t.Fatalf("stop = %s", outcome.Stop)
	}
}

func TestTeamDropsUncitedFindings(t *testing.T) {
	// The grounding gate: a claim without evidence must never become a fact a
	// later agent builds on, and the drop must be visible.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, findingsJSON(
		`{"kind":"access","target":"example.com","claim":"target is fully compromised","confidence":0.9}`,
		findingJSON("recon", "nginx detected", "http_probe /"),
	))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	var lines []string
	orchestrator := newOrchestrator(repo, stub)
	orchestrator.OnStep = func(line string) { lines = append(lines, line) }

	outcome, err := orchestrator.Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if repo.count() != 1 {
		t.Fatalf("recorded = %d, want 1: the uncited claim must be dropped", repo.count())
	}
	if outcome.Findings[0].Claim != "nginx detected" {
		t.Fatalf("stored the wrong finding: %+v", outcome.Findings[0])
	}
	if !strings.Contains(strings.Join(lines, "\n"), "finding refused") {
		t.Fatalf("the refusal was not reported:\n%s", strings.Join(lines, "\n"))
	}
}

func TestTeamAcceptsEvidenceShapesModelsActuallyEmit(t *testing.T) {
	// Regression: a model emitted evidence as a bare string, the batch failed to
	// decode, and every finding in that response was lost.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, `{"findings":[
		{"kind":"recon","claim":"string evidence","confidence":0.7,"evidence":"curl -I showed nginx"},
		{"kind":"recon","claim":"array of strings","confidence":0.7,"evidence":["nmap output","header dump"]}
	]}`)
	stub.push(DutyCritic, `{"findings":[{"id":"f1","accept":true},{"id":"f2","accept":true}],"note":""}`)

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repo.count() != 2 {
		t.Fatalf("recorded = %d, want 2: coercible evidence must not lose the finding", repo.count())
	}
}

func TestTeamAcceptsConfidenceAsString(t *testing.T) {
	// Regression: a model emitted "confidence": "0.8", the whole batch failed to
	// decode, and every finding in that response was lost over one field's type.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, `{"findings":[
		{"kind":"recon","claim":"string confidence","confidence":"0.75","evidence":["probe"]}
	]}`)
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repo.count() != 1 {
		t.Fatalf("recorded = %d, want 1: a numeric string must not lose the finding", repo.count())
	}
	if repo.rows[0].Confidence != 0.75 {
		t.Fatalf("confidence = %v, want 0.75", repo.rows[0].Confidence)
	}
}

func TestFlexibleFloatMapsConfidenceWords(t *testing.T) {
	// ARTEX grades confidence with words, not floats. Rejecting them discarded
	// every finding in the response; accepting them keeps the semantics.
	tests := map[string]float64{
		`"observed"`: 0.9,
		`"inferred"`: 0.5,
		`"low"`:      0.3,
		`"OBSERVED"`: 0.9,
		`0.75`:       0.75,
		`"0.6"`:      0.6,
	}
	for raw, want := range tests {
		var value flexibleFloat
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			t.Fatalf("flexibleFloat(%s) error = %v", raw, err)
		}
		if float64(value) != want {
			t.Fatalf("flexibleFloat(%s) = %v, want %v", raw, value, want)
		}
	}
}

func TestFlexibleFloatRejectsUnparseableValues(t *testing.T) {
	// A value that is neither a number nor a known level must still fail:
	// silently becoming zero would turn "unknown" into "no confidence" unnoticed.
	for _, raw := range []string{`"banana"`, `{}`} {
		var value flexibleFloat
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("flexibleFloat accepted %s", raw)
		}
	}
	// A JSON null is possible for a missing field and means "not stated".
	var absent flexibleFloat
	if err := json.Unmarshal([]byte("null"), &absent); err != nil {
		t.Fatalf("flexibleFloat(null) error = %v", err)
	}
	if absent != 0 {
		t.Fatalf("flexibleFloat(null) = %v, want 0", absent)
	}
}

func TestDecodeEvidenceAcceptsASingleCitationObject(t *testing.T) {
	// Observed in practice: a model emitted one citation object instead of an
	// array, and every finding in that response was refused.
	refs, err := decodeEvidence(json.RawMessage(`{"kind":"tool_output","ref":"curl -I /","quote":"HTTP/1.1 200"}`))
	if err != nil {
		t.Fatalf("decodeEvidence() error = %v", err)
	}
	if len(refs) != 1 || refs[0].Ref != "curl -I /" {
		t.Fatalf("refs = %+v", refs)
	}
}

func TestDecodeEvidenceRejectsUnrecognisedShapes(t *testing.T) {
	for _, raw := range []string{`{"kind":"x"}`, `123`, `true`} {
		if _, err := decodeEvidence(json.RawMessage(raw)); err == nil {
			t.Fatalf("decodeEvidence(%s) accepted an unrecognised shape", raw)
		}
	}
	// Empty evidence is absence, not an error: Validate rejects it with a clearer
	// message than a decode failure would give.
	for _, raw := range []string{"", "null"} {
		refs, err := decodeEvidence(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("decodeEvidence(%q) error = %v", raw, err)
		}
		if len(refs) != 0 {
			t.Fatalf("decodeEvidence(%q) = %v, want empty", raw, refs)
		}
	}
}

func TestTeamDeduplicatesCorroboratingFindings(t *testing.T) {
	// Two workers confirming the same fact must converge on one row, otherwise a
	// report lists the same weakness twice and looks stronger than it is.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan,
		roundJSON(false, "recon then web", "recon"),
		roundJSON(false, "web", "web"),
		roundJSON(true, "done"),
	)
	stub.push(DutyRecon, findingsJSON(findingJSON("recon", "server is nginx", "probe a")))
	stub.push(DutyWeb, findingsJSON(findingJSON("recon", "server is nginx", "probe b")))
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repo.count() != 1 {
		t.Fatalf("recorded = %d, want 1 after dedupe", repo.count())
	}
}

func TestTeamRejectsFindingWhenCriticRefuses(t *testing.T) {
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "web", "web"), roundJSON(true, "done"))
	stub.push(DutyWeb, findingsJSON(findingJSON("access", "uploaded shell executed", "http_request GET /upload/x.php")))
	stub.push(DutyCritic, `{"findings":[{"id":"f1","accept":false,"reason":"response was the source page"}],"note":"rejected"}`)
	stub.push(DutyReport, "no confirmed access")

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Accepted) != 0 {
		t.Fatalf("accepted = %d, want 0", len(outcome.Accepted))
	}
	if len(outcome.Findings) != 1 || !outcome.Findings[0].Rejected {
		t.Fatalf("the rejected finding was not kept for the trail: %+v", outcome.Findings)
	}
	// The report input must be built from accepted findings only, so the rejected
	// claim cannot reappear in the narrative.
	if strings.Contains(stub.inputFor(DutyReport), "uploaded shell executed") {
		t.Fatal("the report was asked to describe a rejected finding")
	}
}

func TestTeamAcceptsNothingWhenCriticOutputIsUnusable(t *testing.T) {
	// Fail closed: a critic that cannot answer must not thereby approve
	// everything, which would make the review decorative.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, findingsJSON(findingJSON("recon", "nginx detected", "probe")))
	stub.push(DutyCritic, "I think it is probably fine.")

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Accepted) != 0 {
		t.Fatalf("accepted = %d, want 0 when the critic answers in prose", len(outcome.Accepted))
	}
	if repo.count() != 1 {
		t.Fatal("the finding should still be recorded, just not accepted")
	}
}

func TestTeamDoesNotAcceptUnmentionedFindings(t *testing.T) {
	// A critic that silently skips a finding must not thereby approve it.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, findingsJSON(
		findingJSON("recon", "first fact", "probe a"),
		findingJSON("recon", "second fact", "probe b"),
	))
	stub.push(DutyCritic, `{"findings":[{"id":"f1","accept":true,"reason":"ok"}],"note":""}`)

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(outcome.Accepted) != 1 {
		t.Fatalf("accepted = %d, want only the explicitly accepted one", len(outcome.Accepted))
	}
}

func TestTeamPropagatesWorkerFailure(t *testing.T) {
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"))
	stub.errors[DutyRecon] = errors.New("model endpoint refused")

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err == nil {
		t.Fatal("a worker transport failure was swallowed")
	}
	if outcome.Stop != StopFatal {
		t.Fatalf("stop = %s, want fatal", outcome.Stop)
	}
	if len(outcome.Attempts) != 1 || outcome.Attempts[0].State != AttemptBlocked {
		t.Fatalf("a transport failure must be recorded as blocked, got %+v", outcome.Attempts)
	}
}

func TestTeamPropagatesFindingStoreFailure(t *testing.T) {
	repo := newFakeFindings()
	repo.failNext = errors.New("database is down")
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"))
	stub.push(DutyRecon, findingsJSON(findingJSON("recon", "fact", "probe")))

	outcome, err := newOrchestrator(repo, stub).Run(context.Background(), "goal")
	if err == nil {
		t.Fatal("a storage failure was swallowed, so the finding would be lost silently")
	}
	if outcome.Stop != StopFatal {
		t.Fatalf("stop = %s, want fatal", outcome.Stop)
	}
}

func TestPlannerParsingAcceptsTheLegacyStepsShape(t *testing.T) {
	// A model that has seen the older batch prompt still produces "steps".
	resp, err := parsePlannerResponse(`{"steps":[{"duty":"recon","goal":"look"}]}`)
	if err != nil {
		t.Fatalf("parsePlannerResponse() error = %v", err)
	}
	if len(resp.Intents) != 1 || resp.Intents[0].Duty != "recon" {
		t.Fatalf("intents = %+v", resp.Intents)
	}
}

func TestPlannerParsingRejectsEmptyGoal(t *testing.T) {
	if _, err := parsePlannerResponse(`{"intents":[{"duty":"recon","goal":"  "}]}`); err == nil {
		t.Fatal("an intent with no goal was accepted")
	}
}

func TestFindingDedupKeyIgnoresEvidence(t *testing.T) {
	// Two agents confirming the same fact with different outputs have still
	// confirmed the same fact.
	first := domain.Finding{Kind: "recon", Target: "example.com", Claim: "server is nginx",
		Evidence: []domain.EvidenceRef{{Kind: "tool_output", Ref: "probe a"}}}
	second := domain.Finding{Kind: "recon", Target: "EXAMPLE.COM", Claim: "Server  is   nginx",
		Evidence: []domain.EvidenceRef{{Kind: "tool_output", Ref: "probe b"}}}

	if first.NormalizedDedupKey() != second.NormalizedDedupKey() {
		t.Fatal("the same fact produced two dedup keys")
	}

	third := domain.Finding{Kind: "exposure", Target: "example.com", Claim: "server is nginx"}
	if first.NormalizedDedupKey() == third.NormalizedDedupKey() {
		t.Fatal("a different kind collapsed into the same key")
	}
}

func TestFindingValidateRejectsUnsupportedClaims(t *testing.T) {
	base := domain.Finding{TaskID: "t", Kind: "recon", Claim: "x",
		Evidence: []domain.EvidenceRef{{Kind: "tool_output", Ref: "probe"}}}

	if err := base.Validate(); err != nil {
		t.Fatalf("a well-formed finding was rejected: %v", err)
	}

	noEvidence := base
	noEvidence.Evidence = nil
	if err := noEvidence.Validate(); err == nil {
		t.Fatal("a finding with no evidence was accepted")
	}

	emptyRef := base
	emptyRef.Evidence = []domain.EvidenceRef{{Kind: "tool_output"}}
	if err := emptyRef.Validate(); err == nil {
		t.Fatal("a finding citing an empty reference was accepted")
	}

	badKind := base
	badKind.Kind = "vibes"
	if err := badKind.Validate(); err == nil {
		t.Fatal("an unknown kind was accepted")
	}

	badConfidence := base
	badConfidence.Confidence = 1.5
	if err := badConfidence.Validate(); err == nil {
		t.Fatal("an out-of-range confidence was accepted")
	}
}

func TestTeamCapturesFindingsFromProseWrappedJSON(t *testing.T) {
	// Models routinely wrap JSON in prose; rejecting that would lose real work.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(false, "recon", "recon"), roundJSON(true, "done"))
	stub.push(DutyRecon, "分析完成，结果如下：\n```json\n"+
		findingsJSON(findingJSON("recon", "nginx 1.20.1", "probe"))+"\n```\n以上。")
	stub.push(DutyCritic, criticJSON(map[string]bool{"f1": true}))

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "goal"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repo.count() != 1 {
		t.Fatalf("recorded = %d, want 1", repo.count())
	}
}

func TestTeamTellsThePlannerTheAuthorizedTarget(t *testing.T) {
	// Regression: the planner was given only the prose goal, invented the parent
	// domain, and every subsequent tool call failed on an unauthorized host.
	repo := newFakeFindings()
	stub := newScriptedAgent()
	stub.push(DutyPlan, roundJSON(true, "nothing to do"))
	stub.push(DutyCritic, `{"findings":[],"note":""}`)

	if _, err := newOrchestrator(repo, stub).Run(context.Background(), "拿下这个站点"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(stub.inputFor(DutyPlan), "example.com:443") {
		t.Fatalf("the planner was not told the authorized target:\n%s", stub.inputFor(DutyPlan))
	}
}

func TestExtractJSONObjectHandlesProseAndNesting(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: `{"a":1}`, want: `{"a":1}`},
		{name: "prose around", in: `结果如下：{"a":1} 以上`, want: `{"a":1}`},
		{name: "fenced", in: "```json\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "nested", in: `{"a":{"b":2}}`, want: `{"a":{"b":2}}`},
		{name: "braces in string", in: `{"a":"}{"}`, want: `{"a":"}{"}`},
		{name: "no object", in: "no json here", want: ""},
		{name: "unbalanced", in: `{"a":1`, want: ""},
	}
	for _, tc := range tests {
		if got := extractJSONObject(tc.in); got != tc.want {
			t.Fatalf("%s: extractJSONObject(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestFindingsJSONRoundTrip(t *testing.T) {
	// Guards the wire shape the prompt promises, so a prompt edit that changes it
	// fails here rather than silently producing zero findings.
	raw := findingsJSON(findingJSON("exposure", "php upload accepted", "http_request POST /upload.php"))
	var payload struct {
		Findings []struct {
			Kind     string          `json:"kind"`
			Claim    string          `json:"claim"`
			Evidence json.RawMessage `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].Kind != "exposure" {
		t.Fatalf("payload = %+v", payload)
	}
	refs, err := decodeEvidence(payload.Findings[0].Evidence)
	if err != nil {
		t.Fatalf("decodeEvidence() error = %v", err)
	}
	if len(refs) != 1 || refs[0].Ref == "" {
		t.Fatalf("evidence lost: %+v", refs)
	}
}
