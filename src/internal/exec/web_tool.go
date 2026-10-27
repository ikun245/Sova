package exec

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/webattack"
)

// maxIntruderPayloads bounds one intruder run. A brute force that is allowed to
// run unbounded is indistinguishable from a denial of service, and the
// engagement rate only limits speed, not total volume.
const maxIntruderPayloads = 200

// maxPreviewBytes is how much of a response body is shown to a model. The full
// body is summarised by length and digest so a large page cannot flood context.
const maxPreviewBytes = 8 << 10

// WebTool is a built-in HTTP tool. It needs no external binary, which is what
// makes the platform usable for web work on any OS, including the Windows
// workstation used for development.
type WebTool struct {
	name        string
	description string
	// baseRisk is the risk when the request is read-only. A state-changing
	// method raises it to active, because a POST is an attempt to modify the
	// target even when it looks like a login form.
	baseRisk domain.RiskLevel
	runner   *Runner
	engine   *webattack.Engine
}

// Spec exposes the model-facing contract.
func (t *WebTool) Spec() ToolSpec {
	return ToolSpec{
		Name:        t.name,
		Description: t.description,
		Risk:        t.baseRisk,
		Parameters:  webToolSchema(t.name),
	}
}

// Invoke runs the tool with no approval id.
func (t *WebTool) Invoke(ctx context.Context, raw json.RawMessage) domain.ToolResult {
	return t.InvokeWithApproval(ctx, raw, "", 0)
}

type webRequestArgs struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	// Body is plain text; BodyBase64 wins when both are set so binary payloads
	// survive the JSON hop.
	Body       string               `json:"body"`
	BodyBase64 string               `json:"body_base64"`
	Multipart  *webattack.Multipart `json:"multipart"`
	// Reason is recorded in the approval binding, so a human sees why the
	// request is being made instead of just its bytes.
	Reason string `json:"reason"`
	// Risk lets the caller state a higher risk than the method implies. It can
	// only raise: a GET that runs a shell gets declared intrusive, while a
	// request cannot be declared harmless to dodge the ceiling.
	Risk            string `json:"risk"`
	FollowRedirects bool   `json:"follow_redirects"`
	SkipTLSVerify   bool   `json:"skip_tls_verify"`
	TimeoutSec      int    `json:"timeout_seconds"`
}

// InvokeWithApproval sends one request under the engagement gates.
//
// This is the "Repeater": the operator or the model states the exact request,
// sees the exact response, and can change one byte and send it again. Nothing
// is normalised, so a test result is reproducible.
func (t *WebTool) InvokeWithApproval(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult {
	if t.name == "http_intruder" {
		return t.Intruder(ctx, raw, approvalID, timeout)
	}
	return t.repeater(ctx, raw, approvalID, timeout)
}

func (t *WebTool) repeater(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult {
	var args webRequestArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return domain.Failure(domain.WrapToolError(domain.CodeInvalidArgument,
			"arguments are not valid JSON for this tool",
			`supply {"url": "https://host/path"} and optionally method, headers, body`, err))
	}

	method, err := webattack.NormalizeMethod(args.Method)
	if err != nil {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument, err.Error(),
			"use one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE"))
	}

	parsed, err := url.Parse(strings.TrimSpace(args.URL))
	if err != nil || parsed.Hostname() == "" {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"url must be an absolute URL such as https://host/path",
			"include the scheme and the host so the target can be authorised"))
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"url scheme must be http or https",
			"correct the scheme; other schemes are not executed"))
	}

	body, contentType, err := webBody(args)
	if err != nil {
		return domain.Failure(domain.WrapToolError(domain.CodeInvalidArgument,
			err.Error(), "fix the body encoding or the multipart parts", err))
	}
	// A multipart body generates its own boundary; let it win over anything the
	// caller guessed.
	if contentType != "" {
		if args.Headers == nil {
			args.Headers = map[string]string{}
		}
		args.Headers["Content-Type"] = contentType
	}

	port := portOf(parsed)
	target := domain.Target{Host: parsed.Hostname(), Port: port}

	// A state-changing method is a different risk class: it can create,
	// modify or delete server-side state even when the payload is benign.
	risk := t.baseRisk
	if webattack.StateChanging(method) {
		risk = domain.RiskActive
	}
	// A caller may raise the risk, never lower it. This is how a GET that reads
	// a command parameter is recorded honestly as code execution instead of
	// slipping through as a "light" read.
	if declared := domain.RiskLevel(strings.ToLower(strings.TrimSpace(args.Risk))); declared != "" {
		if !validRisk(declared) {
			return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
				fmt.Sprintf("risk %q is not a known level", args.Risk),
				"use passive, light, active, intrusive or code_execution, or omit risk"))
		}
		if !declared.AtMost(risk) {
			risk = declared
		}
	}

	approvalArgv := webApprovalArgv(t.name, method, args.URL, args.Headers, body, args.Reason)
	if timeout <= 0 && args.TimeoutSec > 0 {
		timeout = time.Duration(args.TimeoutSec) * time.Second
	}

	var response webattack.Response
	var sendErr error
	result, gateErr := t.runner.ExecuteCustom(ctx, CustomRequest{
		ToolName:   t.name,
		Argv:       approvalArgv,
		Target:     target,
		Risk:       risk,
		Timeout:    timeout,
		ApprovalID: approvalID,
		Run: func(runCtx context.Context) (Result, error) {
			response, sendErr = t.engine.Send(runCtx, webattack.Request{
				Method:          method,
				URL:             args.URL,
				Headers:         args.Headers,
				Body:            body,
				FollowRedirects: args.FollowRedirects,
				SkipTLSVerify:   args.SkipTLSVerify,
				Timeout:         timeout,
				// Every redirect hop is re-checked, so a 302 cannot move the
				// request out of scope mid-flight.
				AllowHost: func(host string) error {
					return t.runner.checkTarget(runCtx, domain.Target{Host: host, Port: port})
				},
			})
			if sendErr != nil {
				return Result{Stdout: responseText(response), Stderr: sendErr.Error(), ExitCode: 1}, nil
			}
			// A non-2xx status is evidence, not a failure: a 403 tells the
			// operator the filter exists.
			out := Result{
				Stdout:    responseText(response),
				ExitCode:  0,
				Risk:      risk,
				Truncated: response.Truncated,
			}
			return out, nil
		},
	})
	if gateErr != nil {
		return domain.Failure(gateErr).WithMeta(t.meta(target, result))
	}
	if sendErr != nil {
		return domain.Failure(domain.WrapToolError(domain.CodeCommandFailed,
			"the request did not complete",
			"check the target is reachable and the timeout is large enough", sendErr)).
			WithMeta(t.meta(target, result))
	}

	return domain.Success("ok", webResponsePayload(response)).WithMeta(t.meta(target, result))
}

// IntruderArgs is one payload-position attack: the same request, replayed with
// the marker replaced by each candidate.
type IntruderArgs struct {
	webRequestArgs
	// Marker is the placeholder inside the URL, a header, a field value, or a
	// filename. It is removed in the control request so the baseline is the
	// request with no payload at all.
	Marker string `json:"marker"`
	// Payloads is the candidate list. It is capped, and the cap is reported.
	Payloads []string `json:"payloads"`
	// Match is a substring that marks a successful attempt in the response.
	// An operator who knows "uploaded" appears only on success gets a clear
	// pass/fail table instead of eyeballing lengths.
	Match string `json:"match"`
	// Concurrency is intentionally absent: the engagement rate decides speed,
	// and parallel attempts would defeat the rate limit.
}

// Intruder replays a request once per payload and reports a comparable table.
//
// This is the "Intruder" primitive: it exists so a brute force is bounded,
// rate-limited, audited and approved as one reviewed action instead of N
// unlogged requests the platform cannot account for.
func (t *WebTool) Intruder(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult {
	var args IntruderArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return domain.Failure(domain.WrapToolError(domain.CodeInvalidArgument,
			"arguments are not valid JSON for this tool",
			`supply {"url": ..., "marker": "FUZZ", "payloads": ["a","b"]}`, err))
	}
	if strings.TrimSpace(args.Marker) == "" {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"marker is required so the payload position is explicit",
			`set marker to the placeholder that appears in the request, e.g. "FUZZ"`))
	}
	if len(args.Payloads) == 0 {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"payloads is empty", "supply at least one candidate value"))
	}
	if len(args.Payloads) > maxIntruderPayloads {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			fmt.Sprintf("payloads exceeds the %d item cap for one run", maxIntruderPayloads),
			"split the wordlist into smaller runs so each is reviewed and rate-limited").
			WithDetail("payloads", fmt.Sprintf("%d", len(args.Payloads))))
	}

	method, err := webattack.NormalizeMethod(args.Method)
	if err != nil {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument, err.Error(),
			"use one of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE"))
	}
	parsed, err := url.Parse(strings.TrimSpace(args.URL))
	if err != nil || parsed.Hostname() == "" {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"url must be an absolute URL", "include the scheme and host"))
	}
	port := portOf(parsed)
	target := domain.Target{Host: parsed.Hostname(), Port: port}

	// Brute forcing is always active regardless of method: a list of GETs is
	// still an enumeration attempt.
	risk := domain.RiskActive

	// The approval binds the template and the payload count, not each payload:
	// a human approves "200 attempts against this field", which is the actual
	// capability being granted.
	approvalArgv := webApprovalArgv(t.name, method, args.URL, args.Headers, nil,
		fmt.Sprintf("marker=%s payloads=%d reason=%s", args.Marker, len(args.Payloads), args.Reason))

	if timeout <= 0 {
		// A run needs budget proportional to its size, otherwise a slow target
		// makes a legitimate 50-payload run look like a timeout.
		timeout = time.Duration(len(args.Payloads)) * 20 * time.Second
	}

	controlReady := false
	controlStatus := 0
	controlLength := 0
	var attempts []intruderAttempt
	result, gateErr := t.runner.ExecuteCustom(ctx, CustomRequest{
		ToolName:   t.name,
		Argv:       approvalArgv,
		Target:     target,
		Risk:       risk,
		Timeout:    timeout,
		ApprovalID: approvalID,
		Run: func(runCtx context.Context) (Result, error) {
			// A control request first: without a baseline, "length 1615" is not
			// interpretable, and a filter that rejects everything looks like a
			// payload that succeeded.
			controlBody, _, err := buildIntruderBody(args.webRequestArgs, args.Marker, "")
			if err != nil {
				return Result{Stderr: err.Error(), ExitCode: 1}, nil
			}
			control, controlErr := t.engine.Send(runCtx, webattack.Request{
				Method:        method,
				URL:           substituteAll(args.URL, args.Marker, ""),
				Headers:       substituteHeaders(args.Headers, args.Marker, ""),
				Body:          controlBody,
				SkipTLSVerify: args.SkipTLSVerify,
				Timeout:       timeout,
				AllowHost: func(host string) error {
					return t.runner.checkTarget(runCtx, domain.Target{Host: host, Port: port})
				},
			})
			controlReady = controlErr == nil
			controlStatus = control.Status
			controlLength = len(control.Body)

			var builder strings.Builder
			if controlReady {
				builder.WriteString(fmt.Sprintf("[control] status=%d length=%d\n", control.Status, len(control.Body)))
			} else if controlErr != nil {
				builder.WriteString(fmt.Sprintf("[control] error=%v\n", controlErr))
			}

			for index, payload := range args.Payloads {
				if err := runCtx.Err(); err != nil {
					break
				}
				body, _, bodyErr := buildIntruderBody(args.webRequestArgs, args.Marker, payload)
				attempt := intruderAttempt{Index: index, Payload: payload}
				if bodyErr != nil {
					attempt.Error = bodyErr.Error()
					attempts = append(attempts, attempt)
					continue
				}
				started := time.Now()
				resp, sendErr := t.engine.Send(runCtx, webattack.Request{
					Method:        method,
					URL:           substituteAll(args.URL, args.Marker, payload),
					Headers:       substituteHeaders(args.Headers, args.Marker, payload),
					Body:          body,
					SkipTLSVerify: args.SkipTLSVerify,
					Timeout:       timeout,
					AllowHost: func(host string) error {
						return t.runner.checkTarget(runCtx, domain.Target{Host: host, Port: port})
					},
				})
				attempt.DurationMS = time.Since(started).Milliseconds()
				if sendErr != nil {
					attempt.Error = sendErr.Error()
					attempts = append(attempts, attempt)
					continue
				}
				attempt.Status = resp.Status
				attempt.Length = len(resp.Body)
				attempt.Matched = args.Match != "" && strings.Contains(string(resp.Body), args.Match)
				attempts = append(attempts, attempt)

				builder.WriteString(fmt.Sprintf("[%d] payload=%q status=%d length=%d matched=%t\n",
					index, payload, attempt.Status, attempt.Length, attempt.Matched))
			}

			return Result{Stdout: builder.String(), ExitCode: 0, Risk: risk}, nil
		},
	})
	if gateErr != nil {
		return domain.Failure(gateErr).WithMeta(t.meta(target, result))
	}

	// Compare every attempt against the baseline so a caller does not have to
	// diff lengths by hand. differing tells nothing on its own: read the status
	// and length, then decide.
	if controlReady {
		for i := range attempts {
			if attempts[i].Error != "" {
				continue
			}
			attempts[i].Different = attempts[i].Status != controlStatus || attempts[i].Length != controlLength
		}
	}

	summary := map[string]any{
		"attempts":      attempts,
		"count":         len(attempts),
		"matched":       countMatched(attempts),
		"control_ready": controlReady,
		"marker":        args.Marker,
	}
	if controlReady {
		summary["control"] = map[string]int{"status": controlStatus, "length": controlLength}
	}
	if len(attempts) > 0 && attempts[0].Error != "" {
		summary["note"] = "every attempt failed; inspect the first error before changing payloads"
	}
	return domain.Success("ok", summary).WithMeta(t.meta(target, result))
}

type intruderAttempt struct {
	Index      int    `json:"index"`
	Payload    string `json:"payload"`
	Status     int    `json:"status,omitempty"`
	Length     int    `json:"length,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Matched    bool   `json:"matched,omitempty"`
	// Different is set when a baseline existed; it is a weak signal on purpose
	// and the caller should read status and length, not just this flag.
	Different bool   `json:"different,omitempty"`
	Error     string `json:"error,omitempty"`
}

func countMatched(attempts []intruderAttempt) int {
	total := 0
	for _, attempt := range attempts {
		if attempt.Matched {
			total++
		}
	}
	return total
}

// Tool is the uniform contract an agent iterates over. Built-in tools and
// external-binary tools appear in the same list, so a prompt builder does not
// have to special-case either kind.
type Tool interface {
	Spec() ToolSpec
	Invoke(ctx context.Context, raw json.RawMessage) domain.ToolResult
}

// Tools returns every tool the engagement exposes, binaries and built-ins
// alike. The list is stable for a given runner so prompts do not drift.
func Tools(runner *Runner) []Tool {
	out := make([]Tool, 0, len(WebCatalog(runner))+len(Catalog(runner)))
	for _, tool := range WebCatalog(runner) {
		out = append(out, tool)
	}
	for _, tool := range Catalog(runner) {
		out = append(out, tool)
	}
	return out
}

// webBody resolves the request body and its content type from whichever
// representation the caller supplied. Multipart wins because it is the only
// form that can carry a filename, which is what an upload test needs.
func webBody(args webRequestArgs) ([]byte, string, error) {
	if args.Multipart != nil {
		body, contentType, err := args.Multipart.Build()
		return body, contentType, err
	}
	if strings.TrimSpace(args.BodyBase64) != "" {
		decoded, err := base64.StdEncoding.DecodeString(args.BodyBase64)
		if err != nil {
			return nil, "", fmt.Errorf("body_base64 is not valid base64: %w", err)
		}
		return decoded, "application/octet-stream", nil
	}
	return []byte(args.Body), "", nil
}

func buildIntruderBody(args webRequestArgs, marker, payload string) ([]byte, string, error) {
	substituted := args
	if substituted.Multipart != nil {
		copied := *substituted.Multipart
		copied.Fields = map[string]string{}
		for name, value := range substituted.Multipart.Fields {
			copied.Fields[name] = webattack.Substitute(value, marker, payload)
		}
		copied.Files = make([]webattack.File, 0, len(substituted.Multipart.Files))
		for _, file := range substituted.Multipart.Files {
			// The filename is the usual filter bypass position: send payload.php
			// where the front end only checked that it ended in .png.
			file.Field = webattack.Substitute(file.Field, marker, payload)
			file.Filename = webattack.Substitute(file.Filename, marker, payload)
			copied.Files = append(copied.Files, file)
		}
		substituted.Multipart = &copied
	}
	substituted.Body = webattack.Substitute(substituted.Body, marker, payload)
	if substituted.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(substituted.BodyBase64)
		if err == nil {
			substituted.Body = webattack.Substitute(string(decoded), marker, payload)
			substituted.BodyBase64 = ""
		}
	}
	return webBody(substituted)
}

func substituteAll(value, marker, payload string) string {
	return webattack.Substitute(value, marker, payload)
}

func substituteHeaders(headers map[string]string, marker, payload string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[name] = webattack.Substitute(value, marker, payload)
	}
	return out
}

// webApprovalArgv builds the synthetic command line an approval binds to. It is
// stable for the same action and changes when the request changes, so a human
// approval cannot be reused for a different body.
func webApprovalArgv(tool, method, rawURL string, headers map[string]string, body []byte, reason string) []string {
	sum := sha256.Sum256(body)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)

	argv := []string{tool, method, rawURL,
		"body_sha256=" + hex.EncodeToString(sum[:8]),
		fmt.Sprintf("body_bytes=%d", len(body)),
		"headers=" + strings.Join(names, ","),
	}
	if strings.TrimSpace(reason) != "" {
		argv = append(argv, "reason="+reason)
	}
	return argv
}

// validRisk rejects a typo instead of silently ignoring it. A misspelled risk
// would otherwise look accepted while the request ran at the method default,
// which is exactly the kind of silent gap this platform must not have.
func validRisk(risk domain.RiskLevel) bool {
	switch risk {
	case domain.RiskPassive, domain.RiskLight, domain.RiskActive,
		domain.RiskIntrusive, domain.RiskCodeExecution:
		return true
	default:
		return false
	}
}

func portOf(parsed *url.URL) int {
	if parsed.Port() != "" {
		port := 0
		fmt.Sscanf(parsed.Port(), "%d", &port)
		return port
	}
	if parsed.Scheme == "https" {
		return 443
	}
	return 80
}

func webResponsePayload(resp webattack.Response) map[string]any {
	preview := resp.Body
	truncated := false
	if len(preview) > maxPreviewBytes {
		preview = preview[:maxPreviewBytes]
		truncated = true
	}
	sum := sha256.Sum256(resp.Body)

	payload := map[string]any{
		"status":      resp.Status,
		"proto":       resp.Proto,
		"headers":     resp.Headers,
		"length":      len(resp.Body),
		"body_sha256": hex.EncodeToString(sum[:]),
		"body_utf8":   string(preview),
		"duration_ms": resp.Duration.Milliseconds(),
	}
	if truncated {
		payload["preview_truncated"] = true
		payload["preview_bytes"] = maxPreviewBytes
	}
	if len(resp.Redirects) > 0 {
		payload["redirects"] = resp.Redirects
	}
	if resp.FinalURL != "" {
		payload["final_url"] = resp.FinalURL
	}
	return payload
}

func responseText(resp webattack.Response) string {
	return fmt.Sprintf("status=%d length=%d duration_ms=%d",
		resp.Status, len(resp.Body), resp.Duration.Milliseconds())
}

func (t *WebTool) meta(target domain.Target, result Result) *domain.ResultMeta {
	return &domain.ResultMeta{
		Tool:       t.name,
		Risk:       string(result.Risk),
		Target:     target.String(),
		ExitCode:   result.ExitCode,
		DurationMS: result.Duration.Milliseconds(),
		Truncated:  result.Truncated,
		TimedOut:   result.TimedOut,
	}
}

func webToolSchema(name string) json.RawMessage {
	if name == "http_intruder" {
		return json.RawMessage(`{
			"type": "object",
			"required": ["url", "marker", "payloads"],
			"properties": {
				"url": {"type": "string", "description": "absolute URL containing the marker"},
				"method": {"type": "string", "description": "HTTP method, default GET"},
				"headers": {"type": "object", "additionalProperties": {"type": "string"}},
				"body": {"type": "string"},
				"body_base64": {"type": "string"},
				"multipart": {"type": "object", "description": "form fields and files; marker may appear in a filename"},
				"marker": {"type": "string", "description": "placeholder replaced by each payload"},
				"payloads": {"type": "array", "items": {"type": "string"}, "maxItems": 200},
				"match": {"type": "string", "description": "substring that marks a successful attempt"},
				"reason": {"type": "string", "description": "why this run is authorized, shown to the approver"},
				"skip_tls_verify": {"type": "boolean"},
				"timeout_seconds": {"type": "integer"}
			}
		}`)
	}
	return json.RawMessage(`{
		"type": "object",
		"required": ["url"],
		"properties": {
			"url": {"type": "string", "description": "absolute URL including scheme"},
			"method": {"type": "string", "description": "HTTP method, default GET"},
			"headers": {"type": "object", "additionalProperties": {"type": "string"}},
			"body": {"type": "string"},
			"body_base64": {"type": "string"},
			"multipart": {"type": "object", "description": "form fields and files for multipart uploads"},
			"reason": {"type": "string", "description": "why this request is being made"},
			"follow_redirects": {"type": "boolean"},
			"skip_tls_verify": {"type": "boolean"},
			"timeout_seconds": {"type": "integer"}
		}
	}`)
}

// WebCatalog builds the built-in HTTP tools. They are separate from Catalog
// because they need no binary, so their availability does not depend on what is
// installed in the execution environment.
func WebCatalog(runner *Runner) []*WebTool {
	engine := webattack.NewEngine(1 << 20)
	return []*WebTool{
		{
			name: "http_request",
			description: "Send one exact HTTP request and return status, headers and body " +
				"(Repeater). Supports raw bodies and multipart uploads, so a captured " +
				"request can be replayed byte for byte. Light for GET/HEAD, active for " +
				"state-changing methods.",
			baseRisk: domain.RiskLight,
			runner:   runner,
			engine:   engine,
		},
		{
			name: "http_intruder",
			description: "Replay one request once per payload with a marker, returning a " +
				"comparable status/length/matched table against a no-payload control " +
				"(Intruder). Always active and always needs approval.",
			baseRisk: domain.RiskActive,
			runner:   runner,
			engine:   engine,
		},
	}
}
