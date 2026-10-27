package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

// ToolSpec is the model-facing contract of an executable tool. It mirrors the
// harness shape so the registry can expose these alongside other tools.
type ToolSpec struct {
	Name        string
	Description string
	Parameters  json.RawMessage
	Risk        domain.RiskLevel
}

// ScanTool exposes a scoped reconnaissance command as a model-callable tool.
// The model supplies the target; the runner decides, in code, whether that
// target is authorized.
type ScanTool struct {
	argv   []string
	spec   ToolSpec
	runner *Runner
	signal func(ctx context.Context)
}

// NewScanTool builds a tool from a fixed command template. Only the target is
// model-supplied, so the model cannot invent new flags or switch binaries.
func NewScanTool(name, description string, argv []string, risk domain.RiskLevel, runner *Runner) *ScanTool {
	return &ScanTool{
		argv:   argv,
		runner: runner,
		spec: ToolSpec{
			Name:        name,
			Description: description,
			Risk:        risk,
			Parameters: json.RawMessage(`{
				"type": "object",
				"required": ["host"],
				"properties": {
					"host": {"type": "string", "description": "target hostname or IP"},
					"port": {"type": "integer", "description": "target port, if the command needs one"},
					"path": {"type": "string", "description": "absolute request path beginning with /, for tools that fetch a page"}
				}
			}`),
		},
	}
}

func (t *ScanTool) Spec() ToolSpec {
	return t.spec
}

type scanArgs struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
}

// Invoke runs the tool and always returns the same envelope shape, whether the
// call succeeded, was refused, or failed. A model never has to interpret two
// formats, and no meaning lives only in a prose message.
func (t *ScanTool) Invoke(ctx context.Context, raw json.RawMessage) domain.ToolResult {
	return t.InvokeWithApproval(ctx, raw, "", 0)
}

// InvokeWithApproval is Invoke with the controls a managed caller needs: an
// approval id for "ask" decisions and an explicit timeout. Agents normally rely
// on the runner defaults; a CLI probe usually needs to name both.
func (t *ScanTool) InvokeWithApproval(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult {
	var args scanArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return domain.Failure(domain.WrapToolError(domain.CodeInvalidArgument,
			"arguments are not valid JSON for this tool",
			`supply {"host": "<target>"} and optionally {"port": <n>}`, err))
	}
	if strings.TrimSpace(args.Host) == "" {
		return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
			"host is required", `supply {"host": "<target>"}`))
	}

	// A path is a single argv element, so it cannot break out of the command.
	// It still must look like a path: a leading dash would be parsed as a flag
	// and a newline would split a request line on the target side.
	path := args.Path
	if path != "" {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n") {
			return domain.Failure(domain.NewToolError(domain.CodeInvalidArgument,
				"path must be an absolute path without whitespace",
				`supply {"path": "/upload/"} or omit it for the site root`))
		}
	}

	port := args.Port
	if port == 0 {
		port = 443
	}
	hostPort := fmt.Sprintf("%s:%d", args.Host, port)

	argv := make([]string, 0, len(t.argv))
	for _, part := range t.argv {
		// Placeholders appear inside larger literals such as
		// "https://{host_port}/", so substitute rather than compare.
		part = strings.ReplaceAll(part, "{host_port}", hostPort)
		part = strings.ReplaceAll(part, "{host}", args.Host)
		part = strings.ReplaceAll(part, "{path}", path)
		argv = append(argv, part)
	}

	result, err := t.runner.Execute(ctx, Request{
		Argv:       argv,
		Target:     domain.Target{Host: args.Host, Port: args.Port},
		ApprovalID: approvalID,
		Timeout:    timeout,
	})

	meta := &domain.ResultMeta{
		Tool:       t.spec.Name,
		Risk:       string(t.spec.Risk),
		Target:     domain.Target{Host: args.Host, Port: args.Port}.String(),
		ExitCode:   result.ExitCode,
		DurationMS: result.Duration.Milliseconds(),
		Truncated:  result.Truncated,
		TimedOut:   result.TimedOut,
	}
	if err != nil {
		// A refusal that still ran (e.g. non-zero exit) keeps its evidence:
		// stdout and stderr are part of the failure, not discarded.
		failure := domain.Failure(err).WithMeta(meta)
		if result.Stdout != "" || result.Stderr != "" {
			failure.Data = map[string]string{
				"stdout": result.Stdout,
				"stderr": result.Stderr,
			}
		}
		return failure
	}

	payload := map[string]string{"stdout": result.Stdout}
	if result.Stderr != "" {
		payload["stderr"] = result.Stderr
	}
	if result.Truncated {
		payload["note"] = "output truncated by the runner; rerun with a narrower scope if the tail matters"
	}
	return domain.Success("ok", payload).WithMeta(meta)
}

// Call keeps the string-based harness signature. It returns the JSON envelope
// plus the coded error so Go callers can branch while the model always receives
// the same structured shape.
func (t *ScanTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	envelope := t.Invoke(ctx, raw)
	if envelope.OK {
		return envelope.JSON(), nil
	}
	return envelope.JSON(), domain.NewToolError(envelope.Code, envelope.Message, envelope.Hint)
}

// Catalog is the set of scan tools an engagement exposes. It is deliberately
// small: each entry adds a binary the worker can invoke, so additions are
// deliberate rather than automatic.
func Catalog(runner *Runner) []*ScanTool {
	return []*ScanTool{
		NewScanTool("dns_lookup", "Resolve DNS records for an authorized target (passive).",
			[]string{"dig", "+short", "{host}"}, domain.RiskPassive, runner),
		NewScanTool("http_probe", "Fetch HTTP headers from an authorized target (light).",
			[]string{"curl", "-sS", "-I", "--max-time", "15", "https://{host_port}/"}, domain.RiskLight, runner),
		NewScanTool("web_fetch", "Fetch one page body from an authorized target with a read-only GET (light).",
			[]string{"curl", "-sS", "--max-time", "20", "-w", " [http_status=%{http_code}]", "https://{host_port}{path}"}, domain.RiskLight, runner),
		NewScanTool("port_scan", "Probe common TCP ports on an authorized target (active; needs approval).",
			[]string{"nmap", "-sT", "-Pn", "--top-ports", "100", "{host}"}, domain.RiskActive, runner),
		NewScanTool("service_scan", "Fingerprint services on an authorized target (active; needs approval).",
			[]string{"nmap", "-sV", "-Pn", "{host}"}, domain.RiskActive, runner),
		NewScanTool("web_enum", "Enumerate web paths on an authorized target (active; needs approval).",
			[]string{"ffuf", "-s", "-w", "/usr/share/wordlists/common.txt", "-u", "https://{host_port}/FUZZ"}, domain.RiskActive, runner),
	}
}
