package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
	"soc/agent/internal/platform"
	"soc/agent/internal/store"
	"soc/agent/internal/webattack"
)

// runWeb drives the built-in HTTP tools from a shell.
//
// It exists because web testing is the common case and a JSON payload file is
// the only way to express multipart uploads, binary bodies and intruder lists
// without a flag for every combination. The flags cover the fast path; --json
// covers everything else.
func runWeb(args []string) error {
	flags := flag.NewFlagSet("web", flag.ContinueOnError)
	scopeID := flags.String("scope", "", "stored scope id (required)")
	toolName := flags.String("tool", "http_request", "tool: http_request, http_intruder")
	jsonPath := flags.String("json", "", "path to a JSON argument file (use - for stdin)")
	rawURL := flags.String("url", "", "request URL")
	method := flags.String("method", "GET", "HTTP method")
	body := flags.String("body", "", "raw request body")
	approval := flags.String("approval", "", "approval id, required when the action is active risk")
	timeout := flags.Duration("timeout", 60*time.Second, "overall timeout")
	insecure := flags.Bool("insecure", true, "skip TLS verification (lab targets usually self-sign)")
	reason := flags.String("reason", "", "why this request is authorized; recorded with the approval")

	var headers headerFlag
	flags.Var(&headers, "header", `request header, repeatable: -header "X-Token: abc"`)
	var uploads uploadFlag
	flags.Var(&uploads, "upload", `multipart file part, repeatable: -upload "file=/tmp/shell.php"`)
	var uploadNames uploadNameFlag
	flags.Var(&uploadNames, "upload-name", `filename for an upload part: -upload-name "file=shell.php.png"`)

	if err := flags.Parse(args); err != nil {
		return err
	}
	if *scopeID == "" {
		return errors.New("usage: soc web --scope <id> (--url <url> [--method M] [--body B] [-header K:V] [-upload field=path]) | --json <file>")
	}

	payload, err := buildWebPayload(*jsonPath, *rawURL, *method, *body, *reason,
		headers, uploads, uploadNames, *insecure)
	if err != nil {
		return err
	}

	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	database, err := store.OpenPostgres(ctx, config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	record, err := database.GetScope(ctx, *scopeID)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}
	if !record.Active(time.Now()) {
		return errors.New("the scope is revoked or expired; this request would be unauthorized")
	}

	runner := exec.NewRunner(exec.Policy{
		Ceiling:  record.Scope.MaxRisk,
		AskAbove: domain.RiskLight,
	}, record.Scope, storeAuditor{database: database})
	runner.Approvals = database
	runner.Backend = backendFor(config)

	var tool *exec.WebTool
	for _, candidate := range exec.WebCatalog(runner) {
		if candidate.Spec().Name == *toolName {
			tool = candidate
			break
		}
	}
	if tool == nil {
		return fmt.Errorf("unknown web tool %q; available: http_request, http_intruder", *toolName)
	}

	fmt.Printf("scope   %s (ticket %s, max_risk %s)\n", record.Scope.ID, record.Scope.TicketID, record.Scope.MaxRisk)
	fmt.Printf("tool    %s (risk %s)\n", tool.Spec().Name, tool.Spec().Risk)
	if runner.Limiter != nil {
		fmt.Printf("rate    %d/min (interval %s)\n", record.Scope.MaxRatePerMinute, runner.Limiter.Interval())
	}

	result := tool.InvokeWithApproval(ctx, payload, *approval, *timeout)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))

	if !result.OK {
		// Return the code, not a paragraph: callers and scripts branch on it.
		return fmt.Errorf("web tool failed: %s", result.Code)
	}
	return nil
}

func buildWebPayload(jsonPath, rawURL, method, body, reason string,
	headers headerFlag, uploads uploadFlag, uploadNames uploadNameFlag, insecure bool) (json.RawMessage, error) {

	if jsonPath != "" {
		var data []byte
		if jsonPath == "-" {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("read stdin: %w", err)
			}
			data = raw
		} else {
			raw, err := os.ReadFile(jsonPath)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", jsonPath, err)
			}
			data = raw
		}
		if !json.Valid(data) {
			return nil, errors.New("the JSON argument file is not valid JSON")
		}
		return json.RawMessage(data), nil
	}

	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("--url is required when --json is not used")
	}

	args := map[string]any{
		"url":             rawURL,
		"method":          method,
		"skip_tls_verify": insecure,
	}
	if body != "" {
		args["body"] = body
	}
	if reason != "" {
		args["reason"] = reason
	}
	if len(headers) > 0 {
		args["headers"] = map[string]string(headers)
	}

	if len(uploads) > 0 {
		multipart := &webattack.Multipart{Fields: map[string]string{}, Files: []webattack.File{}}
		for field, value := range uploads {
			path := strings.TrimSpace(value)
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read upload %s: %w", path, err)
			}
			name := filepath.Base(path)
			if override := uploadNames[field]; override != "" {
				name = override
			}
			multipart.Files = append(multipart.Files, webattack.File{
				Field:       field,
				Filename:    name,
				ContentType: contentTypeFor(name),
				ContentB64:  base64.StdEncoding.EncodeToString(content),
			})
		}
		args["multipart"] = multipart
	}

	return json.Marshal(args)
}

// contentTypeFor keeps an uploaded script looking like what its extension says,
// so a filter that trusts the declared type behaves as it would in a browser.
func contentTypeFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".php", ".phtml", ".php5":
		return "application/x-php"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

// headerFlag accumulates repeated -header "Name: value" flags.
type headerFlag map[string]string

func (h *headerFlag) String() string { return "" }

func (h *headerFlag) Set(value string) error {
	name, val, found := strings.Cut(value, ":")
	if !found || strings.TrimSpace(name) == "" {
		return fmt.Errorf("header must be \"Name: value\", got %q", value)
	}
	if *h == nil {
		*h = map[string]string{}
	}
	(*h)[strings.TrimSpace(name)] = strings.TrimSpace(val)
	return nil
}

// uploadFlag accumulates repeated -upload "field=path" flags.
type uploadFlag map[string]string

func (u *uploadFlag) String() string { return "" }

func (u *uploadFlag) Set(value string) error {
	field, path, found := strings.Cut(value, "=")
	if !found || strings.TrimSpace(field) == "" || strings.TrimSpace(path) == "" {
		return fmt.Errorf("upload must be \"field=path\", got %q", value)
	}
	if *u == nil {
		*u = map[string]string{}
	}
	(*u)[strings.TrimSpace(field)] = strings.TrimSpace(path)
	return nil
}

// uploadNameFlag overrides the filename sent for a field, which is how an
// extension bypass is tested without editing a file on disk.
type uploadNameFlag map[string]string

func (u *uploadNameFlag) String() string { return "" }

func (u *uploadNameFlag) Set(value string) error {
	field, name, found := strings.Cut(value, "=")
	if !found || strings.TrimSpace(field) == "" || strings.TrimSpace(name) == "" {
		return fmt.Errorf("upload-name must be \"field=filename\", got %q", value)
	}
	if *u == nil {
		*u = map[string]string{}
	}
	(*u)[strings.TrimSpace(field)] = strings.TrimSpace(name)
	return nil
}
