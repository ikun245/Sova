// Package webattack implements the request engine behind the built-in HTTP
// tools. It has no notion of authorization: the executor decides whether a
// request may be sent, and passes AllowHost so this package can refuse a
// redirect hop that leaves the authorized host.
package webattack

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Request is one HTTP request as the operator wrote it, not as a browser would
// normalise it. Headers are sent verbatim so a test can reproduce a captured
// request byte for byte.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	// FollowRedirects is off by default: a scanner wants to see the 302 itself,
	// and silently following it can leave the authorized host.
	FollowRedirects bool
	// SkipTLSVerify is required for the many CTF and lab targets with
	// self-signed certificates. It only disables certificate validation; the
	// scope check still applies to every hop.
	SkipTLSVerify bool
	// AllowHost is called for the initial host and for every redirect hop. A
	// non-nil error aborts the request. Nil means the caller has already
	// checked and accepts the risk.
	AllowHost func(host string) error
	Timeout   time.Duration
}

// Response is what the target returned, with the pieces an operator compares
// between attempts: status, length, and the raw header block.
type Response struct {
	Status     int
	Proto      string
	Headers    map[string][]string
	Body       []byte
	Truncated  bool
	Duration   time.Duration
	FinalURL   string
	Redirects  []string
	BytesSent  int
	BytesRead  int
	RequestRaw string
}

// Engine sends requests with a bounded body and a redirect check on every hop.
type Engine struct {
	// MaxBody caps how much of a response is kept in memory.
	MaxBody int
}

// NewEngine builds an engine with a default cap of 1 MiB per response.
func NewEngine(maxBody int) *Engine {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	return &Engine{MaxBody: maxBody}
}

var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true, http.MethodTrace: true,
}

// StateChanging reports whether a method is expected to modify the target.
// The executor uses this to raise the risk of an otherwise read-only tool.
func StateChanging(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// NormalizeMethod validates and upper-cases a method.
func NormalizeMethod(method string) (string, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(method))
	if trimmed == "" {
		return http.MethodGet, nil
	}
	if !allowedMethods[trimmed] {
		return "", fmt.Errorf("unsupported HTTP method %q", trimmed)
	}
	return trimmed, nil
}

// Send performs one request. It returns a Response even for non-2xx statuses:
// a 403 is evidence, not a tool failure.
func (e *Engine) Send(ctx context.Context, req Request) (Response, error) {
	method, err := NormalizeMethod(req.Method)
	if err != nil {
		return Response{}, err
	}

	parsed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil {
		return Response{}, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Response{}, fmt.Errorf("URL scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return Response{}, errors.New("URL has no host")
	}
	if req.AllowHost != nil {
		if err := req.AllowHost(parsed.Hostname()); err != nil {
			return Response{}, err
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// #nosec G402 -- lab and CTF targets routinely use self-signed certs. The
	// authorization check is on the host, not on the certificate, and is
	// applied to every redirect hop below.
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: req.SkipTLSVerify},
		MaxIdleConns:          1,
		IdleConnTimeout:       10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
	}

	redirects := make([]string, 0, 4)
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if !req.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.AllowHost != nil {
				if err := req.AllowHost(next.URL.Hostname()); err != nil {
					return err
				}
			}
			redirects = append(redirects, next.URL.String())
			return nil
		},
	}

	body := io.Reader(nil)
	if len(req.Body) > 0 {
		body = strings.NewReader(string(req.Body))
	}
	httpReq, err := http.NewRequestWithContext(runCtx, method, parsed.String(), body)
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}
	for name, value := range req.Headers {
		lower := strings.ToLower(name)
		// Host is derived from the URL; setting it through Header has no effect
		// and would mislead the operator into thinking it was honoured.
		if lower == "host" || lower == "content-length" {
			continue
		}
		httpReq.Header.Set(name, value)
	}
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	started := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(started)
	if err != nil {
		return Response{Duration: duration, Redirects: redirects}, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, int64(e.MaxBody)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Response{Duration: duration, Redirects: redirects}, fmt.Errorf("read response body: %w", err)
	}
	truncated := len(data) > e.MaxBody
	if truncated {
		data = data[:e.MaxBody]
	}

	return Response{
		Status:    resp.StatusCode,
		Proto:     resp.Proto,
		Headers:   resp.Header,
		Body:      data,
		Truncated: truncated,
		Duration:  duration,
		FinalURL:  resp.Request.URL.String(),
		Redirects: redirects,
		BytesSent: len(req.Body),
		BytesRead: len(data),
	}, nil
}
