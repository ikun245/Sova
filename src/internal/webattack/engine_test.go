package webattack

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeMethod(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: "GET"},
		{in: "post", want: "POST"},
		{in: "  Delete ", want: "DELETE"},
		{in: "PATCH", want: "PATCH"},
		{in: "FETCH", wantErr: true},
		{in: "GET / HTTP/1.1", wantErr: true},
	}
	for _, tc := range tests {
		got, err := NormalizeMethod(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeMethod(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeMethod(%q) returned error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeMethod(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStateChanging(t *testing.T) {
	// A read must not require approval, and a write must not skip it.
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if StateChanging(method) {
			t.Fatalf("%s must be treated as read-only", method)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if !StateChanging(method) {
			t.Fatalf("%s must be treated as state-changing", method)
		}
	}
}

func TestSendCapturesStatusAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe", "yes")
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprint(w, "short and stout")
	}))
	defer server.Close()

	engine := NewEngine(1024)
	resp, err := engine.Send(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	// A non-2xx status is evidence, not a transport failure.
	if resp.Status != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", resp.Status, http.StatusTeapot)
	}
	if string(resp.Body) != "short and stout" {
		t.Fatalf("body = %q", string(resp.Body))
	}
	if got := resp.Headers["X-Probe"]; len(got) != 1 || got[0] != "yes" {
		t.Fatalf("header X-Probe = %v", got)
	}
}

func TestSendTruncatesLargeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("A", 500))
	}))
	defer server.Close()

	engine := NewEngine(64)
	resp, err := engine.Send(context.Background(), Request{Method: "GET", URL: server.URL})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(resp.Body) != 64 {
		t.Fatalf("body length = %d, want the 64 byte cap", len(resp.Body))
	}
	if !resp.Truncated {
		t.Fatal("Truncated = false, want true")
	}
}

func TestSendChecksEveryRedirectHop(t *testing.T) {
	var reached bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer other.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()

	engine := NewEngine(1024)
	_, err := engine.Send(context.Background(), Request{
		Method:          "GET",
		URL:             server.URL,
		FollowRedirects: true,
		AllowHost: func(host string) error {
			// Refuse anything that is not the original host: this models a
			// redirect trying to move the request out of scope.
			if host != strings.TrimPrefix(server.URL, "http://") {
				return fmt.Errorf("host %q is not authorized", host)
			}
			return nil
		},
	})
	if err == nil {
		t.Fatal("Send followed a redirect to an unauthorized host")
	}
	if reached {
		t.Fatal("the unauthorized host was contacted despite the check")
	}
}

func TestSendRejectsNonHTTPScheme(t *testing.T) {
	engine := NewEngine(1024)
	_, err := engine.Send(context.Background(), Request{Method: "GET", URL: "file:///etc/passwd"})
	if err == nil {
		t.Fatal("a non-HTTP scheme must be rejected")
	}
}

func TestMultipartBoundaryIsDeterministic(t *testing.T) {
	build := func() ([]byte, string) {
		multipart := Multipart{
			Fields: map[string]string{"name": "probe"},
			Files: []File{{
				Field:       "file",
				Filename:    "probe.php",
				ContentType: "application/x-php",
				ContentB64:  base64.StdEncoding.EncodeToString([]byte(`<?php echo 1;`)),
			}},
		}
		body, contentType, err := multipart.Build()
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}
		return body, contentType
	}

	first, firstType := build()
	second, secondType := build()

	// Approval binds to a digest of the body, so the same logical request must
	// produce the same bytes twice; a random boundary would break that.
	if string(first) != string(second) {
		t.Fatal("the same multipart input produced different bytes")
	}
	if firstType != secondType {
		t.Fatalf("content type changed: %q vs %q", firstType, secondType)
	}
	if !strings.Contains(string(first), "filename=\"probe.php\"") {
		t.Fatalf("body does not carry the filename: %s", string(first))
	}
}

func TestMultipartRejectsBadBase64(t *testing.T) {
	multipart := Multipart{Files: []File{{Field: "file", Filename: "x.php", ContentB64: "!!!"}}}
	if _, _, err := multipart.Build(); err == nil {
		t.Fatal("invalid base64 must be rejected rather than uploaded as garbage")
	}
}

func TestSubstitute(t *testing.T) {
	if got := Substitute("aFUZZb", "FUZZ", "X"); got != "aXb" {
		t.Fatalf("Substitute = %q", got)
	}
	// An empty payload is how the control request removes the marker.
	if got := Substitute("aFUZZb", "FUZZ", ""); got != "ab" {
		t.Fatalf("control substitution = %q", got)
	}
	if got := Substitute("plain", "", "X"); got != "plain" {
		t.Fatalf("empty marker must not alter the value: %q", got)
	}
}
