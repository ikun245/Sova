package webattack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"
)

// File is one uploaded part. Content is base64 so arbitrary bytes survive the
// JSON hop between the model and the tool.
type File struct {
	Field       string `json:"field"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	ContentB64  string `json:"content_base64"`
}

// Multipart describes a form submission. Field and file values may contain the
// intruder marker, which is how payloads reach a filename.
type Multipart struct {
	Fields map[string]string `json:"fields,omitempty"`
	Files  []File            `json:"files,omitempty"`
}

// Build renders the body and the matching Content-Type, including the boundary.
//
// The boundary is derived from the content rather than drawn at random. That
// matters for approval: an approval binds to a digest of the body, so a random
// boundary would make every run of the same logical request produce a different
// digest, and an approved request could never be retried.
func (m Multipart) Build() ([]byte, string, error) {
	if len(m.Fields) == 0 && len(m.Files) == 0 {
		return nil, "", fmt.Errorf("multipart needs at least one field or file")
	}

	boundary, err := m.boundary()
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, "", err
	}

	// Sorted keys make the body deterministic for the same input, so an
	// approval digest stays stable across retries.
	names := make([]string, 0, len(m.Fields))
	for name := range m.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writer.WriteField(name, m.Fields[name]); err != nil {
			return nil, "", err
		}
	}

	for _, file := range m.Files {
		if strings.TrimSpace(file.Field) == "" {
			return nil, "", fmt.Errorf("file part is missing a field name")
		}
		content, err := base64.StdEncoding.DecodeString(file.ContentB64)
		if err != nil {
			return nil, "", fmt.Errorf("file %q content_base64 is invalid: %w", file.Filename, err)
		}
		header := make(textproto.MIMEHeader)
		filename := strings.ReplaceAll(file.Filename, `"`, "")
		header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			strings.ReplaceAll(file.Field, `"`, ""), filename))
		contentType := file.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		header.Set("Content-Type", contentType)
		part, err := writer.CreatePart(header)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(content); err != nil {
			return nil, "", err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), writer.FormDataContentType(), nil
}

// boundary hashes the logical parts. Finding content whose hash over itself
// equals a substring of itself is a fixed-point search, so the delimiter cannot
// realistically be forged into the payload.
func (m Multipart) boundary() (string, error) {
	hash := sha256.New()

	names := make([]string, 0, len(m.Fields))
	for name := range m.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(hash, "field\x00%s\x00%s\x00", name, m.Fields[name])
	}
	for _, file := range m.Files {
		content, err := base64.StdEncoding.DecodeString(file.ContentB64)
		if err != nil {
			return "", fmt.Errorf("file %q content_base64 is invalid: %w", file.Filename, err)
		}
		fmt.Fprintf(hash, "file\x00%s\x00%s\x00%s\x00%s\x00",
			file.Field, file.Filename, file.ContentType, hex.EncodeToString(content))
	}
	return "----soc" + hex.EncodeToString(hash.Sum(nil)[:12]), nil
}

// Substitute replaces every marker occurrence. With an empty payload the
// marker is removed, which is how a control request is produced.
func Substitute(value, marker, payload string) string {
	if marker == "" {
		return value
	}
	return strings.ReplaceAll(value, marker, payload)
}
