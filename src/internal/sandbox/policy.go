// Package sandbox models process confinement independently of the platform
// runner that enforces it.
//
// The vocabulary follows deepseek-harness deliberately: a mode describes file
// effects only. Network reachability and process visibility are explicitly out
// of scope, because a filesystem jail does not stop a script from opening a
// socket. Anything that needs network confinement must say so separately — see
// NetworkConfinement.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Mode is the file-effect policy for a confined process.
type Mode string

const (
	// ModeReadOnly refuses writes, except required sinks such as /dev/null
	// that a shell needs to function.
	ModeReadOnly Mode = "read-only"
	// ModeWorkspaceWrite permits writes under the workspace root, explicit
	// extra roots, and backend-defined temp areas.
	ModeWorkspaceWrite Mode = "workspace-write"
	// ModeFullAccess bypasses confinement entirely. A caller in this mode must
	// spawn the raw argv and must not pretend it was sandboxed.
	ModeFullAccess Mode = "danger-full-access"
)

// Confined reports whether this mode actually confines anything.
func (m Mode) Confined() bool { return m != ModeFullAccess }

// Valid reports whether the mode is a known value.
func (m Mode) Valid() bool {
	switch m {
	case ModeReadOnly, ModeWorkspaceWrite, ModeFullAccess:
		return true
	}
	return false
}

// Enforcement is how completely a backend can honour the requested mode.
//
// Reporting this honestly is the difference between a boundary and a decoration:
// a backend that only partially enforces must be visible to callers that need an
// absolute guarantee, rather than being silently treated as full.
type Enforcement string

const (
	EnforcementFull    Enforcement = "full"
	EnforcementPartial Enforcement = "partial"
)

// Policy is the confinement decision for one call. It is carried per call, never
// pinned on a backend, so concurrent callers can run under different boundaries.
type Policy struct {
	Mode Mode
	// WorkspaceRoot is the absolute directory ModeWorkspaceWrite may write
	// under. It is carried even for modes that ignore it, so callers can resolve
	// once and then choose an enforcement path.
	WorkspaceRoot string
	// AdditionalWritableRoots are extra absolute directories granted write
	// access under workspace-write. They grant nothing under read-only.
	AdditionalWritableRoots []string
	// Enforcement reports what the backend can actually do. Zero means unknown,
	// which callers must treat as partial.
	Enforcement Enforcement
	// Backend names the runner that will enforce this (bwrap, seatbelt, acl,
	// container). Recorded for audit.
	Backend string
}

// ErrUnavailable means no backend could enforce the requested mode. Following
// deepseek-harness, the call fails instead of running unconfined: silently
// degrading to full access would make every other guarantee a fiction.
type ErrUnavailable struct {
	Mode    Mode
	Backend string
	Reason  string
}

func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("sandbox mode %q is unavailable%s: %s", e.Mode, backendSuffix(e.Backend), e.Reason)
}

func backendSuffix(backend string) string {
	if backend == "" {
		return ""
	}
	return " on backend " + backend
}

// ErrFileDenied means the mode refused a file effect. It names the mode so a
// model can tell "writes are off" apart from "that path is outside the
// workspace".
type ErrFileDenied struct {
	Mode Mode
	Path string
}

func (e *ErrFileDenied) Error() string {
	return fmt.Sprintf("file access denied under %s mode: %s", e.Mode, e.Path)
}

// Validate checks that a policy is internally consistent. It does not touch the
// filesystem; see ResolveRoots for that.
func (p Policy) Validate() error {
	if !p.Mode.Valid() {
		return fmt.Errorf("unknown sandbox mode %q", p.Mode)
	}
	if p.Mode == ModeWorkspaceWrite {
		if strings.TrimSpace(p.WorkspaceRoot) == "" {
			return fmt.Errorf("workspace-write requires a workspace root")
		}
		if !filepath.IsAbs(p.WorkspaceRoot) {
			return fmt.Errorf("workspace root must be absolute, got %q", p.WorkspaceRoot)
		}
	}
	for _, root := range p.AdditionalWritableRoots {
		if !filepath.IsAbs(root) {
			return fmt.Errorf("additional writable root must be absolute, got %q", root)
		}
	}
	return nil
}

// ResolveRoots validates writable roots against the real filesystem and returns
// their canonical forms.
//
// Symlinks are rejected rather than followed: a directory that was legitimate
// during configuration can be replaced by a symlink between calls, and following
// it would silently widen the writable area outside the workspace.
func (p Policy) ResolveRoots() ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Mode != ModeWorkspaceWrite {
		// Only workspace-write consumes roots; returning them for other modes
		// would imply a grant that does not exist.
		return nil, nil
	}

	candidates := append([]string{p.WorkspaceRoot}, p.AdditionalWritableRoots...)
	out := make([]string, 0, len(candidates))
	seen := map[string]bool{}

	for _, root := range candidates {
		info, err := os.Lstat(root)
		if err != nil {
			return nil, fmt.Errorf("writable root %q: %w", root, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("writable root %q is a symlink; declare the real directory instead", root)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("writable root %q is not a directory", root)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("writable root %q cannot be resolved: %w", root, err)
		}
		if resolved != filepath.Clean(root) {
			return nil, fmt.Errorf("writable root %q resolves to %q; declare the canonical path", root, resolved)
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, resolved)
	}
	return out, nil
}

// AllowsWrite reports whether a path may be written under this policy.
func (p Policy) AllowsWrite(path string) error {
	if p.Mode == ModeFullAccess {
		return nil
	}
	if p.Mode == ModeReadOnly {
		return &ErrFileDenied{Mode: p.Mode, Path: path}
	}
	if p.Mode != ModeWorkspaceWrite {
		return &ErrFileDenied{Mode: p.Mode, Path: path}
	}

	target, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return &ErrFileDenied{Mode: p.Mode, Path: path}
	}
	// Resolve the target's parent so a symlinked directory cannot smuggle the
	// write outside the workspace. The file itself may not exist yet.
	if resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(target)); err == nil {
		target = filepath.Join(resolvedParent, filepath.Base(target))
	}

	// Both sides must be canonicalized the same way. On Windows,
	// EvalSymlinks returns 8.3 short names ("CRACKE~1"), so comparing a
	// resolved target against a raw long-name root would deny legitimate
	// paths inside the workspace.
	target = canonical(target)
	for _, root := range append([]string{p.WorkspaceRoot}, p.AdditionalWritableRoots...) {
		if root == "" {
			continue
		}
		if within(target, canonical(root)) {
			return nil
		}
	}
	return &ErrFileDenied{Mode: p.Mode, Path: path}
}

// canonical resolves a path to compare like with like: absolute, symlinks
// resolved where possible, and case-folded on case-insensitive filesystems.
func canonical(path string) string {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		absolute = filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	if runtime.GOOS == "windows" {
		// Windows paths are case-insensitive; comparing them case-sensitively
		// would reject a legitimate path that differs only in letter case.
		return strings.ToLower(absolute)
	}
	return absolute
}

// within reports whether path is inside root, using path boundaries so
// "/ws-evil" is not considered inside "/ws".
func within(path, root string) bool {
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
