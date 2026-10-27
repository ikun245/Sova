package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestModeConfined(t *testing.T) {
	cases := map[Mode]bool{
		ModeReadOnly:       true,
		ModeWorkspaceWrite: true,
		ModeFullAccess:     false,
	}
	for mode, want := range cases {
		if got := mode.Confined(); got != want {
			t.Fatalf("%q Confined() = %v, want %v", mode, got, want)
		}
	}
}

func TestPolicyValidateRejectsRelativeWorkspace(t *testing.T) {
	policy := Policy{Mode: ModeWorkspaceWrite, WorkspaceRoot: "relative/path"}
	if err := policy.Validate(); err == nil {
		t.Fatal("a relative workspace root must be rejected; it resolves differently per process")
	}
}

func TestPolicyValidateRequiresWorkspaceForWorkspaceWrite(t *testing.T) {
	if err := (Policy{Mode: ModeWorkspaceWrite}).Validate(); err == nil {
		t.Fatal("workspace-write without a root authorizes nothing")
	}
}

func TestPolicyRejectsUnknownMode(t *testing.T) {
	if err := (Policy{Mode: "sandboxed-ish"}).Validate(); err == nil {
		t.Fatal("an unknown mode must not be accepted")
	}
}

func TestResolveRootsRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	policy := Policy{
		Mode:                    ModeWorkspaceWrite,
		WorkspaceRoot:           root,
		AdditionalWritableRoots: []string{link},
	}
	// A symlinked root can be repointed between calls, which would silently
	// move the writable area; it must be refused, not followed.
	if _, err := policy.ResolveRoots(); err == nil {
		t.Fatal("a symlinked writable root must be rejected")
	}
}

func TestResolveRootsRejectsMissingDirectory(t *testing.T) {
	root := t.TempDir()
	policy := Policy{
		Mode:                    ModeWorkspaceWrite,
		WorkspaceRoot:           root,
		AdditionalWritableRoots: []string{filepath.Join(root, "does-not-exist")},
	}
	if _, err := policy.ResolveRoots(); err == nil {
		t.Fatal("a missing writable root must be rejected")
	}
}

func TestAllowsWriteRespectsBoundary(t *testing.T) {
	root := t.TempDir()
	policy := Policy{Mode: ModeWorkspaceWrite, WorkspaceRoot: root}

	if err := policy.AllowsWrite(filepath.Join(root, "out.txt")); err != nil {
		t.Fatalf("a path inside the workspace should be allowed: %v", err)
	}

	// A sibling directory sharing a name prefix must not count as inside.
	sibling := root + "-evil"
	if err := policy.AllowsWrite(filepath.Join(sibling, "x")); err == nil {
		t.Fatal("a sibling path must not be treated as inside the workspace")
	}

	var denied *ErrFileDenied
	if err := policy.AllowsWrite(filepath.Join(root, "..", "escape.txt")); !errors.As(err, &denied) {
		t.Fatal("path traversal must be reported as a denial")
	}
}

func TestReadOnlyDeniesEveryWrite(t *testing.T) {
	policy := Policy{Mode: ModeReadOnly}
	if err := policy.AllowsWrite("/tmp/x"); err == nil {
		t.Fatal("read-only must deny writes")
	}
}

func TestFullAccessAllowsWrites(t *testing.T) {
	policy := Policy{Mode: ModeFullAccess}
	if err := policy.AllowsWrite("/tmp/x"); err != nil {
		t.Fatalf("full access should allow writes: %v", err)
	}
}

func TestDenialMarkerIsStable(t *testing.T) {
	// A model branches on this token, so its shape must not drift.
	marker := DenialMarker(ModeReadOnly)
	if marker != "[sandbox: file access denied under read-only mode]" {
		t.Fatalf("marker = %q", marker)
	}
}

// --- escalation ---

func TestEscalationLadderIsStrictlyWider(t *testing.T) {
	// Narrowing is never an escalation, even though it is "safe".
	_, err := Resolve(ModeWorkspaceWrite, EscalationRequest{To: ModeReadOnly, Justification: "x"})
	if err == nil {
		t.Fatal("narrowing must be rejected as an invalid escalation")
	}

	// Same mode is not an escalation: the caller should just retry.
	outcome, err := Resolve(ModeWorkspaceWrite, EscalationRequest{To: ModeWorkspaceWrite})
	if err != nil {
		t.Fatalf("requesting the current mode should be a no-op, got %v", err)
	}
	if outcome.RequiresApproval {
		t.Fatal("no widening means no approval")
	}
}

func TestEscalationRequiresJustification(t *testing.T) {
	_, err := Resolve(ModeReadOnly, EscalationRequest{To: ModeWorkspaceWrite})
	if err == nil {
		t.Fatal("widening without a justification must be refused")
	}
}

func TestEscalationToFullAccessNeedsApproval(t *testing.T) {
	outcome, err := Resolve(ModeReadOnly, EscalationRequest{
		To:            ModeFullAccess,
		Justification: "generating a payload file next to the report",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !outcome.RequiresApproval {
		t.Fatal("any widening must require a human")
	}
	if outcome.Mode != ModeFullAccess {
		t.Fatalf("Mode = %q", outcome.Mode)
	}
	if outcome.Justification == "" {
		t.Fatal("the justification must be carried into the audit record")
	}
}

func TestEscalationHintOnlyWhenPathExists(t *testing.T) {
	// Promising an escalation path that is not offered would make a model loop.
	if hint := EscalationHint(ModeReadOnly, false); hint != "" {
		t.Fatal("no hint should be given when escalation is unavailable")
	}
	hint := EscalationHint(ModeReadOnly, true)
	if !strings.Contains(hint, "sandbox_permissions") {
		t.Fatalf("hint = %q", hint)
	}
	// Full access cannot go wider.
	if hint := EscalationHint(ModeFullAccess, true); hint != "" {
		t.Fatal("full access has nowhere to escalate to")
	}
}

// --- network confinement (the axis sandbox does not cover) ---

func TestNetworkConfinementIsSeparateFromMode(t *testing.T) {
	// The whole point: a read-only filesystem says nothing about sockets.
	mode := Policy{Mode: ModeReadOnly}
	if !mode.Mode.Confined() {
		t.Fatal("read-only is a confined filesystem mode")
	}
	if NetworkUnconfined.Confined() {
		t.Fatal("an unconfined network must not report as confined, regardless of the filesystem mode")
	}
}

func TestCheckInterpreterEgressRequiresAttestation(t *testing.T) {
	// An unnamed claim is not auditable, so it does not count.
	err := CheckInterpreterEgress("python", Attestation{Network: NetworkEgressFiltered})
	if err == nil {
		t.Fatal("an attestation without a responsible party must be refused")
	}

	err = CheckInterpreterEgress("python", Attestation{
		Network:    NetworkEgressFiltered,
		AttestedBy: "soc-lead",
	})
	if err != nil {
		t.Fatalf("a recorded, filtered attestation should pass: %v", err)
	}
}

func TestCheckInterpreterEgressRejectsUnconfined(t *testing.T) {
	// Recording "unconfined" is an explicit refusal, not a loophole.
	err := CheckInterpreterEgress("python", Attestation{
		Network:    NetworkUnconfined,
		AttestedBy: "soc-lead",
	})
	var unconfined *ErrNetworkUnconfined
	if !errors.As(err, &unconfined) {
		t.Fatalf("error = %v, want ErrNetworkUnconfined", err)
	}
	if !strings.Contains(err.Error(), "unconfined") {
		t.Fatalf("the error must name the state, got %v", err)
	}
}

func TestCheckInterpreterEgressRejectsUnknownState(t *testing.T) {
	err := CheckInterpreterEgress("python", Attestation{
		Network:    NetworkUnknown,
		AttestedBy: "soc-lead",
	})
	if err == nil {
		t.Fatal("an unspecified network state must be refused; silence is not confinement")
	}
}

func TestNetworkIsolatedAllowsLocalProcessing(t *testing.T) {
	err := CheckInterpreterEgress("python", Attestation{
		Network:    NetworkIsolated,
		AttestedBy: "soc-lead",
		Note:       "container with no route",
	})
	if err != nil {
		t.Fatalf("a network-isolated worker may run local scripts: %v", err)
	}
}
