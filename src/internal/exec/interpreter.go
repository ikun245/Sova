package exec

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// interpreters run arbitrary code. They are listed separately from toolRisk
// because their effect is not knowable from argv: a tool like nmap has a
// predictable action, an interpreter does not.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"python": true, "python3": true, "python2": true,
	"java": true, "node": true, "nodejs": true,
	"perl": true, "ruby": true, "php": true,
	"powershell": true, "pwsh": true, "cmd": true,
}

// IsInterpreter reports whether a program is a general-purpose code runner.
func IsInterpreter(program string) bool {
	return interpreters[baseName(program)]
}

// ScriptInfo describes what an interpreter was asked to run. The runner records
// this because the code, not the command line, is the real payload.
type ScriptInfo struct {
	// Inline is the code passed with -c / -e, when present.
	Inline string
	// File is the script path when the code lives on disk.
	File string
	// SHA256 identifies the payload even when the body is truncated in a log.
	SHA256 string
	// Bytes is the payload length, so an oversized submission is visible.
	Bytes int
}

// ExtractScript pulls the code out of an interpreter invocation. It understands
// the common -c/-e flags and otherwise treats the first non-flag argument as a
// script file.
func ExtractScript(argv []string) ScriptInfo {
	if len(argv) < 2 {
		return ScriptInfo{}
	}

	var info ScriptInfo
	args := argv[1:]
	codeFlags := map[string]bool{
		"-c": true, "-e": true, "--eval": true, "-command": true, "-encodedcommand": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg)

		if codeFlags[lower] && i+1 < len(args) {
			info.Inline = args[i+1]
			break
		}
		// Handle the -c=... form as well.
		for flag := range codeFlags {
			if strings.HasPrefix(lower, flag+"=") {
				info.Inline = arg[len(flag)+1:]
			}
		}
		if info.Inline != "" {
			break
		}
	}

	if info.Inline == "" {
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			info.File = arg
			break
		}
	}

	payload := info.Inline
	if payload == "" {
		payload = info.File
	}
	if payload != "" {
		sum := sha256.Sum256([]byte(payload))
		info.SHA256 = hex.EncodeToString(sum[:])
		info.Bytes = len(payload)
	}
	return info
}

// NeedsWorkspace reports whether a program should run with its working
// directory pinned to the sandbox workspace, so relative paths land in the
// writable area rather than the worker's own installation directory.
func NeedsWorkspace(program string) bool {
	return IsInterpreter(program)
}
