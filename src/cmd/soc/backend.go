package main

import (
	"soc/agent/internal/exec"
	"soc/agent/internal/platform"
)

// backendFor builds the execution backend named by configuration.
//
// This is the only place that knows an environment can hold Kali tools, so the
// executor stays testable and a future remote backend (SSH, a job runner) can be
// added here without touching any security check.
func backendFor(config platform.Config) exec.Backend {
	if config.ExecBackend == platform.ExecBackendDocker {
		return exec.DockerBackend{
			Container: config.ToolboxContainer,
			WorkDir:   config.ToolboxWorkDir,
		}
	}
	return exec.LocalBackend{}
}
