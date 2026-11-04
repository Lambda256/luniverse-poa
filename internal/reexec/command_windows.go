// This file originates from Docker/Moby,
// https://github.com/moby/moby/blob/8e610b2b55bf/pkg/reexec/command_windows.go
// Licensed under Apache License 2.0: https://github.com/moby/moby/blob/master/LICENSE
// Copyright 2013-2018 Docker, Inc.

package reexec

import (
	"os/exec"
)

// Self returns the path to the current process's binary.
// Uses os.Args[0].
func Self() string {
	return naiveSelf()
}

// Command returns *exec.Cmd which has Path as current binary.
// For example if current binary is "docker.exe" at "C:\", then cmd.Path will
// be set to "C:\docker.exe".
func Command(args ...string) *exec.Cmd {
	return &exec.Cmd{
		Path: Self(),
		Args: args,
	}
}
