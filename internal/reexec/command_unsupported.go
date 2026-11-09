// This file originates from Docker/Moby,
// https://github.com/moby/moby/blob/8e610b2b55bf/pkg/reexec/command_unsupported.go
// Licensed under Apache License 2.0: https://github.com/moby/moby/blob/master/LICENSE
// Copyright 2013-2018 Docker, Inc.

//go:build !linux && !windows && !freebsd && !darwin
// +build !linux,!windows,!freebsd,!darwin

package reexec

import (
	"os/exec"
)

func Self() string {
	return ""
}

// Command is unsupported on operating systems apart from Linux, Windows, and Darwin.
func Command(args ...string) *exec.Cmd {
	return nil
}
