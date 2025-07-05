package mdaas

import (
	"fmt"
	"path/filepath"
	"strings"
)

// TargetOSFromExternal translate external string (probably from uname) to targetOS
func TargetOSFromExternal(external string) (TargetOS, error) {
	external = strings.ToLower(external)

	if targetOS, ok := TargetOSMap[external]; ok {
		return targetOS, nil
	}

	return TargetOSUnknown, fmt.Errorf("unknown os: %s", external)
}

// TargetArmFromExternal translate external string (probably from uname) to targetArch
func TargetArmFromExternal(external string) (string, error) {
	external = strings.ToLower(external)

	if strings.HasPrefix(external, "armv5") {
		return "5", nil
	}

	if strings.HasPrefix(external, "armv7") {
		return "7", nil
	}

	return "", fmt.Errorf("unknown arm: %s", external)
}

// TargetArchFromExternal translate external string (probably from uname) to targetArm
func TargetArchFromExternal(external string) (TargetArch, error) {
	external = strings.ToLower(external)

	if strings.HasPrefix(external, "arm") {
		external = "arm"
	}

	if external == "x86_64" {
		external = "amd64"
	}

	if targetArch, ok := TargetArchMap[external]; ok {
		return targetArch, nil
	}

	return TargetArchUnknown, fmt.Errorf("unknown os: %s", external)
}

// ProgramFromExternal translate external string (probably from uname) to program
func ProgramFromExternal(external string) (string, error) {
	external = strings.ToLower(external)

	if external == "simple-ssh" {
		return filepath.Join("mdaas", "simple-ssh", "simple-ssh.go"), nil
	}
	if external == "bind-shell" {
		return filepath.Join("mdaas", "bind-shell", "bind-shell.go"), nil
	}
	return "", fmt.Errorf("unknown program: %s", external)
}
