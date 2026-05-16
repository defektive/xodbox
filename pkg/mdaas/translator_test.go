package mdaas

import (
	"path/filepath"
	"testing"
)

func TestTargetOSFromExternal(t *testing.T) {
	tests := []struct {
		input   string
		want    TargetOS
		wantErr bool
	}{
		{"linux", TargetOSLinux, false},
		{"LINUX", TargetOSLinux, false}, // case-insensitive
		{"darwin", TargetOSDarwin, false},
		{"windows", TargetOSWindows, false},
		{"plan9", TargetOSPlan9, false},
		{"made-up", TargetOSUnknown, true},
		{"", TargetOSUnknown, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := TargetOSFromExternal(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTargetArchFromExternal(t *testing.T) {
	tests := []struct {
		input   string
		want    TargetArch
		wantErr bool
	}{
		{"amd64", TargetArchAmd64, false},
		{"x86_64", TargetArchAmd64, false},     // mapped to amd64
		{"X86_64", TargetArchAmd64, false},     // case-insensitive
		{"arm", TargetArchArm, false},          // bare arm
		{"armv7l", TargetArchArm, false},       // any "arm*" collapses to arm
		{"aarch64", TargetArchArm64, false},    // mapped to arm64
		{"aarch64-be", TargetArchArm64, false}, // prefix match
		{"riscv64", TargetArchRiscv64, false},
		{"wat", TargetArchUnknown, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := TargetArchFromExternal(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTargetArmFromExternal(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"armv5tej", "5", false},
		{"ARMV5", "5", false},
		{"armv7l", "7", false},
		{"armv7", "7", false},
		{"armv6", "", true},
		{"x86", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := TargetArmFromExternal(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProgramFromExternal(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"simple-ssh", filepath.Join("mdaas", "simple-ssh", "simple-ssh.go"), false},
		{"SIMPLE-SSH", filepath.Join("mdaas", "simple-ssh", "simple-ssh.go"), false},
		{"bind-shell", filepath.Join("mdaas", "bind-shell", "bind-shell.go"), false},
		{"unknown", "", true},
		{"", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ProgramFromExternal(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
