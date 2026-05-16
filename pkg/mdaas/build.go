package mdaas

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	builder "github.com/NoF0rte/cmd-builder"
)

func Build(targetOS TargetOS, targetArch TargetArch, arm, program, outDir string, ldFlags []string) (string, error) {
	execName := filepath.Base(program)
	execName = strings.TrimSuffix(execName, filepath.Ext(execName))
	if targetOS == "windows" {
		execName += ".exe"
	}

	if targetArch == "arm" {
		execName += arm
	}

	outputDir := filepath.Join(outDir, string(targetOS), string(targetArch))
	outFile := filepath.Join(outputDir, execName)

	lg().Debug("building", "targetOS", targetOS, "targetArch", targetArch, "outFile", outFile, "ldFlags", ldFlags)

	if _, err := os.Stat(outFile); err == nil {
		return outFile, nil
	}

	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return "", fmt.Errorf("mkdir build output: %w", err)
	}

	bf := builder.NewFactory(builder.CmdFactoryOptions{Env: []string{
		fmt.Sprintf("GOOS=%s", targetOS),
		fmt.Sprintf("GOARCH=%s", targetArch),
		fmt.Sprintf("GOARM=%s", arm),
	}})

	bc := bf.Cmd("go", "build", "-trimpath", "-o", outFile, fmt.Sprintf("-ldflags=-s -w %s", strings.Join(ldFlags, " ")), program)

	out, err := bc.Output()
	if err != nil {
		return "", err
	}

	log.Println(out)

	return outFile, nil
}

//
