package httpx

import (
	"fmt"
	"github.com/defektive/xodbox/pkg/mdaas"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func Build(w http.ResponseWriter, e *Event, handler *Handler) error {
	r := e.Request()
	targetOS, err := getOSFromRequest(r)
	if err != nil {
		lg().Error("error getting os", "err", err)
		return nil
	}

	targetArch, err := getArchFromQuery(r)
	if err != nil {
		lg().Error("error getting arch", "err", err)
		fmt.Fprint(w, "error")
		return nil
	}

	arm := ""
	if targetArch == mdaas.TargetArchArm {
		arm, err = getArmFromQuery(r)
		if err != nil {
			lg().Error("error getting arm", "err", err)
		}
	}

	program, err := getProgramFromQuery(r)
	if err != nil {
		lg().Error("error getting program", "err", err)
		fmt.Fprint(w, "error")
		return err
	}

	ldFlags := []string{}

	if handler.MDaaSLogLevel != "" {
		ldFlags = append(ldFlags, fmt.Sprintf("-X main.logLevel=%s", handler.MDaaSLogLevel))
	}
	if handler.MDaaSBindListener != "" {
		ldFlags = append(ldFlags, fmt.Sprintf("-X main.listener=%s", handler.MDaaSBindListener))
	}
	if handler.MDaaSAllowedCIDR != "" {
		ldFlags = append(ldFlags, fmt.Sprintf("-X main.allowedCIDR=%s", handler.MDaaSAllowedCIDR))
	}

	outFile, err := mdaas.Build(targetOS, targetArch, arm, program, filepath.Join(handler.StaticDir, "dist"), ldFlags)

	if err != nil {
		lg().Error("error building", "err", err)
		fmt.Fprint(w, "error")
		return err
	}

	basename := filepath.Base(outFile)
	lg().Debug("mdaas responding with file", "outFile", outFile, "basename", basename)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+basename+`"`)
	return sendFile(outFile, w)
}

func sendFile(outFile string, w http.ResponseWriter) error {
	f, err := os.Open(outFile)
	if err != nil {
		log.Println(err)
		return nil
	}
	_, err = io.Copy(w, f)
	return err
}

func getOSFromRequest(v *http.Request) (mdaas.TargetOS, error) {
	requestedVal := ""
	p := strings.Split(v.URL.Path, "/")
	lp := len(p)
	if lp > 3 {
		requestedVal = p[lp-3]
	} else {
		requestedVal = v.URL.Query().Get("o")
	}
	return mdaas.TargetOSFromExternal(requestedVal)
}

func getArchFromQuery(v *http.Request) (mdaas.TargetArch, error) {
	requestedVal := ""
	p := strings.Split(v.URL.Path, "/")
	lp := len(p)
	if lp > 3 {
		requestedVal = p[lp-2]
	} else {
		requestedVal = v.URL.Query().Get("a")
	}
	return mdaas.TargetArchFromExternal(requestedVal)
}

func getArmFromQuery(v *http.Request) (string, error) {
	requestedVal := ""
	p := strings.Split(v.URL.Path, "/")
	lp := len(p)
	if lp > 3 {
		requestedVal = p[lp-2]
	} else {
		requestedVal = v.URL.Query().Get("a")
	}
	return mdaas.TargetArmFromExternal(requestedVal)
}

func getProgramFromQuery(v *http.Request) (string, error) {
	requestedVal := ""
	p := strings.Split(v.URL.Path, "/")
	lp := len(p)
	if lp > 3 {
		requestedVal = p[lp-1]
	} else {
		requestedVal = v.URL.Query().Get("p")
	}
	return mdaas.ProgramFromExternal(requestedVal)
}
