package xlog

import (
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"strings"
)

var logLevel = new(slog.LevelVar)
var logger *slog.Logger

var appPkg string
var appName string

func init() {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
}

func SetAppName(name string) {
	appName = name
}

func Logger() *slog.Logger {
	return logger
}

func WithGroup(groupName string) *slog.Logger {
	return logger.With(slog.Group(getAppName(), slog.String("pkg", groupName)))
}
func WithGroupFromFn(fnRef interface{}) *slog.Logger {
	return WithGroup(relPkg(fnRef))
}

func LogLevel(level slog.Level) {
	logLevel.Set(level)
}

func getAppName() string {
	if appName == "" {
		split := strings.Split(getAppPkg(), "/")
		appName = split[len(split)-1]
	}
	return appName
}

func getAppPkg() string {
	if appPkg == "" {
		pkgPath := fullPkg(getAppPkg)
		split := strings.Split(pkgPath, "/")
		appPkg = strings.Join(split[0:3], "/")
	}
	return appPkg
}

func Get() *slog.Logger {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		panic("could not get caller info")
	}

	callerPkg := pkgFromFnPointer(pc)
	return WithGroup(callerPkg)
}

func fullPkg(l interface{}) string {
	return pkgFromFnPointer(reflect.ValueOf(l).Pointer())
}

func pkgFromFnPointer(p uintptr) string {
	strs := strings.Split((runtime.FuncForPC(p).Name()), "/")
	strs[len(strs)-1] = strings.Split(strs[len(strs)-1], ".")[0]
	return strings.Join(strs, "/")
}

func relPkg(l interface{}) string {
	return strings.Replace(fullPkg(l), getAppPkg()+"/", "", -1)
}
