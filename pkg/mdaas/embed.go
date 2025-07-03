package mdaas

import (
	"embed"
	"log"
	"os"
	"path"
	"path/filepath"
)

//go:embed simple-ssh
//go:embed bind-shell
var MDaaSFS embed.FS

func init() {
	SetupDirs("mdaas")
}

func GetInternalPrograms() ([]string, error) {
	programs := []string{}
	dirs, err := MDaaSFS.ReadDir(".")
	if err != nil {
		return programs, err
	}

	for _, dir := range dirs {
		programs = append(programs, dir.Name())
	}

	return programs, nil
}

func SetupDirs(dest string) error {
	return CopyDirFromFS(".", dest, MDaaSFS)
}

func CopyDirFromFS(src, dest string, embeddedFS embed.FS) error {
	fsDirs, err := embeddedFS.ReadDir(src)
	if err != nil {
		return err
	}

	for _, dirEntry := range fsDirs {
		localDest := filepath.Join(dest, dirEntry.Name())
		fsSrc := path.Join(src, dirEntry.Name())
		if dirEntry.IsDir() {
			err := os.MkdirAll(localDest, 0755)
			if err != nil {
				log.Printf("error creating directory %s: %s", localDest, err)
			}
			if err := CopyDirFromFS(fsSrc, localDest, embeddedFS); err != nil {
				log.Printf("error copying directory %s: %s", localDest, err)
			}
		} else {
			if err := copyFileFromEmbeddedFS(fsSrc, localDest, embeddedFS); err != nil {
				log.Printf("error copying file %s: %s", localDest, err)
			}
		}
	}

	return nil
}

func copyFileFromEmbeddedFS(src, dest string, embeddedFS embed.FS) error {
	fileBytes, err := embeddedFS.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dest, fileBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

//func copyTemplateFromEmbeddedFS(src, dest string, embeddedFS embed.FS, data any) error {
//	fileBytes, err := embeddedFS.ReadFile(src)
//	if err != nil {
//		return err
//	}
//
//	tmpl, err := template.New(src).Parse(string(fileBytes))
//	if err != nil {
//		return err
//	}
//
//	var templateBytes bytes.Buffer
//	err = tmpl.Execute(&templateBytes, data)
//	if err != nil {
//		return err
//	}
//
//	err = os.WriteFile(dest, templateBytes.Bytes(), 0644)
//	if err != nil {
//		return err
//	}
//	return nil
//}
