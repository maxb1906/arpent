// Package config gère le dossier de données portable (arpent-data/) et les
// préférences (config.yaml).
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// DirName est le nom du dossier de données placé à côté de l'exécutable.
const DirName = "arpent-data"

// DataDir choisit le dossier de données : flag, sinon variable ARPENT_DATA,
// sinon arpent-data/ à côté de l'exécutable (dans le dossier courant pour
// « go run » ou « go test »). Le dossier est créé et doit être inscriptible.
func DataDir(flag string) (string, error) {
	dir := flag
	if dir == "" {
		dir = os.Getenv("ARPENT_DATA")
	}
	if dir == "" {
		exe, err := os.Executable()
		if err == nil {
			exe, _ = filepath.EvalSymlinks(exe)
		}
		base := filepath.Dir(exe)
		if err != nil || isTempBuild(exe) {
			base, _ = os.Getwd()
		}
		dir = filepath.Join(base, DirName)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return "", errors.New("dossier de données non inscriptible : " + dir)
	}
	f.Close()
	os.Remove(f.Name())
	return dir, nil
}

func isTempBuild(exe string) bool {
	s := filepath.ToSlash(exe)
	return strings.Contains(s, "/go-build") || strings.HasSuffix(s, ".test") || strings.HasSuffix(s, ".test.exe")
}
