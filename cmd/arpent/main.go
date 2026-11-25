// Commande arpent : point d'entrée (CLI, puis lancement de l'interface web).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/maxb1906/arpent/internal/i18n"
)

// version est injectée à la compilation : -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	bundle, err := i18n.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	fs := flag.NewFlagSet("arpent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lang := fs.String("lang", "", "fr|en")
	parseErr := fs.Parse(args)

	if *lang == "" {
		*lang = bundle.Detect()
	} else if !bundle.Has(*lang) {
		tr := bundle.Translator(bundle.Detect())
		fmt.Fprintln(stderr, tr.T("cli.unknown_lang", "lang", *lang, "available", strings.Join(bundle.Languages(), ", ")))
		return 2
	}
	tr := bundle.Translator(*lang)

	usage := func(w io.Writer) {
		fmt.Fprintln(w, tr.T("cli.usage"))
		fmt.Fprintln(w, tr.T("cli.commands"))
	}
	if parseErr == flag.ErrHelp {
		usage(stdout)
		return 0
	}
	if parseErr != nil {
		fmt.Fprintln(stderr, parseErr)
		usage(stderr)
		return 2
	}

	cmd := "hello"
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}
	switch cmd {
	case "hello":
		fmt.Fprintln(stdout, tr.T("hello.greeting", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH))
		fmt.Fprintln(stdout, tr.T("app.tagline"))
		fmt.Fprintln(stdout, tr.T("hello.legal"))
	case "version":
		fmt.Fprintln(stdout, version)
	case "help":
		usage(stdout)
	default:
		fmt.Fprintln(stderr, tr.T("cli.unknown_command", "command", cmd))
		usage(stderr)
		return 2
	}
	return 0
}
