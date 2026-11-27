// Commande arpent : point d'entrée (CLI, puis lancement de l'interface web).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/maxb1906/arpent/internal/config"
	"github.com/maxb1906/arpent/internal/i18n"
)

// stdin est remplaçable dans les tests.
var stdin io.Reader = os.Stdin

// version est injectée à la compilation : -ldflags "-X main.version=v0.1.0".
var version = "dev"

// env regroupe ce dont une commande a besoin.
type env struct {
	ctx    context.Context
	bundle *i18n.Bundle
	tr     *i18n.Translator
	data   string // --data
	cfg    *config.Config
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (e *env) T(key string, pairs ...string) string { return e.tr.T(key, pairs...) }

// fail affiche une erreur traduite et renvoie le code de sortie 1.
func (e *env) fail(err error) int {
	fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
	return 1
}

// newFlags crée le jeu d'options d'une commande ; l'aide est rendue par usage.
func (e *env) newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse analyse les options ; renvoie (code, false) si la commande doit s'arrêter.
func (e *env) parse(fs *flag.FlagSet, args []string) (int, bool) {
	err := fs.Parse(args)
	if err == nil {
		return 0, true
	}
	if err == flag.ErrHelp {
		e.commandHelp(fs, e.stdout)
		return 0, false
	}
	fmt.Fprintln(e.stderr, e.T("cli.error", "error", err.Error()))
	e.commandHelp(fs, e.stderr)
	return 2, false
}

func (e *env) commandHelp(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprintln(w, e.T("cli.cmd_usage", "command", fs.Name()))
	fs.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(w, "  --%-12s %s\n", f.Name, e.T("flag."+fs.Name()+"."+f.Name))
	})
}

type command struct {
	run func(e *env, args []string) int
}

var commands = map[string]command{}

// order fixe l'ordre d'affichage des commandes dans l'aide.
var order = []string{"ui", "scan", "sites", "audits", "show", "compare", "report", "annotate", "search", "export", "import", "config", "templates", "discover", "ports", "interfaces", "arp", "advanced", "hello", "version", "help"}

func init() {
	commands["hello"] = command{run: cmdHello}
	commands["ui"] = command{run: cmdUI}
	commands["version"] = command{run: func(e *env, _ []string) int { fmt.Fprintln(e.stdout, version); return 0 }}
	commands["help"] = command{run: func(e *env, _ []string) int { usage(e, e.stdout); return 0 }}
	commands["interfaces"] = command{run: cmdInterfaces}
	commands["arp"] = command{run: cmdARP}
	commands["discover"] = command{run: cmdDiscover}
	commands["ports"] = command{run: cmdPorts}
	commands["scan"] = command{run: cmdScan}
	commands["sites"] = command{run: cmdSites}
	commands["audits"] = command{run: cmdAudits}
	commands["show"] = command{run: cmdShow}
	commands["annotate"] = command{run: cmdAnnotate}
	commands["report"] = command{run: cmdReport}
	commands["compare"] = command{run: cmdCompare}
	commands["config"] = command{run: cmdConfig}
	commands["templates"] = command{run: cmdTemplates}
	commands["export"] = command{run: cmdExport}
	commands["import"] = command{run: cmdImport}
	commands["search"] = command{run: cmdSearch}
	commands["advanced"] = command{run: cmdAdvanced}
}

func usage(e *env, w io.Writer) {
	fmt.Fprintln(w, e.T("cli.usage"))
	fmt.Fprintln(w, e.T("cli.commands"))
	for _, c := range order {
		fmt.Fprintf(w, "  %-12s %s\n", c, e.T("cmd."+c))
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := func() (code int) {
		// Lancé par double-clic, la fenêtre se ferme à la sortie : on garde
		// l'erreur (ou le plantage) visible jusqu'à ce que l'utilisateur valide.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
				code = 3
			}
			if code != 0 && launchedAlone() {
				showConsole(true) // masquée pendant la fenêtre Arpent
				pause(os.Args[1:])
			}
		}()
		return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	}()
	stop()
	os.Exit(code)
}

// pause affiche « Appuyez sur Entrée » et attend.
func pause(args []string) {
	msg := "Appuyez sur Entrée pour fermer cette fenêtre. / Press Enter to close this window."
	if b, err := i18n.Default(); err == nil {
		lang := b.Detect()
		for i, a := range args {
			if a == "--lang" && i+1 < len(args) && b.Has(args[i+1]) {
				lang = args[i+1]
			}
		}
		msg = b.Translator(lang).T("cli.press_enter")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, msg)
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	bundle, err := i18n.Default()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	e := &env{ctx: ctx, bundle: bundle, stdin: stdin, stdout: stdout, stderr: stderr}

	fs := flag.NewFlagSet("arpent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	lang := fs.String("lang", "", "fr|en")
	data := fs.String("data", "", "")
	parseErr := fs.Parse(args)

	e.data = *data
	if *lang == "" && os.Getenv("ARPENT_LANG") == "" {
		// Langue enregistrée dans config.yaml, sinon celle du système.
		e.tr = bundle.Translator(bundle.Detect())
		if l := e.config().Lang; bundle.Has(l) {
			*lang = l
		}
	}
	if *lang == "" {
		*lang = bundle.Detect()
	} else if !bundle.Has(*lang) {
		e.tr = bundle.Translator(bundle.Detect())
		fmt.Fprintln(stderr, e.T("cli.unknown_lang", "lang", *lang, "available", strings.Join(bundle.Languages(), ", ")))
		return 2
	}
	e.tr = bundle.Translator(*lang)

	if parseErr == flag.ErrHelp {
		usage(e, stdout)
		return 0
	}
	if parseErr != nil {
		fmt.Fprintln(stderr, e.T("cli.error", "error", parseErr.Error()))
		usage(e, stderr)
		return 2
	}

	// Sans commande (double-clic sur l'exe) : interface (fenêtre ou navigateur).
	name, rest := "ui", []string(nil)
	if fs.NArg() > 0 {
		name, rest = fs.Arg(0), fs.Args()[1:]
	}
	c, ok := commands[name]
	if !ok {
		fmt.Fprintln(stderr, e.T("cli.unknown_command", "command", name))
		usage(e, stderr)
		return 2
	}
	return c.run(e, rest)
}
