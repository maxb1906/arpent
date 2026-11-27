//go:build !windows || !production

package desktop

// Supported : la fenêtre native est compilée dans cet exécutable (Windows,
// build avec les tags « desktop,production » exigés par Wails).
const Supported = false

// Available indique si la fenêtre native peut être ouverte ; sinon la raison.
func Available() (bool, string) { return false, "windows only" }

// Run n'est disponible que sous Windows.
func Run(Options) error { return ErrUnavailable }
