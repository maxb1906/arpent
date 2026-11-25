# CLAUDE.md — Arpent

**Le document de référence du projet est [docs/STRUCTURE.md](docs/STRUCTURE.md).** Lis-le avant toute tâche : il fixe le périmètre, les choix techniques, l'architecture (§ 7) et l'ordre des étapes (§ 10). En cas de doute, c'est lui qui tranche ; si un choix doit s'en écarter, demande d'abord.

## Suivi obligatoire dans docs/STRUCTURE.md

À la fin de chaque étape :

1. **Coche l'étape terminée** dans le § 10 (`- [ ]` → `- [x]`), et coche aussi les questions ouvertes du § 12 qui ont été résolues.
2. **Complète le « Journal des décisions »** en fin de fichier : une ligne datée (`- **AAAA-MM-JJ** — …`) par décision prise ou écart par rapport au cadrage (versions retenues, bibliothèques ajoutées, limites découvertes…).
3. Mets à jour le statut en tête du fichier si besoin.

Ne réalise qu'une étape à la fois et arrête-toi à la fin de l'étape demandée ; chaque étape doit se terminer par un binaire Windows testable (`make windows`).

## Conventions

- Go installé dans `/usr/local/go` (binaire officiel go.dev, pas apt) ; `export PATH=$PATH:/usr/local/go/bin` si `go` n'est pas trouvé.
- Module : `github.com/maxb1906/arpent`. Pas de CGO (`CGO_ENABLED=0`), dépendances pures Go uniquement.
- Code propre à un OS dans des fichiers `_windows.go` / `_linux.go` / `_darwin.go` (ou contraintes `//go:build`).
- **Aucune chaîne utilisateur en dur** : toute chaîne passe par `internal/i18n` et des clés présentes dans `assets/i18n/fr.json` **et** `en.json` (le test `TestEmbeddedCatalogsAreComplete` échoue sinon).
- Avant de pousser : `make fmt-check vet test build-all`.
- Ne jamais scanner le réseau de la devbox Oracle : tests réseau uniquement contre `127.0.0.1` ici, tests réels sur le LAN du homelab depuis le PC Windows.
