# Code signing policy / Politique de signature de code

**English** · [Français](#français)

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

> Status: **application pending.** Until the first signed release, Arpent binaries are unsigned; verify them with the `SHA256SUMS` file attached to each release.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [maxb1906](https://github.com/maxb1906) |
| Approvers (signing requests) | [maxb1906](https://github.com/maxb1906) |

## What is signed

Only `arpent.exe` (windows/amd64), built **entirely by GitHub Actions** from this public repository (workflow `.github/workflows/release.yml`, then `.github/workflows/sign.yml`) for a release tag `vX.Y.Z`. No binary built elsewhere is ever submitted for signing. Every signing request is approved manually by an approver.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

Arpent is a network audit tool: it sends probes **only to the network ranges the user chooses to audit**, after the user confirms being authorised to do so. Its web interface listens on `127.0.0.1` only. It has no telemetry, no update check and no cloud service; audit data stays in the `arpent-data/` folder next to the executable. The optional one-click PDF feature runs the browser already installed on the computer, locally, on a local file.

---

## Français

Signature de code gratuite fournie par [SignPath.io](https://about.signpath.io), certificat émis par [SignPath Foundation](https://signpath.org).

> Statut : **candidature à déposer.** Jusqu'à la première version signée, les binaires ne sont pas signés ; vérifiez-les avec le fichier `SHA256SUMS` joint à chaque release.

- **Rôles** : auteur, relecteur et approbateur des demandes de signature : [maxb1906](https://github.com/maxb1906).
- **Ce qui est signé** : uniquement `arpent.exe` (windows/amd64), construit entièrement par GitHub Actions depuis ce dépôt public pour un tag `vX.Y.Z` ; chaque demande de signature est approuvée manuellement.
- **Confidentialité** : ce programme ne transmet aucune information à d'autres systèmes en réseau, sauf demande expresse de l'utilisateur. Il ne sonde que les plages que l'utilisateur choisit d'auditer, après confirmation d'autorisation ; l'interface n'écoute que sur `127.0.0.1` ; aucune télémétrie, aucune vérification de mise à jour, aucun service en ligne ; les données restent dans `arpent-data/` à côté de l'exécutable.
