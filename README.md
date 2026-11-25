# Arpent

**Français** · [English](README.en.md)

[![CI](https://github.com/maxb1906/arpent/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/arpent/actions/workflows/ci.yml)
[![Licence : GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

Outil **portable** d'audit et de documentation réseau. Un seul exécutable, sans installation ni droits administrateur : on le lance depuis une clé USB sur un PC branché au réseau, il découvre les appareils, identifie les ports et services ouverts, puis produit un inventaire visuel et un rapport d'audit à remettre au client. Relancé quelques mois plus tard, il met en évidence ce qui a changé.

> **Statut : en développement (étape 0 — socle).** Rien n'est encore utilisable pour auditer un réseau. Le cadrage complet est dans [docs/STRUCTURE.md](docs/STRUCTURE.md).

## ⚠️ Cadre légal

Scanner un réseau sans autorisation est **illégal**, en Belgique comme ailleurs. N'utilisez Arpent que sur des réseaux qui vous appartiennent ou pour lesquels vous disposez d'une autorisation explicite du propriétaire.

## Fonctionnalités prévues

- Découverte des appareils du sous-réseau (table ARP de l'OS, `SendARP` sous Windows, DNS inverse, NetBIOS, mDNS, SSDP) et fabricant via la base OUI.
- Scan TCP « connect » à débit limité, profils rapide / standard / complet.
- Identification des services et bannières (HTTP, TLS, SSH, SMB, SNMP…).
- Points d'attention (Telnet, SMBv1, certificats expirés, bases de données exposées…).
- Historique par site et détection des changements entre deux audits.
- Rapport HTML autonome, PDF, exports CSV/JSON — en français ou en anglais.

## Utilisation

**Double-cliquez sur `arpent.exe`** : Arpent démarre une interface locale sur `127.0.0.1` et ouvre votre navigateur. Créez un site (le client), lancez un audit, consultez l'inventaire. Les données sont rangées dans `arpent-data/`, à côté de l'exécutable : tout reste sur la clé USB. Fermez la fenêtre noire pour quitter.

En ligne de commande :

```
arpent scan --site "Pharmacie X" --range 192.168.1.0/24 --profile standard --technician "Nom"
arpent sites | arpent audits --site "Pharmacie X" | arpent show --site "Pharmacie X"
arpent discover | arpent ports | arpent interfaces | arpent arp --active
arpent help
```

Options globales : `--lang fr|en` (sinon langue du système) et `--data <dossier>` (sinon `arpent-data/` à côté de l'exe ou variable `ARPENT_DATA`).

## Compilation

Prérequis : [Go](https://go.dev/dl/) (version indiquée dans `go.mod`). Aucun CGO.

```sh
make test        # tests unitaires
make build       # binaire pour la machine courante → dist/arpent
make windows     # dist/arpent-windows-amd64.exe
make build-all   # windows/amd64, linux/amd64, linux/arm64, darwin/arm64
```

## Traductions

Tous les textes passent par `assets/i18n/fr.json` et `assets/i18n/en.json`, embarqués dans l'exécutable. Pour ajouter un texte : ajoutez la même clé dans les deux fichiers (un test vérifie qu'ils restent synchronisés), puis appelez `tr.T("ma.cle", "variable", valeur)` dans le code.

## Licence

[GPL-3.0](LICENSE).
