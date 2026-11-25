# Arpent

**Français** · [English](README.en.md)

[![CI](https://github.com/maxb1906/arpent/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/arpent/actions/workflows/ci.yml)
[![Licence : GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

Outil **portable** d'audit et de documentation réseau. Un seul exécutable, **sans installation ni droits administrateur** : lancez-le depuis une clé USB sur un PC branché au réseau, il découvre les appareils, identifie les ports et services ouverts, relève les points d'attention et produit un **rapport d'audit** à remettre au client. Relancé quelques mois plus tard, il met en évidence **ce qui a changé**.

Pensé pour les techniciens, indépendants et MSP qui interviennent dans des PME.

## ⚠️ Cadre légal

Scanner un réseau sans autorisation est **illégal**, en Belgique comme ailleurs. N'utilisez Arpent que sur des réseaux qui vous appartiennent ou pour lesquels vous disposez d'une autorisation explicite du propriétaire. Le premier audit de chaque site exige une confirmation, horodatée et reprise dans le rapport.

## Fonctionnalités

- **Découverte** des appareils : ping (si permis), sondes TCP, requêtes ARP actives sous Windows (`SendARP`, sans Npcap), table ARP du système ; fabricant d'après la base OUI de l'IEEE embarquée ; noms par DNS inverse, NetBIOS, mDNS/Bonjour et UPnP.
- **Scan des ports** TCP à débit limité (profils rapide ≈ 100 ports, standard ≈ 1400, complet 65535) et UDP ciblé (DNS, NetBIOS, SNMP, SSDP, mDNS).
- **Identification des services** : bannières (SSH, FTP, SMTP, POP3, IMAP, Telnet, MySQL, VNC), HTTP (titre, serveur, redirection, favicon), TLS (certificat, expiration, auto-signé, version), SMB (SMBv1, signature), SNMP.
- **Type d'appareil** deviné par signatures (imprimante, NAS, caméra, routeur, hyperviseur, téléphone…).
- **Points d'attention** classés Info / Attention / Critique, expliqués simplement pour le client : Telnet, SMBv1, RDP, admin HTTP sans TLS, certificats expirés, SNMP `public`, bases de données exposées, logiciels anciens…
- **Historique par site** et **détection des changements** : nouvel appareil inconnu, appareil disparu, port ouvert ou fermé, version ou certificat modifié, changement d'IP ; liste d'appareils « connus / validés » et annotations.
- **Rapport** HTML autonome (un seul fichier, lisible hors ligne, imprimable en PDF), exports CSV et JSON, en **français ou en anglais** indépendamment de la langue de l'interface ; émetteur et logo personnalisables.
- Interface web **locale** (127.0.0.1 uniquement) : rien n'est exposé sur le réseau audité, rien n'est envoyé sur Internet.

## Démarrage

1. Téléchargez `arpent_<version>_windows_amd64.zip` depuis les [Releases](https://github.com/maxb1906/arpent/releases) et décompressez-le sur une clé USB.
2. **Double-cliquez sur `arpent.exe`** : une fenêtre console s'ouvre et votre navigateur affiche l'interface.
3. Créez un site (le client), lancez un audit, consultez l'inventaire, puis générez le rapport.
4. Fermez la fenêtre console (ou « Quitter » dans l'interface) pour arrêter.

Toutes les données sont dans le dossier `arpent-data/`, **à côté de l'exécutable** : préférences (`config.yaml`) et un dossier par site (`sites/<site>/site.db` et `rapports/`). Rien n'est écrit dans le registre ni dans `%APPDATA%`.

> **Windows bloque l'exe** : l'exécutable n'est pas encore signé. Selon le PC :
> - **SmartScreen** (« Windows a protégé votre ordinateur ») : cliquez sur « Informations complémentaires » puis « Exécuter quand même ».
> - **Contrôle intelligent des applications** (Windows 11) : l'exe est bloqué **sans bouton pour passer outre** ni exception par application. La seule solution est de le désactiver (Sécurité Windows → *Contrôle des applications et du navigateur* → *Paramètres du Contrôle intelligent des applications* → *Désactivé*) ; depuis la mise à jour d'avril 2026 de Windows 11, on peut le réactiver ensuite sans réinstaller Windows. Sinon, utilisez un autre poste ou une VM.
> - Un outil qui scanne le réseau peut aussi être signalé par certains **antivirus**.
>
> Vérifiez l'empreinte avec le fichier `SHA256SUMS` de la release. La signature de code via SignPath Foundation, qui lèvera ces blocages, est en préparation : voir [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## Ligne de commande

```
arpent                      # interface web (par défaut)
arpent scan --site "Pharmacie X" --range 192.168.1.0/24 --profile standard
arpent report --site "Pharmacie X" --format html --report-lang en
arpent sites | audits --site … | show --site … | annotate --site … --ip … --label … --known
arpent discover | ports | interfaces | arp --active
arpent config --technician "Nom" --company "Ma société" --logo logo.png
arpent help                 # toutes les commandes ; arpent <commande> -h pour les options
```

Options globales : `--lang fr|en` et `--data <dossier>` (ou variable `ARPENT_DATA`).

## Ce qu'Arpent fait et ne fait pas

Arpent observe le réseau **depuis un poste, sans identifiants** : il ne tente aucune connexion authentifiée ni exploitation, et ne remplace pas un test d'intrusion. Sans droits administrateur, la découverte repose sur des connexions TCP « complètes » et sur les API du système ; l'adresse MAC n'est connue que pour le sous-réseau local.

## Compilation

Prérequis : [Go](https://go.dev/dl/) (version de `go.mod`). Aucun CGO : la cross-compilation vers Windows fonctionne depuis Linux ou macOS.

```sh
make test        # tests unitaires (avec détecteur de courses)
make windows     # dist/arpent-windows-amd64.exe
make build-all   # windows/amd64, linux/amd64, linux/arm64, darwin/arm64
```

Les versions sont publiées par GitHub Actions + GoReleaser à chaque tag `vX.Y.Z`.

## Contribuer

- Traductions : `assets/i18n/fr.json` et `en.json` (mêmes clés, vérifié par les tests).
- Règles d'audit : `assets/rules.yaml` ; signatures d'appareils : `assets/signatures.yaml` — modifiables sans toucher au moteur.
- Cadrage et décisions : [docs/STRUCTURE.md](docs/STRUCTURE.md).

## Licence

[GPL-3.0](LICENSE). La base OUI provient du registre public de l'IEEE.
