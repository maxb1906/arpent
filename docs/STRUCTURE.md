# Arpent — Outil d'audit et de documentation réseau automatisé — Structure projet

> Fichier de cadrage et de suivi d'implémentation. Il consigne tous les choix du projet et sert de référence à Claude Code pendant le développement sur la devbox Oracle.
> Statut : **étapes 0 à 10 et 12 à 15 terminées ; étape 11 prête** sauf le test sur le LAN du homelab et la publication de la v1.0 (voir `docs/TEST-HOMELAB.md`).
> Nom : **Arpent** — licence **GPL-3.0** — dépôt GitHub public.

---

## 1. Concept

Un **exécutable portable unique**, sans installation, qu'on lance sur n'importe quel PC branché sur un réseau pour en faire l'audit :

1. il découvre les appareils du sous-réseau ;
2. il identifie les ports ouverts, les services actifs et leurs bannières (HTTP, SSH, TLS…) ;
3. il génère un **inventaire visuel propre** et un **rapport d'audit exportable** ;
4. il **détecte les changements** depuis l'audit précédent du même site (nouvel appareil inconnu, port ouvert récemment, version qui change…).

Cas d'usage visé : un technicien, un indépendant ou un MSP arrive chez une PME, lance l'exe depuis une clé USB, et repart avec un rapport à remettre au client. Il revient trois mois plus tard, relance l'audit, et obtient l'évolution.

**Hors périmètre** : agent permanent, LXC, service qui tourne 24/7, supervision continue. C'est un outil d'audit **ponctuel**.

---

## 2. Contraintes structurantes

| Contrainte | Conséquence |
|---|---|
| Un seul fichier, portable, rien à installer | Pas de Python/PyInstaller, pas de dépendance à nmap, pas de driver Npcap |
| Fonctionne **sans droits administrateur** | Scan TCP « connect » (pas de SYN scan brut), découverte via table ARP de l'OS plutôt que ARP brut |
| Cible principale : **Windows x64** (le PC du technicien) | Build `windows/amd64` prioritaire ; Linux et macOS en bonus |
| Développement sur la **devbox Oracle (Ubuntu 24.04, ARM64)** | Le langage doit cross-compiler vers Windows x64 depuis Linux ARM64 sans effort |
| Les données de l'audit doivent pouvoir voyager | Tout est stocké dans un dossier à côté de l'exe (clé USB) |
| Budget 0 € | Uniquement des briques libres, pas de service payant |

---

## 3. Choix techniques

### Langage : Go
- Binaire unique statique, aucune dépendance runtime.
- Cross-compilation native : `GOOS=windows GOARCH=amd64 go build` depuis la devbox ARM64.
- Concurrence (goroutines) idéale pour scanner des centaines d'hôtes × ports rapidement.
- `embed` permet d'inclure l'interface web, la base OUI et les signatures **dans l'exe**.

### Stockage : SQLite pur Go
- Driver `modernc.org/sqlite` (sans CGO → la cross-compilation reste triviale).
- Un fichier `.db` par **site audité**.

### Interface : serveur web local embarqué
- Au lancement, l'exe démarre un serveur HTTP sur `127.0.0.1` (port libre aléatoire) et **ouvre le navigateur par défaut**.
- Front léger : HTML + CSS + un peu de JS (htmx ou vanilla), tout embarqué. Pas de framework lourd, pas de build Node.
- Écoute **uniquement en local** (jamais `0.0.0.0`) : l'outil ne s'expose pas sur le réseau audité.

### Mode CLI en parallèle
- `arpent scan --site "Pharmacie X" --range 192.168.1.0/24 --profile standard`
- `arpent report --site "Pharmacie X" --format html`
- Utile pour automatiser, et pour tester sur la devbox sans navigateur.

---

## 4. Arborescence portable (à côté de l'exe)

```
arpent.exe
arpent-data/
├── config.yaml              # préférences (profil par défaut, nom du technicien, logo…)
└── sites/
    └── pharmacie-x/
        ├── site.db          # tous les audits de ce site (historique)
        └── rapports/
            ├── 2026-11-25_audit.html
            └── 2026-11-25_audit.pdf
```

L'exe ne s'installe nulle part, n'écrit rien dans le registre ni dans `%APPDATA%`.

---

## 5. Fonctionnalités

### 5.1 Découverte des appareils
- Détection automatique des interfaces réseau et proposition du/des sous-réseau(x) à scanner (modifiable).
- Balayage « réveil » : ping ICMP si autorisé + sondes TCP/UDP légères sur chaque IP, pour peupler la table ARP de l'OS.
- Lecture de la **table ARP de l'OS** (`GetIpNetTable2` sous Windows, `/proc/net/arp` sous Linux) → adresse MAC.
- Sous Windows, **requête ARP active sans Npcap ni droits admin** via l'API système `SendARP` (iphlpapi) pour chaque IP du sous-réseau local : découverte fiable même des appareils qui ne répondent ni au ping ni en TCP.
- **Fabricant** via la base OUI IEEE embarquée (préfixe MAC).
- **Noms d'appareils** : DNS inverse, NetBIOS (UDP 137), mDNS/Bonjour (UDP 5353), SSDP/UPnP (UDP 1900, récupère modèle et fabricant).
- Limite connue : la MAC n'est visible que pour le sous-réseau local (au-delà d'un routeur, IP uniquement).

### 5.2 Scan des ports
- Scan TCP connect concurrent, avec **limite de débit** et de connexions simultanées (ne pas saturer un vieux switch ou une imprimante chez le client).
- Profils :
  - **Rapide** : ~100 ports les plus courants ;
  - **Standard** : ~1000 ports les plus courants (défaut) ;
  - **Complet** : 1–65535 (long, à confirmer par l'utilisateur).
- UDP ciblé uniquement sur quelques services connus (DNS 53, NetBIOS 137, SNMP 161, SSDP 1900, mDNS 5353).

### 5.3 Identification des services et bannières
- Lecture de la bannière brute pour les services qui parlent en premier (SSH, FTP, SMTP, POP3, IMAP, Telnet, MySQL…).
- **HTTP/HTTPS** : code de réponse, titre de la page, en-tête `Server`, `X-Powered-By`, redirection, favicon (hash pour reconnaître les interfaces connues).
- **TLS** : émetteur, sujet, date d'expiration, auto-signé ou non, version TLS.
- **SSH** : version annoncée (`SSH-2.0-OpenSSH_8.9…`).
- **SMB** : présence, version de protocole (SMBv1 = point d'attention).
- **SNMP** : réponse à la communauté `public` (point d'attention).
- Petit fichier de **signatures embarqué** (YAML/JSON) pour reconnaître produits et interfaces : imprimantes, NAS, caméras, routeurs, interfaces d'admin…

### 5.4 Points d'attention (règles d'audit)
Chaque règle a un niveau (**Info / Attention / Critique**) et une explication en langage simple, destinée au client final.

Exemples de règles de départ :
- Telnet ouvert (23) → Critique
- FTP en clair (21) → Attention
- SMBv1 actif → Critique
- RDP (3389) ouvert → Attention
- Interface d'administration en HTTP sans TLS → Attention
- Certificat TLS expiré ou expirant sous 30 jours → Attention
- Certificat auto-signé sur un service exposé → Info
- SNMP répondant avec `public` → Attention
- Bases de données joignables sur le réseau (3306, 5432, 1433, 27017, 6379) → Attention
- UPnP actif sur le routeur → Info
- Version SSH/serveur web obsolète connue (liste simple embarquée) → Attention

Les règles sont dans un fichier embarqué, faciles à enrichir sans toucher au code du moteur.

### 5.5 Inventaire visuel
- Tableau des appareils : IP, MAC, fabricant, nom, type deviné (PC, imprimante, NAS, caméra, téléphone, réseau…), ports ouverts, nombre de points d'attention.
- Fiche détaillée par appareil : services, bannières, certificat, historique de l'appareil sur les audits précédents.
- Vue d'ensemble : nombre d'appareils par type, répartition des points d'attention, ports les plus ouverts.
- Possibilité d'**annoter** un appareil (nom convivial, emplacement, propriétaire) et de le marquer **« connu / validé »**.

### 5.6 Détection des changements
Comparaison automatique avec l'audit précédent du même site :
- 🆕 nouvel appareil (et s'il n'est pas dans la liste « connus ») ;
- ❌ appareil disparu ;
- 🔓 port nouvellement ouvert / 🔒 port fermé ;
- 🔄 bannière, version ou certificat modifié ;
- 🔁 même MAC sur une nouvelle IP (ou même IP avec une autre MAC → à signaler).

L'identité d'un appareil repose d'abord sur la **MAC**, à défaut sur l'IP + le nom.

### 5.7 Rapport d'audit
- **HTML autonome** (un seul fichier, CSS inline, lisible hors ligne, envoyable par mail).
- **PDF** : d'abord via la feuille de style d'impression du HTML (bouton « Imprimer → PDF »), puis **génération PDF en un clic** (§ 11.1).
- Contenu : page de garde (site, date, technicien, logo optionnel), résumé exécutif non technique, points d'attention priorisés, inventaire complet, évolution depuis le dernier audit, annexe technique.
- Export **CSV/JSON** de l'inventaire en complément.

### 5.8 Cadre légal intégré
- Au premier scan d'un site : écran de confirmation « Je confirme être autorisé à auditer ce réseau » (horodaté dans la base et mentionné dans le rapport).
- Mention dans le README et dans l'outil : scanner un réseau sans autorisation est illégal (en Belgique comme ailleurs).

---

## 6. Modèle de données (SQLite, par site)

- `site` : nom, adresse, contact, notes
- `audit` : id, date début/fin, technicien, plages scannées, profil, confirmation d'autorisation
- `device` : identité stable (MAC ou empreinte), nom convivial, statut connu/validé, notes
- `observation` : audit × device → IP, nom(s), fabricant, type deviné
- `service` : observation × port/protocole → état, service identifié, bannière, détails HTTP/TLS/SSH (JSON)
- `finding` : point d'attention → règle, niveau, appareil, service, texte
- `change` : audit × type de changement × device/service → avant/après

---

## 7. Architecture du code (Go)

```
cmd/arpent/           # point d'entrée (CLI + lancement UI)
internal/netinfo/     # interfaces, sous-réseaux, table ARP par OS
internal/discovery/   # réveil des hôtes, NetBIOS, mDNS, SSDP, DNS inverse
internal/portscan/    # scan TCP/UDP concurrent avec limitation de débit
internal/pace/        # limiteur de débit commun (sondes par seconde)
internal/i18n/        # traductions fr/en (catalogues assets/i18n)
internal/probe/       # bannières : http, tls, ssh, smb, snmp, générique
internal/fingerprint/ # signatures, devinette du type d'appareil, base OUI
internal/audit/       # orchestration d'un audit : découverte → ports → sondes
internal/engine/      # audit enregistré de bout en bout + analyses (règles, diff)
internal/rules/       # moteur de points d'attention
internal/diff/        # comparaison entre deux audits
internal/store/       # SQLite (schéma, migrations, requêtes)
internal/config/      # dossier de données portable, config.yaml
internal/report/      # rendu HTML autonome, CSV, JSON
internal/web/         # serveur local + API + assets embarqués
assets/               # oui.tsv.gz, signatures.yaml, rules.yaml, templates, CSS/JS
tools/ouigen/         # génère assets/oui.tsv.gz depuis le registre IEEE
```

Code spécifique à l'OS isolé par fichiers `_windows.go` / `_linux.go` / `_darwin.go`.

---

## 8. Développement et tests

- **Dev** sur la devbox Oracle (Go pour linux/arm64), dépôt Git.
- **Builds** : `windows/amd64` (prioritaire), `linux/amd64`, `linux/arm64`, `darwin/arm64` via un `Makefile` ou GoReleaser.
- **Tests unitaires** : parsers de bannières, moteur de règles, diff, tout ce qui ne touche pas au réseau (avec des jeux de données enregistrés).
- **Tests réels** : la devbox ne voit pas un vrai LAN (et scanner le réseau d'Oracle est à éviter, ça contrevient à leurs conditions). Les tests réseau se font en copiant l'exe sur le PC Windows et en scannant le LAN du homelab (192.168.1.0/24), qui offre une bonne variété d'appareils (Proxmox, NAS QNAP, Raspberry Pi, objets Tapo, Shield…).
- Sur la devbox, tests possibles en local contre `127.0.0.1` avec quelques services lancés exprès (serveur HTTP, SSH).

---

## 9. Risques identifiés

| Risque | Parade |
|---|---|
| **Antivirus / Windows Defender / SmartScreen** qui bloquent un exe non signé qui scanne le réseau | Le documenter ; soumettre l'exe à Microsoft pour analyse faux positif ; **signature de code gratuite via SignPath Foundation** (§ 11.6) |
| Scan qui perturbe un équipement fragile chez le client | Limitation de débit, profils, pas de scan complet par défaut |
| Découverte incomplète sans droits admin (pas d'ARP brut) | Combinaison de plusieurs méthodes (TCP, ICMP, UDP, mDNS, NetBIOS, SSDP) ; `SendARP` sous Windows ; mode avancé Npcap si installé (§ 11.3) |
| Pare-feu Windows qui demande l'autorisation au premier lancement | Le serveur n'écoute qu'en local, donc la plupart du temps pas de demande ; le documenter |
| Concurrence d'outils gratuits (NetAlertX, WatchYourLAN…) | Se différencier par le **rapport d'audit remis au client** et le **portable sans installation**, pas par la supervision |

---

## 10. Étapes d'implémentation (suivi pour Claude Code)

- [x] **Étape 0 — Socle** : installer Go sur la devbox, initialiser le dépôt GitHub public et le module, fichier `LICENSE`, README FR/EN, structure de dossiers, mécanisme de traduction (fr/en), `Makefile` de cross-compilation, GitHub Actions (tests + build), binaire « hello » qui tourne sur Windows.
- [x] **Étape 1 — Réseau local** : détection des interfaces et sous-réseaux, lecture de la table ARP (Windows + Linux), requête ARP active via `SendARP` sous Windows.
- [x] **Étape 2 — Découverte** : réveil des hôtes, DNS inverse, base OUI embarquée → liste d'appareils en CLI.
- [x] **Étape 3 — Scan de ports** : TCP connect concurrent, profils, limitation de débit.
- [x] **Étape 4 — Sondes** : bannières génériques, HTTP, TLS, SSH.
- [x] **Étape 5 — Stockage** : schéma SQLite, sites, audits, sauvegarde des résultats.
- [x] **Étape 6 — Interface web locale** : lancement du serveur + navigateur, liste des sites, lancement d'un audit avec progression, tableau d'inventaire, fiche appareil.
- [x] **Étape 7 — Points d'attention** : moteur de règles + règles de départ (§ 5.4).
- [x] **Étape 8 — Diff** : comparaison avec l'audit précédent, liste « connus / validés », annotations.
- [x] **Étape 9 — Rapport** : HTML autonome, mise en page d'impression PDF, exports CSV/JSON.
- [x] **Étape 10 — Découverte enrichie** : NetBIOS, mDNS, SSDP, SMB, SNMP, devinette du type d'appareil.
- [ ] **Étape 11 — Finitions v1.0** : écran d'autorisation légale, config de base (nom du technicien), README FR/EN, test complet sur le LAN du homelab, publication de la **v1.0** dans les GitHub Releases.

**Version complète (après la v1.0)** — détail au § 11 :

- [x] **Étape 12 — PDF en un clic** : détection d'Edge/Chrome, génération via `chromedp`, en-têtes/pieds de page, repli impression.
- [x] **Étape 13 — Rapports à la marque** : profil émetteur, logo/couleurs, modèles surchargeables, types de rapport, recommandations éditables.
- [x] **Étape 14 — Comparaison libre et historique** : diff entre deux audits au choix, frise par appareil, graphique d'évolution.
- [x] **Étape 15 — Multi-sites** : portefeuille, rappels d'audit, export/import `.arpent`, recherche transverse.
- [ ] **Étape 16 — Mode avancé Npcap** : détection Npcap + admin, ARP brut, scan SYN, écoute passive.
- [ ] **Étape 17 — Signature de code** : candidature SignPath Foundation, intégration dans GitHub Actions, `CODE_SIGNING_POLICY.md`, première version signée.

Chaque étape se termine par un binaire Windows testable.

---

## 11. Fonctionnalités avancées (version complète)

Ces fonctionnalités viennent après le socle (étapes 0 à 11) et font d'Arpent un outil complet. Elles sont intégrées au plan d'implémentation (étapes 12 à 17, § 10).

### 11.1 PDF en un clic
- Le PDF est généré **à partir du même modèle HTML que le rapport** : une seule mise en page à maintenir.
- Arpent pilote en arrière-plan, sans fenêtre, le navigateur Chromium déjà présent sur la machine (**Edge est installé d'office sur Windows 10/11**, sinon Chrome/Chromium) via le protocole DevTools (bibliothèque Go `chromedp`), et lui demande d'imprimer en PDF.
- Rien à embarquer dans l'exe, rendu fidèle (polices, graphiques, sauts de page).
- Repli automatique si aucun navigateur Chromium n'est trouvé : bouton « Imprimer → PDF » classique.
- En-têtes et pieds de page : nom du site, date, numéro de page, mention de confidentialité.

### 11.2 Rapports à la marque du technicien
- **Profil émetteur** dans `arpent-data/config.yaml` : nom, société, logo, coordonnées, couleur principale, mentions légales.
- Logo et couleur appliqués à la page de garde, aux en-têtes et à l'interface.
- **Modèles personnalisables** : les modèles de rapport sont embarqués, mais si un dossier `arpent-data/templates/` existe, ses fichiers les remplacent. Un technicien adapte le rapport sans recompiler.
- Plusieurs **types de rapport** : complet, résumé direction (2 pages, non technique), technique (tout le détail), évolution (seulement les changements).
- Section « Recommandations » éditable par le technicien avant export (texte libre par point d'attention).

### 11.3 Mode avancé (Npcap + administrateur)
- Si Npcap est installé **et** qu'Arpent est lancé en administrateur (root sous Linux/macOS), un **mode avancé** se déverrouille ; sinon tout fonctionne en mode standard, sans message d'erreur.
- Apports : ARP brut, **scan SYN** (plus rapide et plus discret que le scan connect), écoute passive quelques minutes (ARP, DHCP, mDNS) pour repérer les appareils silencieux.
- Npcap **n'est pas embarqué** (sa licence gratuite n'autorise pas la redistribution) : Arpent détecte sa présence et propose un lien vers le site officiel.
- L'interface indique clairement le mode utilisé, et le rapport le mentionne.

### 11.4 Comparaison libre et historique
- Comparer **deux audits quelconques** d'un même site (pas seulement le dernier et l'avant-dernier).
- **Frise chronologique par appareil** : première apparition, changements d'IP, ports ouverts/fermés, versions, disparition.
- Graphique d'évolution du site : nombre d'appareils, de services exposés et de points d'attention par audit.

### 11.5 Vue multi-sites (portefeuille)
- Tableau de bord de tous les sites : date du dernier audit, nombre d'appareils, points critiques ouverts, tendance.
- **Rappel d'audit** : fréquence souhaitée par site (ex. trimestrielle), mise en avant des sites en retard.
- **Export / import d'un site** en un seul fichier (`.arpent`, archive de la base + rapports) pour passer un site d'une clé USB à une autre ou à un collègue ; fusion des audits à l'import.
- Recherche transverse : retrouver un appareil, une MAC, un service ou une version sur tous les sites (ex. « où ai-je encore du SMBv1 ? »).

### 11.6 Signature de code de l'exe
- **SignPath Foundation** fournit gratuitement un certificat de signature de code aux projets open source, ce qui supprime les avertissements à l'installation/au lancement.
- Conditions principales : licence approuvée par l'OSI **sans double licence** (GPL-3.0 convient), builds entièrement automatisés depuis le dépôt GitHub public, MFA activée sur GitHub et SignPath, au moins une version déjà publiée.
- Le certificat est émis au nom de SignPath Foundation (qui apparaît comme éditeur) ; mention obligatoire dans le README et politique de signature (`CODE_SIGNING_POLICY.md`).
- Candidature après la publication de la v1.0 (étape 11).

### 11.7 Modèle économique (compatible GPL-3.0)
- Pas de clé de licence ni d'édition commerciale fermée : en GPL-3.0 une clé se retire facilement dans un fork, et le programme SignPath exclut la double licence.
- Revenus possibles autour de l'outil : **audits réalisés pour des PME** avec Arpent, accompagnement à la correction des points d'attention, modèles de rapport personnalisés pour des MSP, formation, GitHub Sponsors.
- L'outil public sert de vitrine et de carte de visite.

---

## 12. Décisions et questions ouvertes

- [x] **Langues : français + anglais dès le départ.** Tous les textes (interface, règles d'audit, rapport) passent par des fichiers de traduction embarqués (`assets/i18n/fr.json`, `en.json`), aucune chaîne en dur dans le code. Langue choisie par l'utilisateur dans l'interface, et **langue du rapport choisie séparément** (un technicien francophone peut remettre un rapport en anglais).
- [x] **Dépôt : GitHub public.** Binaires publiés dans les GitHub Releases (build automatique par GitHub Actions + GoReleaser à chaque tag), avec sommes de contrôle SHA-256.
- [x] **Open source.**
- [x] **Licence : GPL-3.0.** Toute version modifiée et redistribuée doit rester open source ; laisse la porte ouverte à une offre payante autour du projet (support, audits, version personnalisée).
- [x] **Nom : Arpent** — de l'arpenteur, celui qui mesure et documente un terrain ; le mot existe aussi en anglais ; contient « ARP », clin d'œil au protocole de découverte. Binaire `arpent` / `arpent.exe`, module Go `github.com/maxb1906/arpent`.
- [x] Dépôt `arpent` libre sur GitHub : créé le 2026-11-25 → https://github.com/maxb1906/arpent
- [ ] Vérifier qu'un éventuel nom de domaine est libre (non fait à l'étape 0).

---

## Journal des décisions

- **2026-11-25** — Outil d'audit **ponctuel** sous forme d'**exe portable** lancé n'importe où, pas d'agent permanent ni de LXC. Reprise des pistes d'amélioration : rapport d'audit exportable (HTML/PDF) remis au client, points d'attention, historique par site, liste d'appareils validés, noms d'appareils enrichis. Dev sur la devbox Oracle.
- **2026-11-25** — Choix techniques proposés : Go (binaire unique, cross-compilation depuis ARM64), SQLite pur Go, UI web locale embarquée sur 127.0.0.1, fonctionnement sans droits admin ni nmap/Npcap.
- **2026-11-25** — Interface et rapports en français + anglais ; dépôt GitHub public ; projet open source (licence précise et nom à trancher).
- **2026-11-25** — Nom retenu : **Arpent**. Licence : **GPL-3.0**. Cadrage terminé.
- **2026-11-25** — Pistes « plus tard » intégrées au périmètre pour un outil complet : PDF en un clic (Edge/Chrome headless), rapports à la marque et modèles personnalisables, mode avancé Npcap, comparaison libre et historique, multi-sites avec export/import, signature de code via SignPath Foundation. Édition commerciale fermée abandonnée (incompatible GPL-3.0 et SignPath) au profit de revenus de services.
- **2026-11-25** — Étape 0 terminée. Go **1.27.4** (archive officielle go.dev linux/arm64, SHA-256 vérifié) installé dans `/usr/local/go`. Dépôt public `maxb1906/arpent` créé avec `gh` (licence GPL-3.0), module `github.com/maxb1906/arpent`.
- **2026-11-25** — Traduction : package `internal/i18n` maison, sans dépendance, catalogues JSON plats `assets/i18n/{fr,en}.json` embarqués via le package `assets` ; variables `{nom}` ; repli sur `fr` puis sur la clé ; un `Bundle` donne plusieurs `Translator` (langue de l'UI ≠ langue du rapport). Détection : `--lang`, puis `ARPENT_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG`, puis `GetUserDefaultLocaleName` sous Windows. Un test impose que toutes les langues aient les mêmes clés.
- **2026-11-25** — Build : `Makefile` (pas encore GoReleaser, prévu pour les releases à l'étape 11), `CGO_ENABLED=0`, `-trimpath -s -w`, version injectée par `-X main.version` depuis `git describe`. Binaires `dist/arpent-<os>-<arch>[.exe]`. CI GitHub Actions : tests sur Ubuntu + Windows (`-race`), cross-compilation des 4 cibles avec SHA256SUMS en artefact, et lancement réel de l'exe sur un runner Windows.
- **2026-11-25** — Les paquets de § 7 existent déjà sous forme de `doc.go` vides, à remplir étape par étape.
- **2026-11-25** — Étape 1 terminée. `internal/netinfo` : interfaces + IPv4 (`net.Interfaces`), sous-réseaux proposés (interfaces actives hors boucle locale, lien-local et interfaces virtuelles Docker/veth/VM ; un réseau plus grand qu'un /22 est réduit au /24 de la machine), plages saisies (CIDR jusqu'au /16, adresse, intervalle `a.b.c.10-50`). Table ARP : `/proc/net/arp` (Linux), `GetIpNetTable2` via `iphlpapi.dll` avec décodage manuel de `MIB_IPNET_ROW2` (88 octets, testé sur Linux avec des lignes forgées), `arp -an` (macOS). ARP actif : `SendARP` sous Windows uniquement. Aucune dépendance externe (pas de `golang.org/x/sys`, `syscall` suffit).
- **2026-11-25** — CLI réorganisée en sous-commandes (`interfaces`, `arp [--active] [--range]`), aides et options traduites (un test vérifie qu'aucune clé n'apparaît brute). Le CI lance `interfaces` et `arp` sur le runner Windows (lecture seule, aucun paquet envoyé sur le réseau d'Azure).
- **2026-11-25** — Choix de rythme : les étapes s'enchaînent sans pause à la demande de l'utilisateur, chacune poussée avec le CI vert avant la suivante.
- **2026-11-25** — Étape 2 terminée. Base OUI : registre IEEE MA-L (≈ 40 500 préfixes) converti par `tools/ouigen` en `assets/oui.tsv.gz` (≈ 390 Ko embarqués, chargés à la première utilisation). Les MAC administrées localement (aléatoires) sont signalées « MAC aléatoire » plutôt que d'afficher un faux fabricant ; les MAC multicast/diffusion et adresses 224.0.0.0/4 sont écartées de la table ARP.
- **2026-11-25** — Découverte (`internal/discovery`, commande `arpent discover`) : par hôte, `SendARP` (Windows, sous-réseaux locaux uniquement), ping ICMP non privilégié (`IcmpSendEcho` sous Windows ; socket `udp4` de `golang.org/x/net/icmp` sous Linux/macOS, ignoré si `ping_group_range` l'interdit — c'est le cas sur la devbox), puis connexions TCP sur 12 ports courants (un refus de connexion prouve aussi que l'hôte existe), puis relecture de la table ARP et DNS inverse. Débit plafonné (300 sondes/s par défaut) par un petit paquet `internal/pace` (ajouté au § 7, utilisé aussi par le scan de ports).
- **2026-11-25** — Dépendance ajoutée : `golang.org/x/net` v0.62.0 (pure Go, BSD) pour ICMP, et plus tard le parsing HTML. Règle suivie : ne prendre que des versions publiées depuis au moins deux semaines.
- **2026-11-25** — Limite connue : sous Windows, une connexion TCP refusée met ≈ 1 s à être signalée (Windows réessaie le SYN) ; la découverte locale s'appuie donc surtout sur `SendARP`.
- **2026-11-25** — Étape 3 terminée. `internal/portscan` + commande `arpent ports` : scan TCP connect avec trois plafonds réglables (500 connexions/s, 256 simultanées au total, 16 par hôte) ; les tâches sont distribuées port par port sur tous les hôtes pour étaler la charge. Le profil complet exige une confirmation (`--yes` pour l'automatiser). Par défaut, découverte préalable puis scan des seuls hôtes actifs (`--no-discover` pour tout scanner).
- **2026-11-25** — Listes de ports établies à la main (IANA + usages courants PME/maison/IoT) plutôt que reprises de `nmap-services`, dont la licence (NPSL) n'est pas compatible avec une redistribution GPL simple : rapide = 94 ports, standard = 1–1024 + rapide + ≈ 370 ports courants au-delà (1395 ports au total, un peu plus que les « ≈ 1000 » du cadrage).
- **2026-11-25** — UDP ciblé : charges utiles construites à la main (DNS `version.bind` TXT CH, NetBIOS NBSTAT `*`, SNMPv1 GetRequest `sysDescr.0` communauté `public`, SSDP M-SEARCH, mDNS `_services._dns-sd._udp.local`). La réponse brute est conservée pour les sondes de l'étape 10.
- **2026-11-25** — Étape 4 terminée. `internal/probe` : (1) bannière spontanée (1,5 s) reconnue pour SSH, FTP, SMTP, POP3, IMAP, Telnet (négociation IAC), VNC (RFB), MySQL (paquet de poignée de main) ; (2) sinon TLS puis HTTP, ou HTTP puis TLS selon le port, et bascule vers TLS quand un port « HTTP » répond 400 (requête en clair sur port HTTPS). HTTP : `GET /` sans suivre les redirections, titre (tokenizer `x/net/html`, Latin-1 toléré), `Server`, `X-Powered-By`, `Location`, realm `WWW-Authenticate`, favicon (`<link rel=icon>` ou `/favicon.ico`) haché au format Shodan (MurmurHash3 du base64). TLS : version, suite, sujet/émetteur, SAN, validité, auto-signé, empreinte SHA-256, taille de clé ; TLS 1.0 et suites anciennes acceptées pour pouvoir observer les vieux équipements (vérification désactivée volontairement, le certificat est analysé à part). User-Agent explicite « Arpent (network audit; +URL du dépôt) ».
- **2026-11-25** — Nouveau paquet `internal/audit` (ajouté au § 7) qui enchaîne découverte → ports → sondes, partagé par la CLI, le stockage et l'interface web. Commande `arpent scan` (affichage seul ; la sauvegarde arrive à l'étape 5).
- **2026-11-25** — Étape 5 terminée. `internal/store` : une base `arpent-data/sites/<slug>/site.db` par site (slug sans accents via `golang.org/x/text/unicode/norm`), schéma du § 6 versionné par `PRAGMA user_version` (migrations uniquement additives), WAL + clés étrangères. Identité d'un appareil : `mac:<mac>`, à défaut `ip:<ip>|<nom>`. Les points d'attention seront stockés sous forme `règle + paramètres JSON` (pas de texte figé) pour pouvoir produire le rapport dans n'importe quelle langue.
- **2026-11-25** — Dossier de données (`internal/config`) : `--data`, sinon `ARPENT_DATA`, sinon `arpent-data/` à côté de l'exe (dossier courant pour `go run`/tests) ; il doit être inscriptible. CLI : `scan --site … [--technician] [--authorized]`, `sites`, `audits --site`, `show --site [--audit N]`. Le premier audit d'un site exige la confirmation « autorisé à auditer », horodatée dans `audit.authorized_at` (§ 5.8, en avance sur l'étape 11).
- **2026-11-25** — Dépendances ajoutées : `modernc.org/sqlite` v1.62.0 (la v1.63.0 avait moins de deux semaines), `golang.org/x/text` v0.44.0. L'exe Windows passe de ≈ 3 Mo à ≈ 12 Mo à cause du moteur SQLite transpilé.
- **2026-11-25** — Étape 6 terminée. `internal/web` + commande `arpent ui`, lancée par défaut sans argument (double-clic) : écoute `127.0.0.1:<port libre>`, ouvre le navigateur (`rundll32 url.dll` sous Windows, `open`, `xdg-open`). Sécurité : jeton aléatoire passé une fois dans l'URL puis cookie `HttpOnly; SameSite=Strict`, en-tête `Host` limité à 127.0.0.1/localhost:port (contre le DNS rebinding), `Origin` vérifié sur les POST, CSP stricte, aucune ressource externe. Pages rendues côté serveur (`html/template`, un jeu de modèles cloné par requête pour y lier la langue), CSS et JS maison (~150 lignes, sans htmx finalement : inutile pour ce volume), thème clair/sombre, feuille d'impression.
- **2026-11-25** — Écrans : liste des sites + création ; site (fiche, historique des audits, formulaire d'audit pré-rempli avec les sous-réseaux proposés ou les plages du dernier audit, confirmation d'autorisation au premier audit, confirmation du profil complet) ; progression par phase (interrogation toutes les 0,7 s, arrêt possible) ; inventaire (statistiques, filtre, tri) ; fiche appareil (services HTTP/TLS/SSH détaillés, bannière brute, historique). Un seul audit à la fois. Bouton « Quitter ».
- **2026-11-25** — Nouveau paquet `internal/engine` : audit enregistré de bout en bout, avec des « post-traitements » enregistrables (règles à l'étape 7, diff à l'étape 8) — la CLI et l'UI partagent ce chemin. Bug corrigé grâce à `-race` en CI : la progression est appelée depuis plusieurs goroutines ; `make test` utilise désormais `-race`.
- **2026-11-25** — Piège noté : `go:embed` ignore les fichiers commençant par `_` ou `.` ; les modèles partiels sont préfixés `part_`.
- **2026-11-25** — Pas de navigateur sur la devbox (installation de Chromium refusée par le mode automatique) : le rendu est vérifié par des tests HTTP de bout en bout (création de site → audit de 127.0.0.1 → inventaire → fiche, fr et en, aucune clé de traduction brute), pas encore visuellement.
- **2026-11-25** — Étape 7 terminée. `internal/rules` + `assets/rules.yaml` (lu avec `gopkg.in/yaml.v3` v3.0.1) : 16 règles évaluées service par service (Telnet, FTP, SMBv1, RDP, VNC, API Docker, admin HTTP sans TLS, certificat expiré / expirant sous 30 j / auto-signé, TLS 1.0-1.1, SNMP `public`, bases de données, UPnP/SSDP, SSH-1, logiciels anciens d'après le produit, l'en-tête `Server` et `X-Powered-By`). Conditions déclaratives (ports, services, critères TLS/HTTP/SSH/SMB/SNMP, seuils de version) : on enrichit le fichier sans toucher au moteur. « Admin HTTP » = page en clair avec realm d'authentification ou mots-clés de connexion dans le titre/le début de la page (l'extrait de 4 Kio est désormais conservé en base).
- **2026-11-25** — Textes des règles : titre, explication pour le client et recommandation, en fr et en (`rule.<id>.title|explain|fix`), avec variables (`{port}`, `{date}`, `{product}`…). Seuls l'identifiant de règle et les paramètres sont stockés (table `finding`), le texte est traduit à l'affichage. Un test vérifie que chaque règle a ses 3 textes dans chaque langue.
- **2026-11-25** — Affichage : section « Points d'attention » de l'audit (compteurs par niveau, détail dépliable), colonne triable dans l'inventaire, section sur la fiche appareil ; `arpent show` et `arpent scan --site` listent les points. La règle SMBv1 attend la sonde SMB de l'étape 10.
- **2026-11-25** — Étape 8 terminée. `internal/diff` : comparaison par identité d'appareil (table `device`) entre un audit et le précédent, enregistrée dans `change` après chaque audit (post-traitement). Types : nouvel appareil, appareil disparu (seulement s'il était dans les plages du nouvel audit, pour ne pas signaler comme « disparu » ce qu'on n'a pas cherché), port ouvert/fermé, service modifié (nom, produit+version, en-tête `Server`, certificat = sujet+expiration+empreinte, logiciel SSH — pas le titre des pages, trop changeant), nouvelle IP pour une même MAC, même IP avec une autre MAC. `diff.Between` compare aussi deux audits quelconques (prépare l'étape 14).
- **2026-11-25** — Annotations et liste « connus / validés » : formulaire sur la fiche appareil (nom convivial, emplacement, propriétaire, notes, case « connu / validé »), bouton « valider » sur chaque nouvel appareil de la liste des changements, étiquette « nouveau » dans l'inventaire ; CLI `arpent annotate --site … --ip|--device … [--label …] [--known|--unknown]` (seules les options données sont modifiées). `show`/`scan` affichent les changements.
- **2026-11-25** — Étape 9 terminée. `internal/report` : rapport HTML autonome (un seul fichier, CSS intégré, aucune ressource externe — vérifié par test), mis en page pour A4 (`@page`, sauts de page, en-têtes de tableau répétés) avec bouton « Imprimer / PDF ». Contenu : page de garde (site, adresse, date, technicien, émetteur et logo prévus pour l'étape 13, mention de confidentialité), résumé non technique (niveau de risque global, phrases générées, chiffres clés, actions prioritaires), points d'attention regroupés par règle avec explication et recommandation, évolution depuis l'audit précédent, inventaire, annexe technique par appareil, méthode et cadre (plages, profil, période, mode, autorisation horodatée, limites de l'audit).
- **2026-11-25** — Exports : CSV (une ligne par service, BOM UTF-8 pour Excel, séparateur `;` en français), JSON (clés anglaises stables, textes des points dans la langue choisie). Langue du rapport indépendante de l'interface (`?lang=` dans l'UI, `--report-lang` en CLI). Fichiers enregistrés dans `sites/<slug>/rapports/AAAA-MM-JJ_audit-<n>.<ext>` (numéro d'audit ajouté au nom du § 4 pour distinguer plusieurs audits le même jour). CLI `arpent report --site … [--format html|csv|json] [--report-lang en] [--out fichier|-]`.
- **2026-11-25** — Fonctions de modèles partagées entre interface et rapport déplacées dans `internal/i18n` (`TemplateFuncs`).
- **2026-11-25** — CI : l'exe lancé sans argument ouvrant désormais l'interface, l'étape Windows restait bloquée ; le workflow appelle `hello` explicitement, a un délai maximal de 15 min et teste réellement `ui` (démarrage, connexion par le jeton, page d'accueil) puis `report`.
- **2026-11-25** — Étape 10 terminée. Nouvelle phase d'audit « enrichissement » : décodage des réponses UDP déjà reçues au scan — NetBIOS NBSTAT (nom, groupe/domaine, utilisateur connecté `<03>`, partage `<20>`), SNMP `sysDescr` (BER), DNS `version.bind`, SSDP (en-têtes) puis description UPnP XML (nom, fabricant, modèle, type — seulement si elle est hébergée par l'appareil lui-même), mDNS (types de services) puis requête mDNS unicast inverse pour le nom `.local`. Les noms NetBIOS/mDNS complètent les noms DNS. Données conservées dans `observation.extra` (JSON, migration 2 du schéma — testée depuis une base v1).
- **2026-11-25** — Sonde SMB (TCP 445, sans authentification) : une négociation ne proposant que `NT LM 0.12` (acceptée = SMBv1 actif, ce qui active la règle critique `smb_v1`), puis une négociation SMB2 proposant 2.0.2 à 3.0.2 (dialecte retenu et signature exigée/activée). 3.1.1 n'est pas proposé (il exige des contextes de négociation) : le dialecte affiché est donc « au moins » celui-là.
- **2026-11-25** — Type d'appareil : `assets/signatures.yaml` (≈ 80 signatures pondérées : fabricant OUI, noms, ports, titres et serveurs HTTP, UPnP, mDNS, SNMP, NetBIOS, MAC aléatoire) ; le type au score le plus élevé (≥ 3) est retenu, avec un libellé produit (ex. « QNAP NAS », « Proxmox VE »). 20 types traduits. La devinette est faite à la fin de `audit.Run` (et non via le stockage) pour éviter un cycle d'imports. Le type et le produit apparaissent dans l'inventaire, la fiche, le rapport et la CLI ; la fiche affiche une section « Protocoles de découverte ».
- **2026-11-25** — Étape 11 (préparée, non cochée) : `config.yaml` (`internal/config`) — technicien, profil et langue de rapport par défaut, débit, fréquence d'audit, émetteur des rapports (nom, société, coordonnées, mentions, couleur, logo lu dans `arpent-data/` et intégré en data: URI, 512 Kio max., chemins hors du dossier refusés) ; page « Réglages » dans l'interface et commande `arpent config`. La lecture de la config ne crée jamais le dossier de données (`config.Resolve`). Rappel légal sur l'accueil, en plus de la confirmation au premier audit. README FR/EN réécrits pour la v1.0 (démarrage, SmartScreen, CLI, limites, contribution).
- **2026-11-25** — Publication : `.goreleaser.yaml` (GoReleaser v2.20.1 épinglé ; zip pour Windows avec `arpent.exe`, LICENSE et README ; `SHA256SUMS`) + workflow `release.yml` déclenché par un tag `v*`. Le CI exécute GoReleaser à blanc (`--snapshot --skip=publish`) à chaque push pour valider la configuration. **Pas de tag v1.0.0 posé** : le cadrage exige d'abord le test complet sur le LAN du homelab, impossible depuis la devbox (§ 8) ; liste de contrôle dans `docs/TEST-HOMELAB.md`.
- **2026-11-25** — Étape 12 terminée. `report.PDF` : le même modèle HTML que le rapport est écrit dans un dossier temporaire puis imprimé par Edge/Chrome/Chromium/Brave sans fenêtre via `chromedp` v0.22.1 (nouvelle API générique `Run`/`Do`/`PrintToPDF`), A4, fonds imprimés, en-tête (site, titre, date) et pied de page (mention de confidentialité, « Page n / total ») traduits. Profil de navigateur jetable (`UserDataDir` temporaire, supprimé ensuite) : rien n'est laissé sur le PC du client. Détection : chemins Windows (`Program Files`, `Program Files (x86)`, `LocalAppData`), macOS, `PATH` Linux ; `ARPENT_BROWSER` pour en imposer un. Délai global de 2 min.
- **2026-11-25** — Repli : si aucun navigateur n'est trouvé ou si l'impression échoue, l'interface affiche un message qui renvoie vers le rapport HTML et « Imprimer / PDF » du navigateur. Boutons « PDF » (affichage) et « Enregistrer (PDF) » sur la page d'audit ; `arpent report --format pdf`. Pas de navigateur sur la devbox (installation refusée) : le test PDF y est ignoré mais il est **exigé** en CI (`ARPENT_REQUIRE_BROWSER=1`) sur Ubuntu et Windows, où Chrome et Edge sont présents.
- **2026-11-25** — CI : deux appels de l'exe sans commande (`--lang fr`/`--lang en`) restaient dans le test Windows et lançaient l'interface ; corrigés (`hello`). Leçon : toute nouvelle commande par défaut doit être répercutée dans les scripts du CI.
- **2026-11-25** — Étape 13 terminée. Profil émetteur (déjà dans `config.yaml` à l'étape 11) appliqué à la page de garde, au pied du rapport, à la couleur du rapport **et de l'interface**. Types de rapport : complet, résumé direction (garde + résumé + actions prioritaires + évolution, sans détail technique), technique (points, inventaire, annexe, sans résumé), évolution (changements) — `?kind=` dans l'UI, `--kind` en CLI, suffixe dans le nom de fichier (`…_audit-3_executive.pdf`). Numéros de section retirés (ils dépendent du type).
- **2026-11-25** — Personnalisation avant export (migration 3) : synthèse libre du technicien par audit (`audit.comment`) et recommandation personnalisée **par règle** et par audit (table `recommendation`, un champ par type de point d'attention plutôt que par occurrence : c'est ainsi que le rapport les regroupe). Formulaire « Personnaliser le rapport » sur la page d'audit ; texte vide = texte par défaut.
- **2026-11-25** — Modèles surchargeables : si `arpent-data/templates/report.html` et/ou `report.css` existent, ils remplacent les modèles embarqués ; `arpent templates` les y copie comme point de départ (sans écraser). Testé (CSS personnalisée prise en compte).
- **2026-11-25** — PDF : sur le runner Ubuntu, Edge était trouvé en premier mais plantait (sandbox SUID mal installée) ; désormais tous les navigateurs trouvés sont essayés dans l'ordre (Chrome d'abord sous Linux), erreurs cumulées.
- **2026-11-25** — Étape 14 terminée. Comparaison libre : page « Comparer deux audits » (deux listes déroulantes, premier → dernier par défaut) et `arpent compare --site … [--from N] [--to M]`, calculées à la volée par `diff.Between` (même logique que le diff enregistré). Frise par appareil (`diff.Timeline`) : première apparition, ports ouverts/fermés, versions et certificats modifiés, changements d'IP, disparition (seulement si l'audit couvrait son adresse) et réapparition.
- **2026-11-25** — Graphique d'évolution du site (page du site, dès deux audits) : trois petits graphiques d'une série chacun (appareils, services exposés, points critiques + attention) plutôt qu'un graphique à plusieurs échelles, SVG généré côté serveur sans bibliothèque, infobulle par point, dernière valeur étiquetée, tableau des valeurs dépliable. Couleur de série validée avec le script de la compétence dataviz (`#1a6aa8` en clair, `#3d8fd0` en sombre : bande de luminosité, chroma, contraste OK). Rendu non vérifié visuellement (pas de navigateur sur la devbox) : à regarder pendant le test homelab.
- **2026-11-25** — Étape 15 terminée. Tableau de bord du portefeuille (accueil) : par site, nombre d'audits, date du dernier, appareils, points critiques/attention ouverts, tendance par rapport à l'audit précédent, prochain audit ; sites en retard en tête et surlignés. Rappel d'audit : fréquence par site (migration 4 : `site.reminder_days`, vide = valeur des réglages, 0 = aucun) ; `arpent sites` affiche aussi l'échéance.
- **2026-11-25** — Export/import `.arpent` : zip avec `manifest.json`, copie cohérente de la base (`VACUUM INTO`) et rapports. Import : création du site, ou **fusion** si le site existe — chaque audit a désormais un identifiant stable (`audit.uid`, migration 4) ; les audits absents sont copiés via `ATTACH DATABASE` avec correspondance des appareils par identité (annotations complétées, « connu » conservé), observations, services, points d'attention et recommandations ; les changements sont ensuite recalculés dans l'ordre chronologique (`diff.RecomputeAll`). `PreviousAudit` suit désormais la date et non l'identifiant. Protections : manifeste obligatoire, taille maximale, noms de rapports sans chemin (zip slip testé), base de l'archive ouverte et migrée avant fusion. UI : export par site, import par fichier ; CLI : `arpent export|import`.
- **2026-11-25** — Recherche transverse (`store.Search`, champ dans l'en-tête de l'UI, `arpent search …`) sur le dernier audit de chaque site : IP, MAC, noms, fabricant, annotations, type, services, produits/versions, titres et serveurs web, certificats, SMB (« smbv1 »), SSH, bannières, identifiants de règles. Comparaison tolérante (casse, espaces et ponctuation ignorés : « SMB v1 » = « SMBv1 », `00-11-22` = `00:11:22`).
