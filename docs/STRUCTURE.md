# Arpent — Outil d'audit et de documentation réseau automatisé — Structure projet

> Fichier de cadrage et de suivi d'implémentation. Il consigne tous les choix du projet et sert de référence à Claude Code pendant le développement sur la devbox Oracle.
> Statut : **étape 1 (réseau local) terminée** — prochaine étape : 2 (découverte).
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
internal/probe/       # bannières : http, tls, ssh, smb, snmp, générique
internal/fingerprint/ # signatures, devinette du type d'appareil, base OUI
internal/rules/       # moteur de points d'attention
internal/diff/        # comparaison entre deux audits
internal/store/       # SQLite (schéma, migrations, requêtes)
internal/report/      # rendu HTML autonome, CSV, JSON
internal/web/         # serveur local + API + assets embarqués
assets/               # oui.txt, signatures.yaml, rules.yaml, templates, CSS/JS
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
- [ ] **Étape 2 — Découverte** : réveil des hôtes, DNS inverse, base OUI embarquée → liste d'appareils en CLI.
- [ ] **Étape 3 — Scan de ports** : TCP connect concurrent, profils, limitation de débit.
- [ ] **Étape 4 — Sondes** : bannières génériques, HTTP, TLS, SSH.
- [ ] **Étape 5 — Stockage** : schéma SQLite, sites, audits, sauvegarde des résultats.
- [ ] **Étape 6 — Interface web locale** : lancement du serveur + navigateur, liste des sites, lancement d'un audit avec progression, tableau d'inventaire, fiche appareil.
- [ ] **Étape 7 — Points d'attention** : moteur de règles + règles de départ (§ 5.4).
- [ ] **Étape 8 — Diff** : comparaison avec l'audit précédent, liste « connus / validés », annotations.
- [ ] **Étape 9 — Rapport** : HTML autonome, mise en page d'impression PDF, exports CSV/JSON.
- [ ] **Étape 10 — Découverte enrichie** : NetBIOS, mDNS, SSDP, SMB, SNMP, devinette du type d'appareil.
- [ ] **Étape 11 — Finitions v1.0** : écran d'autorisation légale, config de base (nom du technicien), README FR/EN, test complet sur le LAN du homelab, publication de la **v1.0** dans les GitHub Releases.

**Version complète (après la v1.0)** — détail au § 11 :

- [ ] **Étape 12 — PDF en un clic** : détection d'Edge/Chrome, génération via `chromedp`, en-têtes/pieds de page, repli impression.
- [ ] **Étape 13 — Rapports à la marque** : profil émetteur, logo/couleurs, modèles surchargeables, types de rapport, recommandations éditables.
- [ ] **Étape 14 — Comparaison libre et historique** : diff entre deux audits au choix, frise par appareil, graphique d'évolution.
- [ ] **Étape 15 — Multi-sites** : portefeuille, rappels d'audit, export/import `.arpent`, recherche transverse.
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
