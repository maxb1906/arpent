# Test complet sur le LAN du homelab (avant la v1.0)

À faire sur le PC Windows, branché sur le LAN 192.168.1.0/24 (§ 8). La devbox Oracle ne doit jamais scanner son propre réseau.

## Préparation
- [ ] Récupérer l'exe : artefact `arpent-binaries` du dernier CI vert (onglet Actions) ou `make windows` sur la devbox, puis copier `arpent-windows-amd64.exe` sur une clé USB (renommé `arpent.exe`).
- [ ] Noter l'avertissement SmartScreen / Defender éventuel (texte exact, capture) pour le README.

## Lancement
- [ ] Double-clic : la console s'ouvre, le navigateur affiche l'interface, `arpent-data/` est créé à côté de l'exe.
- [ ] Pare-feu Windows : une demande d'autorisation apparaît-elle ? (attendu : non, écoute sur 127.0.0.1 seulement).
- [ ] Réglages : technicien, société, logo (`arpent-data/logo.png`), langue des rapports.

## Premier audit (profil standard)
- [ ] Site « Homelab », plage proposée correcte (192.168.1.0/24), confirmation d'autorisation demandée.
- [ ] Durée de l'audit : ……… ; aucun équipement perturbé (Tapo, Shield, imprimante…).
- [ ] Appareils attendus trouvés, avec MAC et fabricant : Proxmox, NAS QNAP, Raspberry Pi, objets Tapo, Shield, box, PC…
- [ ] Appareils silencieux (ni ping ni TCP) trouvés grâce à `SendARP`.
- [ ] Types devinés corrects ? Noter les erreurs (signature à ajouter dans `assets/signatures.yaml`).
- [ ] Noms NetBIOS / mDNS / UPnP présents.
- [ ] Services : interface Proxmox (8006, TLS), QTS du QNAP, SSH du Raspberry Pi, RTSP des caméras…
- [ ] Points d'attention plausibles (pas de faux positif gênant).

## Rapport
- [ ] Rapport HTML en français et en anglais : page de garde, résumé, points, inventaire, annexe.
- [ ] Impression en PDF depuis Edge : sauts de page corrects, logo, couleurs.
- [ ] Exports CSV (ouverture dans Excel : accents, colonnes) et JSON.

## Second audit
- [ ] Débrancher un appareil, en brancher un autre, ouvrir un port (ex. `python -m http.server` sur un PC) puis relancer l'audit.
- [ ] Changements détectés : nouvel appareil, disparu, port ouvert ; bouton « valider » d'un nouvel appareil.
- [ ] CLI : `arpent.exe scan --site Homelab --profile quick`, `arpent.exe show --site Homelab`.

## Bilan
- [ ] Reporter les problèmes en issues GitHub, puis cocher l'étape 11 et taguer `v1.0.0` (le workflow Release publie les binaires).
