# Signature de code — procédure SignPath Foundation (étape 17)

Le dépôt est prêt ; il reste les démarches qui demandent ton compte. Conditions (§ 11.6) : licence OSI sans double licence (GPL-3.0 ✓), builds entièrement automatisés depuis le dépôt public (✓ GitHub Actions + GoReleaser), MFA activée sur GitHub et SignPath, **au moins une version publiée** (v1.0.0, après le test homelab).

1. Activer la MFA sur le compte GitHub `maxb1906` (si ce n'est pas déjà fait).
2. Publier la v1.0.0 : `git tag v1.0.0 && git push origin v1.0.0` (le workflow *Release* publie les binaires et `SHA256SUMS`).
3. Candidater sur https://signpath.org/apply en indiquant le dépôt, la licence GPL-3.0, `CODE_SIGNING_POLICY.md` et le workflow `.github/workflows/sign.yml`.
4. Une fois accepté, dans SignPath : créer le projet `arpent`, la politique `release-signing` (approbation manuelle), un *Trusted Build System* « GitHub.com » lié au dépôt, et un *artifact configuration* acceptant `arpent.exe` (PE).
5. Dans GitHub (Settings → Secrets and variables → Actions) :
   - secret `SIGNPATH_API_TOKEN` (jeton d'un utilisateur CI SignPath) ;
   - variables `SIGNPATH_ORGANIZATION_ID`, et au besoin `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_POLICY_SLUG`.
6. Relancer *Sign* sur la release v1.0.0 (Actions → Sign → Run workflow, tag `v1.0.0`) ou publier v1.0.1 : la demande arrive dans SignPath, l'approuver ; l'archive Windows et `SHA256SUMS` de la release sont remplacés par la version signée.
7. Vérifier sur Windows : clic droit sur `arpent.exe` → Propriétés → Signatures numériques (éditeur « SignPath Foundation »), puis cocher l'étape 17 dans `docs/STRUCTURE.md` et retirer la mention « non signé » des README.
