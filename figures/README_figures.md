# figures/ — toutes les figures de l'étude, chacune à son lieu sûr

## Installation
Copier le dossier `figures/` à la racine du dépôt (à côté de `plot_style.py`). `figures/plot_style.py` est la copie IDENTIQUE de
votre fichier ; si vous modifiez la palette, modifiez celle-ci (l'empreinte des figures change alors et elles sont régénérées).

## Commandes
```bash
python3 figures/make_figures.py --list                                   # catalogue : campagne, identifiant, entrées requises
python3 figures/make_figures.py --v2-dir <dossier_analyse_v2> --out figures_out --campaign v2
python3 figures/make_figures.py --v3-dir analysis_v3 --out figures_out --campaign v3_resume v3_comp v3_load pont
python3 figures/make_figures.py --v2-dir ... --v3-dir ... --out figures_out         # tout
python3 figures/make_figures.py ... --only F02 R02                       # certaines figures
python3 figures/make_figures.py ... --force                              # régénère (l'ancienne version est archivée)
```
`--v2-dir` : dossier (même en sous-dossiers) contenant `conn.csv.gz`, `flight_timeline_summary.csv`, `p3_k_pred_vs_obs.csv`.
`--v3-dir` : sortie de `13_analyse_extensions.py` (`p6_connexions.csv.gz`, `p6_load_niveaux.csv`, `p6_pont_v2.csv`).
Un fichier d'entrée trouvé à deux endroits est REFUSÉ (liste des chemins affichée) : jamais de choix au hasard.
Une figure dont l'entrée manque est sautée : on peut lancer avant la fin des bras v3.

## Où va chaque figure (aucune collision possible)
```
figures_out/<campagne>/<FID>_<slug>/<variante>/{figure.pdf, figure.png, data.csv, meta.json}
figures_out/<campagne>/<FID>_<slug>/_FIGURE.json      empreinte + liste des variantes
figures_out/_archive/<campagne>/<FID>_<slug>__<UTC>/  anciennes versions (jamais supprimées)
figures_out/INDEX.csv                                 reconstruit à chaque exécution
```
Campagnes : `v2`, `v3_resume`, `v3_comp`, `v3_load`, `pont`. Garde-fous :
1. identifiant (campagne, FID) et dossier (campagne, slug) uniques, vérifiés à l'import ;
2. écriture dans `.tmp/` puis renommage atomique ; erreur en cours = l'ancien résultat reste intact ;
3. entrées + code + palette inchangés ⇒ « à jour », rien n'est réécrit ; sinon l'ancienne version est ARCHIVÉE avant remplacement ;
4. verrou `.lock` : deux exécutions simultanées sur le même dossier de sortie sont refusées ;
5. `data.csv` = exactement les valeurs tracées ; `meta.json` = hash sha256 des entrées, versions, graine du bootstrap.

## Catalogue
| ID | Campagne | Figure |
|----|----------|--------|
| F01 | v2 | violons de latence par niveau × profil réseau (9 variantes) |
| F02 | v2 | pénalité ML-DSA − ECDSA en fonction du RTT, avec repères 1 et 2 RTT (4) |
| F03 | v2 | taille des vols serveur vs fenêtre initiale TCP / anti-amplification QUIC |
| F04 | v2 | CPU et mémoire client/serveur avec IC bootstrap de blocs (18) |
| F05 | v2 | ratio de latence de chaque KEM vs courbe NIST classique (9) |
| F06 | v2 | latence (médiane et p95) vs perte × RTT (12) |
| F07 | v2 | taux d'échec de handshake (Clopper-Pearson) |
| F08 | v2 | CCDF des queues à RTT 50 ms (4) |
| F09 | v2 | contrôle qualité : sentinelles, température, fréquence par bloc |
| F10 | v2 | surcoût de l'authentification mutuelle (3) |
| F11 | v2 | k prédit vs k observé |
| R01–R05 | v3_resume | latence, pénalité ML-DSA avec/sans reprise, octets, taux de reprise effectif, gain vs perte |
| C01–C03 | v3_comp | octets, latence, vérification « type 25 vu sur le fil » (TLS seulement) |
| L01–L03 | v3_load | débit/latence/CPU/échecs vs concurrence (points client saturé marqués), calibration serveur MT, CPU par connexion |
| X01 | pont | sentinelles v3 − v2 (bande ±0,5 ms) |

## Statistique
Unité = le BLOC. Chaque point est la médiane des médianes de bloc ; IC 95 % = bootstrap percentile de blocs entiers
(B=2000, graine 12345 — mêmes conventions que les scripts 01–13). Différences ML-DSA − ECDSA, complet − reprise, MT − stock :
APPARIÉES par bloc. Pas de barre min–max là où l'ancien style en traçait.

## Avertissement
Les figures v3 ont été testées sur DONNÉES SYNTHÉTIQUES (voir `analysis/synth_ext.py`) : elles valident le code, pas le monde réel.
