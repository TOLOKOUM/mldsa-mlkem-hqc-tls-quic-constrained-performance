# Campagne S2 — mode d'emploi (copier-coller)

S2 intervient sur la **capacité du premier tour** (fenêtre initiale TCP du serveur ; premier vol client QUIC) et teste si le seuil se déplace comme prédit (voir `PREREGISTRATION_S2.md`).
Trois familles, **une exécution complète par famille** (dossier de gel, de captures et d'état séparés) : `TLS_IW4`, `TLS_IW20`, `QUIC_C`.

Dépôt : `$REPO` = `/home/tolokoum/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance` (le dossier `seuil_S` de la campagne S doit déjà s'y trouver).

## Durée (estimation d'ordre de grandeur, même base que la campagne S, à recalibrer après la phase 0)
| Étape | TLS_IW4 | TLS_IW20 | QUIC_C |
|---|---|---|---|
| Phase 0 (6 visites ; TLS : RTT 50 ms, QUIC : RTT 0) | ≈ 5–8 min | ≈ 5–8 min | ≈ 5 min |
| Un bloc (visites) | 37 (≈ 0,5 h) | 37 (≈ 0,5 h) | 29 (≈ 0,4 h) |
| 20 blocs | ≈ 10,3 h | ≈ 10,3 h | ≈ 8,1 h |
Le lanceur limite à 4 blocs par jour (`--max-blocks-per-day`, défaut 4) : ≈ 5 jours par famille si vous gardez cette limite.

## 0. Installer les scripts et le patch du lanceur
```bash
export REPO=/home/tolokoum/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance
cd "$REPO"
ZIP=$(find ~ -name seuil_S2_pkg.zip -not -path '*/.cache/*' 2>/dev/null | head -1); echo "$ZIP"
unzip -o "$ZIP" -d .            # crée seuil_S2/
ls seuil_S2
python3 -c "import numpy, pandas; print('ok')"
cp Launcher_ext.sh Launcher_ext.sh.avant_S2
patch -p1 --dry-run < seuil_S2/launcher_initcwnd.patch && patch -p1 < seuil_S2/launcher_initcwnd.patch && bash -n Launcher_ext.sh && echo "patch OK"
sha256sum Launcher_ext.sh.avant_S2 Launcher_ext.sh
printf '\ncaptures_S2*/\ncampaign_state_S2*/\nanalysis_S2*/\nLauncher_ext.sh.avant_S2\n' >> .gitignore
```
Si `patch --dry-run` échoue (votre `Launcher_ext.sh` local diffère de celui sur lequel le patch a été écrit), **ne forcez pas** : envoyez-moi la sortie.
Effet du patch : variable `INIT_CWND` (vide par défaut). Vide : rien ne change (seule une ligne `initcwnd[...]=default` est ajoutée au manifeste du bloc). Renseignée : `ip route change … initcwnd N` sur le serveur, **vérifié** (arrêt fatal sinon), journalisé
(`initcwnd[...]=N route_avant=… route_apres=…`) et suffixe `__iwN` ajouté à l'étiquette de la cellule.

Test isolé du patch (30 s, ne touche pas à la campagne) :
```bash
bash seuil_S2/test_initcwnd.sh uma-tls-quic-pq-34-v3 4
```
Attendu : `OK (1,2): route portant initcwnd 4`. Si `ip route change` est refusé, dites-le-moi avant d'aller plus loin.
Prérequis machine (comme avant) : secteur ; `cat /sys/devices/system/cpu/intel_pstate/no_turbo` = `1` ; gouverneur `performance`.

## 1. Phase 0 (une famille à la fois ; aucune durée affichée)
```bash
cd "$REPO"
export FAM=TLS_IW4         # puis TLS_IW20, puis QUIC_C
PYTHONPATH=. python3 seuil_S2/predict_freeze_S2.py --family $FAM --tools tools --out seuil_S2/freeze_draft_$FAM
PYTHONPATH=. python3 seuil_S2/make_plan_S2.py --pred seuil_S2/freeze_draft_$FAM --out seuil_S2/plans_draft_$FAM --tools tools
export CAPTURES_ROOT=$PWD/captures_S2_phase0_$FAM
time ./run_campaign_ext.sh --plan seuil_S2/plans_draft_$FAM/plan_S2_phase0.csv --n-blocks 1 --block 1 \
   --master-seed 20261114 --state-dir $PWD/campaign_state_S2_phase0_$FAM --no-sentinels --warmup 2
python3 seuil_S/phase0_check.py --root captures_S2_phase0_$FAM --pred seuil_S2/freeze_draft_$FAM
```
Valeurs prédites à comparer avec la colonne `segs_first` (TLS) de la sortie :
```bash
python3 - <<'PY'
import os, pandas as pd
p = pd.read_csv("seuil_S2/freeze_draft_%s/predictions_frozen.csv" % os.environ["FAM"])
print(p[p.kind.isin(["base","pad","bridge"])][["sig","chain_target","kind","flight_a","fw_seg_a","fw_seg_b"]].to_string(index=False))
PY
```
Critères (détail dans `PREREGISTRATION_S2.md` §4) :
- **TLS** (phase 0 à RTT 50 ms ; le détecteur de rondes ne voit rien à RTT 0) : P0-T1 taux de réussite 100 % ; **P0-T2 `segs_first` (médiane) = `fw_seg_a`** dans les cellules où `fw_seg_a` ≠ `fw_seg_b` (IW4 : pad 4300, 11750, 20000, soit 4 attendu contre 5, 10, 10 ; IW20 : pad 11750, 25050, 46000, soit 11, 20, 20 attendus contre 10, 10, 10) ; P0-T3 « cellules avec |Rx − vol prédit| ≤ 10 o » = toutes ;
  P0-T4 : `grep -h "initcwnd\[" captures_S2_phase0_$FAM/*/*/*/block_manifest*.log | head` (ou, à défaut, `grep -rh "initcwnd\[" captures_S2_phase0_$FAM | head`) doit montrer `=4` (ou `=20`) avec la route après.
  **Si P0-T2 échoue : ne gelez pas cette famille, envoyez-moi la sortie.**
- **QUIC_C** : noter la ligne `=> ARGUMENTS A DONNER …` (`--quic-dgram`, `--bc hqc128=…`, `--amp-sub`, `--q-offset`). **Si `B_c` vaut 2440, ne gelez pas QUIC_C** (règles confondues : à rapporter, pas à corriger).
Si une taille échoue, la retirer de `S2_FAMILIES[...]["sizes"]` dans `seuil_S2/predict_freeze_S2.py` **avant** gel (à signaler dans l'article). Ne regarder aucune autre sortie.

## 2. Gel (avant le bloc 1 de la famille)
```bash
cd "$REPO"
# TLS : aucun argument supplémentaire.  QUIC_C : coller EXACTEMENT les arguments affichés par phase0_check (exemple de forme : --quic-dgram 1220 --bc hqc128=3660 --amp-sub 28 --q-offset 42)
PYTHONPATH=. python3 seuil_S2/predict_freeze_S2.py --family $FAM --tools tools --out seuil_S2/freeze_S2_$FAM  [ARGUMENTS_QUIC_C]
PYTHONPATH=. python3 seuil_S2/make_plan_S2.py --pred seuil_S2/freeze_S2_$FAM --out seuil_S2/plans_S2_$FAM --tools tools
( cd seuil_S2 && sha256sum freeze_S2_$FAM/* plans_S2_$FAM/plan_S2_all.csv predict_freeze_S2.py make_plan_S2.py analyse_S2.py launcher_initcwnd.patch PREREGISTRATION_S2.md ) | tee seuil_S2/SHA256_GEL_$FAM.txt
sha256sum Launcher_ext.sh | tee -a seuil_S2/SHA256_GEL_$FAM.txt
# remplir le tableau §10 de PREREGISTRATION_S2.md et le journal de calage de phase 0 (§4), puis :
git add seuil_S2 Launcher_ext.sh .gitignore && git commit -m "Pré-enregistrement campagne S2 ($FAM) : gel" && git tag prereg-S2-$FAM && git push && git push origin prereg-S2-$FAM
```
(Pas de `--force`.) Recommandé : déposer `PREREGISTRATION_S2.md` + `freeze_S2_*` sur OSF Registries ou Zenodo (horodatage tiers).

## 3. Mesure (20 blocs)
```bash
cd "$REPO"
export CAPTURES_ROOT=$PWD/captures_S2_$FAM
SEED=20261121                  # TLS_IW4 ; mettre 20261122 pour TLS_IW20 et 20261123 pour QUIC_C
for K in 1 2 3 4; do ./run_campaign_ext.sh --plan seuil_S2/plans_S2_$FAM/plan_S2_all.csv --master-seed $SEED --state-dir $PWD/campaign_state_S2_$FAM --no-sentinels --block $K || break; done
# jours suivants : K = 5..8, 9..12, 13..16, 17..20 (même graine, même état ; rien à mettre à jour sur la machine entre les blocs)
```
Contrôle sans durée : `python3 seuil_S/phase0_check.py --root captures_S2_$FAM --pred seuil_S2/freeze_S2_$FAM | tail -15`.
Si un bloc échoue : relancer **la même commande** (seules les parties manquantes sont refaites). Ne jamais utiliser `--force`.

## 4. Analyse (après le bloc 20 de la famille seulement)
```bash
cd "$REPO"
python3 seuil_S2/analyse_S2.py --root captures_S2_$FAM --pred seuil_S2/freeze_S2_$FAM --out analysis_S2_$FAM --boot 10000
python3 seuil_S2/analyse_S2.py --root captures_S2_$FAM --pred seuil_S2/freeze_S2_$FAM --out analysis_S2_${FAM}_hs --metric hs_ms
python3 seuil_S/fw_segments.py --pcaps captures_S2_$FAM --pred seuil_S2/freeze_S2_$FAM --out analysis_S2_$FAM/mech
```
Sorties : `S2_report.txt` (E1/E2, E3, E4, E5, E6, contrôles), `S2_cells.csv`, `S_brackets.csv`, `S_controls.csv`, `S2_staircase.pdf`, `mech/`.

## 5. Test à blanc de l'analyse (aucune donnée réelle ; déjà passé ici sur les trois familles)
```bash
cd "$REPO"
python3 seuil_S2/analyse_S2.py --selftest --world b --pred seuil_S2/freeze_S2_$FAM --out /tmp/st_S2_$FAM --boot 1000    # mondes : a, b, flat
```
Résultat attendu : monde `a` → règle a confirmée ; monde `b` → règle b confirmée ; monde `flat` → « NON INTERPRETABLE (E3 non conforme) ».

## Ordre conseillé
1. test du patch ; 2. TLS_IW4 (déplacement vers le bas, le plus net) ; 3. TLS_IW20 (deuxième dose : dose–réponse 4 / 10 / 20) ; 4. QUIC_C.
Chaque famille est autonome : si l'une est abandonnée en phase 0, les autres ne sont pas affectées.
