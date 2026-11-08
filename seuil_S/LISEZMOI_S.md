# Campagne S — mode d'emploi (copier-coller, chemins réels)

Dépôt : `/home/tolokoum/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance` (noté `$REPO`).
Il contient déjà `Launcher_ext.sh`, `run_campaign_ext.sh`, `pq_common.py` à la racine et `tools/07_threshold_model.py`, `tools/11_modele_ecritures_tls.py`.
L'image Docker `uma-tls-quic-pq-34-v3` doit exister (campagne v3 déjà lancée).

## Durée (estimation d'ordre de grandeur, à recalibrer après la phase 0)
| Étape | Durée |
|---|---|
| Phase 0 (23 visites, RTT 0, 1 bloc) | ≈ 20–25 min |
| Un bloc de mesure (122 visites : 98 cellules de mesure + 24 cellules pcap) | ≈ 1,7 h |
| 20 blocs | ≈ 34 h de banc, soit ≈ 5 jours à 4 blocs par jour au plus |
| Analyse | quelques minutes |

Base : surcoût fixe ≈ 40 s par visite (mesuré en v2) + ≈ 1 s par connexion (échauffement compris).
Si vous remettez `--micro-batches 2` (non recommandé) : ≈ 61 h.

## 0. Installer les scripts
```bash
export REPO=/home/tolokoum/Documents/mldsa-mlkem-hqc-tls-quic-constrained-performance
cd "$REPO"
ZIP=$(find ~ -name seuil_S_pkg.zip -not -path '*/.cache/*' 2>/dev/null | head -1); echo "$ZIP"
mkdir -p seuil_S && unzip -o "$ZIP" -d seuil_S
ls seuil_S
python3 -c "import dpkt, pandas, numpy; print('ok')"     # sinon : pip install --break-system-packages dpkt pandas numpy
docker image inspect uma-tls-quic-pq-34-v3 >/dev/null && echo "image ok"
printf '\ncaptures_S/\ncaptures_S_phase0/\ncampaign_state_S/\ncampaign_state_S_phase0/\n' >> .gitignore
```
Prérequis machine (comme pour les campagnes précédentes) : secteur branché ; `cat /sys/devices/system/cpu/intel_pstate/no_turbo` doit afficher `1` (sinon `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`) ; gouverneur `performance` (`sudo cpupower frequency-set -g performance`).

## 1. Phase 0 (≈ 20–25 min, aucune durée affichée)
```bash
cd "$REPO"
PYTHONPATH=. python3 seuil_S/predict_freeze.py --tools tools --out seuil_S/freeze_draft
PYTHONPATH=. python3 seuil_S/make_plan_S.py --pred seuil_S/freeze_draft --out seuil_S/plans_draft --tools tools
export CAPTURES_ROOT=$PWD/captures_S_phase0
time ./run_campaign_ext.sh --plan seuil_S/plans_draft/plan_S_phase0.csv --n-blocks 1 --block 1 \
   --master-seed 20261110 --state-dir $PWD/campaign_state_S_phase0 --no-sentinels --warmup 2
python3 seuil_S/phase0_check.py --root captures_S_phase0 --pred seuil_S/freeze_draft
```
Le banc enregistre `pcap_perconn/block1of1/<sig>_<kem>/block.pcap` + `conn_windows.csv` ; `phase0_check.py` les lit (aucune dépendance `dpkt` requise).

La commande `time` donne la durée réelle de la phase 0 : durée d'un bloc ≈ (cette durée) × 122 / 23 × 1,05 environ.

Lire la sortie de `phase0_check.py` : (1) taux de réussite 100 % partout ; (2) TLS : « cellules avec |Rx − vol prédit| ≤ 10 o » = toutes ; (3) QUIC : noter la ligne `--quic-dgram N` et les `B_c`.
Si une taille échoue, la retirer de `FAMILIES[...]["sizes"]` dans `seuil_S/predict_freeze.py` (à signaler dans l'article). Ne regarder aucune autre sortie.

## 2. Gel (avant le bloc 1)
```bash
cd "$REPO"
# 1) regénérer le brouillon avec le modèle courant, puis lire les valeurs de calage dans la sortie de phase0_check.py
PYTHONPATH=. python3 seuil_S/predict_freeze.py --tools tools --out seuil_S/freeze_draft > /dev/null
python3 seuil_S/phase0_check.py --root captures_S_phase0 --pred seuil_S/freeze_draft 2>&1 | grep -A1 "ARGUMENTS"
# 2) geler avec EXACTEMENT les arguments affichés (exemple de ce que vous obtiendrez :
#    --quic-dgram 1220 --bc x25519_mlkem512=2440 --bc x448_mlkem768=2440 --amp-sub 28 --q-offset 42)
PYTHONPATH=. python3 seuil_S/predict_freeze.py --tools tools --out seuil_S/freeze_S ARGUMENTS_AFFICHES
PYTHONPATH=. python3 seuil_S/make_plan_S.py --pred seuil_S/freeze_S --out seuil_S/plans_S --tools tools
( cd seuil_S && sha256sum freeze_S/* plans_S/plan_S_all.csv predict_freeze.py analyse_seuil.py fw_segments.py PREREGISTRATION_S.md ) | tee seuil_S/SHA256_GEL.txt
# remplir le tableau §10 de seuil_S/PREREGISTRATION_S.md avec ces empreintes, puis :
git add seuil_S .gitignore && git commit -m "Pré-enregistrement campagne S (gel)" && git tag prereg-S && git push && git push origin prereg-S
```
(Pas de `--force`.) Recommandé : déposer `PREREGISTRATION_S.md` + `freeze_S/` sur OSF Registries (horodatage tiers).

## 3. Mesure (20 blocs, 4 par jour au plus)
```bash
cd "$REPO"
export CAPTURES_ROOT=$PWD/captures_S
time ./run_campaign_ext.sh --plan seuil_S/plans_S/plan_S_all.csv --master-seed 20261111 --state-dir $PWD/campaign_state_S --block 1
# puis --block 2, 3, ... 20 (même graine, même état ; ne rien mettre à jour sur la machine entre les blocs)
```
Boucle possible pour un jour (4 blocs) : `for K in 1 2 3 4; do ./run_campaign_ext.sh --plan seuil_S/plans_S/plan_S_all.csv --master-seed 20261111 --state-dir $PWD/campaign_state_S --block $K || break; done`

Contrôle sans durée : `python3 seuil_S/phase0_check.py --root captures_S --pred seuil_S/freeze_S | tail -15` (n'affiche pas de durée).

## 4. Analyse (après le bloc 20 seulement)
```bash
cd "$REPO"
python3 seuil_S/analyse_seuil.py --root captures_S --pred seuil_S/freeze_S --out analysis_S --boot 10000
python3 seuil_S/analyse_seuil.py --root captures_S --pred seuil_S/freeze_S --out analysis_S_hs --metric hs_ms
python3 seuil_S/fw_segments.py --pcaps captures_S --pred seuil_S/freeze_S --out analysis_S/mech
```
Sorties : `S_endpoints.csv` (E1–E4), `S_brackets.csv` (E6), `S_controls.csv`, `S_monotonicity.csv`, `S_cells.csv`, `S_staircase.pdf`, `S_report.txt`, `mech/M1_cells.csv`.

## 5. Test à blanc de l'analyse (aucune donnée réelle)
```bash
cd "$REPO"
python3 seuil_S/analyse_seuil.py --selftest --world b --pred seuil_S/freeze_S --out /tmp/st_b     # mondes : a, b, shift, flat
```
