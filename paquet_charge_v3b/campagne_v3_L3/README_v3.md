# Campagnes v3 — niveau de sécurité 3 : reprise de session, compression de certificat, charge concurrente

Contenu : voir l'arborescence ; mode d'emploi complet dans la réponse du chat. Ordre impératif :
1. construire l'image v3 (`Dockerfile.v3` + `docker_ctx_overlay/` copiés sur une COPIE du contexte de build v2) ;
2. `probe_features.sh` dans l'image (verdicts OK/KO par mécanisme) ;
3. `make_plans_ext.sh` (QUIC_COMP=1 seulement si la sonde est positive) ;
4. pilote d'un bloc, puis pré-enregistrement figé (`PREREGISTRATION_v3.md`, commit), puis 20 blocs par bras ;
5. `analysis/13_analyse_extensions.py`.

Aucun fichier de ce dossier ne modifie la campagne v2 : état (`campaign_state_v3`), sorties (`captures_v3`), image
(`uma-tls-quic-pq-34-v3`) et graine maître sont distincts.
`analysis/synth_ext.py` génère des données SYNTHÉTIQUES pour tester le pipeline (scénarios h0 / falsify) : ce ne sont pas des mesures.

## Bras « charge » (v3b) — générateurs persistants
- Image `uma-tls-quic-pq-34-v3b` = v3 + `tls_load_client` + `quics_load` + `perftestLoadClient.sh` (`Dockerfile.v3b`).
  Construire UNIQUEMENT quand aucun bloc de mesure ne tourne (la compilation fausse le CPU).
- Pilote 2 : `plan_pilot_load_v3b.csv` (c = 1 4 16 32, 12 s, + calibration serveur stock vs MT à c = 1), `IMAGE=uma-tls-quic-pq-34-v3b`,
  `CAPTURES_ROOT=captures_v3_load_pilot`, état et graine distincts.
- Critères d'acceptation avant toute donnée principale : CPU client < 85 % à c = 32 ; CPU serveur proche de la saturation ;
  0 échec à c ≤ 16 ; calibration MT/stock équivalente à c = 1. Les bandes L0–L6 sont ensuite réécrites dans un addendum daté.
