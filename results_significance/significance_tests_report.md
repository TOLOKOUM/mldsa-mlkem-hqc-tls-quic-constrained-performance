# Tests statistiques formels — Mann-Whitney U / Cliff's delta

**2 comparaison(s)**, correction FDR (Benjamini-Hochberg) appliquée sur l'ensemble des p-values de ce batch.

| Comparaison | N_a (fail) | N_b (fail) | Médiane a (ms) | Médiane b (ms) | U1 | z | p (brut) | p (FDR) | Cliff's delta | Taille d'effet | Signif. (α=0.05, FDR) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| hqc_degraded_vs_stable | 500 (0) | 500 (0) | 331.03 | 25.495 | 182643.0 | 12.623 | 0.0 | 0.0 | 0.461 | moyen | oui |
| tls_vs_quic_mldsa65 | 500 (0) | 500 (0) | 1.59 | 2.12 | 9292.0 | -25.34 | 0.0 | 0.0 | -0.926 | grand | oui |

## Note méthodologique

Mann-Whitney U calculé par rangs avec correction pour ex-aequo dans l'approximation normale du z (pas de dépendance scipy, cohérent avec le reste du pipeline). Cliff's delta dérivé directement de U1 : delta = 2*U1/(n1*n2) - 1. Seuls les runs réussis (durée numérique) entrent dans chaque distribution comparée ; les échecs (NaN) sont comptés séparément (colonne 'fail') mais exclus du test, cohérent avec le traitement déjà appliqué dans parse_handshake_logs.py et analyze_handshake_performance.py. La correction de Benjamini-Hochberg est appliquée sur l'ensemble des p-values obtenues dans le même run de ce script, pas comparaison par comparaison en isolation.