# Performance de handshake — captures/tls/single/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 1.915 | [1.786, 2.167] | bootstrap_blocs | 1.765 | 2.58 | 2.94 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 1.766 | [1.654, 1.973] | bootstrap_blocs | 1.65 | 2.23 | 2.69 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 1.697 | [1.639, 1.793] | bootstrap_blocs | 1.62 | 2.11 | 2.38 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 1.545 | [1.506, 1.597] | bootstrap_blocs | 1.47 | 1.98 | 2.231 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 22.993 | [21.7, 24.955] | bootstrap_blocs | 22.53 | 26.612 | 27.522 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 7.705 | [7.24, 8.418] | bootstrap_blocs | 7.35 | 9.37 | 9.881 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 17.421 | [16.431, 18.967] | bootstrap_blocs | 16.905 | 20.23 | 21.312 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 2.124 | [2.003, 2.342] | bootstrap_blocs | 2.0 | 2.8 | 3.3 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 22.65 | [21.413, 24.706] | bootstrap_blocs | 21.895 | 26.403 | 28.563 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 7.493 | [7.092, 8.216] | bootstrap_blocs | 7.155 | 9.13 | 10.02 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 17.093 | [16.524, 17.923] | bootstrap_blocs | 16.855 | 18.89 | 21.613 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 2.064 | [1.812, 2.317] | bootstrap_blocs | 1.965 | 2.831 | 3.291 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 17.204 | [16.391, 18.617] | bootstrap_blocs | 16.69 | 19.84 | 20.802 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 1.825 | [1.731, 2.009] | bootstrap_blocs | 1.71 | 2.362 | 2.69 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 18.233 | [16.504, 21.479] | bootstrap_blocs | 16.89 | 25.101 | 26.701 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 1.62 | [1.527, 1.782] | bootstrap_blocs | 1.52 | 2.14 | 2.501 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 3.0 | [2.858, 3.239] | bootstrap_blocs | 2.87 | 3.69 | 3.94 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 2.608 | [2.42, 2.974] | bootstrap_blocs | 2.42 | 3.55 | 3.943 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 4.433 | [4.094, 5.047] | bootstrap_blocs | 4.105 | 6.08 | 6.66 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 3.67 | [3.566, 3.778] | bootstrap_blocs | 3.57 | 4.231 | 4.85 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 54.161 | [50.974, 59.966] | bootstrap_blocs | 51.465 | 66.041 | 69.399 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 9.387 | [8.848, 10.112] | bootstrap_blocs | 9.17 | 10.951 | 11.671 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 48.244 | [45.93, 52.061] | bootstrap_blocs | 46.23 | 55.037 | 56.393 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 3.337 | [3.149, 3.653] | bootstrap_blocs | 3.15 | 4.3 | 4.651 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 53.95 | [51.386, 58.906] | bootstrap_blocs | 51.365 | 63.901 | 72.06 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 10.437 | [9.855, 11.384] | bootstrap_blocs | 10.17 | 12.31 | 13.786 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 48.924 | [46.353, 53.539] | bootstrap_blocs | 46.48 | 56.761 | 57.891 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 4.749 | [4.453, 5.261] | bootstrap_blocs | 4.47 | 5.87 | 6.91 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 46.968 | [44.598, 51.65] | bootstrap_blocs | 44.705 | 54.693 | 58.684 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 1.73 | [1.634, 1.909] | bootstrap_blocs | 1.63 | 2.23 | 2.502 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 47.251 | [45.16, 51.055] | bootstrap_blocs | 45.49 | 53.703 | 55.365 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 3.037 | [2.941, 3.201] | bootstrap_blocs | 2.925 | 3.6 | 3.95 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 3.039 | [2.867, 3.346] | bootstrap_blocs | 2.9 | 3.781 | 4.15 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 4.588 | [4.294, 5.138] | bootstrap_blocs | 4.315 | 5.774 | 7.632 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 89.218 | [85.897, 94.629] | bootstrap_blocs | 86.765 | 98.102 | 103.224 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 9.653 | [8.893, 10.988] | bootstrap_blocs | 9.095 | 12.241 | 14.231 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 90.369 | [86.873, 96.086] | bootstrap_blocs | 87.68 | 100.194 | 103.251 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 10.661 | [10.141, 11.536] | bootstrap_blocs | 10.35 | 12.572 | 13.564 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 83.794 | [81.251, 88.58] | bootstrap_blocs | 81.62 | 92.511 | 96.631 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 1.842 | [1.728, 2.047] | bootstrap_blocs | 1.72 | 2.42 | 2.932 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 82.362 | [81.11, 84.096] | bootstrap_blocs | 81.38 | 87.25 | 95.344 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 3.411 | [3.236, 3.732] | bootstrap_blocs | 3.21 | 4.442 | 4.89 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 1.915 | 1.731 | 10.6 |
| L1 | mldsa44 | P-256 | classique | 1.697 | 1.731 | -2.0 |
| L1 | ed25519 | x25519 | classique | 1.766 | 1.731 | 2.0 |
| L1 | mldsa44 | x25519 | classique | 1.545 | 1.731 | -10.7 |
| L1 | ed25519 | p256_hqc128 | hybride | 22.993 | 1.731 | 1228.3 |
| L1 | mldsa44 | p256_hqc128 | hybride | 22.65 | 1.731 | 1208.5 |
| L1 | ed25519 | p256_mlkem512 | hybride | 7.705 | 1.731 | 345.1 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 7.493 | 1.731 | 332.9 |
| L1 | ed25519 | x25519_hqc128 | hybride | 17.421 | 1.731 | 906.4 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 17.093 | 1.731 | 887.5 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 2.124 | 1.731 | 22.7 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 2.064 | 1.731 | 19.2 |
| L1 | ed25519 | hqc128 | pq_pur | 17.204 | 1.731 | 893.9 |
| L1 | mldsa44 | hqc128 | pq_pur | 18.233 | 1.731 | 953.3 |
| L1 | ed25519 | mlkem512 | pq_pur | 1.825 | 1.731 | 5.4 |
| L1 | mldsa44 | mlkem512 | pq_pur | 1.62 | 1.731 | -6.4 |
| L3 | mldsa65 | P-384 | classique | 3.0 | 3.428 | -12.5 |
| L3 | secp384r1 | P-384 | classique | 4.433 | 3.428 | 29.3 |
| L3 | mldsa65 | x448 | classique | 2.608 | 3.428 | -23.9 |
| L3 | secp384r1 | x448 | classique | 3.67 | 3.428 | 7.1 |
| L3 | mldsa65 | p384_hqc192 | hybride | 54.161 | 3.428 | 1480.0 |
| L3 | secp384r1 | p384_hqc192 | hybride | 53.95 | 3.428 | 1473.8 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 9.387 | 3.428 | 173.8 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 10.437 | 3.428 | 204.5 |
| L3 | mldsa65 | x448_hqc192 | hybride | 48.244 | 3.428 | 1307.4 |
| L3 | secp384r1 | x448_hqc192 | hybride | 48.924 | 3.428 | 1327.2 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 3.337 | 3.428 | -2.7 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 4.749 | 3.428 | 38.5 |
| L3 | mldsa65 | hqc192 | pq_pur | 46.968 | 3.428 | 1270.1 |
| L3 | secp384r1 | hqc192 | pq_pur | 47.251 | 3.428 | 1278.4 |
| L3 | mldsa65 | mlkem768 | pq_pur | 1.73 | 3.428 | -49.5 |
| L3 | secp384r1 | mlkem768 | pq_pur | 3.037 | 3.428 | -11.4 |
| L5 | mldsa87 | P-521 | classique | 3.039 | 3.814 | -20.3 |
| L5 | secp521r1 | P-521 | classique | 4.588 | 3.814 | 20.3 |
| L5 | mldsa87 | p521_hqc256 | hybride | 89.218 | 3.814 | 2239.2 |
| L5 | secp521r1 | p521_hqc256 | hybride | 90.369 | 3.814 | 2269.4 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 9.653 | 3.814 | 153.1 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 10.661 | 3.814 | 179.5 |
| L5 | mldsa87 | hqc256 | pq_pur | 83.794 | 3.814 | 2097.0 |
| L5 | secp521r1 | hqc256 | pq_pur | 82.362 | 3.814 | 2059.5 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 1.842 | 3.814 | -51.7 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 3.411 | 3.814 | -10.6 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 1.9147 | 1.6974 | 0.2174 | [0.1308, 0.3738] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 17.2039 | 18.2326 | -1.0287 | [-2.8155, 0.0428] | non | 0.5 | 0.125 |
| L1 | mlkem512 | 1.8251 | 1.6197 | 0.2054 | [0.1805, 0.2289] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 22.9929 | 22.6501 | 0.3428 | [0.0446, 0.7479] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 7.7048 | 7.493 | 0.2118 | [0.1138, 0.3097] | oui | 0.125 | 0.125 |
| L1 | x25519 | 1.7662 | 1.5446 | 0.2217 | [0.1417, 0.3748] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 17.4205 | 17.0926 | 0.328 | [-0.1223, 1.0435] | non | 0.75 | 0.125 |
| L1 | x25519_mlkem512 | 2.1239 | 2.0643 | 0.0596 | [-0.2121, 0.2057] | non | 0.625 | 0.125 |
| L3 | P-384 | 4.4325 | 3.0 | 1.4325 | [1.1909, 1.8006] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 47.251 | 46.9682 | 0.2828 | [-0.5944, 0.9356] | non | 0.625 | 0.125 |
| L3 | mlkem768 | 3.0372 | 1.7301 | 1.3071 | [1.2875, 1.3265] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 53.9499 | 54.1608 | -0.2109 | [-1.0359, 0.5096] | non | 0.875 | 0.125 |
| L3 | p384_mlkem768 | 10.4365 | 9.3866 | 1.0499 | [0.8706, 1.2723] | oui | 0.125 | 0.125 |
| L3 | x448 | 3.6702 | 2.6079 | 1.0623 | [0.801, 1.248] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 48.924 | 48.2443 | 0.6797 | [-0.3252, 1.506] | non | 0.375 | 0.125 |
| L3 | x448_mlkem768 | 4.7493 | 3.3367 | 1.4127 | [1.2456, 1.6066] | oui | 0.125 | 0.125 |
| L5 | P-521 | 4.5884 | 3.0392 | 1.5491 | [1.3888, 1.7917] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 82.3618 | 83.7936 | -1.4318 | [-4.3988, 0.4997] | non | 0.625 | 0.125 |
| L5 | mlkem1024 | 3.4106 | 1.8425 | 1.5681 | [1.4967, 1.6846] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 90.3694 | 89.2184 | 1.1509 | [0.977, 1.437] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 10.661 | 9.6529 | 1.008 | [0.5687, 1.3052] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.