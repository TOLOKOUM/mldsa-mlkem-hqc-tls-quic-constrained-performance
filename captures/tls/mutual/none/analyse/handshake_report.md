# Performance de handshake — captures/tls/mutual/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 6.03 | [5.359, 7.023] | bootstrap_blocs | 5.61 | 8.032 | 8.615 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 5.837 | [5.426, 6.623] | bootstrap_blocs | 5.47 | 7.392 | 9.85 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 22.025 | [20.771, 23.641] | bootstrap_blocs | 21.5 | 25.06 | 25.614 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 21.926 | [19.208, 25.155] | bootstrap_blocs | 21.25 | 27.78 | 29.493 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 26.096 | [24.249, 29.733] | bootstrap_blocs | 24.23 | 34.024 | 40.109 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 11.653 | [11.002, 12.46] | bootstrap_blocs | 11.49 | 13.232 | 14.612 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 21.037 | [19.848, 22.889] | bootstrap_blocs | 20.42 | 24.011 | 25.89 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 6.186 | [5.883, 6.54] | bootstrap_blocs | 6.02 | 7.211 | 7.883 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 43.209 | [40.796, 47.108] | bootstrap_blocs | 41.53 | 49.701 | 53.546 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 29.518 | [27.558, 32.969] | bootstrap_blocs | 28.13 | 36.832 | 41.403 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 38.324 | [35.568, 42.708] | bootstrap_blocs | 36.42 | 45.7 | 48.971 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 23.486 | [21.519, 26.635] | bootstrap_blocs | 22.0 | 28.961 | 31.078 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 21.216 | [19.533, 23.731] | bootstrap_blocs | 20.255 | 25.608 | 29.873 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 6.047 | [5.592, 6.652] | bootstrap_blocs | 5.83 | 7.66 | 8.381 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 37.55 | [35.024, 41.386] | bootstrap_blocs | 36.035 | 44.471 | 47.352 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 23.565 | [21.515, 27.066] | bootstrap_blocs | 21.975 | 30.112 | 36.113 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 33.019 | [31.042, 35.968] | bootstrap_blocs | 31.89 | 40.581 | 45.395 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 31.12 | [24.576, 39.098] | bootstrap_blocs | 30.555 | 43.424 | 50.198 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 9.076 | [8.465, 10.102] | bootstrap_blocs | 8.63 | 11.251 | 11.73 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 8.634 | [7.892, 9.748] | bootstrap_blocs | 8.19 | 10.971 | 13.381 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 83.922 | [77.559, 93.388] | bootstrap_blocs | 80.365 | 100.842 | 104.818 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 38.129 | [35.683, 41.628] | bootstrap_blocs | 36.865 | 44.401 | 46.36 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 76.294 | [70.699, 84.97] | bootstrap_blocs | 73.8 | 92.721 | 98.786 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 33.933 | [31.895, 37.302] | bootstrap_blocs | 32.55 | 40.208 | 41.803 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 59.18 | [55.366, 66.765] | bootstrap_blocs | 55.31 | 72.534 | 84.692 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 15.268 | [14.249, 16.816] | bootstrap_blocs | 14.725 | 17.962 | 21.682 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 53.78 | [50.81, 58.918] | bootstrap_blocs | 51.285 | 63.314 | 66.931 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 10.119 | [9.028, 11.702] | bootstrap_blocs | 9.565 | 12.994 | 13.721 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 75.563 | [72.426, 78.834] | bootstrap_blocs | 74.75 | 83.489 | 89.562 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 31.734 | [28.373, 36.039] | bootstrap_blocs | 30.745 | 38.86 | 40.871 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 51.265 | [49.131, 54.871] | bootstrap_blocs | 49.495 | 58.341 | 60.711 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 8.632 | [7.891, 9.895] | bootstrap_blocs | 8.155 | 11.613 | 12.531 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 43.471 | [31.991, 55.182] | bootstrap_blocs | 44.95 | 61.438 | 71.119 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 10.1 | [9.356, 10.856] | bootstrap_blocs | 10.06 | 11.652 | 12.291 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 135.094 | [129.049, 145.935] | bootstrap_blocs | 129.905 | 155.262 | 167.722 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 48.247 | [39.933, 55.728] | bootstrap_blocs | 50.805 | 59.945 | 62.053 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 96.238 | [91.673, 103.514] | bootstrap_blocs | 93.255 | 111.807 | 117.383 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 16.156 | [15.438, 17.467] | bootstrap_blocs | 15.7 | 18.78 | 20.173 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 126.204 | [120.888, 134.64] | bootstrap_blocs | 122.965 | 142.562 | 149.932 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 43.416 | [41.123, 45.912] | bootstrap_blocs | 43.74 | 47.551 | 53.405 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 91.848 | [85.534, 102.808] | bootstrap_blocs | 86.785 | 110.033 | 134.866 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 9.002 | [8.217, 10.218] | bootstrap_blocs | 8.51 | 11.62 | 12.981 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 6.03 | 13.954 | -56.8 |
| L1 | mldsa44 | P-256 | classique | 22.025 | 13.954 | 57.8 |
| L1 | ed25519 | x25519 | classique | 5.837 | 13.954 | -58.2 |
| L1 | mldsa44 | x25519 | classique | 21.926 | 13.954 | 57.1 |
| L1 | ed25519 | p256_hqc128 | hybride | 26.096 | 13.954 | 87.0 |
| L1 | mldsa44 | p256_hqc128 | hybride | 43.209 | 13.954 | 209.7 |
| L1 | ed25519 | p256_mlkem512 | hybride | 11.653 | 13.954 | -16.5 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 29.518 | 13.954 | 111.5 |
| L1 | ed25519 | x25519_hqc128 | hybride | 21.037 | 13.954 | 50.8 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 38.324 | 13.954 | 174.6 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 6.186 | 13.954 | -55.7 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 23.486 | 13.954 | 68.3 |
| L1 | ed25519 | hqc128 | pq_pur | 21.216 | 13.954 | 52.0 |
| L1 | mldsa44 | hqc128 | pq_pur | 37.55 | 13.954 | 169.1 |
| L1 | ed25519 | mlkem512 | pq_pur | 6.047 | 13.954 | -56.7 |
| L1 | mldsa44 | mlkem512 | pq_pur | 23.565 | 13.954 | 68.9 |
| L3 | mldsa65 | P-384 | classique | 33.019 | 20.462 | 61.4 |
| L3 | secp384r1 | P-384 | classique | 9.076 | 20.462 | -55.6 |
| L3 | mldsa65 | x448 | classique | 31.12 | 20.462 | 52.1 |
| L3 | secp384r1 | x448 | classique | 8.634 | 20.462 | -57.8 |
| L3 | mldsa65 | p384_hqc192 | hybride | 83.922 | 20.462 | 310.1 |
| L3 | secp384r1 | p384_hqc192 | hybride | 59.18 | 20.462 | 189.2 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 38.129 | 20.462 | 86.3 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 15.268 | 20.462 | -25.4 |
| L3 | mldsa65 | x448_hqc192 | hybride | 76.294 | 20.462 | 272.9 |
| L3 | secp384r1 | x448_hqc192 | hybride | 53.78 | 20.462 | 162.8 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 33.933 | 20.462 | 65.8 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 10.119 | 20.462 | -50.5 |
| L3 | mldsa65 | hqc192 | pq_pur | 75.563 | 20.462 | 269.3 |
| L3 | secp384r1 | hqc192 | pq_pur | 51.265 | 20.462 | 150.5 |
| L3 | mldsa65 | mlkem768 | pq_pur | 31.734 | 20.462 | 55.1 |
| L3 | secp384r1 | mlkem768 | pq_pur | 8.632 | 20.462 | -57.8 |
| L5 | mldsa87 | P-521 | classique | 43.471 | 26.785 | 62.3 |
| L5 | secp521r1 | P-521 | classique | 10.1 | 26.785 | -62.3 |
| L5 | mldsa87 | p521_hqc256 | hybride | 135.094 | 26.785 | 404.4 |
| L5 | secp521r1 | p521_hqc256 | hybride | 96.238 | 26.785 | 259.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 48.247 | 26.785 | 80.1 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 16.156 | 26.785 | -39.7 |
| L5 | mldsa87 | hqc256 | pq_pur | 126.204 | 26.785 | 371.2 |
| L5 | secp521r1 | hqc256 | pq_pur | 91.848 | 26.785 | 242.9 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 43.416 | 26.785 | 62.1 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 9.002 | 26.785 | -66.4 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 6.0297 | 22.0252 | -15.9954 | [-16.6183, -15.3962] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 21.2155 | 37.5499 | -16.3344 | [-17.6435, -15.4896] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 6.047 | 23.5646 | -17.5176 | [-20.5059, -15.6347] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 26.0956 | 43.2093 | -17.1136 | [-17.6827, -16.5446] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 11.6533 | 29.5178 | -17.8644 | [-20.5758, -16.381] | oui | 0.125 | 0.125 |
| L1 | x25519 | 5.8371 | 21.9257 | -16.0886 | [-18.5258, -13.7657] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 21.0373 | 38.3239 | -17.2866 | [-19.9806, -15.1497] | oui | 0.125 | 0.125 |
| L1 | x25519_mlkem512 | 6.1864 | 23.4865 | -17.3001 | [-20.1657, -15.4765] | oui | 0.125 | 0.125 |
| L3 | P-384 | 9.0763 | 33.0195 | -23.9432 | [-25.866, -22.5574] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 51.2649 | 75.5628 | -24.2979 | [-25.8451, -22.7507] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 8.6324 | 31.7341 | -23.1016 | [-26.1438, -20.4818] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 59.18 | 83.9219 | -24.742 | [-27.3138, -22.1702] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 15.2676 | 38.1286 | -22.8609 | [-24.9462, -20.8918] | oui | 0.125 | 0.125 |
| L3 | x448 | 8.6337 | 31.1204 | -22.4867 | [-29.3502, -16.3141] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 53.7802 | 76.294 | -22.5138 | [-26.052, -19.2456] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 10.1185 | 33.9332 | -23.8147 | [-25.5736, -22.2696] | oui | 0.125 | 0.125 |
| L5 | P-521 | 10.1 | 43.4706 | -33.3706 | [-44.5603, -21.9313] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 91.8484 | 126.2037 | -34.3553 | [-36.4678, -31.6956] | oui | 0.125 | 0.125 |
| L5 | mlkem1024 | 9.0017 | 43.416 | -34.4143 | [-37.1384, -31.6901] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 96.238 | 135.0942 | -38.8561 | [-42.7106, -36.4661] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 16.1556 | 48.2469 | -32.0913 | [-38.9542, -24.4811] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.