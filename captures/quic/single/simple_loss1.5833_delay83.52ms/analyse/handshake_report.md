# Performance de handshake — captures/quic/single/simple_loss1.5833_delay83.52ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 181.334 | [175.849, 186.819] | bootstrap_blocs | 169.89 | 171.71 | 347.65 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 177.073 | [172.721, 179.729] | bootstrap_blocs | 169.715 | 171.39 | 336.701 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 390.412 | [378.997, 401.194] | bootstrap_blocs | 337.14 | 339.086 | 2439.554 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 374.621 | [365.173, 384.069] | bootstrap_blocs | 336.875 | 338.817 | 2439.112 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 221.305 | [216.24, 226.37] | bootstrap_blocs | 200.48 | 218.287 | 1652.728 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 195.928 | [183.059, 208.796] | bootstrap_blocs | 180.07 | 191.712 | 1368.623 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 213.204 | [204.368, 221.333] | bootstrap_blocs | 191.885 | 208.607 | 1650.212 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 206.578 | [196.022, 217.435] | bootstrap_blocs | 171.79 | 175.161 | 1364.572 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 390.544 | [376.04, 407.437] | bootstrap_blocs | 367.825 | 392.403 | 840.106 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 378.934 | [352.62, 405.248] | bootstrap_blocs | 348.025 | 358.92 | 2370.895 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 401.94 | [385.893, 416.136] | bootstrap_blocs | 359.46 | 391.232 | 1856.508 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 371.068 | [346.539, 395.597] | bootstrap_blocs | 338.965 | 342.482 | 2368.019 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 224.806 | [216.663, 232.948] | bootstrap_blocs | 191.935 | 212.843 | 1648.75 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 208.43 | [188.271, 230.298] | bootstrap_blocs | 169.635 | 171.57 | 1362.173 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 395.214 | [386.048, 401.686] | bootstrap_blocs | 357.1 | 380.183 | 1853.542 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 378.367 | [354.129, 402.605] | bootstrap_blocs | 337.09 | 338.63 | 2366.111 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 400.831 | [383.833, 421.278] | bootstrap_blocs | 340.24 | 345.152 | 3337.397 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 388.18 | [367.625, 413.943] | bootstrap_blocs | 338.055 | 340.988 | 3336.796 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 190.005 | [183.596, 198.31] | bootstrap_blocs | 174.49 | 179.985 | 1171.703 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 189.895 | [184.831, 194.642] | bootstrap_blocs | 172.545 | 176.393 | 1171.131 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 453.628 | [435.089, 472.567] | bootstrap_blocs | 415.885 | 615.728 | 774.349 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 394.995 | [375.338, 420.863] | bootstrap_blocs | 350.615 | 363.973 | 2526.483 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 430.686 | [406.598, 454.775] | bootstrap_blocs | 406.485 | 594.921 | 771.763 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 366.759 | [357.62, 375.898] | bootstrap_blocs | 340.995 | 345.162 | 971.999 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 277.079 | [258.366, 295.84] | bootstrap_blocs | 245.09 | 281.731 | 1833.15 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 230.393 | [224.467, 237.631] | bootstrap_blocs | 185.335 | 200.049 | 1711.12 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 243.958 | [225.088, 269.574] | bootstrap_blocs | 236.015 | 262.772 | 390.081 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 214.288 | [205.256, 224.532] | bootstrap_blocs | 175.31 | 181.998 | 1703.596 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 449.463 | [429.549, 469.378] | bootstrap_blocs | 403.17 | 607.519 | 2097.622 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 382.199 | [363.833, 397.375] | bootstrap_blocs | 337.03 | 339.38 | 2338.684 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 264.226 | [241.509, 296.815] | bootstrap_blocs | 232.07 | 261.151 | 1825.975 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 186.889 | [181.18, 193.647] | bootstrap_blocs | 171.48 | 174.716 | 1170.362 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 382.282 | [373.685, 396.988] | bootstrap_blocs | 339.99 | 343.851 | 982.397 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 192.237 | [184.132, 202.533] | bootstrap_blocs | 174.505 | 179.105 | 1173.741 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 961.931 | [923.437, 995.024] | bootstrap_blocs | 916.31 | 1127.968 | 2088.405 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 415.843 | [410.795, 423.837] | bootstrap_blocs | 350.245 | 364.496 | 2682.07 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 923.362 | [901.062, 945.661] | bootstrap_blocs | 909.35 | 954.587 | 1725.803 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 213.308 | [190.291, 238.52] | bootstrap_blocs | 184.92 | 197.453 | 1708.95 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 952.864 | [932.75, 974.978] | bootstrap_blocs | 903.34 | 1088.83 | 2057.536 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 380.0 | [366.766, 393.595] | bootstrap_blocs | 337.245 | 339.592 | 2671.49 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 908.075 | [882.115, 937.395] | bootstrap_blocs | 896.32 | 951.004 | 1720.889 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 205.535 | [193.294, 216.631] | bootstrap_blocs | 171.72 | 175.32 | 1699.825 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 181.334 | 280.86 | -35.4 |
| L1 | mldsa44 | P-256 | classique | 390.412 | 280.86 | 39.0 |
| L1 | ed25519 | x25519 | classique | 177.073 | 280.86 | -37.0 |
| L1 | mldsa44 | x25519 | classique | 374.621 | 280.86 | 33.4 |
| L1 | ed25519 | p256_hqc128 | hybride | 221.305 | 280.86 | -21.2 |
| L1 | mldsa44 | p256_hqc128 | hybride | 390.544 | 280.86 | 39.1 |
| L1 | ed25519 | p256_mlkem512 | hybride | 195.928 | 280.86 | -30.2 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 378.934 | 280.86 | 34.9 |
| L1 | ed25519 | x25519_hqc128 | hybride | 213.204 | 280.86 | -24.1 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 401.94 | 280.86 | 43.1 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 206.578 | 280.86 | -26.4 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 371.068 | 280.86 | 32.1 |
| L1 | ed25519 | hqc128 | pq_pur | 224.806 | 280.86 | -20.0 |
| L1 | mldsa44 | hqc128 | pq_pur | 395.214 | 280.86 | 40.7 |
| L1 | ed25519 | mlkem512 | pq_pur | 208.43 | 280.86 | -25.8 |
| L1 | mldsa44 | mlkem512 | pq_pur | 378.367 | 280.86 | 34.7 |
| L3 | mldsa65 | P-384 | classique | 400.831 | 292.228 | 37.2 |
| L3 | secp384r1 | P-384 | classique | 190.005 | 292.228 | -35.0 |
| L3 | mldsa65 | x448 | classique | 388.18 | 292.228 | 32.8 |
| L3 | secp384r1 | x448 | classique | 189.895 | 292.228 | -35.0 |
| L3 | mldsa65 | p384_hqc192 | hybride | 453.628 | 292.228 | 55.2 |
| L3 | secp384r1 | p384_hqc192 | hybride | 277.079 | 292.228 | -5.2 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 394.995 | 292.228 | 35.2 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 230.393 | 292.228 | -21.2 |
| L3 | mldsa65 | x448_hqc192 | hybride | 430.686 | 292.228 | 47.4 |
| L3 | secp384r1 | x448_hqc192 | hybride | 243.958 | 292.228 | -16.5 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 366.759 | 292.228 | 25.5 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 214.288 | 292.228 | -26.7 |
| L3 | mldsa65 | hqc192 | pq_pur | 449.463 | 292.228 | 53.8 |
| L3 | secp384r1 | hqc192 | pq_pur | 264.226 | 292.228 | -9.6 |
| L3 | mldsa65 | mlkem768 | pq_pur | 382.199 | 292.228 | 30.8 |
| L3 | secp384r1 | mlkem768 | pq_pur | 186.889 | 292.228 | -36.0 |
| L5 | mldsa87 | P-521 | classique | 382.282 | 287.26 | 33.1 |
| L5 | secp521r1 | P-521 | classique | 192.237 | 287.26 | -33.1 |
| L5 | mldsa87 | p521_hqc256 | hybride | 961.931 | 287.26 | 234.9 |
| L5 | secp521r1 | p521_hqc256 | hybride | 923.362 | 287.26 | 221.4 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 415.843 | 287.26 | 44.8 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 213.308 | 287.26 | -25.7 |
| L5 | mldsa87 | hqc256 | pq_pur | 952.864 | 287.26 | 231.7 |
| L5 | secp521r1 | hqc256 | pq_pur | 908.075 | 287.26 | 216.1 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 380.0 | 287.26 | 32.3 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 205.535 | 287.26 | -28.4 |

## Comparaison appariée classique vs ML-DSA (même KEM, même niveau)

Remplace la logique de chevauchement de deux IC95% séparés : l'IC95% porte directement sur Δ = classique − ML-DSA, par bootstrap de blocs APPARIÉS (même block_index des deux côtés). `exact_permutation_p` est un test de permutation exact complémentaire (2^n_blocs arrangements) ; sa p-value minimale atteignable (`exact_permutation_min_p`) doit être citée à chaque fois que ce nombre est mentionné dans l'article.

| Niveau | KEM | Classique (ms) | ML-DSA (ms) | Δ (ms) | IC95% de Δ | Signif. (bootstrap apparié) | p exacte | p min. atteignable |
|---|---|---|---|---|---|---|---|---|
| L1 | P-256 | 181.3339 | 390.4121 | -209.0781 | [-218.0071, -200.1492] | oui | 0.125 | 0.125 |
| L1 | hqc128 | 224.8058 | 395.2139 | -170.4081 | [-183.5336, -154.9304] | oui | 0.125 | 0.125 |
| L1 | mlkem512 | 208.4303 | 378.3672 | -169.9369 | [-212.3554, -127.5184] | oui | 0.125 | 0.125 |
| L1 | p256_hqc128 | 221.3047 | 390.5441 | -169.2394 | [-182.8846, -157.8588] | oui | 0.125 | 0.125 |
| L1 | p256_mlkem512 | 195.9276 | 378.9341 | -183.0065 | [-208.7432, -157.2698] | oui | 0.125 | 0.125 |
| L1 | x25519 | 177.0729 | 374.6212 | -197.5483 | [-208.9956, -186.1011] | oui | 0.125 | 0.125 |
| L1 | x25519_hqc128 | 213.2039 | 401.9398 | -188.7359 | [-195.3004, -182.1715] | oui | 0.125 | 0.125 |
| L1 | x25519_mlkem512 | 206.578 | 371.0684 | -164.4904 | [-184.6257, -145.2021] | oui | 0.125 | 0.125 |
| L3 | P-384 | 190.0049 | 400.8313 | -210.8264 | [-231.7805, -191.4172] | oui | 0.125 | 0.125 |
| L3 | hqc192 | 264.2256 | 449.4632 | -185.2376 | [-210.2587, -166.8632] | oui | 0.125 | 0.125 |
| L3 | mlkem768 | 186.8889 | 382.1987 | -195.3098 | [-204.778, -180.0025] | oui | 0.125 | 0.125 |
| L3 | p384_hqc192 | 277.0789 | 453.6278 | -176.5489 | [-180.9471, -172.1508] | oui | 0.125 | 0.125 |
| L3 | p384_mlkem768 | 230.3929 | 394.995 | -164.6021 | [-183.2626, -147.815] | oui | 0.125 | 0.125 |
| L3 | x448 | 189.8951 | 388.1795 | -198.2844 | [-221.623, -174.9458] | oui | 0.125 | 0.125 |
| L3 | x448_hqc192 | 243.9579 | 430.6863 | -186.7284 | [-204.6768, -169.4496] | oui | 0.125 | 0.125 |
| L3 | x448_mlkem768 | 214.2885 | 366.7591 | -152.4706 | [-162.8206, -140.3887] | oui | 0.125 | 0.125 |
| L5 | P-521 | 192.2367 | 382.2822 | -190.0456 | [-195.2409, -183.7717] | oui | 0.125 | 0.125 |
| L5 | hqc256 | 908.0748 | 952.864 | -44.7892 | [-65.5002, -31.3048] | oui | 0.125 | 0.125 |
| L5 | mlkem1024 | 205.5346 | 379.9996 | -174.465 | [-200.3011, -150.1347] | oui | 0.125 | 0.125 |
| L5 | p521_hqc256 | 923.3617 | 961.9314 | -38.5697 | [-55.4696, -16.9587] | oui | 0.125 | 0.125 |
| L5 | p521_mlkem1024 | 213.3084 | 415.8431 | -202.5348 | [-220.7379, -185.3167] | oui | 0.125 | 0.125 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.