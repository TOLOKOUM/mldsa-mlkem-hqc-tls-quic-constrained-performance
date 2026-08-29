# Performance de handshake — captures/tls/single/simple_loss1.3_delay62.51ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 275.537 | [266.903, 284.171] | bootstrap_blocs | 256.465 | 257.552 | 1261.682 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 266.141 | [260.562, 270.998] | bootstrap_blocs | 255.97 | 256.741 | 636.134 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 278.343 | [267.028, 286.228] | bootstrap_blocs | 255.875 | 379.495 | 1263.809 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 288.326 | [280.361, 297.353] | bootstrap_blocs | 255.615 | 381.241 | 1260.674 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 331.83 | [328.517, 337.076] | bootstrap_blocs | 317.73 | 333.308 | 795.899 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 282.48 | [278.963, 286.244] | bootstrap_blocs | 268.74 | 273.365 | 909.654 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 329.08 | [319.09, 342.185] | bootstrap_blocs | 306.16 | 544.118 | 1285.295 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 284.8 | [271.017, 299.99] | bootstrap_blocs | 257.3 | 258.262 | 1283.725 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 345.129 | [330.897, 359.362] | bootstrap_blocs | 314.325 | 445.641 | 1318.698 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 302.081 | [294.348, 313.671] | bootstrap_blocs | 269.11 | 393.524 | 1324.026 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 332.473 | [320.521, 344.606] | bootstrap_blocs | 303.935 | 433.785 | 1327.316 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 290.754 | [272.925, 303.856] | bootstrap_blocs | 256.535 | 382.907 | 1293.804 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 332.276 | [315.168, 346.934] | bootstrap_blocs | 306.95 | 544.361 | 1322.109 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 273.871 | [264.357, 281.584] | bootstrap_blocs | 256.33 | 257.393 | 1265.845 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 335.841 | [321.904, 349.778] | bootstrap_blocs | 303.815 | 432.087 | 1316.084 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 276.477 | [268.618, 282.733] | bootstrap_blocs | 255.66 | 381.2 | 762.729 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 291.576 | [279.731, 305.882] | bootstrap_blocs | 260.155 | 541.933 | 770.821 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 287.04 | [277.404, 296.675] | bootstrap_blocs | 258.21 | 415.387 | 769.926 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 276.516 | [269.442, 283.591] | bootstrap_blocs | 263.85 | 266.045 | 644.045 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 289.05 | [280.492, 301.295] | bootstrap_blocs | 262.495 | 267.75 | 1286.293 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 480.232 | [462.416, 498.048] | bootstrap_blocs | 442.775 | 724.808 | 1465.016 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 301.198 | [287.199, 314.384] | bootstrap_blocs | 273.315 | 393.245 | 1280.012 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 477.496 | [471.221, 483.77] | bootstrap_blocs | 438.295 | 564.78 | 1470.325 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 297.43 | [287.124, 307.736] | bootstrap_blocs | 260.98 | 417.252 | 1285.554 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 374.628 | [369.209, 380.576] | bootstrap_blocs | 364.14 | 489.289 | 823.879 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 304.86 | [291.669, 321.954] | bootstrap_blocs | 277.3 | 283.443 | 1309.79 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 385.517 | [366.535, 404.499] | bootstrap_blocs | 359.49 | 519.294 | 1356.739 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 291.558 | [290.36, 293.256] | bootstrap_blocs | 265.15 | 268.412 | 1311.959 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 460.246 | [454.479, 466.012] | bootstrap_blocs | 436.86 | 560.296 | 1420.945 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 289.196 | [275.729, 309.429] | bootstrap_blocs | 255.92 | 382.361 | 1280.987 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 373.779 | [364.2, 381.851] | bootstrap_blocs | 358.805 | 463.506 | 1343.45 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 278.182 | [273.644, 283.799] | bootstrap_blocs | 260.22 | 261.631 | 1304.45 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 309.321 | [300.888, 317.388] | bootstrap_blocs | 260.435 | 542.627 | 1310.533 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 279.073 | [270.184, 288.308] | bootstrap_blocs | 264.06 | 266.522 | 655.113 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 550.219 | [540.735, 559.702] | bootstrap_blocs | 512.305 | 711.411 | 1532.595 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 408.878 | [405.506, 413.866] | bootstrap_blocs | 390.455 | 512.433 | 895.077 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 534.741 | [524.798, 544.487] | bootstrap_blocs | 510.63 | 535.45 | 1545.936 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 303.295 | [293.247, 310.918] | bootstrap_blocs | 279.455 | 284.897 | 1281.399 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 543.688 | [532.481, 552.793] | bootstrap_blocs | 511.915 | 650.279 | 1539.159 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 410.966 | [400.04, 421.777] | bootstrap_blocs | 379.2 | 505.824 | 1393.627 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 532.031 | [521.622, 542.44] | bootstrap_blocs | 502.795 | 640.388 | 1481.013 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 279.583 | [272.656, 286.509] | bootstrap_blocs | 261.305 | 262.85 | 1271.339 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 275.537 | 277.087 | -0.6 |
| L1 | mldsa44 | P-256 | classique | 278.343 | 277.087 | 0.5 |
| L1 | ed25519 | x25519 | classique | 266.141 | 277.087 | -4.0 |
| L1 | mldsa44 | x25519 | classique | 288.326 | 277.087 | 4.1 |
| L1 | ed25519 | p256_hqc128 | hybride | 331.83 | 277.087 | 19.8 |
| L1 | mldsa44 | p256_hqc128 | hybride | 345.129 | 277.087 | 24.6 |
| L1 | ed25519 | p256_mlkem512 | hybride | 282.48 | 277.087 | 1.9 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 302.081 | 277.087 | 9.0 |
| L1 | ed25519 | x25519_hqc128 | hybride | 329.08 | 277.087 | 18.8 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 332.473 | 277.087 | 20.0 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 284.8 | 277.087 | 2.8 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 290.754 | 277.087 | 4.9 |
| L1 | ed25519 | hqc128 | pq_pur | 332.276 | 277.087 | 19.9 |
| L1 | mldsa44 | hqc128 | pq_pur | 335.841 | 277.087 | 21.2 |
| L1 | ed25519 | mlkem512 | pq_pur | 273.871 | 277.087 | -1.2 |
| L1 | mldsa44 | mlkem512 | pq_pur | 276.477 | 277.087 | -0.2 |
| L3 | mldsa65 | P-384 | classique | 291.576 | 286.046 | 1.9 |
| L3 | secp384r1 | P-384 | classique | 276.516 | 286.046 | -3.3 |
| L3 | mldsa65 | x448 | classique | 287.04 | 286.046 | 0.3 |
| L3 | secp384r1 | x448 | classique | 289.05 | 286.046 | 1.1 |
| L3 | mldsa65 | p384_hqc192 | hybride | 480.232 | 286.046 | 67.9 |
| L3 | secp384r1 | p384_hqc192 | hybride | 374.628 | 286.046 | 31.0 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 301.198 | 286.046 | 5.3 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 304.86 | 286.046 | 6.6 |
| L3 | mldsa65 | x448_hqc192 | hybride | 477.496 | 286.046 | 66.9 |
| L3 | secp384r1 | x448_hqc192 | hybride | 385.517 | 286.046 | 34.8 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 297.43 | 286.046 | 4.0 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 291.558 | 286.046 | 1.9 |
| L3 | mldsa65 | hqc192 | pq_pur | 460.246 | 286.046 | 60.9 |
| L3 | secp384r1 | hqc192 | pq_pur | 373.779 | 286.046 | 30.7 |
| L3 | mldsa65 | mlkem768 | pq_pur | 289.196 | 286.046 | 1.1 |
| L3 | secp384r1 | mlkem768 | pq_pur | 278.182 | 286.046 | -2.7 |
| L5 | mldsa87 | P-521 | classique | 309.321 | 294.197 | 5.1 |
| L5 | secp521r1 | P-521 | classique | 279.073 | 294.197 | -5.1 |
| L5 | mldsa87 | p521_hqc256 | hybride | 550.219 | 294.197 | 87.0 |
| L5 | secp521r1 | p521_hqc256 | hybride | 534.741 | 294.197 | 81.8 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 408.878 | 294.197 | 39.0 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 303.295 | 294.197 | 3.1 |
| L5 | mldsa87 | hqc256 | pq_pur | 543.688 | 294.197 | 84.8 |
| L5 | secp521r1 | hqc256 | pq_pur | 532.031 | 294.197 | 80.8 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 410.966 | 294.197 | 39.7 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 279.583 | 294.197 | -5.0 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.