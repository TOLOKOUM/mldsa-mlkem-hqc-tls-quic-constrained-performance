# Performance de handshake — captures/tls/single/simple_loss1.5833_delay83.52ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 367.269 | [358.935, 374.058] | bootstrap_blocs | 340.565 | 342.02 | 1350.126 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 372.829 | [367.98, 378.482] | bootstrap_blocs | 340.06 | 341.355 | 1352.852 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 381.032 | [375.052, 385.637] | bootstrap_blocs | 339.95 | 507.65 | 1674.079 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 377.662 | [366.994, 389.68] | bootstrap_blocs | 339.585 | 550.313 | 1353.222 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 451.821 | [422.805, 478.398] | bootstrap_blocs | 399.495 | 765.757 | 1388.997 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 386.171 | [375.384, 403.197] | bootstrap_blocs | 353.3 | 372.041 | 1522.214 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 432.465 | [419.186, 449.986] | bootstrap_blocs | 390.175 | 708.92 | 1733.088 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 372.967 | [364.927, 384.816] | bootstrap_blocs | 341.21 | 344.566 | 1355.881 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 423.446 | [408.651, 439.014] | bootstrap_blocs | 399.07 | 569.964 | 1048.541 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 395.857 | [382.069, 406.211] | bootstrap_blocs | 353.495 | 523.127 | 1687.248 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 432.465 | [410.538, 449.114] | bootstrap_blocs | 389.005 | 565.053 | 1566.698 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 375.652 | [367.039, 384.265] | bootstrap_blocs | 340.58 | 507.744 | 1021.162 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 420.488 | [405.933, 432.39] | bootstrap_blocs | 387.78 | 707.718 | 1060.342 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 371.095 | [364.488, 378.918] | bootstrap_blocs | 340.43 | 351.574 | 1344.639 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 424.803 | [408.657, 440.95] | bootstrap_blocs | 387.565 | 561.912 | 1401.608 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 376.201 | [365.691, 390.558] | bootstrap_blocs | 339.61 | 508.006 | 1019.488 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 391.066 | [377.237, 404.914] | bootstrap_blocs | 344.12 | 677.338 | 1366.519 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 380.315 | [365.462, 397.412] | bootstrap_blocs | 342.45 | 514.97 | 1683.303 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 372.322 | [359.673, 384.971] | bootstrap_blocs | 348.73 | 354.895 | 1354.576 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 371.037 | [359.988, 382.085] | bootstrap_blocs | 346.66 | 348.71 | 1354.706 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 630.878 | [605.947, 663.249] | bootstrap_blocs | 569.995 | 948.961 | 1917.018 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 412.899 | [407.312, 418.486] | bootstrap_blocs | 358.7 | 533.318 | 1878.633 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 609.02 | [583.027, 639.238] | bootstrap_blocs | 565.395 | 731.899 | 1566.396 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 390.51 | [373.908, 407.112] | bootstrap_blocs | 345.06 | 553.127 | 1355.32 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 488.16 | [452.383, 524.985] | bootstrap_blocs | 450.87 | 638.966 | 1076.873 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 407.471 | [388.783, 424.835] | bootstrap_blocs | 362.58 | 518.934 | 1519.045 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 504.418 | [470.24, 549.248] | bootstrap_blocs | 445.745 | 778.034 | 1627.949 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 369.825 | [360.144, 377.956] | bootstrap_blocs | 349.855 | 356.112 | 1349.511 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 608.893 | [596.101, 628.306] | bootstrap_blocs | 563.705 | 737.346 | 1582.037 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 392.205 | [367.606, 416.805] | bootstrap_blocs | 340.09 | 509.073 | 1874.793 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 496.189 | [474.666, 529.796] | bootstrap_blocs | 443.655 | 802.265 | 1460.518 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 363.424 | [357.845, 367.509] | bootstrap_blocs | 344.19 | 345.952 | 1194.226 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 400.784 | [387.178, 414.391] | bootstrap_blocs | 344.485 | 560.566 | 1854.929 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 374.412 | [364.565, 382.789] | bootstrap_blocs | 349.36 | 351.465 | 1360.715 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 734.742 | [692.366, 811.882] | bootstrap_blocs | 653.285 | 977.472 | 2086.37 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 560.419 | [541.376, 585.66] | bootstrap_blocs | 516.835 | 690.231 | 1862.767 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 705.015 | [653.802, 793.972] | bootstrap_blocs | 635.925 | 838.36 | 1650.259 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 392.369 | [388.68, 396.058] | bootstrap_blocs | 362.93 | 380.587 | 1541.366 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 708.326 | [661.055, 776.661] | bootstrap_blocs | 644.385 | 937.428 | 1390.72 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 549.662 | [542.278, 557.046] | bootstrap_blocs | 505.23 | 673.639 | 1856.824 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 702.635 | [653.935, 771.784] | bootstrap_blocs | 631.08 | 919.1 | 1959.822 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 379.89 | [368.182, 393.295] | bootstrap_blocs | 345.3 | 347.987 | 1517.649 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 367.269 | 374.698 | -2.0 |
| L1 | mldsa44 | P-256 | classique | 381.032 | 374.698 | 1.7 |
| L1 | ed25519 | x25519 | classique | 372.829 | 374.698 | -0.5 |
| L1 | mldsa44 | x25519 | classique | 377.662 | 374.698 | 0.8 |
| L1 | ed25519 | p256_hqc128 | hybride | 451.821 | 374.698 | 20.6 |
| L1 | mldsa44 | p256_hqc128 | hybride | 423.446 | 374.698 | 13.0 |
| L1 | ed25519 | p256_mlkem512 | hybride | 386.171 | 374.698 | 3.1 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 395.857 | 374.698 | 5.6 |
| L1 | ed25519 | x25519_hqc128 | hybride | 432.465 | 374.698 | 15.4 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 432.465 | 374.698 | 15.4 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 372.967 | 374.698 | -0.5 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 375.652 | 374.698 | 0.3 |
| L1 | ed25519 | hqc128 | pq_pur | 420.488 | 374.698 | 12.2 |
| L1 | mldsa44 | hqc128 | pq_pur | 424.803 | 374.698 | 13.4 |
| L1 | ed25519 | mlkem512 | pq_pur | 371.095 | 374.698 | -1.0 |
| L1 | mldsa44 | mlkem512 | pq_pur | 376.201 | 374.698 | 0.4 |
| L3 | mldsa65 | P-384 | classique | 391.066 | 378.685 | 3.3 |
| L3 | secp384r1 | P-384 | classique | 372.322 | 378.685 | -1.7 |
| L3 | mldsa65 | x448 | classique | 380.315 | 378.685 | 0.4 |
| L3 | secp384r1 | x448 | classique | 371.037 | 378.685 | -2.0 |
| L3 | mldsa65 | p384_hqc192 | hybride | 630.878 | 378.685 | 66.6 |
| L3 | secp384r1 | p384_hqc192 | hybride | 488.16 | 378.685 | 28.9 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 412.899 | 378.685 | 9.0 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 407.471 | 378.685 | 7.6 |
| L3 | mldsa65 | x448_hqc192 | hybride | 609.02 | 378.685 | 60.8 |
| L3 | secp384r1 | x448_hqc192 | hybride | 504.418 | 378.685 | 33.2 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 390.51 | 378.685 | 3.1 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 369.825 | 378.685 | -2.3 |
| L3 | mldsa65 | hqc192 | pq_pur | 608.893 | 378.685 | 60.8 |
| L3 | secp384r1 | hqc192 | pq_pur | 496.189 | 378.685 | 31.0 |
| L3 | mldsa65 | mlkem768 | pq_pur | 392.205 | 378.685 | 3.6 |
| L3 | secp384r1 | mlkem768 | pq_pur | 363.424 | 378.685 | -4.0 |
| L5 | mldsa87 | P-521 | classique | 400.784 | 387.598 | 3.4 |
| L5 | secp521r1 | P-521 | classique | 374.412 | 387.598 | -3.4 |
| L5 | mldsa87 | p521_hqc256 | hybride | 734.742 | 387.598 | 89.6 |
| L5 | secp521r1 | p521_hqc256 | hybride | 705.015 | 387.598 | 81.9 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 560.419 | 387.598 | 44.6 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 392.369 | 387.598 | 1.2 |
| L5 | mldsa87 | hqc256 | pq_pur | 708.326 | 387.598 | 82.7 |
| L5 | secp521r1 | hqc256 | pq_pur | 702.635 | 387.598 | 81.3 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 549.662 | 387.598 | 41.8 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 379.89 | 387.598 | -2.0 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.