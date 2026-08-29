# Performance de handshake — captures/tls/mutual/unstable

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 1069.716 | [928.302, 1172.957] | bootstrap_blocs | 424.155 | 4105.526 | 7219.545 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 99.8 | 1435.376 | [1273.496, 1646.146] | bootstrap_blocs | 423.4 | 5167.198 | 13766.404 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 3087.558 | [2696.236, 3572.315] | bootstrap_blocs | 1073.63 | 11460.804 | 52573.525 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 99.4 | 3347.571 | [3147.736, 3546.604] | bootstrap_blocs | 1075.9 | 9169.236 | 67146.909 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 99.8 | 3139.15 | [2857.933, 3533.609] | bootstrap_blocs | 671.35 | 9007.653 | 58928.71 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 99.8 | 1659.07 | [1288.163, 2028.494] | bootstrap_blocs | 633.98 | 4973.225 | 14540.356 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 99.4 | 2964.211 | [2235.566, 4052.366] | bootstrap_blocs | 848.41 | 8266.382 | 53792.843 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 1494.638 | [1153.605, 1835.672] | bootstrap_blocs | 231.145 | 5801.664 | 14400.622 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 99.4 | 3996.016 | [3590.371, 4353.438] | bootstrap_blocs | 1292.14 | 14171.482 | 64836.811 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 99.8 | 4141.668 | [3378.778, 4907.621] | bootstrap_blocs | 1106.77 | 10061.599 | 85152.625 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 99.2 | 4642.262 | [4151.808, 5213.98] | bootstrap_blocs | 1473.45 | 15762.358 | 57676.246 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 99.2 | 2997.358 | [2322.034, 3667.257] | bootstrap_blocs | 1094.405 | 10269.01 | 32834.717 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 99.6 | 2874.176 | [2375.001, 3287.972] | bootstrap_blocs | 847.505 | 11486.554 | 53648.01 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 99.8 | 1566.668 | [1261.215, 1873.347] | bootstrap_blocs | 224.02 | 5629.763 | 23262.675 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 99.2 | 4197.801 | [3558.768, 4842.009] | bootstrap_blocs | 1472.485 | 15192.52 | 56179.946 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 99.4 | 3331.918 | [2429.223, 3979.692] | bootstrap_blocs | 1066.31 | 9910.832 | 55049.472 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 99.8 | 3273.394 | [2657.208, 4208.032] | bootstrap_blocs | 1079.87 | 10857.767 | 53143.425 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 99.6 | 3612.152 | [2932.589, 4133.33] | bootstrap_blocs | 1098.93 | 13330.937 | 56141.806 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 1490.243 | [1173.852, 1785.854] | bootstrap_blocs | 447.885 | 4401.741 | 26812.102 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 99.8 | 1007.675 | [894.665, 1184.507] | bootstrap_blocs | 427.74 | 3385.34 | 7426.623 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 99.8 | 6360.527 | [5148.316, 8466.992] | bootstrap_blocs | 1718.13 | 21290.566 | 108353.321 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 99.4 | 4322.472 | [3123.421, 5538.245] | bootstrap_blocs | 1327.03 | 14656.588 | 64777.8 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 99.0 | 8650.944 | [5859.738, 11524.948] | bootstrap_blocs | 1926.8 | 30601.97 | 109788.642 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 99.8 | 3814.303 | [3064.781, 4317.711] | bootstrap_blocs | 1135.5 | 14614.886 | 53841.561 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 99.6 | 3762.731 | [2266.654, 5299.349] | bootstrap_blocs | 1233.635 | 14343.42 | 54985.867 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 1550.87 | [1224.834, 1896.682] | bootstrap_blocs | 441.685 | 5962.421 | 14835.399 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 99.6 | 3546.287 | [3202.156, 3890.419] | bootstrap_blocs | 894.375 | 11677.516 | 56621.232 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 99.2 | 1900.332 | [1323.484, 2331.752] | bootstrap_blocs | 240.57 | 5870.767 | 21508.585 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 99.0 | 5913.03 | [4979.309, 7327.198] | bootstrap_blocs | 1928.05 | 20920.842 | 109302.316 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 99.8 | 4430.256 | [3746.393, 5103.375] | bootstrap_blocs | 1266.69 | 16257.853 | 56217.857 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 99.6 | 4163.472 | [3789.796, 4593.765] | bootstrap_blocs | 1303.25 | 19339.116 | 52796.528 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 99.6 | 1450.861 | [1167.64, 1926.244] | bootstrap_blocs | 234.98 | 4429.476 | 13581.587 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 99.8 | 4565.244 | [3826.863, 5119.905] | bootstrap_blocs | 1331.86 | 15310.939 | 54985.133 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 99.8 | 1404.406 | [991.268, 1815.893] | bootstrap_blocs | 426.99 | 4363.809 | 13560.464 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 99.0 | 7665.093 | [6913.932, 8342.572] | bootstrap_blocs | 2771.0 | 34312.612 | 106039.029 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 99.0 | 5585.021 | [4985.755, 6454.719] | bootstrap_blocs | 1536.45 | 21176.487 | 106579.981 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 4 | 99.4 | 4559.325 | [3309.254, 5804.375] | bootstrap_blocs | 1541.67 | 16135.26 | 54794.843 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 99.8 | 1574.246 | [1079.475, 2067.037] | bootstrap_blocs | 252.29 | 4993.306 | 14645.99 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 98.6 | 8111.959 | [6724.009, 9516.905] | bootstrap_blocs | 2379.02 | 37184.38 | 106744.272 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 99.8 | 4483.794 | [3520.215, 5443.52] | bootstrap_blocs | 1495.44 | 19961.312 | 54399.875 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 99.0 | 4999.187 | [3353.646, 6936.349] | bootstrap_blocs | 1546.4 | 15080.418 | 55581.363 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 99.6 | 1525.768 | [1213.888, 1930.166] | bootstrap_blocs | 237.805 | 4665.428 | 20799.023 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 1069.716 | 2235.055 | -52.1 |
| L1 | mldsa44 | P-256 | classique | 3087.558 | 2235.055 | 38.1 |
| L1 | ed25519 | x25519 | classique | 1435.376 | 2235.055 | -35.8 |
| L1 | mldsa44 | x25519 | classique | 3347.571 | 2235.055 | 49.8 |
| L1 | ed25519 | p256_hqc128 | hybride | 3139.15 | 2235.055 | 40.5 |
| L1 | mldsa44 | p256_hqc128 | hybride | 3996.016 | 2235.055 | 78.8 |
| L1 | ed25519 | p256_mlkem512 | hybride | 1659.07 | 2235.055 | -25.8 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 4141.668 | 2235.055 | 85.3 |
| L1 | ed25519 | x25519_hqc128 | hybride | 2964.211 | 2235.055 | 32.6 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 4642.262 | 2235.055 | 107.7 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 1494.638 | 2235.055 | -33.1 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 2997.358 | 2235.055 | 34.1 |
| L1 | ed25519 | hqc128 | pq_pur | 2874.176 | 2235.055 | 28.6 |
| L1 | mldsa44 | hqc128 | pq_pur | 4197.801 | 2235.055 | 87.8 |
| L1 | ed25519 | mlkem512 | pq_pur | 1566.668 | 2235.055 | -29.9 |
| L1 | mldsa44 | mlkem512 | pq_pur | 3331.918 | 2235.055 | 49.1 |
| L3 | mldsa65 | P-384 | classique | 3273.394 | 2345.866 | 39.5 |
| L3 | secp384r1 | P-384 | classique | 1490.243 | 2345.866 | -36.5 |
| L3 | mldsa65 | x448 | classique | 3612.152 | 2345.866 | 54.0 |
| L3 | secp384r1 | x448 | classique | 1007.675 | 2345.866 | -57.0 |
| L3 | mldsa65 | p384_hqc192 | hybride | 6360.527 | 2345.866 | 171.1 |
| L3 | secp384r1 | p384_hqc192 | hybride | 3762.731 | 2345.866 | 60.4 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 4322.472 | 2345.866 | 84.3 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 1550.87 | 2345.866 | -33.9 |
| L3 | mldsa65 | x448_hqc192 | hybride | 8650.944 | 2345.866 | 268.8 |
| L3 | secp384r1 | x448_hqc192 | hybride | 3546.287 | 2345.866 | 51.2 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 3814.303 | 2345.866 | 62.6 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 1900.332 | 2345.866 | -19.0 |
| L3 | mldsa65 | hqc192 | pq_pur | 5913.03 | 2345.866 | 152.1 |
| L3 | secp384r1 | hqc192 | pq_pur | 4163.472 | 2345.866 | 77.5 |
| L3 | mldsa65 | mlkem768 | pq_pur | 4430.256 | 2345.866 | 88.9 |
| L3 | secp384r1 | mlkem768 | pq_pur | 1450.861 | 2345.866 | -38.2 |
| L5 | mldsa87 | P-521 | classique | 4565.244 | 2984.825 | 52.9 |
| L5 | secp521r1 | P-521 | classique | 1404.406 | 2984.825 | -52.9 |
| L5 | mldsa87 | p521_hqc256 | hybride | 7665.093 | 2984.825 | 156.8 |
| L5 | secp521r1 | p521_hqc256 | hybride | 4559.325 | 2984.825 | 52.8 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 5585.021 | 2984.825 | 87.1 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 1574.246 | 2984.825 | -47.3 |
| L5 | mldsa87 | hqc256 | pq_pur | 8111.959 | 2984.825 | 171.8 |
| L5 | secp521r1 | hqc256 | pq_pur | 4999.187 | 2984.825 | 67.5 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 4483.794 | 2984.825 | 50.2 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 1525.768 | 2984.825 | -48.9 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.