# Performance de handshake — captures/tls/mutual/simple_loss1.3_delay62.51ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Blocs | Succès% | Moyenne (ms) | IC95% | Méthode IC | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 4 | 100.0 | 295.342 | [287.236, 303.095] | bootstrap_blocs | 268.46 | 274.627 | 1275.551 |
| L1 | ed25519 | x25519 | classique | 500 | 4 | 100.0 | 291.736 | [281.566, 306.664] | bootstrap_blocs | 269.235 | 271.654 | 1273.24 |
| L1 | mldsa44 | P-256 | classique | 500 | 4 | 100.0 | 342.371 | [333.22, 351.522] | bootstrap_blocs | 327.135 | 432.608 | 1312.792 |
| L1 | mldsa44 | x25519 | classique | 500 | 4 | 100.0 | 340.084 | [331.74, 352.218] | bootstrap_blocs | 305.53 | 432.084 | 1311.155 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 345.559 | [333.983, 357.136] | bootstrap_blocs | 325.45 | 356.18 | 1298.658 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 308.094 | [304.345, 311.843] | bootstrap_blocs | 285.8 | 292.618 | 1287.87 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 340.109 | [320.734, 360.657] | bootstrap_blocs | 314.965 | 451.676 | 985.866 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 289.827 | [282.818, 302.33] | bootstrap_blocs | 269.79 | 272.291 | 1033.397 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 4 | 100.0 | 389.446 | [358.223, 432.251] | bootstrap_blocs | 344.445 | 492.385 | 1358.955 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 4 | 100.0 | 347.822 | [336.319, 366.193] | bootstrap_blocs | 314.745 | 468.285 | 925.62 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 4 | 100.0 | 395.262 | [358.505, 438.051] | bootstrap_blocs | 378.995 | 507.127 | 1388.038 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 4 | 100.0 | 332.874 | [319.306, 343.972] | bootstrap_blocs | 303.445 | 339.011 | 1313.988 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 4 | 100.0 | 346.737 | [326.715, 372.249] | bootstrap_blocs | 318.5 | 462.077 | 1348.766 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 282.04 | [277.12, 288.636] | bootstrap_blocs | 268.865 | 273.161 | 906.497 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 4 | 100.0 | 363.865 | [345.038, 389.624] | bootstrap_blocs | 334.705 | 455.347 | 1328.505 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 4 | 100.0 | 331.318 | [311.564, 351.072] | bootstrap_blocs | 306.475 | 425.757 | 813.544 |
| L3 | mldsa65 | P-384 | classique | 500 | 4 | 100.0 | 362.612 | [337.243, 387.981] | bootstrap_blocs | 351.515 | 477.133 | 1185.747 |
| L3 | mldsa65 | x448 | classique | 500 | 4 | 100.0 | 363.56 | [338.923, 408.519] | bootstrap_blocs | 318.66 | 510.437 | 1323.633 |
| L3 | secp384r1 | P-384 | classique | 500 | 4 | 100.0 | 302.976 | [291.582, 311.154] | bootstrap_blocs | 280.565 | 290.641 | 1304.144 |
| L3 | secp384r1 | x448 | classique | 500 | 4 | 100.0 | 299.686 | [287.581, 311.791] | bootstrap_blocs | 279.785 | 283.969 | 1285.044 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 546.117 | [511.835, 597.235] | bootstrap_blocs | 500.68 | 700.418 | 1521.866 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 359.525 | [340.174, 388.802] | bootstrap_blocs | 326.28 | 448.937 | 1319.599 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 520.999 | [499.262, 554.468] | bootstrap_blocs | 493.815 | 617.304 | 1049.667 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 360.3 | [349.02, 379.951] | bootstrap_blocs | 319.23 | 489.531 | 1344.026 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 4 | 100.0 | 407.369 | [378.733, 455.752] | bootstrap_blocs | 372.43 | 499.271 | 844.993 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 4 | 100.0 | 317.582 | [313.162, 322.901] | bootstrap_blocs | 292.805 | 308.909 | 1307.762 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 4 | 100.0 | 400.73 | [371.419, 443.942] | bootstrap_blocs | 368.16 | 495.816 | 980.434 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 4 | 100.0 | 298.07 | [293.137, 303.004] | bootstrap_blocs | 283.11 | 287.031 | 935.075 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 4 | 100.0 | 541.289 | [505.324, 605.057] | bootstrap_blocs | 493.98 | 693.736 | 1528.179 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 372.421 | [352.242, 387.461] | bootstrap_blocs | 356.3 | 494.132 | 1309.553 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 4 | 100.0 | 404.748 | [373.591, 442.11] | bootstrap_blocs | 368.72 | 469.02 | 871.46 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 4 | 100.0 | 292.034 | [287.533, 298.382] | bootstrap_blocs | 278.15 | 284.156 | 909.108 |
| L5 | mldsa87 | P-521 | classique | 500 | 4 | 100.0 | 521.809 | [483.918, 559.7] | bootstrap_blocs | 527.105 | 681.563 | 1479.519 |
| L5 | secp521r1 | P-521 | classique | 500 | 4 | 100.0 | 299.241 | [293.714, 306.083] | bootstrap_blocs | 282.855 | 288.644 | 674.606 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 4 | 100.0 | 665.49 | [586.798, 744.181] | bootstrap_blocs | 696.02 | 841.402 | 1595.835 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 509.395 | [475.714, 557.542] | bootstrap_blocs | 461.465 | 589.535 | 1515.284 |
| L5 | secp521r1 | p521_hqc256 | hybride | 375 | 3 | 100.0 | 598.42 | [536.282, 710.996] | bootstrap_blocs | 535.47 | 762.776 | 1095.094 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 4 | 100.0 | 320.54 | [315.618, 325.588] | bootstrap_blocs | 298.355 | 311.528 | 1302.305 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 4 | 100.0 | 638.608 | [582.045, 736.267] | bootstrap_blocs | 565.475 | 869.397 | 1580.249 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 488.502 | [467.422, 523.607] | bootstrap_blocs | 454.39 | 558.076 | 1457.636 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 4 | 100.0 | 611.849 | [535.915, 687.784] | bootstrap_blocs | 649.81 | 751.632 | 1059.4 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 4 | 100.0 | 298.304 | [290.325, 306.283] | bootstrap_blocs | 281.82 | 286.633 | 926.113 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 295.342 | 317.383 | -6.9 |
| L1 | mldsa44 | P-256 | classique | 342.371 | 317.383 | 7.9 |
| L1 | ed25519 | x25519 | classique | 291.736 | 317.383 | -8.1 |
| L1 | mldsa44 | x25519 | classique | 340.084 | 317.383 | 7.2 |
| L1 | ed25519 | p256_hqc128 | hybride | 345.559 | 317.383 | 8.9 |
| L1 | mldsa44 | p256_hqc128 | hybride | 389.446 | 317.383 | 22.7 |
| L1 | ed25519 | p256_mlkem512 | hybride | 308.094 | 317.383 | -2.9 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 347.822 | 317.383 | 9.6 |
| L1 | ed25519 | x25519_hqc128 | hybride | 340.109 | 317.383 | 7.2 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 395.262 | 317.383 | 24.5 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 289.827 | 317.383 | -8.7 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 332.874 | 317.383 | 4.9 |
| L1 | ed25519 | hqc128 | pq_pur | 346.737 | 317.383 | 9.2 |
| L1 | mldsa44 | hqc128 | pq_pur | 363.865 | 317.383 | 14.6 |
| L1 | ed25519 | mlkem512 | pq_pur | 282.04 | 317.383 | -11.1 |
| L1 | mldsa44 | mlkem512 | pq_pur | 331.318 | 317.383 | 4.4 |
| L3 | mldsa65 | P-384 | classique | 362.612 | 332.209 | 9.2 |
| L3 | secp384r1 | P-384 | classique | 302.976 | 332.209 | -8.8 |
| L3 | mldsa65 | x448 | classique | 363.56 | 332.209 | 9.4 |
| L3 | secp384r1 | x448 | classique | 299.686 | 332.209 | -9.8 |
| L3 | mldsa65 | p384_hqc192 | hybride | 546.117 | 332.209 | 64.4 |
| L3 | secp384r1 | p384_hqc192 | hybride | 407.369 | 332.209 | 22.6 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 359.525 | 332.209 | 8.2 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 317.582 | 332.209 | -4.4 |
| L3 | mldsa65 | x448_hqc192 | hybride | 520.999 | 332.209 | 56.8 |
| L3 | secp384r1 | x448_hqc192 | hybride | 400.73 | 332.209 | 20.6 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 360.3 | 332.209 | 8.5 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 298.07 | 332.209 | -10.3 |
| L3 | mldsa65 | hqc192 | pq_pur | 541.289 | 332.209 | 62.9 |
| L3 | secp384r1 | hqc192 | pq_pur | 404.748 | 332.209 | 21.8 |
| L3 | mldsa65 | mlkem768 | pq_pur | 372.421 | 332.209 | 12.1 |
| L3 | secp384r1 | mlkem768 | pq_pur | 292.034 | 332.209 | -12.1 |
| L5 | mldsa87 | P-521 | classique | 521.809 | 410.525 | 27.1 |
| L5 | secp521r1 | P-521 | classique | 299.241 | 410.525 | -27.1 |
| L5 | mldsa87 | p521_hqc256 | hybride | 665.49 | 410.525 | 62.1 |
| L5 | secp521r1 | p521_hqc256 | hybride | 598.42 | 410.525 | 45.8 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 509.395 | 410.525 | 24.1 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 320.54 | 410.525 | -21.9 |
| L5 | mldsa87 | hqc256 | pq_pur | 638.608 | 410.525 | 55.6 |
| L5 | secp521r1 | hqc256 | pq_pur | 611.849 | 410.525 | 49.0 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 488.502 | 410.525 | 19.0 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 298.304 | 410.525 | -27.3 |

## Note méthodologique

Intervalle de confiance à 95% calculé par **bootstrap de blocs entiers** (5000 rééchantillonnages, respectant la corrélation intra-bloc documentée dans l'article, rho1=0.563) pour toute combinaison collectée en plusieurs blocs indépendants ; repli sur l'approximation normale (z=1.96) pour les combinaisons encore sur un seul bloc, avec la colonne 'Méthode IC' indiquant explicitement laquelle a été utilisée ligne par ligne. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même. Des tests de significativité formels (Mann-Whitney U, Cliff's delta, correction FDR de Benjamini-Hochberg) sont générés systématiquement pour chaque combinaison PQ contre le baseline classique pooléé du même niveau -- voir significance_tests_auto.csv dans ce même dossier.