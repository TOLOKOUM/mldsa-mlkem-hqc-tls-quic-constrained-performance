# Performance de handshake — captures/quic/single/simple_loss0.3_delay30.02ms

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 100.0 | 68.548 | [61.769, 75.327] | 62.24 | 63.05 | 63.496 |
| L1 | ed25519 | x25519 | classique | 500 | 100.0 | 62.283 | [62.045, 62.521] | 62.05 | 62.77 | 63.06 |
| L1 | mldsa44 | P-256 | classique | 500 | 100.0 | 138.364 | [125.544, 151.184] | 122.48 | 122.95 | 373.777 |
| L1 | mldsa44 | x25519 | classique | 500 | 100.0 | 125.343 | [119.61, 131.077] | 122.275 | 122.611 | 122.864 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 100.0 | 87.267 | [85.08, 89.455] | 83.525 | 98.825 | 106.229 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 100.0 | 77.56 | [70.185, 84.936] | 69.875 | 75.127 | 78.815 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 100.0 | 78.865 | [78.535, 79.195] | 77.56 | 84.84 | 89.09 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 100.0 | 66.176 | [61.912, 70.44] | 63.62 | 64.99 | 65.863 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 100.0 | 148.157 | [145.617, 150.696] | 143.615 | 159.265 | 162.42 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 100.0 | 130.591 | [129.829, 131.354] | 129.19 | 133.76 | 135.053 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 100.0 | 142.586 | [139.16, 146.012] | 137.77 | 149.22 | 155.219 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 100.0 | 124.985 | [123.963, 126.007] | 123.935 | 125.231 | 126.161 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 100.0 | 80.685 | [77.631, 83.738] | 76.9 | 87.003 | 89.691 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 100.0 | 64.395 | [60.132, 68.657] | 62.01 | 62.72 | 63.331 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 100.0 | 142.85 | [137.945, 147.754] | 136.62 | 148.02 | 169.105 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 100.0 | 122.84 | [122.101, 123.578] | 122.32 | 122.9 | 123.17 |
| L3 | mldsa65 | P-384 | classique | 500 | 100.0 | 138.805 | [122.104, 155.507] | 124.49 | 126.44 | 363.213 |
| L3 | mldsa65 | x448 | classique | 500 | 100.0 | 147.365 | [123.921, 170.808] | 123.12 | 124.081 | 126.132 |
| L3 | secp384r1 | P-384 | classique | 500 | 100.0 | 67.898 | [63.971, 71.825] | 65.335 | 68.54 | 68.788 |
| L3 | secp384r1 | x448 | classique | 500 | 100.0 | 64.412 | [64.167, 64.657] | 63.97 | 66.036 | 67.032 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 100.0 | 185.321 | [181.94, 188.702] | 179.265 | 201.994 | 246.751 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 100.0 | 134.05 | [132.39, 135.71] | 131.55 | 137.041 | 139.422 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 100.0 | 182.013 | [178.633, 185.393] | 174.935 | 207.576 | 239.59 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 100.0 | 126.584 | [125.239, 127.929] | 125.19 | 126.802 | 127.838 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 100.0 | 120.587 | [117.434, 123.74] | 114.815 | 137.412 | 154.523 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 100.0 | 76.075 | [71.333, 80.818] | 72.45 | 78.64 | 80.804 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 100.0 | 110.965 | [110.365, 111.565] | 108.24 | 125.644 | 135.193 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 100.0 | 66.584 | [66.329, 66.839] | 66.0 | 68.461 | 69.431 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 100.0 | 176.506 | [171.877, 181.134] | 169.67 | 187.56 | 236.485 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 100.0 | 127.0 | [119.091, 134.91] | 122.36 | 122.79 | 123.19 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 100.0 | 108.214 | [107.64, 108.788] | 105.53 | 121.898 | 130.535 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 100.0 | 65.595 | [61.667, 69.524] | 63.29 | 64.71 | 64.891 |
| L5 | mldsa87 | P-521 | classique | 500 | 100.0 | 143.382 | [122.893, 163.871] | 124.78 | 127.034 | 132.533 |
| L5 | secp521r1 | P-521 | classique | 500 | 100.0 | 71.658 | [64.884, 78.432] | 65.195 | 67.35 | 68.753 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 100.0 | 402.243 | [399.316, 405.169] | 395.035 | 430.141 | 463.977 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 100.0 | 133.752 | [132.747, 134.758] | 132.205 | 138.623 | 140.5 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 100.0 | 393.311 | [391.784, 394.838] | 389.05 | 412.514 | 425.524 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 100.0 | 80.673 | [72.497, 88.848] | 72.3 | 79.512 | 83.167 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 100.0 | 393.353 | [391.193, 395.512] | 386.82 | 417.156 | 448.998 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 100.0 | 131.857 | [120.078, 143.637] | 122.725 | 123.33 | 123.81 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 100.0 | 386.438 | [384.032, 388.845] | 380.15 | 403.871 | 467.93 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 100.0 | 66.257 | [61.524, 70.99] | 63.44 | 64.872 | 65.642 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 68.548 | 98.635 | -30.5 |
| L1 | mldsa44 | P-256 | classique | 138.364 | 98.635 | 40.3 |
| L1 | ed25519 | x25519 | classique | 62.283 | 98.635 | -36.9 |
| L1 | mldsa44 | x25519 | classique | 125.343 | 98.635 | 27.1 |
| L1 | ed25519 | p256_hqc128 | hybride | 87.267 | 98.635 | -11.5 |
| L1 | mldsa44 | p256_hqc128 | hybride | 148.157 | 98.635 | 50.2 |
| L1 | ed25519 | p256_mlkem512 | hybride | 77.56 | 98.635 | -21.4 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 130.591 | 98.635 | 32.4 |
| L1 | ed25519 | x25519_hqc128 | hybride | 78.865 | 98.635 | -20.0 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 142.586 | 98.635 | 44.6 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 66.176 | 98.635 | -32.9 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 124.985 | 98.635 | 26.7 |
| L1 | ed25519 | hqc128 | pq_pur | 80.685 | 98.635 | -18.2 |
| L1 | mldsa44 | hqc128 | pq_pur | 142.85 | 98.635 | 44.8 |
| L1 | ed25519 | mlkem512 | pq_pur | 64.395 | 98.635 | -34.7 |
| L1 | mldsa44 | mlkem512 | pq_pur | 122.84 | 98.635 | 24.5 |
| L3 | mldsa65 | P-384 | classique | 138.805 | 104.62 | 32.7 |
| L3 | secp384r1 | P-384 | classique | 67.898 | 104.62 | -35.1 |
| L3 | mldsa65 | x448 | classique | 147.365 | 104.62 | 40.9 |
| L3 | secp384r1 | x448 | classique | 64.412 | 104.62 | -38.4 |
| L3 | mldsa65 | p384_hqc192 | hybride | 185.321 | 104.62 | 77.1 |
| L3 | secp384r1 | p384_hqc192 | hybride | 120.587 | 104.62 | 15.3 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 134.05 | 104.62 | 28.1 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 76.075 | 104.62 | -27.3 |
| L3 | mldsa65 | x448_hqc192 | hybride | 182.013 | 104.62 | 74.0 |
| L3 | secp384r1 | x448_hqc192 | hybride | 110.965 | 104.62 | 6.1 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 126.584 | 104.62 | 21.0 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 66.584 | 104.62 | -36.4 |
| L3 | mldsa65 | hqc192 | pq_pur | 176.506 | 104.62 | 68.7 |
| L3 | secp384r1 | hqc192 | pq_pur | 108.214 | 104.62 | 3.4 |
| L3 | mldsa65 | mlkem768 | pq_pur | 127.0 | 104.62 | 21.4 |
| L3 | secp384r1 | mlkem768 | pq_pur | 65.595 | 104.62 | -37.3 |
| L5 | mldsa87 | P-521 | classique | 143.382 | 107.52 | 33.4 |
| L5 | secp521r1 | P-521 | classique | 71.658 | 107.52 | -33.4 |
| L5 | mldsa87 | p521_hqc256 | hybride | 402.243 | 107.52 | 274.1 |
| L5 | secp521r1 | p521_hqc256 | hybride | 393.311 | 107.52 | 265.8 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 133.752 | 107.52 | 24.4 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 80.673 | 107.52 | -25.0 |
| L5 | mldsa87 | hqc256 | pq_pur | 393.353 | 107.52 | 265.8 |
| L5 | secp521r1 | hqc256 | pq_pur | 386.438 | 107.52 | 259.4 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 131.857 | 107.52 | 22.6 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 66.257 | 107.52 | -38.4 |

## Note méthodologique

Intervalle de confiance à 95% calculé par approximation normale (z=1.96), la taille d'échantillon (n=500 par combinaison dans la majorité des cas) rendant cette approximation valide par le théorème central limite, indépendamment de la forme de la distribution sous-jacente des latences individuelles. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même.