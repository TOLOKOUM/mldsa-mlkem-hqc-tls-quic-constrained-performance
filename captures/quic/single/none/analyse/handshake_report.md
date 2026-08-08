# Performance de handshake — captures/quic/single/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 100.0 | 2.152 | [2.122, 2.182] | 2.01 | 2.841 | 3.391 |
| L1 | ed25519 | x25519 | classique | 500 | 100.0 | 1.869 | [1.848, 1.891] | 1.77 | 2.301 | 2.62 |
| L1 | mldsa44 | P-256 | classique | 500 | 100.0 | 2.216 | [2.189, 2.243] | 2.11 | 2.79 | 3.37 |
| L1 | mldsa44 | x25519 | classique | 500 | 100.0 | 2.019 | [1.994, 2.045] | 1.97 | 2.581 | 3.03 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 100.0 | 25.582 | [25.27, 25.894] | 23.79 | 33.992 | 34.691 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 100.0 | 10.02 | [9.879, 10.161] | 9.555 | 13.96 | 14.832 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 100.0 | 20.063 | [19.806, 20.32] | 18.255 | 25.25 | 25.65 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 100.0 | 3.455 | [3.416, 3.494] | 3.22 | 4.32 | 4.49 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 100.0 | 25.287 | [25.001, 25.574] | 23.76 | 33.81 | 34.68 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 100.0 | 9.864 | [9.732, 9.997] | 9.32 | 13.69 | 14.02 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 100.0 | 19.635 | [19.377, 19.892] | 18.09 | 25.282 | 29.094 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 100.0 | 3.641 | [3.597, 3.685] | 3.48 | 4.59 | 4.94 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 100.0 | 17.614 | [17.405, 17.822] | 16.38 | 22.671 | 23.41 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 100.0 | 1.95 | [1.922, 1.977] | 1.86 | 2.491 | 3.23 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 100.0 | 18.102 | [17.865, 18.339] | 16.575 | 23.02 | 23.952 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 100.0 | 1.937 | [1.911, 1.962] | 1.86 | 2.511 | 3.06 |
| L3 | mldsa65 | P-384 | classique | 500 | 100.0 | 4.546 | [4.496, 4.596] | 4.33 | 5.641 | 6.171 |
| L3 | mldsa65 | x448 | classique | 500 | 100.0 | 3.049 | [3.014, 3.084] | 2.905 | 3.78 | 4.33 |
| L3 | secp384r1 | P-384 | classique | 500 | 100.0 | 5.781 | [5.706, 5.856] | 5.44 | 7.511 | 8.322 |
| L3 | secp384r1 | x448 | classique | 500 | 100.0 | 4.189 | [4.132, 4.247] | 3.87 | 5.63 | 6.161 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 100.0 | 58.537 | [57.969, 59.105] | 55.82 | 74.465 | 79.284 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 100.0 | 12.653 | [12.473, 12.833] | 11.81 | 17.352 | 18.061 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 100.0 | 50.637 | [50.242, 51.033] | 49.14 | 62.865 | 67.731 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 100.0 | 5.26 | [5.197, 5.322] | 5.07 | 6.52 | 7.5 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 100.0 | 59.126 | [58.524, 59.728] | 56.385 | 77.044 | 80.483 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 100.0 | 13.707 | [13.521, 13.893] | 12.85 | 18.96 | 21.013 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 100.0 | 52.695 | [52.158, 53.232] | 49.675 | 67.431 | 70.22 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 100.0 | 6.476 | [6.391, 6.562] | 6.09 | 8.441 | 9.532 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 100.0 | 49.12 | [48.578, 49.662] | 46.275 | 62.221 | 68.832 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 100.0 | 2.174 | [2.147, 2.201] | 2.12 | 2.72 | 3.3 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 100.0 | 49.325 | [48.772, 49.878] | 46.8 | 62.693 | 71.412 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 100.0 | 3.436 | [3.389, 3.482] | 3.23 | 4.54 | 4.871 |
| L5 | mldsa87 | P-521 | classique | 500 | 100.0 | 4.42 | [4.37, 4.471] | 4.175 | 5.6 | 6.162 |
| L5 | secp521r1 | P-521 | classique | 500 | 100.0 | 5.837 | [5.754, 5.92] | 5.41 | 7.54 | 8.553 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 100.0 | 91.37 | [90.877, 91.862] | 88.575 | 102.188 | 111.773 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 100.0 | 12.27 | [12.113, 12.428] | 11.57 | 16.7 | 17.83 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 100.0 | 95.637 | [94.989, 96.284] | 92.27 | 112.681 | 119.121 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 100.0 | 13.92 | [13.721, 14.119] | 12.915 | 18.99 | 20.162 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 100.0 | 84.271 | [83.7, 84.842] | 81.37 | 101.16 | 106.12 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 100.0 | 2.343 | [2.299, 2.386] | 2.245 | 3.03 | 3.422 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 100.0 | 85.53 | [84.904, 86.156] | 82.43 | 101.758 | 107.355 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 100.0 | 3.668 | [3.617, 3.719] | 3.455 | 4.69 | 5.431 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 2.152 | 2.064 | 4.3 |
| L1 | mldsa44 | P-256 | classique | 2.216 | 2.064 | 7.4 |
| L1 | ed25519 | x25519 | classique | 1.869 | 2.064 | -9.4 |
| L1 | mldsa44 | x25519 | classique | 2.019 | 2.064 | -2.2 |
| L1 | ed25519 | p256_hqc128 | hybride | 25.582 | 2.064 | 1139.4 |
| L1 | mldsa44 | p256_hqc128 | hybride | 25.287 | 2.064 | 1125.1 |
| L1 | ed25519 | p256_mlkem512 | hybride | 10.02 | 2.064 | 385.5 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 9.864 | 2.064 | 377.9 |
| L1 | ed25519 | x25519_hqc128 | hybride | 20.063 | 2.064 | 872.0 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 19.635 | 2.064 | 851.3 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 3.455 | 2.064 | 67.4 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 3.641 | 2.064 | 76.4 |
| L1 | ed25519 | hqc128 | pq_pur | 17.614 | 2.064 | 753.4 |
| L1 | mldsa44 | hqc128 | pq_pur | 18.102 | 2.064 | 777.0 |
| L1 | ed25519 | mlkem512 | pq_pur | 1.95 | 2.064 | -5.5 |
| L1 | mldsa44 | mlkem512 | pq_pur | 1.937 | 2.064 | -6.2 |
| L3 | mldsa65 | P-384 | classique | 4.546 | 4.391 | 3.5 |
| L3 | secp384r1 | P-384 | classique | 5.781 | 4.391 | 31.7 |
| L3 | mldsa65 | x448 | classique | 3.049 | 4.391 | -30.6 |
| L3 | secp384r1 | x448 | classique | 4.189 | 4.391 | -4.6 |
| L3 | mldsa65 | p384_hqc192 | hybride | 58.537 | 4.391 | 1233.1 |
| L3 | secp384r1 | p384_hqc192 | hybride | 59.126 | 4.391 | 1246.5 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 12.653 | 4.391 | 188.2 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 13.707 | 4.391 | 212.2 |
| L3 | mldsa65 | x448_hqc192 | hybride | 50.637 | 4.391 | 1053.2 |
| L3 | secp384r1 | x448_hqc192 | hybride | 52.695 | 4.391 | 1100.1 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 5.26 | 4.391 | 19.8 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 6.476 | 4.391 | 47.5 |
| L3 | mldsa65 | hqc192 | pq_pur | 49.12 | 4.391 | 1018.7 |
| L3 | secp384r1 | hqc192 | pq_pur | 49.325 | 4.391 | 1023.3 |
| L3 | mldsa65 | mlkem768 | pq_pur | 2.174 | 4.391 | -50.5 |
| L3 | secp384r1 | mlkem768 | pq_pur | 3.436 | 4.391 | -21.7 |
| L5 | mldsa87 | P-521 | classique | 4.42 | 5.128 | -13.8 |
| L5 | secp521r1 | P-521 | classique | 5.837 | 5.128 | 13.8 |
| L5 | mldsa87 | p521_hqc256 | hybride | 91.37 | 5.128 | 1681.8 |
| L5 | secp521r1 | p521_hqc256 | hybride | 95.637 | 5.128 | 1765.0 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 12.27 | 5.128 | 139.3 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 13.92 | 5.128 | 171.5 |
| L5 | mldsa87 | hqc256 | pq_pur | 84.271 | 5.128 | 1543.4 |
| L5 | secp521r1 | hqc256 | pq_pur | 85.53 | 5.128 | 1567.9 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 2.343 | 5.128 | -54.3 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 3.668 | 5.128 | -28.5 |

## Note méthodologique

Intervalle de confiance à 95% calculé par approximation normale (z=1.96), la taille d'échantillon (n=500 par combinaison dans la majorité des cas) rendant cette approximation valide par le théorème central limite, indépendamment de la forme de la distribution sous-jacente des latences individuelles. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même.