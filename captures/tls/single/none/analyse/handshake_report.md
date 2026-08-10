# Performance de handshake — captures/tls/single/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 100.0 | 4.717 | [4.59, 4.844] | 5.425 | 6.473 | 7.251 |
| L1 | ed25519 | x25519 | classique | 500 | 100.0 | 4.486 | [4.371, 4.6] | 4.925 | 6.31 | 7.25 |
| L1 | mldsa44 | P-256 | classique | 500 | 100.0 | 1.62 | [1.608, 1.632] | 1.58 | 1.94 | 2.1 |
| L1 | mldsa44 | x25519 | classique | 500 | 100.0 | 1.519 | [1.506, 1.531] | 1.48 | 1.81 | 2.04 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 100.0 | 21.629 | [21.554, 21.704] | 21.41 | 23.24 | 24.02 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 100.0 | 18.68 | [18.136, 19.224] | 19.055 | 26.51 | 27.97 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 100.0 | 16.599 | [16.538, 16.66] | 16.46 | 17.682 | 18.261 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 100.0 | 2.048 | [2.032, 2.063] | 1.99 | 2.47 | 2.71 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 100.0 | 22.461 | [22.072, 22.85] | 20.53 | 32.634 | 40.454 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 100.0 | 7.414 | [7.344, 7.484] | 7.23 | 8.962 | 10.111 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 100.0 | 17.68 | [17.328, 18.031] | 15.87 | 27.952 | 31.241 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 100.0 | 1.86 | [1.847, 1.873] | 1.82 | 2.12 | 2.391 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 100.0 | 16.599 | [16.515, 16.683] | 16.37 | 17.861 | 19.321 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 100.0 | 1.749 | [1.734, 1.763] | 1.7 | 2.07 | 2.38 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 100.0 | 16.542 | [16.492, 16.592] | 16.45 | 17.611 | 17.982 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 100.0 | 1.499 | [1.491, 1.507] | 1.48 | 1.64 | 1.86 |
| L3 | mldsa65 | P-384 | classique | 500 | 100.0 | 2.921 | [2.9, 2.941] | 2.86 | 3.361 | 3.85 |
| L3 | mldsa65 | x448 | classique | 500 | 100.0 | 2.343 | [2.327, 2.358] | 2.29 | 2.72 | 2.98 |
| L3 | secp384r1 | P-384 | classique | 500 | 100.0 | 4.036 | [4.016, 4.056] | 3.98 | 4.45 | 4.79 |
| L3 | secp384r1 | x448 | classique | 500 | 100.0 | 3.622 | [3.601, 3.643] | 3.56 | 4.14 | 4.46 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 100.0 | 51.271 | [51.164, 51.377] | 50.89 | 53.624 | 55.841 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 100.0 | 8.72 | [8.68, 8.76] | 8.645 | 9.561 | 9.98 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 100.0 | 45.91 | [45.837, 45.982] | 45.685 | 47.191 | 49.671 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 100.0 | 3.205 | [3.185, 3.225] | 3.13 | 3.72 | 3.94 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 100.0 | 51.935 | [51.821, 52.049] | 51.52 | 54.437 | 55.678 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 100.0 | 9.936 | [9.892, 9.979] | 9.855 | 10.82 | 11.652 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 100.0 | 48.752 | [48.167, 49.337] | 46.72 | 64.333 | 78.992 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 100.0 | 4.502 | [4.477, 4.528] | 4.42 | 4.99 | 5.55 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 100.0 | 44.946 | [44.853, 45.04] | 44.74 | 46.361 | 48.071 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 100.0 | 1.638 | [1.624, 1.652] | 1.59 | 1.99 | 2.18 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 100.0 | 47.274 | [46.682, 47.866] | 45.225 | 62.628 | 79.377 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 100.0 | 2.991 | [2.972, 3.009] | 2.94 | 3.391 | 3.72 |
| L5 | mldsa87 | P-521 | classique | 500 | 100.0 | 2.911 | [2.893, 2.929] | 2.84 | 3.37 | 3.62 |
| L5 | secp521r1 | P-521 | classique | 500 | 100.0 | 5.245 | [5.106, 5.383] | 4.505 | 8.862 | 10.613 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 100.0 | 87.514 | [87.381, 87.647] | 87.125 | 89.841 | 93.412 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 100.0 | 8.774 | [8.735, 8.814] | 8.7 | 9.601 | 9.832 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 100.0 | 88.17 | [88.017, 88.322] | 87.79 | 90.693 | 94.5 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 100.0 | 10.103 | [10.06, 10.146] | 10.035 | 10.98 | 11.481 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 100.0 | 81.206 | [81.101, 81.311] | 80.945 | 83.243 | 85.062 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 100.0 | 1.779 | [1.764, 1.793] | 1.715 | 2.14 | 2.35 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 100.0 | 84.111 | [83.461, 84.761] | 81.98 | 97.456 | 117.174 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 100.0 | 3.224 | [3.207, 3.241] | 3.16 | 3.61 | 3.86 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 4.717 | 3.085 | 52.9 |
| L1 | mldsa44 | P-256 | classique | 1.62 | 3.085 | -47.5 |
| L1 | ed25519 | x25519 | classique | 4.486 | 3.085 | 45.4 |
| L1 | mldsa44 | x25519 | classique | 1.519 | 3.085 | -50.8 |
| L1 | ed25519 | p256_hqc128 | hybride | 21.629 | 3.085 | 601.1 |
| L1 | mldsa44 | p256_hqc128 | hybride | 22.461 | 3.085 | 628.1 |
| L1 | ed25519 | p256_mlkem512 | hybride | 18.68 | 3.085 | 505.5 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 7.414 | 3.085 | 140.3 |
| L1 | ed25519 | x25519_hqc128 | hybride | 16.599 | 3.085 | 438.1 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 17.68 | 3.085 | 473.1 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 2.048 | 3.085 | -33.6 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 1.86 | 3.085 | -39.7 |
| L1 | ed25519 | hqc128 | pq_pur | 16.599 | 3.085 | 438.1 |
| L1 | mldsa44 | hqc128 | pq_pur | 16.542 | 3.085 | 436.2 |
| L1 | ed25519 | mlkem512 | pq_pur | 1.749 | 3.085 | -43.3 |
| L1 | mldsa44 | mlkem512 | pq_pur | 1.499 | 3.085 | -51.4 |
| L3 | mldsa65 | P-384 | classique | 2.921 | 3.23 | -9.6 |
| L3 | secp384r1 | P-384 | classique | 4.036 | 3.23 | 25.0 |
| L3 | mldsa65 | x448 | classique | 2.343 | 3.23 | -27.5 |
| L3 | secp384r1 | x448 | classique | 3.622 | 3.23 | 12.1 |
| L3 | mldsa65 | p384_hqc192 | hybride | 51.271 | 3.23 | 1487.3 |
| L3 | secp384r1 | p384_hqc192 | hybride | 51.935 | 3.23 | 1507.9 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 8.72 | 3.23 | 170.0 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 9.936 | 3.23 | 207.6 |
| L3 | mldsa65 | x448_hqc192 | hybride | 45.91 | 3.23 | 1321.4 |
| L3 | secp384r1 | x448_hqc192 | hybride | 48.752 | 3.23 | 1409.3 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 3.205 | 3.23 | -0.8 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 4.502 | 3.23 | 39.4 |
| L3 | mldsa65 | hqc192 | pq_pur | 44.946 | 3.23 | 1291.5 |
| L3 | secp384r1 | hqc192 | pq_pur | 47.274 | 3.23 | 1363.6 |
| L3 | mldsa65 | mlkem768 | pq_pur | 1.638 | 3.23 | -49.3 |
| L3 | secp384r1 | mlkem768 | pq_pur | 2.991 | 3.23 | -7.4 |
| L5 | mldsa87 | P-521 | classique | 2.911 | 4.078 | -28.6 |
| L5 | secp521r1 | P-521 | classique | 5.245 | 4.078 | 28.6 |
| L5 | mldsa87 | p521_hqc256 | hybride | 87.514 | 4.078 | 2046.0 |
| L5 | secp521r1 | p521_hqc256 | hybride | 88.17 | 4.078 | 2062.1 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 8.774 | 4.078 | 115.2 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 10.103 | 4.078 | 147.7 |
| L5 | mldsa87 | hqc256 | pq_pur | 81.206 | 4.078 | 1891.3 |
| L5 | secp521r1 | hqc256 | pq_pur | 84.111 | 4.078 | 1962.6 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 1.779 | 4.078 | -56.4 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 3.224 | 4.078 | -20.9 |

## Note méthodologique

Intervalle de confiance à 95% calculé par approximation normale (z=1.96), la taille d'échantillon (n=500 par combinaison dans la majorité des cas) rendant cette approximation valide par le théorème central limite, indépendamment de la forme de la distribution sous-jacente des latences individuelles. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même.