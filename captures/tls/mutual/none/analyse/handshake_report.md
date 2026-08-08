# Performance de handshake — captures/tls/mutual/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 100.0 | 5.38 | [5.35, 5.41] | 5.32 | 6.09 | 6.37 |
| L1 | ed25519 | x25519 | classique | 500 | 100.0 | 5.416 | [5.382, 5.45] | 5.3 | 6.22 | 6.57 |
| L1 | mldsa44 | P-256 | classique | 500 | 100.0 | 22.642 | [22.524, 22.76] | 22.325 | 25.261 | 27.495 |
| L1 | mldsa44 | x25519 | classique | 500 | 100.0 | 22.434 | [22.343, 22.524] | 22.25 | 24.232 | 25.622 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 100.0 | 26.384 | [26.184, 26.584] | 25.875 | 29.984 | 37.222 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 100.0 | 11.05 | [10.992, 11.108] | 10.92 | 12.24 | 12.88 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 100.0 | 21.174 | [21.076, 21.272] | 21.095 | 22.581 | 23.919 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 100.0 | 5.922 | [5.883, 5.961] | 5.8 | 6.791 | 7.5 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 100.0 | 42.487 | [42.216, 42.758] | 41.815 | 45.277 | 60.087 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 100.0 | 28.569 | [28.369, 28.769] | 28.185 | 31.89 | 36.919 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 100.0 | 37.01 | [36.87, 37.15] | 36.595 | 39.531 | 41.273 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 100.0 | 22.921 | [22.78, 23.062] | 22.63 | 25.093 | 29.444 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 100.0 | 21.046 | [20.938, 21.153] | 21.02 | 22.492 | 24.131 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 100.0 | 5.749 | [5.709, 5.789] | 5.615 | 6.6 | 7.3 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 100.0 | 37.214 | [36.988, 37.441] | 36.56 | 40.165 | 50.317 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 100.0 | 22.394 | [22.307, 22.48] | 22.27 | 24.173 | 25.207 |
| L3 | mldsa65 | P-384 | classique | 500 | 100.0 | 33.131 | [32.923, 33.34] | 32.495 | 36.484 | 42.084 |
| L3 | mldsa65 | x448 | classique | 500 | 100.0 | 31.741 | [31.647, 31.834] | 31.47 | 34.12 | 35.221 |
| L3 | secp384r1 | P-384 | classique | 500 | 100.0 | 9.015 | [8.959, 9.07] | 8.9 | 10.21 | 10.96 |
| L3 | secp384r1 | x448 | classique | 500 | 100.0 | 8.533 | [8.482, 8.585] | 8.44 | 9.63 | 10.45 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 100.0 | 80.907 | [80.528, 81.285] | 79.94 | 84.574 | 103.125 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 100.0 | 38.426 | [38.309, 38.543] | 38.23 | 41.13 | 42.301 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 100.0 | 75.585 | [75.338, 75.832] | 74.9 | 79.164 | 85.317 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 100.0 | 32.862 | [32.728, 32.997] | 32.505 | 35.532 | 38.701 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 100.0 | 57.286 | [57.091, 57.48] | 56.77 | 60.782 | 63.767 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 100.0 | 15.124 | [14.987, 15.26] | 14.875 | 16.852 | 21.797 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 100.0 | 52.519 | [52.28, 52.757] | 51.73 | 56.281 | 64.813 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 100.0 | 9.508 | [9.46, 9.557] | 9.43 | 10.49 | 11.261 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 100.0 | 74.413 | [74.195, 74.631] | 73.86 | 77.723 | 84.505 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 100.0 | 30.818 | [30.726, 30.911] | 30.635 | 32.92 | 34.292 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 100.0 | 50.854 | [50.66, 51.049] | 50.255 | 54.81 | 57.972 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 100.0 | 7.994 | [7.928, 8.061] | 7.84 | 9.0 | 11.004 |
| L5 | mldsa87 | P-521 | classique | 500 | 100.0 | 48.213 | [48.001, 48.425] | 47.6 | 51.111 | 60.767 |
| L5 | secp521r1 | P-521 | classique | 500 | 100.0 | 9.808 | [9.756, 9.86] | 9.72 | 10.85 | 11.353 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 100.0 | 131.731 | [131.277, 132.186] | 130.98 | 135.526 | 163.172 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 100.0 | 54.025 | [53.834, 54.215] | 53.555 | 57.111 | 61.032 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 100.0 | 94.225 | [93.905, 94.544] | 93.47 | 98.26 | 110.201 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 100.0 | 15.293 | [15.22, 15.367] | 15.275 | 16.771 | 17.23 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 100.0 | 125.673 | [125.334, 126.013] | 124.96 | 130.047 | 140.903 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 100.0 | 47.159 | [46.976, 47.341] | 46.78 | 49.63 | 57.548 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 100.0 | 87.802 | [87.456, 88.148] | 86.995 | 91.601 | 108.532 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 100.0 | 8.861 | [8.815, 8.908] | 8.82 | 9.791 | 10.311 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 5.38 | 13.968 | -61.5 |
| L1 | mldsa44 | P-256 | classique | 22.642 | 13.968 | 62.1 |
| L1 | ed25519 | x25519 | classique | 5.416 | 13.968 | -61.2 |
| L1 | mldsa44 | x25519 | classique | 22.434 | 13.968 | 60.6 |
| L1 | ed25519 | p256_hqc128 | hybride | 26.384 | 13.968 | 88.9 |
| L1 | mldsa44 | p256_hqc128 | hybride | 42.487 | 13.968 | 204.2 |
| L1 | ed25519 | p256_mlkem512 | hybride | 11.05 | 13.968 | -20.9 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 28.569 | 13.968 | 104.5 |
| L1 | ed25519 | x25519_hqc128 | hybride | 21.174 | 13.968 | 51.6 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 37.01 | 13.968 | 165.0 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 5.922 | 13.968 | -57.6 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 22.921 | 13.968 | 64.1 |
| L1 | ed25519 | hqc128 | pq_pur | 21.046 | 13.968 | 50.7 |
| L1 | mldsa44 | hqc128 | pq_pur | 37.214 | 13.968 | 166.4 |
| L1 | ed25519 | mlkem512 | pq_pur | 5.749 | 13.968 | -58.8 |
| L1 | mldsa44 | mlkem512 | pq_pur | 22.394 | 13.968 | 60.3 |
| L3 | mldsa65 | P-384 | classique | 33.131 | 20.605 | 60.8 |
| L3 | secp384r1 | P-384 | classique | 9.015 | 20.605 | -56.2 |
| L3 | mldsa65 | x448 | classique | 31.741 | 20.605 | 54.0 |
| L3 | secp384r1 | x448 | classique | 8.533 | 20.605 | -58.6 |
| L3 | mldsa65 | p384_hqc192 | hybride | 80.907 | 20.605 | 292.7 |
| L3 | secp384r1 | p384_hqc192 | hybride | 57.286 | 20.605 | 178.0 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 38.426 | 20.605 | 86.5 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 15.124 | 20.605 | -26.6 |
| L3 | mldsa65 | x448_hqc192 | hybride | 75.585 | 20.605 | 266.8 |
| L3 | secp384r1 | x448_hqc192 | hybride | 52.519 | 20.605 | 154.9 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 32.862 | 20.605 | 59.5 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 9.508 | 20.605 | -53.9 |
| L3 | mldsa65 | hqc192 | pq_pur | 74.413 | 20.605 | 261.1 |
| L3 | secp384r1 | hqc192 | pq_pur | 50.854 | 20.605 | 146.8 |
| L3 | mldsa65 | mlkem768 | pq_pur | 30.818 | 20.605 | 49.6 |
| L3 | secp384r1 | mlkem768 | pq_pur | 7.994 | 20.605 | -61.2 |
| L5 | mldsa87 | P-521 | classique | 48.213 | 29.011 | 66.2 |
| L5 | secp521r1 | P-521 | classique | 9.808 | 29.011 | -66.2 |
| L5 | mldsa87 | p521_hqc256 | hybride | 131.731 | 29.011 | 354.1 |
| L5 | secp521r1 | p521_hqc256 | hybride | 94.225 | 29.011 | 224.8 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 54.025 | 29.011 | 86.2 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 15.293 | 29.011 | -47.3 |
| L5 | mldsa87 | hqc256 | pq_pur | 125.673 | 29.011 | 333.2 |
| L5 | secp521r1 | hqc256 | pq_pur | 87.802 | 29.011 | 202.7 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 47.159 | 29.011 | 62.6 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 8.861 | 29.011 | -69.5 |

## Note méthodologique

Intervalle de confiance à 95% calculé par approximation normale (z=1.96), la taille d'échantillon (n=500 par combinaison dans la majorité des cas) rendant cette approximation valide par le théorème central limite, indépendamment de la forme de la distribution sous-jacente des latences individuelles. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même.