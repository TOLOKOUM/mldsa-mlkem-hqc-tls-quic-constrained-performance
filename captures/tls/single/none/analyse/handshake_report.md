# Performance de handshake — captures/tls/single/none

**42 combinaison(s) SIG_ALG/KEM analysée(s)**

## Statistiques détaillées

| Niveau | SIG_ALG | KEM | Classe | N | Succès% | Moyenne (ms) | IC95% | Médiane (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 500 | 100.0 | 1.911 | [1.895, 1.928] | 1.86 | 2.25 | 2.541 |
| L1 | ed25519 | x25519 | classique | 500 | 100.0 | 1.772 | [1.757, 1.786] | 1.72 | 2.12 | 2.31 |
| L1 | mldsa44 | P-256 | classique | 500 | 100.0 | 1.601 | [1.587, 1.615] | 1.57 | 1.8 | 2.107 |
| L1 | mldsa44 | x25519 | classique | 500 | 100.0 | 1.687 | [1.669, 1.705] | 1.63 | 2.09 | 2.34 |
| L1 | ed25519 | p256_hqc128 | hybride | 500 | 100.0 | 70.109 | [68.553, 71.665] | 76.685 | 89.369 | 96.486 |
| L1 | ed25519 | p256_mlkem512 | hybride | 500 | 100.0 | 8.684 | [8.301, 9.067] | 8.2 | 10.881 | 14.302 |
| L1 | ed25519 | x25519_hqc128 | hybride | 500 | 100.0 | 49.079 | [48.336, 49.822] | 50.82 | 57.932 | 61.055 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 500 | 100.0 | 2.657 | [2.302, 3.013] | 2.26 | 3.52 | 6.781 |
| L1 | mldsa44 | p256_hqc128 | hybride | 500 | 100.0 | 22.76 | [22.669, 22.851] | 22.72 | 24.3 | 25.684 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 500 | 100.0 | 7.182 | [7.135, 7.229] | 7.055 | 8.26 | 9.26 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 500 | 100.0 | 17.563 | [17.487, 17.64] | 17.5 | 18.75 | 20.241 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 500 | 100.0 | 1.837 | [1.824, 1.851] | 1.79 | 2.17 | 2.43 |
| L1 | ed25519 | hqc128 | pq_pur | 500 | 100.0 | 55.033 | [53.818, 56.248] | 59.18 | 68.621 | 76.452 |
| L1 | ed25519 | mlkem512 | pq_pur | 500 | 100.0 | 1.97 | [1.945, 1.995] | 1.88 | 2.502 | 3.09 |
| L1 | mldsa44 | hqc128 | pq_pur | 500 | 100.0 | 18.354 | [17.536, 19.171] | 15.71 | 39.828 | 63.523 |
| L1 | mldsa44 | mlkem512 | pq_pur | 500 | 100.0 | 1.595 | [1.578, 1.613] | 1.53 | 2.0 | 2.33 |
| L3 | mldsa65 | P-384 | classique | 500 | 100.0 | 2.779 | [2.762, 2.796] | 2.75 | 3.07 | 3.611 |
| L3 | mldsa65 | x448 | classique | 500 | 100.0 | 2.53 | [2.511, 2.55] | 2.47 | 2.961 | 3.23 |
| L3 | secp384r1 | P-384 | classique | 500 | 100.0 | 4.346 | [4.315, 4.377] | 4.27 | 5.1 | 5.521 |
| L3 | secp384r1 | x448 | classique | 500 | 100.0 | 3.673 | [3.639, 3.707] | 3.62 | 4.42 | 4.89 |
| L3 | mldsa65 | p384_hqc192 | hybride | 500 | 100.0 | 56.158 | [54.984, 57.332] | 52.35 | 77.063 | 130.525 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 500 | 100.0 | 9.396 | [9.327, 9.465] | 9.26 | 10.261 | 12.356 |
| L3 | mldsa65 | x448_hqc192 | hybride | 500 | 100.0 | 47.469 | [47.223, 47.716] | 46.93 | 50.493 | 56.396 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 500 | 100.0 | 3.413 | [3.384, 3.442] | 3.325 | 4.042 | 4.44 |
| L3 | secp384r1 | p384_hqc192 | hybride | 500 | 100.0 | 131.697 | [129.169, 134.224] | 143.25 | 168.772 | 183.796 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 500 | 100.0 | 9.388 | [9.317, 9.458] | 9.28 | 10.261 | 13.162 |
| L3 | secp384r1 | x448_hqc192 | hybride | 500 | 100.0 | 111.131 | [106.688, 115.574] | 89.94 | 198.562 | 205.766 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 500 | 100.0 | 4.746 | [4.712, 4.78] | 4.635 | 5.53 | 5.951 |
| L3 | mldsa65 | hqc192 | pq_pur | 500 | 100.0 | 46.139 | [45.942, 46.336] | 45.545 | 49.674 | 57.18 |
| L3 | mldsa65 | mlkem768 | pq_pur | 500 | 100.0 | 1.776 | [1.754, 1.797] | 1.71 | 2.19 | 2.661 |
| L3 | secp384r1 | hqc192 | pq_pur | 500 | 100.0 | 105.156 | [102.458, 107.853] | 93.0 | 164.771 | 200.36 |
| L3 | secp384r1 | mlkem768 | pq_pur | 500 | 100.0 | 3.068 | [3.045, 3.09] | 2.97 | 3.582 | 3.98 |
| L5 | mldsa87 | P-521 | classique | 500 | 100.0 | 2.891 | [2.871, 2.911] | 2.84 | 3.37 | 3.641 |
| L5 | secp521r1 | P-521 | classique | 500 | 100.0 | 4.547 | [4.506, 4.587] | 4.43 | 5.21 | 6.101 |
| L5 | mldsa87 | p521_hqc256 | hybride | 500 | 100.0 | 88.008 | [87.657, 88.359] | 87.22 | 91.356 | 106.337 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 500 | 100.0 | 8.399 | [8.356, 8.443] | 8.37 | 9.1 | 9.742 |
| L5 | secp521r1 | p521_hqc256 | hybride | 500 | 100.0 | 86.367 | [86.133, 86.601] | 85.795 | 88.871 | 93.088 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 500 | 100.0 | 10.66 | [10.613, 10.706] | 10.565 | 11.58 | 12.48 |
| L5 | mldsa87 | hqc256 | pq_pur | 500 | 100.0 | 81.329 | [81.121, 81.536] | 80.81 | 83.83 | 90.846 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 500 | 100.0 | 1.97 | [1.945, 1.996] | 1.89 | 2.56 | 2.97 |
| L5 | secp521r1 | hqc256 | pq_pur | 500 | 100.0 | 84.553 | [83.763, 85.344] | 81.82 | 105.079 | 131.422 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 500 | 100.0 | 3.298 | [3.282, 3.315] | 3.25 | 3.67 | 3.92 |

## Surcoût vs baseline classique (même niveau de sécurité)

| Niveau | SIG_ALG | KEM | Classe | Moyenne (ms) | Baseline classique (ms) | Surcoût (%) |
|---|---|---|---|---|---|---|
| L1 | ed25519 | P-256 | classique | 1.911 | 1.743 | 9.6 |
| L1 | mldsa44 | P-256 | classique | 1.601 | 1.743 | -8.1 |
| L1 | ed25519 | x25519 | classique | 1.772 | 1.743 | 1.7 |
| L1 | mldsa44 | x25519 | classique | 1.687 | 1.743 | -3.2 |
| L1 | ed25519 | p256_hqc128 | hybride | 70.109 | 1.743 | 3922.3 |
| L1 | mldsa44 | p256_hqc128 | hybride | 22.76 | 1.743 | 1205.8 |
| L1 | ed25519 | p256_mlkem512 | hybride | 8.684 | 1.743 | 398.2 |
| L1 | mldsa44 | p256_mlkem512 | hybride | 7.182 | 1.743 | 312.0 |
| L1 | ed25519 | x25519_hqc128 | hybride | 49.079 | 1.743 | 2715.8 |
| L1 | mldsa44 | x25519_hqc128 | hybride | 17.563 | 1.743 | 907.6 |
| L1 | ed25519 | x25519_mlkem512 | hybride | 2.657 | 1.743 | 52.4 |
| L1 | mldsa44 | x25519_mlkem512 | hybride | 1.837 | 1.743 | 5.4 |
| L1 | ed25519 | hqc128 | pq_pur | 55.033 | 1.743 | 3057.4 |
| L1 | mldsa44 | hqc128 | pq_pur | 18.354 | 1.743 | 953.0 |
| L1 | ed25519 | mlkem512 | pq_pur | 1.97 | 1.743 | 13.0 |
| L1 | mldsa44 | mlkem512 | pq_pur | 1.595 | 1.743 | -8.5 |
| L3 | mldsa65 | P-384 | classique | 2.779 | 3.332 | -16.6 |
| L3 | secp384r1 | P-384 | classique | 4.346 | 3.332 | 30.4 |
| L3 | mldsa65 | x448 | classique | 2.53 | 3.332 | -24.1 |
| L3 | secp384r1 | x448 | classique | 3.673 | 3.332 | 10.2 |
| L3 | mldsa65 | p384_hqc192 | hybride | 56.158 | 3.332 | 1585.4 |
| L3 | secp384r1 | p384_hqc192 | hybride | 131.697 | 3.332 | 3852.5 |
| L3 | mldsa65 | p384_mlkem768 | hybride | 9.396 | 3.332 | 182.0 |
| L3 | secp384r1 | p384_mlkem768 | hybride | 9.388 | 3.332 | 181.8 |
| L3 | mldsa65 | x448_hqc192 | hybride | 47.469 | 3.332 | 1324.6 |
| L3 | secp384r1 | x448_hqc192 | hybride | 111.131 | 3.332 | 3235.3 |
| L3 | mldsa65 | x448_mlkem768 | hybride | 3.413 | 3.332 | 2.4 |
| L3 | secp384r1 | x448_mlkem768 | hybride | 4.746 | 3.332 | 42.4 |
| L3 | mldsa65 | hqc192 | pq_pur | 46.139 | 3.332 | 1284.7 |
| L3 | secp384r1 | hqc192 | pq_pur | 105.156 | 3.332 | 3055.9 |
| L3 | mldsa65 | mlkem768 | pq_pur | 1.776 | 3.332 | -46.7 |
| L3 | secp384r1 | mlkem768 | pq_pur | 3.068 | 3.332 | -7.9 |
| L5 | mldsa87 | P-521 | classique | 2.891 | 3.719 | -22.3 |
| L5 | secp521r1 | P-521 | classique | 4.547 | 3.719 | 22.3 |
| L5 | mldsa87 | p521_hqc256 | hybride | 88.008 | 3.719 | 2266.4 |
| L5 | secp521r1 | p521_hqc256 | hybride | 86.367 | 3.719 | 2222.3 |
| L5 | mldsa87 | p521_mlkem1024 | hybride | 8.399 | 3.719 | 125.8 |
| L5 | secp521r1 | p521_mlkem1024 | hybride | 10.66 | 3.719 | 186.6 |
| L5 | mldsa87 | hqc256 | pq_pur | 81.329 | 3.719 | 2086.9 |
| L5 | secp521r1 | hqc256 | pq_pur | 84.553 | 3.719 | 2173.5 |
| L5 | mldsa87 | mlkem1024 | pq_pur | 1.97 | 3.719 | -47.0 |
| L5 | secp521r1 | mlkem1024 | pq_pur | 3.298 | 3.719 | -11.3 |

## Note méthodologique

Intervalle de confiance à 95% calculé par approximation normale (z=1.96), la taille d'échantillon (n=500 par combinaison dans la majorité des cas) rendant cette approximation valide par le théorème central limite, indépendamment de la forme de la distribution sous-jacente des latences individuelles. Le surcoût (%) de chaque combinaison est calculé par rapport à la MOYENNE des combinaisons classiques du même niveau de sécurité NIST (pas un unique point de référence arbitraire), pour lisser le bruit de mesure du baseline lui-même.