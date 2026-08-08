# Microbenchmarks cryptographiques — résultats parsés

**38 mesures extraites**

| Algorithme | Opération | Famille | Ops/s | Temps moyen (µs) |
|---|---|---|---|---|
| 253_bits__ecdh | unknown | classique | 17823.2 | 56.107 |
| 256_bits__ecdh | unknown | classique | 13589.6 | 73.586 |
| 384_bits__ecdh | unknown | classique | 1886.6 | 530.054 |
| 448_bits__ecdh | unknown | classique | 3382.9 | 295.607 |
| 521_bits__ecdh | unknown | classique | 1927.9 | 518.699 |
| ecdsa384 | sign | classique | 2946.1 | 339.433 |
| ecdsa384 | verify | classique | 1391.6 | 718.597 |
| ecdsa521 | sign | classique | 2238.1 | 446.812 |
| ecdsa521 | verify | classique | 1229.3 | 813.452 |
| ed25519 | sign | classique | 18077.2 | 55.318 |
| ed25519 | verify | classique | 5889.0 | 169.808 |
| hqc128 | decaps | pq_pur | 102.9 | 9718.173 |
| hqc128 | encaps | pq_pur | 167.6 | 5966.587 |
| hqc128 | keygen | pq_pur | 314.6 | 3178.344 |
| hqc192 | decaps | pq_pur | 34.1 | 29323.529 |
| hqc192 | encaps | pq_pur | 54.0 | 18534.323 |
| hqc192 | keygen | pq_pur | 107.0 | 9345.182 |
| hqc256 | decaps | pq_pur | 18.7 | 53422.46 |
| hqc256 | encaps | pq_pur | 27.6 | 36209.386 |
| hqc256 | keygen | pq_pur | 64.1 | 15600.624 |
| mldsa44 | keygen | pq_pur | 23179.8 | 43.141 |
| mldsa44 | sign | pq_pur | 8849.9 | 112.995 |
| mldsa44 | verify | pq_pur | 26396.1 | 37.884 |
| mldsa65 | keygen | pq_pur | 13370.4 | 74.792 |
| mldsa65 | sign | pq_pur | 5826.5 | 171.63 |
| mldsa65 | verify | pq_pur | 15350.8 | 65.143 |
| mldsa87 | keygen | pq_pur | 8505.3 | 117.573 |
| mldsa87 | sign | pq_pur | 4604.1 | 217.197 |
| mldsa87 | verify | pq_pur | 8914.0 | 112.183 |
| mlkem1024 | decaps | pq_pur | 34636.4 | 28.871 |
| mlkem1024 | encaps | pq_pur | 31465.8 | 31.781 |
| mlkem1024 | keygen | pq_pur | 29194.1 | 34.253 |
| mlkem512 | decaps | pq_pur | 78699.1 | 12.707 |
| mlkem512 | encaps | pq_pur | 72824.4 | 13.732 |
| mlkem512 | keygen | pq_pur | 63903.7 | 15.649 |
| mlkem768 | decaps | pq_pur | 50279.8 | 19.889 |
| mlkem768 | encaps | pq_pur | 44533.1 | 22.455 |
| mlkem768 | keygen | pq_pur | 42132.2 | 23.735 |

## Note méthodologique

Ces mesures portent sur l'opération cryptographique isolée (hors coût réseau, hors coût du protocole TLS/QUIC). Elles sont complémentaires — pas redondantes — avec les mesures CPU/mémoire par handshake capturées par `Launcher_unified.sh` (qui incluent le harnais de test complet). Les KEM hybrides ne sont pas benchmarkés isolément ici : leur coût de calcul est approximativement composable à partir de leurs composantes classique et PQ mesurées séparément ci-dessus ; leur coût réel en contexte de handshake complet reste mesuré par le launcher principal.