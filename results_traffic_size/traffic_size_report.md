# Taille du trafic — comparaison classique / hybride / PQ pur

| Protocole | Auth | SIG_ALG | KEM | Classe | Total (octets) | Paquets | ClientHello | Certificate |
|---|---|---|---|---|---|---|---|---|
| quic | single | ed25519 | P-256 | classique | 3963 | 4 | 459 | 313 |
| quic | single | ed25519 | x25519 | classique | 3963 | 4 | 426 | 313 |
| quic | single | mldsa44 | P-256 | classique | 11058 | 6 | 459 | 3974 |
| quic | single | mldsa44 | x25519 | classique | 11025 | 6 | 426 | 3974 |
| quic | single | mldsa65 | P-384 | classique | 13594 | 6 | 491 | 5503 |
| quic | single | mldsa65 | x448 | classique | 13553 | 6 | 450 | 5503 |
| quic | single | mldsa87 | P-521 | classique | 17035 | 6 | 527 | 7461 |
| quic | single | secp384r1 | P-384 | classique | 3963 | 4 | 491 | 440 |
| quic | single | secp384r1 | x448 | classique | 3963 | 4 | 450 | 440 |
| quic | single | secp521r1 | P-521 | classique | 3963 | 4 | 527 | 514 |
| quic | single | ed25519 | p256_hqc128 | hybride | 16910 | 9 | 2700 | 313 |
| quic | single | ed25519 | p256_mlkem512 | hybride | 5548 | 4 | 1251 | 313 |
| quic | single | ed25519 | x25519_hqc128 | hybride | 16877 | 9 | 2667 | 313 |
| quic | single | ed25519 | x25519_mlkem512 | hybride | 5515 | 4 | 1218 | 313 |
| quic | single | mldsa44 | p256_hqc128 | hybride | 23749 | 10 | 2700 | 3974 |
| quic | single | mldsa44 | p256_mlkem512 | hybride | 13089 | 6 | 1251 | 3974 |
| quic | single | mldsa44 | x25519_hqc128 | hybride | 23749 | 10 | 2667 | 3974 |
| quic | single | mldsa44 | x25519_mlkem512 | hybride | 13056 | 6 | 1218 | 3974 |
| quic | single | mldsa65 | p384_hqc192 | hybride | 36716 | 14 | 5005 | 5503 |
| quic | single | mldsa65 | p384_mlkem768 | hybride | 15947 | 6 | 1667 | 5503 |
| quic | single | mldsa65 | x448_hqc192 | hybride | 35371 | 12 | 4964 | 5503 |
| quic | single | mldsa65 | x448_mlkem768 | hybride | 15904 | 6 | 1626 | 5503 |
| quic | single | mldsa87 | p521_hqc256 | hybride | 49409 | 13 | 7764 | 7461 |
| quic | single | mldsa87 | p521_mlkem1024 | hybride | 19879 | 6 | 2087 | 7461 |
| quic | single | secp384r1 | p384_hqc192 | hybride | 25529 | 10 | 5005 | 440 |
| quic | single | secp384r1 | p384_mlkem768 | hybride | 6403 | 4 | 1667 | 440 |
| quic | single | secp384r1 | x448_hqc192 | hybride | 25497 | 10 | 4964 | 440 |
| quic | single | secp384r1 | x448_mlkem768 | hybride | 6403 | 4 | 1626 | 440 |
| quic | single | secp521r1 | p521_hqc256 | hybride | 38833 | 14 | 7764 | 514 |
| quic | single | secp521r1 | p521_mlkem1024 | hybride | 6737 | 4 | 2087 | 514 |
| quic | single | ed25519 | hqc128 | pq_pur | 16668 | 8 | 2635 | 313 |
| quic | single | ed25519 | mlkem512 | pq_pur | 5483 | 4 | 1186 | 313 |
| quic | single | mldsa44 | hqc128 | pq_pur | 23749 | 10 | 2635 | 3974 |
| quic | single | mldsa44 | mlkem512 | pq_pur | 13024 | 6 | 1186 | 3974 |
| quic | single | mldsa65 | hqc192 | pq_pur | 36619 | 14 | 4908 | 5503 |
| quic | single | mldsa65 | mlkem768 | pq_pur | 15831 | 6 | 1570 | 5503 |
| quic | single | mldsa87 | hqc256 | pq_pur | 48063 | 13 | 7631 | 7461 |
| quic | single | mldsa87 | mlkem1024 | pq_pur | 19734 | 6 | 1954 | 7461 |
| quic | single | secp384r1 | hqc192 | pq_pur | 24171 | 9 | 4908 | 440 |
| quic | single | secp384r1 | mlkem768 | pq_pur | 5951 | 4 | 1570 | 440 |
| quic | single | secp521r1 | hqc256 | pq_pur | 38698 | 14 | 7631 | 514 |
| quic | single | secp521r1 | mlkem1024 | pq_pur | 6603 | 4 | 1954 | 514 |
| tls | single | ed25519 | P-256 | classique | 2844 | 16 | 424 | 313 |
| tls | single | ed25519 | x25519 | classique | 2778 | 16 | 391 | 313 |
| tls | single | mldsa44 | P-256 | classique | 8993 | 18 | 424 | 3974 |
| tls | single | mldsa44 | x25519 | classique | 8927 | 18 | 391 | 3974 |
| tls | single | mldsa65 | P-384 | classique | 11607 | 20 | 456 | 5503 |
| tls | single | mldsa65 | x448 | classique | 11525 | 20 | 415 | 5503 |
| tls | single | mldsa87 | P-521 | classique | 15087 | 22 | 492 | 7461 |
| tls | single | secp384r1 | P-384 | classique | 3073 | 16 | 456 | 438 |
| tls | single | secp384r1 | x448 | classique | 2989 | 16 | 415 | 438 |
| tls | single | secp521r1 | P-521 | classique | 3254 | 16 | 492 | 513 |
| tls | single | ed25519 | p256_hqc128 | hybride | 9650 | 18 | 2665 | 313 |
| tls | single | ed25519 | p256_mlkem512 | hybride | 4404 | 16 | 1216 | 313 |
| tls | single | ed25519 | x25519_hqc128 | hybride | 9584 | 18 | 2632 | 313 |
| tls | single | ed25519 | x25519_mlkem512 | hybride | 4338 | 16 | 1183 | 313 |
| tls | single | mldsa44 | p256_hqc128 | hybride | 15799 | 20 | 2665 | 3974 |
| tls | single | mldsa44 | p256_mlkem512 | hybride | 10553 | 18 | 1216 | 3974 |
| tls | single | mldsa44 | x25519_hqc128 | hybride | 15733 | 20 | 2632 | 3974 |
| tls | single | mldsa44 | x25519_mlkem512 | hybride | 10487 | 18 | 1183 | 3974 |
| tls | single | mldsa65 | p384_hqc192 | hybride | 25363 | 24 | 4970 | 5503 |
| tls | single | mldsa65 | p384_mlkem768 | hybride | 13871 | 20 | 1632 | 5503 |
| tls | single | mldsa65 | x448_hqc192 | hybride | 25479 | 27 | 4929 | 5503 |
| tls | single | mldsa65 | x448_mlkem768 | hybride | 13789 | 20 | 1591 | 5503 |
| tls | single | mldsa87 | p521_hqc256 | hybride | 37339 | 31 | 7729 | 7461 |
| tls | single | mldsa87 | p521_mlkem1024 | hybride | 18215 | 22 | 2052 | 7461 |
| tls | single | secp384r1 | p384_hqc192 | hybride | 17025 | 23 | 4970 | 438 |
| tls | single | secp384r1 | p384_mlkem768 | hybride | 5335 | 16 | 1632 | 438 |
| tls | single | secp384r1 | x448_hqc192 | hybride | 16812 | 21 | 4929 | 438 |
| tls | single | secp384r1 | x448_mlkem768 | hybride | 5255 | 16 | 1591 | 438 |
| tls | single | secp521r1 | p521_hqc256 | hybride | 25573 | 26 | 7729 | 513 |
| tls | single | secp521r1 | p521_mlkem1024 | hybride | 6382 | 16 | 2052 | 513 |
| tls | single | ed25519 | hqc128 | pq_pur | 9520 | 18 | 2600 | 313 |
| tls | single | ed25519 | mlkem512 | pq_pur | 4274 | 16 | 1151 | 313 |
| tls | single | mldsa44 | hqc128 | pq_pur | 15669 | 20 | 2600 | 3974 |
| tls | single | mldsa44 | mlkem512 | pq_pur | 10423 | 18 | 1151 | 3974 |
| tls | single | mldsa65 | hqc192 | pq_pur | 25367 | 27 | 4873 | 5503 |
| tls | single | mldsa65 | mlkem768 | pq_pur | 13677 | 20 | 1535 | 5503 |
| tls | single | mldsa87 | hqc256 | pq_pur | 37007 | 30 | 7596 | 7461 |
| tls | single | mldsa87 | mlkem1024 | pq_pur | 17949 | 22 | 1919 | 7461 |
| tls | single | secp384r1 | hqc192 | pq_pur | 16831 | 23 | 4873 | 438 |
| tls | single | secp384r1 | mlkem768 | pq_pur | 5141 | 16 | 1535 | 438 |
| tls | single | secp521r1 | hqc256 | pq_pur | 25307 | 26 | 7596 | 513 |
| tls | single | secp521r1 | mlkem1024 | pq_pur | 6117 | 16 | 1919 | 513 |

## Moyenne du total d'octets par protocole et classe KEM

| Protocole | Classe KEM | N | Total moyen (octets) |
|---|---|---|---|
| quic | classique | 10 | 8608 |
| quic | hybride | 20 | 20056.0 |
| quic | pq_pur | 12 | 21216.2 |
| tls | classique | 10 | 7107.7 |
| tls | hybride | 20 | 14549.3 |
| tls | pq_pur | 12 | 15606.8 |

## Note méthodologique

Une seule connexion capturée par combinaison (pas de distribution statistique sur plusieurs runs) : la taille des messages de handshake TLS/QUIC est déterministe pour une combinaison SIG_ALG/KEM donnée (à la taille du nonce/des champs aléatoires près, négligeable). Le total (`total_bytes`) inclut l'overhead de transport (en-têtes TCP/QUIC), filtré sur le port applicatif (4433) pour exclure tout bruit réseau ambiant (ICMPv6, ARP, mDNS). Les colonnes de détail par type de message handshake proviennent du déchiffrement TLS via le fichier de clés (SSLKEYLOGFILE) capturé au moment de la connexion — pas de clé privée du serveur requise, seulement les secrets de session éphémères de cette connexion précise.

Les colonnes par type de message (`ClientHello_bytes`, `Certificate_bytes`, etc.) utilisent la taille intrinsèque du message (`tls.handshake.length`, corps du message hors en-tête de 4 octets), PAS la taille de la trame TCP qui le contient : plusieurs messages handshake partagent souvent une même trame (regroupement qui varie selon le volume total transmis, donc selon la combinaison testée), et leur attribuer la taille de la trame entière produirait des valeurs incomparables d'une ligne à l'autre — biais détecté empiriquement lors du développement de ce script (ex: `ServerHello` variant de 102 à plus de 4600 octets selon la combinaison testée alors qu'il s'agit d'un message de taille quasi fixe).