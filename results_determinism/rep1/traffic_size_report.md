# Taille du trafic — comparaison classique / hybride / PQ pur

| Protocole | Auth | SIG_ALG | KEM | Classe | Total (octets) | Paquets | ClientHello | Certificate |
|---|---|---|---|---|---|---|---|---|
| tls | single | mldsa44 | P-256 | classique | 8993 | 18 | 424 | 3974 |
| tls | single | mldsa44 | hqc128 | pq_pur | 15669 | 20 | 2600 | 3974 |
| tls | single | mldsa65 | mlkem768 | pq_pur | 13677 | 20 | 1535 | 5503 |

## Moyenne du total d'octets par protocole et classe KEM

| Protocole | Classe KEM | N | Total moyen (octets) |
|---|---|---|---|
| tls | classique | 1 | 8993 |
| tls | pq_pur | 2 | 14673 |

## Note méthodologique

Une seule connexion capturée par combinaison (pas de distribution statistique sur plusieurs runs) : la taille des messages de handshake TLS/QUIC est déterministe pour une combinaison SIG_ALG/KEM donnée (à la taille du nonce/des champs aléatoires près, négligeable). Le total (`total_bytes`) inclut l'overhead de transport (en-têtes TCP/QUIC), filtré sur le port applicatif (4433) pour exclure tout bruit réseau ambiant (ICMPv6, ARP, mDNS). Les colonnes de détail par type de message handshake proviennent du déchiffrement TLS via le fichier de clés (SSLKEYLOGFILE) capturé au moment de la connexion — pas de clé privée du serveur requise, seulement les secrets de session éphémères de cette connexion précise.

Les colonnes par type de message (`ClientHello_bytes`, `Certificate_bytes`, etc.) utilisent la taille intrinsèque du message (`tls.handshake.length`, corps du message hors en-tête de 4 octets), PAS la taille de la trame TCP qui le contient : plusieurs messages handshake partagent souvent une même trame (regroupement qui varie selon le volume total transmis, donc selon la combinaison testée), et leur attribuer la taille de la trame entière produirait des valeurs incomparables d'une ligne à l'autre — biais détecté empiriquement lors du développement de ce script (ex: `ServerHello` variant de 102 à plus de 4600 octets selon la combinaison testée alors qu'il s'agit d'un message de taille quasi fixe).