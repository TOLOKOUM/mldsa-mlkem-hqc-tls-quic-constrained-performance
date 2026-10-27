# Pré-enregistrement — campagnes v3 (niveau de sécurité 3 uniquement)

**À figer AVANT le premier bloc** : `git add . && git commit -m "preregistration v3"` (ou dépôt OSF), puis noter
l'empreinte de `analysis/13_analyse_extensions.py` (`sha256sum`). Toute modification de bande après coup doit être déclarée
comme telle dans l'article (colonne « modifié après données »).

Règle de verdict (fixe) : **PASS** = IC95 % (bootstrap sur les 20 blocs) entièrement dans la bande ; **FAIL** = entièrement hors
de la bande ; **INCONCLUSIF** = chevauche. Un FAIL est un résultat, rapporté tel quel.

Base du bruit (mesuré sur la campagne v2, 20 blocs, mêmes pas de bloc) : écart-type inter-blocs de la médiane « app-ready »
≈ 0,3 ms (TLS, RTT 0), ≈ 0,9 ms (TLS, RTT 50) ; écart-type de D = ML-DSA − ECDSA (apparié dans le bloc) ≈ 0,3 ms (TLS),
≈ 0,7 ms (QUIC, RTT 50) ⇒ erreur-type de la moyenne sur 20 blocs ≈ 0,07–0,15 ms. Les bandes ci-dessous sont plusieurs fois
plus larges que ce bruit, sauf les bandes de calibration (±0,5 ms / ±1 ms) qui sont volontairement serrées.

## Reprise de session (TLS 1.3 PSK-DHE / QUIC), toutes en authentification simple, L3
| id | prédiction | bande | mécanisme / ce qu'un FAIL signifierait |
|---|---|---|---|
| R0 | ≥ 98 % des reprises prévues ont réellement repris | [0,98 ; 1] | contrôle de manipulation ; sinon la campagne ne mesure pas la reprise |
| R1 | TLS ML-KEM-768 : pente de D(RTT)=ML-DSA−ECDSA ≈ 0, en complet ET en reprise | [−0,10 ; 0,10] | la pénalité ML-DSA n'existe pas en TLS (vol < IW10) ; un FAIL contredit le modèle d'écritures de la phase 5b |
| R2-full | QUIC ML-KEM-768 : pente de D(RTT), connexion complète | [0,80 ; 1,20] | la pénalité = 1 RTT (déjà observée en v2 : 0,99–1,01) |
| R2-res | QUIC ML-KEM-768 : pente de D(RTT), reprise | [−0,15 ; 0,15] | sans certificat ni CertificateVerify, plus de pénalité : **prédiction centrale** ; un FAIL signifierait que la pénalité ne vient pas de la taille du certificat |
| R2-diff | QUIC : pente(complet) − pente(reprise) | [0,80 ; 1,20] | idem |
| R3 | HQC-192 : le décalage CPU HQC−ML-KEM est identique en complet et en reprise (psk_dhe_ke refait l'échange) | [−3 ; +3] ms | la reprise n'économise pas le coût du KEM |
| R4 | octets reçus en reprise / complet, ML-DSA-65 | TLS ≤ 0,25 ; QUIC ≤ 0,30 | le certificat ML-DSA (≈ 5,5 ko) + CertificateVerify (≈ 3,3 ko) disparaissent |
| R5 | QUIC RTT 50 : la pente en perte de D est plus faible en reprise qu'en complet | différence > 0 (sens seulement) | rappel : ce résultat de perte est le plus faible de la v2 |

## Compression de certificat (RFC 8879), TLS (QUIC seulement si `probe_features.sh` est positif)
| id | prédiction | bande | remarque |
|---|---|---|---|
| C0 | TLS : bras `none` sans Certificate compressé ; témoins ECDSA remplis avec zlib/brotli : ≥ 98 % compressés | ≤ 0,01 ; ≥ 0,98 | contrôle de manipulation |
| C1 | gain en octets pour ML-DSA-65 (chaîne 1 et 2, zlib/brotli) | [−10 ; 400] o | clés et signatures ML-DSA quasi aléatoires (test local : zlib ≥ taille d'origine ; OpenSSL refuse de compresser) |
| C2 | k inchangé pour ML-DSA-65 compressé : pente de dT(RTT) | [−0,15 ; 0,15] | « la compression de certificat ne résout pas la pénalité ML-DSA » |
| C3 | témoin ECDSA rempli à 16 000 o (TLS et QUIC), compression ⇒ k : 1 → 0 | pente [−1,30 ; −0,70] | **contrôle positif** : montre que le banc détecte une compression efficace |
| C4 | témoin ECDSA rempli à 8 700 o : TLS pente ≈ 0 (vol < IW10) ; QUIC pente ≈ −1 | TLS [−0,15 ; 0,15] ; QUIC [−1,30 ; −0,70] | frontière différente entre TCP (IW10) et QUIC (3 × octets client) |
| C5 | coût CPU de la décompression (RTT 0, ML-DSA-65) | [−0,5 ; 0,5] ms | négligeable |

## Charge concurrente (boucle fermée, c ∈ {1,2,4,8,16,32}, serveur sur 1 CPU logique, fenêtre 20 s rognée de 2 s)
| id | prédiction | bande | remarque |
|---|---|---|---|
| L0 | garde : ≥ 90 % des niveaux c max ont un client < 85 % de ses cœurs | [0,90 ; 1] | si FAIL, les données de saturation sont inutilisables (le générateur est le goulot) |
| L1 | TLS (MT) ML-DSA-65 + ML-KEM-768, RTT 0 : utilisation CPU du serveur à c max | [0,90 ; 1,05] | le serveur sature |
| L1b | X(c max) × S_marginal | [0,85 ; 1,15] | débit saturé = 1 / CPU marginal par connexion (S_marginal : pente de la régression CPU–débit hors saturation) |
| L2 | X_sat(ML-KEM)/X_sat(HQC), ECDSA, TLS-MT, RTT 0 | [3,0 ; 4,6] | rapport des CPU serveur de la phase 4 (51 / 13,5 ms) |
| L3 | X_sat(ML-DSA)/X_sat(ECDSA), ML-KEM, TLS-MT, RTT 0 | [0,90 ; 1,20] | la signature pèse peu devant le KEM côté serveur |
| L4a | QUIC RTT 50, c = 1 : D = R(ML-DSA) − R(ECDSA) | [35 ; 65] ms | pénalité = 1 RTT (v2 : 48,2 ms) |
| L4b | QUIC RTT 50, **si saturé** : D(c max)/R_ECDSA(c max) | [−0,05 ; 0,15] | la pénalité RTT est noyée sous la file ; « NON TESTABLE » si le serveur QUIC n'est pas saturé à c = 32 |
| L5 | calibration TLS : serveur multi-connexions − serveur `s_server`, c = 1 | RTT 0 : ±0,5 ms ; RTT 50 : ±1 ms ; CPU/connexion MT/stock [0,85 ; 1,15] | si FAIL, le serveur MT n'est pas équivalent : le déclarer et ne pas comparer TLS/QUIC en charge |
| L6 | taux d'échec moyen pour c ≤ 8 | [0 ; 0,01] | |

## Pont avec la campagne v2
| B1 | sentinelles (pré/mi/post) : médiane v3 − médiane v2, par (protocole, signature) | ±0,5 ms | l'image v3 n'a pas déplacé la mesure de base (nécessite `--v2-root`) |

## Limites déclarées d'avance
* Pile unique : OpenSSL (fork) + oqs-provider + MsQuic ; RTT/perte émulés par netem sur pont Docker local ; débit 100 Mbit/s.
* Charge : processus par connexion (comme en v2) ⇒ le coût inclut la création du processus côté client ; le serveur TLS de
  la campagne de charge (tls_mt_server) n'est pas `openssl s_server` : l'équivalence est testée (L5), pas supposée.
* Compression : OpenSSL ne compresse que des chaînes pré-compressées ; le comportement des serveurs de production
  (compression à la volée avec cache) n'est pas couvert.
* 0-RTT : exploratoire (QUIC seulement), hors pré-enregistrement.
