# Reprise de session — TLS — handshake complet vs repris

| Combo | Handshake complet (ms) | Succès complet (%) | Reprise (ms) | Succès reprise (%) | Gain (%) |
|---|---|---|---|---|---|
| mldsa65_mlkem768 | 211.83 | 100.0 | 211.73 | 100.0 | 0.0 |
| mldsa87_hqc256 | 249.01 | 100.0 | 252.02 | 100.0 | -1.2 |

## Note méthodologique

Mesuré via openssl s_client standard côté TLS, avec sauvegarde/réutilisation explicite du ticket de session (-sess_out/-sess_in). Le serveur (perftestServerTlsQuic.sh) est inchangé entre phase 1 et phase 2.