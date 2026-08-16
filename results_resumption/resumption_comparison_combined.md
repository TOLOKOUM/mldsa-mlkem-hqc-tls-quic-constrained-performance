# Reprise de session — comparaison TLS vs QUIC

| Protocole | Combo | Complet (ms) | Reprise (ms) | Gain (%) |
|---|---|---|---|---|
| tls | mldsa65_mlkem768 | 211.83 | 211.73 | 0.0 |
| tls | mldsa87_hqc256 | 249.01 | 252.02 | -1.2 |
| quic | mldsa65_mlkem768 | 2.9 | 2.87 | 1.0 |
| quic | mldsa87_hqc256 | 117.53 | 118.54 | -0.9 |

⚠️ Reprise de session QUIC connue non fonctionnelle dans cette stack (`quics_connection` accepte `-sess_out` silencieusement sans rien écrire). Les chiffres 'resumed' ci-dessus correspondent en réalité à un second handshake complet, pas à une vraie reprise — un gain proche de 0% est donc attendu et NE VALIDE PAS le support de la reprise côté QUIC.