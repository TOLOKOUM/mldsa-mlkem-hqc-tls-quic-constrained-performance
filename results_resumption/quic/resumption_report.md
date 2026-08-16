# Reprise de session — QUIC — handshake complet vs repris

| Combo | Handshake complet (ms) | Succès complet (%) | Reprise (ms) | Succès reprise (%) | Gain (%) |
|---|---|---|---|---|---|
| mldsa65_mlkem768 | 2.9 | 100.0 | 2.87 | 100.0 | 1.0 |
| mldsa87_hqc256 | 117.53 | 100.0 | 118.54 | 100.0 | -0.9 |

## Avertissement

⚠️ Reprise de session QUIC connue non fonctionnelle dans cette stack (`quics_connection` accepte `-sess_out` silencieusement sans rien écrire). Les chiffres 'resumed' ci-dessus correspondent en réalité à un second handshake complet, pas à une vraie reprise — un gain proche de 0% est donc attendu et NE VALIDE PAS le support de la reprise côté QUIC.