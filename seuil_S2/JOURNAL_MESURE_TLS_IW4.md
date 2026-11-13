# Journal de mesure — TLS_IW4
13/11/2026 : limite de blocs par jour levée dès le bloc 1 (`--max-blocks-per-day 20`), comme pour TLS_IW20 ; les 20 blocs sont exécutés d'affilée. Les écarts D_b sont calculés à l'intérieur de chaque bloc, par rapport à la base du même bloc ; l'IC bootstrap ne tient pas compte d'une corrélation entre blocs d'un même jour. Aucune durée consultée.

13/11/2026 : redémarrage de la machine pendant l'exécution (bloc 12 interrompu). Réglages remis (no_turbo=1, gouverneur performance) avant la reprise ; le bloc 12 est repris sans refaire les cellules déjà terminées, ses visites sont donc réparties avant et après le redémarrage. Une analyse de sensibilité sans ce bloc sera rapportée. Aucune durée consultée.
