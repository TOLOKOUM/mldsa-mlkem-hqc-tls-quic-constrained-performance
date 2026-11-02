#!/usr/bin/env bash
###############################################################################
# prepare_env.sh — Stabilise la machine AVANT une campagne/pilote et VERIFIE.
# A relancer apres CHAQUE redemarrage/hibernation (les reglages sont perdus).
# Usage : bash launchers/prepare_env.sh
###############################################################################
set -uo pipefail
ok=1
echo ">> governor performance"
sudo cpupower frequency-set -g performance >/dev/null 2>&1 || { echo "   cpupower absent/echec : essayez 'sudo apt install linux-tools-common linux-tools-generic'"; ok=0; }
echo ">> turbo coupe (no_turbo=1)"
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo >/dev/null 2>&1 || ok=0
echo ">> gestionnaires d'energie arretes"
sudo systemctl stop power-profiles-daemon tlp 2>/dev/null || true
echo ">> veille/hibernation masquees pour la session (annule au redemarrage : 'sudo systemctl unmask ...')"
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1 || ok=0
echo ">> capot ferme : ne rien faire (ignore pendant la campagne)"
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing' 2>/dev/null || true
echo
echo "---- verification ----"
g=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u | tr '\n' ' ')
t=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo NA)
echo "governor : $g (attendu : performance)"
echo "no_turbo : $t (attendu : 1)"
if command -v upower >/dev/null; then echo "alimentation : $(upower -i "$(upower -e | grep -E 'line_power|AC' | head -1)" 2>/dev/null | grep -i online | tr -s ' ')  (attendu : online: yes)"; fi
ac=NA
for f in /sys/class/power_supply/*/type; do
    [[ -e "$f" ]] || continue; d="$(dirname "$f")"
    [[ "$(cat "$f" 2>/dev/null)" == "Mains" ]] || continue
    if [[ "$(cat "$d/online" 2>/dev/null)" == "1" ]]; then ac=yes; break; fi; ac=no
done
echo "secteur  : $ac (attendu : yes)"
if [[ "$ac" == "no" && "${ALLOW_BATTERY:-0}" != "1" ]]; then echo "❌ machine sur BATTERIE : branchez l'alimentation (ou ALLOW_BATTERY=1 pour forcer)"; exit 1; fi
[[ "$g" == "performance " && "$t" == "1" ]] && echo "✅ environnement pret" || { echo "❌ environnement NON pret"; exit 1; }
