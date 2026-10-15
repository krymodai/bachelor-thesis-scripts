# Skripte zur Bachelorarbeit

Dieses Repository enthält die im Rahmen der Bachelorarbeit verwendeten Skripte zur Durchführung, Aufbereitung und Auswertung der Messungen.

## Hauptmessungen

Die folgenden Bash-Skripte wurden für die Durchführung und Verarbeitung der Hauptmessungen verwendet:

- `scripts/preflight_check.sh`: Prüfung der Laborumgebung vor den Messläufen
- `scripts/capture_run.sh`: Steuerung und Dokumentation der Messaufzeichnung
- `scripts/analyze_run.sh`: Analyse der aufgezeichneten Messläufe
- `scripts/collect_results.sh`: Zusammenführung der erzeugten Analyseergebnisse

## Kontrollmessung

- `scripts/control/capture_whonix_qubes.sh`: Steuerung und Dokumentation der ergänzenden Whonix-on-Qubes-Kontrollmessungen


## Verzeichnisstruktur

    scripts/
    ├── analyze_run.sh
    ├── capture_run.sh
    ├── collect_results.sh
    ├── preflight_check.sh
    └── control/
        └── capture_whonix_qubes.sh


## Hinweis

Diese Skripte entsprechen dem für die Bachelorarbeit verwendeten Stand. Sie dienen der Dokumentation und Nachvollziehbarkeit der durchgeführten Untersuchung.
