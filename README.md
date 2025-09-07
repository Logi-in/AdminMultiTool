AdminMultiTool
FISI Multi-Tool (PowerShell Admin Toolkit)
Funktionsumfang

FISI Multi-Tool ist ein PowerShell-Skript für Windows-Administratoren und Fachinformatiker.
Es automatisiert die wichtigsten Health-Checks, Systemanalysen und Druckerinstallationen.
Features

    Full Check:
    Prüft System, Netzwerk, Treiber, Festplatten, Events, Security – alles mit einem Klick.
    Smart Check:
    Schneller Gesundheitscheck für Netzwerk und Logs.
    Netzwerkdrucker finden/installieren:
    Findet Drucker im LAN automatisch (Portscan), installiert sie mit Treiber.
    Fehlerdatenbank:
    Liefert Sofortlösungen für typische Windows-Fehlercodes (Bluescreen, Update, Treiber usw.).
    Admin-Elevation:
    Startet sich selbst als Admin, falls nötig.
    Farbcodierte Ausgabe:
    Alles auf einen Blick – OK (grün), Problem (rot), Hinweis (gelb), Sektion (cyan).
    Speedtest-Integration:
    Prüft die Internetgeschwindigkeit automatisch (lädt Speedtest-CLI nach).

Bedienung

    Starten (immer als Admin):**

.\FISI-Multitool.ps1 (Das Skript prüft und startet sich automatisch mit Adminrechten, falls nicht vorhanden.)

    Menü auswählen: Einfach Zahl eingeben:

1: Komplett-Check (Full Check)

2: Schneller Smart-Check (Netzwerk & Logs)

3: Netzwerkdrucker suchen/installieren

0: Beenden

Beispiele

Full Check Analysiert Systemstatus, Netzwerk, Treiber, Eventlogs, Security und meldet alles kompakt zurück.

Drucker suchen/installieren Findet alle netzwerkfähigen Drucker im lokalen Subnetz, listet sie auf, installiert sie (inkl. Port/Treiber) direkt per Auswahl.

Fehlercode-Datenbank Wird ein bekannter Fehlercode in den Eventlogs erkannt, erscheint sofort die passende Beschreibung + Lösung.

Technische Details

Admin-Elevation: Das Skript prüft zu Beginn, ob es als Administrator läuft. Falls nicht, wird es selbst mit erhöhten Rechten neu gestartet.

Checks: Alle Diagnose-Checks (System, Netzwerk, Hardware, Eventlogs, Security) sind modular aufgebaut.

Speedtest: Die CLI von Ookla wird automatisch heruntergeladen, falls nicht vorhanden.

Fehlerdatenbank: Typische Windows-Fehlercodes werden mit Beschreibung und Lösung eingeblendet, sobald erkannt.

Hinweis

PowerShell 5 oder 7+ erforderlich

Script überschreibt/ändert nichts am System ohne explizite Auswahl

Alle Checks und Logs laufen lokal, keine Daten werden übertragen

Druckerinstallation nutzt Standard-Windows-Treiber (Generic/Text-Only)

Speedtest lädt CLI direkt von Ookla bei Bedarf

Lizenz

MIT-Lizenz

TL;DR

Ein Skript, alle Admin-Checks: Perfekt für Sysadmins, IT-Support und Azubis. Schnellcheck, Fehlerlösung und Druckersuche in einer Datei. Einfach starten, Zahl wählen, Probleme fixen.

///1. Tool übe noch\\