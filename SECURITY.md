# Sicherheitsrichtlinie

## Sicherheitslücken melden

Bitte melde Sicherheitslücken **nicht** über ein öffentliches Issue. Nutze stattdessen
GitHubs **private Meldung**: Reiter **Security → Report a vulnerability** in diesem
Repository.

Hilfreich sind:

- eine Beschreibung der Lücke und ihrer Auswirkung
- Schritte zum Nachstellen (Browser, Version, ggf. Beispieldatei **ohne echte Zugangsdaten**)
- falls vorhanden ein Vorschlag zur Behebung

Ich versuche, Meldungen zeitnah zu beantworten. Da KeyBook ein privates Projekt ist,
kann ich aber keine festen Reaktionszeiten zusagen.

## Unterstützte Versionen

Sicherheitskorrekturen gibt es nur für die jeweils **neueste Version** auf dem `main`-Branch.

## Geltungsbereich

Relevant sind insbesondere:

- Schwächen in der Verschlüsselung oder Schlüsselableitung (`Crypto`-Modul in `app/app.js`)
- Klartext, der nach dem Sperren im DOM, in der Zwischenablage oder im Speicher bleibt
- XSS oder CSS-Injection, z. B. über präparierte Import- oder Backup-Dateien
- Datenverlust oder unbeabsichtigtes Überschreiben bei der Tresor-Datei

Nicht im Geltungsbereich sind Angriffe, die bereits vollen Zugriff auf das entsperrte Gerät
oder den Browser voraussetzen (z. B. bösartige Browser-Erweiterungen, Keylogger), sowie
schwache Master-Passwörter.

## Hinweis

KeyBook wurde keinem unabhängigen Sicherheits-Audit unterzogen.
