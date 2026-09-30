# PowerWEB 4.0: eigene Engine und Sitzungen

Die neue Engine ist eigener MIT-lizenzierter PowerShell/.NET-Code. Sie braucht keine externe Scan-Engine, Node.js oder einen Browser. Sie ist ein begrenzter aktiver HTTP-Scanner; ein vollstaendiger Pentest erfordert weitere manuelle Pruefungen.

## Start

1. In Reiter 1 Zielbereich, Start-URLs, Ausschluesse, Linktiefe, Pause und Timeout einstellen.
2. In Reiter 8 Regeln und Grenzen auswaehlen. Standard: zehn Seiten, 150 Anfragen, drei Query-Parameter je Seite und zehn Minuten.
3. Die aktiven Tests fuer den Zielbereich freigeben und **Eigene Engine starten** klicken.
4. Pruefergebnisse in Reiter 8, Befunde in Reiter 2 und Anfragen im Verlauf ansehen. Den HTML-Bericht fuer strukturierte Kontroll- und Testbelege exportieren.

Der Scanner sendet GET-Anfragen. Auch GET kann bei fehlerhaften Anwendungen Daten veraendern. Vorhandene Query-Werte werden gezielt ersetzt; Namen mit Hinweisen auf Zugangsdaten oder Tokens bleiben ausgenommen. Formulare werden nicht automatisch abgeschickt. Externe Weiterleitungsziele werden nicht aufgerufen. Abbruch und erreichte Anfrage-/Zeitgrenzen erhalten bereits abgeschlossene Ergebnisse.

## Regeln und Aussagekraft

| Regel | Nachweis | Grenze |
| --- | --- | --- |
| SQL-Fehler | Neue SQL-Fehlermeldung bei Quote, Vergleich mit Ausgangsantwort und Escape-Kontrolle | SQL-Injection-Verdacht; kein bestaetigter Datenbankzugriff |
| SQL-Antwortvergleich | Stabile Ausgangsantwort und zwei wiederholte True-/False-Paare | Nur numerische Ausgangswerte; dynamische Antworten werden ausgelassen; manuell bestaetigen |
| Template-Auswertung | Zwei verschiedene Berechnungen mit eindeutigen Markern | Zwei Ausdruckssyntaxen; kein Nachweis beliebiger Codeausfuehrung |
| HTML-Reflexion | Inertes HTML-Element unveraendert in einer HTML-Antwort | Kein XSS- oder DOM-Ausfuehrungsnachweis |
| Weiterleitungen | Zwei unterschiedliche Testhosts im Location-Header | Keine Verbindung zu den Testhosts |
| Header-Injektion | Zwei eindeutige Marker als echte Antwortheader | Keine weitergehende Ausnutzung |
| CORS | Zwei fremde Origins werden mit Credentials-Freigabe gespiegelt | Kein Browsernachweis lesbarer vertraulicher Daten |

Die Ergebnistabelle unterscheidet Befund, Kein Nachweis, Uebersprungen und Unvollstaendig. **Kein Nachweis bedeutet nicht sicher.** Die Laufzusammenfassung nennt Grenzen, Restqueue und ausgefuehrte Pruefungen. Befunde beginnen mit Status Offen; die angegebene Sicherheit betrifft das beobachtete Muster, nicht pauschal die Ausnutzbarkeit.

Ab 3.1.1 werden gekuerzte oder ungelesene Basisantworten fuer Textpruefungen ausgelassen. Ein negativer Test mit gekuerzter Antwort gilt als unvollstaendig. Zeitgrenzen werden zwischen Anfragen geprueft; laufende Anfragen und Betriebssystem-DNS koennen das Minutenlimit ueberschreiten.

## Belege

Ein Befund enthaelt Regelkennung, Sicherheit und Belege fuer Ausgangs-, Kontroll- und Testanfragen: Zeitpunkt in UTC, Methode, bereinigte URL, HTTP-Status, Headerzeit, gelesene Bytes, Kuerzungshinweis, ausgewaehlte Antwortheader und gegebenenfalls einen kurzen Textausschnitt. TextSHA256 ist der SHA-256 des dekodierten Antworttexts, als UTF-8 gehasht; kein Hash der originalen Netzwerkbytes. Vollstaendige Antworten und Anmeldeheader werden nicht als Scanbelege gespeichert.

Bekannte Token-/Cookie-Werte und typische geheime Query-Werte werden in den neuen Engine-Belegen nach Moeglichkeit maskiert. Dies ist keine vollstaendige Anonymisierung; sehr kurze oder unbekannte Geheimnisse sowie manuelle Inhalte koennen verbleiben. Andere Arbeitsbereiche behalten ihre bisherigen Speicherregeln. Projekte und Berichte vor Weitergabe pruefen. Maskierte Werte muessen fuer eine Reproduktion separat bereitgestellt werden; ein Bericht enthaelt keine Anmeldesitzung.

Strukturierte Belege bleiben beim Speichern und Laden von Projekten erhalten und erscheinen im HTML-Bericht in aufklappbaren Abschnitten. CSV speichert strukturierte Felder als JSON-Text.

## Zwei getrennte Sitzungen

- In Reiter 8 Sitzung A oder B waehlen. Jede hat eigene Anmeldeheader und einen eigenen Cookie-Speicher.
- Anmeldeheader in Reiter 1 eingeben oder in Reiter 3 eine passende Login-POST-Anfrage senden. Set-Cookie wird fuer weitere native Anfragen und Scans behalten.
- Ein expliziter Cookie-Header hat fuer die jeweilige Anfrage Vorrang vor gespeicherten Cookies.
- Sitzungen werden an den zuerst verwendeten Ursprung gebunden. Fuer einen anderen Host oder Port die Sitzung leeren oder wechseln.
- Fuer den Rollenvergleich dieselbe URL mit A und B abrufen. Status, Textgleichheit, Hashes und Kuerzungshinweise unterstuetzen die manuelle Bewertung. Gleiche Antworten allein beweisen keinen Berechtigungsfehler.
- Sitzungen bleiben nur im Arbeitsspeicher, werden nicht in Projekte gespeichert und lassen sich einzeln leeren. Es gibt keine automatische Anmeldung, Token-Erneuerung oder MFA-Steuerung.

Der fruehere Browser-Reiter (JavaScript-Rendering per Node.js) wurde entfernt; PowerWEB benoetigt kein Node.js mehr. Fuer manuelles Browsen dient der Proxy (Reiter 9) mit "Open browser through proxy".

## Lokale Validierung

`tests/Test-NativeScanner.ps1` prueft sieben positive Testfaelle, negative Vergleichsfaelle, dynamische Antworten, feste CORS-Freigaben, Anfragegrenzen, Scope, Maskierung, Belegexport, Projekt-Rundlauf und zwei getrennte Cookie-Sitzungen. Der WPF-Test bedient Scan, Login, Sitzungswechsel, Rollenvergleich und Zuruecksetzen. Die Serverantworten sind kontrollierte Testfixtures; dies ist kein Nachweis umfassender Erkennung an realen Anwendungen.
