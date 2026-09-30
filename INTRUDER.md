# PowerWEB 4.0: Intruder

Der Ablauf beginnt mit einer vorhandenen Anfrage. Sende sie aus dem Proxy-Verlauf direkt an **Intruder**, oder nutze **From tab 3** im Anfrageeditor. Bei einer Query-URL markiert PowerWEB den ersten geeigneten Wert automatisch. Weitere Werte kannst du im URL-, Header- oder Body-Feld auswaehlen und mit **Mark selected ...** einklammern. `Clear marks` entfernt die Markierungen, ohne den Request-Inhalt zu loeschen.

Trage Testwerte in **Payload set 1** ein, jeweils einen Wert pro Zeile. **Preview requests** zeigt die Positionen, die geplante Anfragezahl und ob das eingestellte Limit greift. Danach **Start tests**. Die Ergebnisliste zeigt Status, Groesse, Dauer, Match/Extract und Fehler. Beim Auswaehlen erscheint ein kurzer Antwortausschnitt. **Open selected in request editor** oeffnet die konkrete Testanfrage zur manuellen Nachpruefung.

Modi: **Sniper** ersetzt jeweils eine Position mit Set 1. **Battering ram** setzt einen Wert aus Set 1 in alle Positionen. **Pitchfork** nimmt pro Position ein Set und laeuft parallel durch die Zeilen. **Cluster bomb** bildet alle Kombinationen. Fuer Pitchfork/Cluster bomb sind bis zu vier Positionen und entsprechend vier Payload-Sets ueber die Oberflaeche moeglich. Die Engine unterstuetzt bis zu acht Positionen fuer Sniper/Battering ram. Pro Set hoechstens 1000 Werte, pro Wert 2048 Zeichen, pro Lauf hoechstens 5000 Anfragen.

Zielbereich, Ausschluesse, Pause, Timeout und die aktive Sitzung A/B gelten fuer jede Anfrage. Aendernde Methoden brauchen die Freigabe-Checkbox je Lauf. URL-Payloads werden auf Wunsch kodiert; Header- und Body-Werte werden woertlich eingefuegt. Eine Reflexion allein ist kein Schwachstellennachweis. Ergebnisse enthalten nach Moeglichkeit maskierte Geheimnisse, koennen aber weiterhin vertrauliche Daten enthalten; Berichte vor Weitergabe pruefen.

`tests/Test-Intruder.ps1` prueft Modi, Anfragegrenzen, Zielbereich, Markierungsfehler, Vorschau und das erneute Oeffnen einer erzeugten Anfrage. `tests/Test-Workflow.ps1` prueft die Uebergabe Proxy → Intruder → Anfrageeditor in WPF.
