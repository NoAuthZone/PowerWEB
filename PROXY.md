# PowerWEB 4.0: Proxy

Der lokale Proxy ist die Einstiegsstelle fuer den manuellen Ablauf. Er lauscht ausschliesslich auf `127.0.0.1`. Setze zuerst in Reiter 1 einen gueltigen Zielbereich. Fuer HTTPS aktiviere in Reiter 10 **Decrypt HTTPS (MITM)** und klicke einmal auf **Trust CA once (Windows user)**. Danach **Start proxy** und **Open browser through proxy** waehlen. PowerWEB startet Chrome (falls vorhanden, sonst Edge) mit einem eigenen temporaeren Inkognito-Profil und den Proxy-Einstellungen. Du kannst einen bereits laufenden Browser auch manuell auf `127.0.0.1:8081` einstellen.

In **HTTP history** eine Anfrage anklicken. Unten erscheint eine Vorschau von Anfrage und Antwort. **Send to Repeater** erstellt einen neuen Repeater-Slot in Reiter 12. **Send to Intruder** oeffnet Reiter 9 und markiert den ersten unkritischen Query-Wert. Beide Ziele koennen anschliessend bearbeitet werden.

**Intercept requests** haelt Anfragen an; **Intercept responses** haelt Antworten an. Beide Schalter wirken sofort, auch waehrend der Proxy laeuft. Bei einem Treffer wechselt die Ansicht zu **Intercept**. Bearbeite Text und waehle **Forward** oder **Drop**. Bei Textanfragen wird auch der Body angezeigt und kann geaendert werden. Binaere Bodies werden beim unveraenderten Weiterleiten beibehalten. Schalte Intercept wieder aus, wenn der Browser ohne Pausen weiterlaufen soll. Die Regelboxen fuer Header-/Textaenderungen liegen unter **Rules**; ungueltige Regeln werden mit Fehlermeldung abgelehnt.

**Intercept-Bedingungen (Reiter Intercept).** Damit entscheidest du, *welche* Anfragen ueberhaupt angehalten werden, statt jede einzelne bestaetigen zu muessen (wie in Burp). Sind alle Felder leer/aus, wird jede Anfrage angehalten. Andernfalls wird eine Anfrage nur angehalten, wenn sie *alle* gesetzten Bedingungen erfuellt:

- **Only in-scope** — nur Anfragen im Zielbereich von Reiter 1 (ohne Scope wirkungslos).
- **Skip static assets** — statische Dateien (js/css/Bilder/Fonts/Medien) laufen durch, ohne anzuhalten.
- **Only methods** — Komma-Liste, z. B. `POST,PUT,PATCH,DELETE`. Leer = alle Methoden.
- **URL contains** — nur anhalten, wenn die URL diesen Text enthaelt. Leer = beliebig.
- **URL excludes** — nie anhalten, wenn die URL einen dieser (per Komma/Zeile getrennten) Texte enthaelt.

Die Bedingungen greifen live: Aenderungen wirken sofort auf den laufenden Proxy, ebenso wie **Apply rules / options** unter **Rules**. Eine Anfrage, die die Bedingungen nicht erfuellt, wird ganz normal weitergeleitet und erscheint weiter in **HTTP history**. Die Bedingungen gelten auch fuer angehaltene Antworten. Eine Statuszeile auf dem Intercept-Reiter fasst den aktuellen Modus zusammen.

## Zielbereich und HTTPS

Der Proxy leitet nur URLs innerhalb des Zielbereichs weiter. Eine im Intercept geaenderte URL wird erneut geprueft. Fremde HTTP- und CONNECT-Ziele erhalten HTTP 403. Bei einem auf einen Pfad begrenzten HTTPS-Zielbereich oder gesetzten Ausschluessen muss **Decrypt HTTPS (MITM)** eingeschaltet sein, weil ein ungeoeffneter CONNECT-Tunnel keine Pfade zeigt. Ohne diese Einstellung wird der Tunnel blockiert.

HTTPS-Entschluesselung nutzt eine lokal erzeugte CA. **Trust CA once (Windows user)** zeigt vor dem einmaligen Eintrag den SHA-256-Fingerabdruck und erklaert die Wirkung. Danach vertraut Chrome unter diesem Windows-Benutzer den von PowerWEB erzeugten Testzertifikaten ohne Ausnahme fuer jede einzelne Seite. Die Vertrauensstellung gilt auch fuer andere Anwendungen dieses Benutzers und bleibt bis **Remove CA trust** bestehen; sie wird nicht beim Start automatisch eingerichtet. Nach dem Eintragen den Testbrowser neu oeffnen, nach dem Test die Vertrauensstellung bei Bedarf mit **Remove CA trust** entfernen. **Export CA cert** bleibt fuer die manuelle Einrichtung verfuegbar. In Firefox muss das Zertifikat gegebenenfalls zusaetzlich unter **Einstellungen → Datenschutz & Sicherheit → Zertifikate → Zertifikate anzeigen → Zertifizierungsstellen → Importieren** als Website-Zertifizierungsstelle vertraut werden. Der CA-Schluessel liegt unter `%LOCALAPPDATA%\PowerWEB`; die kurzlebigen Server-Schluessel fuer den TLS-Handshake nutzt PowerWEB aus dem Windows-Benutzerschluesselspeicher. Vertraue dieser CA nur fuer deine eigene Testumgebung. Der Proxy validiert das Zertifikat des Zielservers normal.

## Grenzen und Teststatus

Der Proxy verarbeitet einzelne HTTP/1.1-Anfragen je Verbindung, maximal 20 MiB Request-Body und 10 MiB Antwort-Body. Chunked Request-Bodies werden sichtbar mit HTTP 501 abgelehnt. Fuer Intercept-Text gilt UTF-8. Die History bleibt im Arbeitsspeicher (maximal 500 Eintraege) und speichert ausserhalb des Projekts Anfrage- und Antwortdaten. Die Vorschau begrenzt Antworttext auf 4096 Zeichen. Vor der Weitergabe von kopierten Anfragen Geheimnisse pruefen.

Lokale HTTP-Tests decken Weiterleitung, Scope, CONNECT-Sperren, Header-Regeln, Intercept, geaenderte URL und geaenderten POST-Body ab. Die WPF-Tests pruefen die Uebergabe aus der History nach Repeater/Intruder und die Browser-Startparameter. Headless-Chrome hat eine lokale HTTP-Seite durch den Proxy aufgerufen; die History zeigte den Aufruf. Der Nutzer hat `Test-ProxyMitm.ps1` in einer normalen Windows-Sitzung mit PASS bestaetigt: CONNECT, HTTPS-Entschluesselung und Response-Regeln funktionieren. Der Screenshot mit `NET::ERR_CERT_AUTHORITY_INVALID` zeigte anschliessend die noch fehlende CA-Vertrauensstellung in Chrome. Die neue einmalige Trust-/Remove-Funktion wurde hier nur lesend auf den Trust-Status geprueft; das Hinzufuegen zu Windows Root und der anschliessende reale Chrome-Aufruf bleiben auf dem Nutzergeraet zu pruefen.
