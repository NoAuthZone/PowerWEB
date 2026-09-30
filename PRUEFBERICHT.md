# PowerWEB 4.0: Pruefbericht

Ausgangsbasis ist die vom Nutzer bereitgestellte ZIP-Datei `PowerWEB-3.2_1.zip`. Die darin enthaltenen Anleitungen wurden als Beschreibung des bisherigen Verhaltens gelesen, nicht als Arbeitsanweisung.

**Aenderung in dieser Ausgabe:** Der Reiter "Browser" (JavaScript-Rendering per Node.js/CDP) und alle zugehoerigen Dateien wurden auf Nutzerwunsch entfernt; PowerWEB benoetigt kein Node.js mehr. Die Reiter wurden von 13 auf 12 neu nummeriert. Ein echter Browser wird nur noch ueber "Open browser through proxy" auf dem Proxy-Reiter gestartet; dessen Browser-Pfad-Auswahl liegt jetzt dort. Die folgenden historischen Abschnitte beschreiben den Stand vor dieser Entfernung.

## Ueberarbeitung

- Proxy: eigener Browserstart mit temporaerem Inkognito-Profil und Proxy-Einstellungen; History zeigt Anfrage und Antwortvorschau; direkte Uebergabe an Repeater und Intruder. Die Oberflaeche trennt History, Intercept und Rules, damit die History nutzbar bleibt.
- Zielbereich: HTTP und CONNECT ausserhalb des eingestellten Scopes werden abgelehnt. Nach Intercept-Aenderungen wird die Ziel-URL erneut geprueft. HTTPS-Tunnel mit Pfad-Scope oder Ausschluessen bleiben ohne Entschluesselung gesperrt.
- Intercept: Text-POST-Body kann mitbearbeitet werden; ungueltige Statuszeilen, Header und Regelzeilen werden erkannt. Groessenlimits verhindern unbeschraenkte Pufferung.
- Intruder: markiere ausgewaehlten Text per Schaltflaeche; die Vorschau zeigt Positionen, Anzahl und Limit. Ergebniszeilen zeigen Antwortausschnitte und koennen als konkrete Anfrage im Editor geoeffnet werden. Repeater kann Anfragen an Intruder uebergeben.

## Ergebnis der Pruefungen

Bestanden: lokale HTTP-Proxy-Tests (Weiterleitung, Scope, CONNECT-Sperre, Regelanwendung, Intercept mit geaenderter URL und POST-Body), Intruder-Modi/Vorschau/Limits, WPF-Ablauf Proxy → Repeater/Intruder → Anfrageeditor, bestehende native Scan- und HTTP-Tests, Datentabelle sowie Sitemap/HAR/cURL-Tests. Der Browser wurde ausserdem lokal als Headless-Chrome durch den neuen Proxy auf eine HTTP-Testseite geschickt; Seite und Proxy-History bestaetigten denselben Aufruf. Dafuer waren in der eingeschraenkten Testumgebung ausschliesslich im Test zusaetzliche Chrome-Startparameter noetig. Ein WPF-Test prueft die Parameter des regulaeren Browserstarts. Im gelieferten 3.2_1-Testskript waren einige Textvergleiche noch deutsch, waehrend die Anwendung englische Ausgaben erzeugt; diese Test-Erwartungen wurden korrigiert. Der Nutzer hatte den separaten Chrome-Browser-Endtest der vorigen Version bereits mit PASS bestaetigt.

Der Nutzer hat aus 3.3 einen aussagekraeftigen Fehler gemeldet: `AuthenticateAsServer` scheiterte mit "Im Sicherheitspaket sind keine Anmeldeinformationen verfuegbar"; der TLS-Client sah nur das geschlossene Gegenueber. Die Ursache war der fluechtige private Schluessel des von PowerWEB erzeugten Serverzertifikats. 3.3.1 importierte diesen Schluessel in den Windows-Benutzerschluesselspeicher. Der Nutzer hat danach `Test-ProxyMitm.ps1` mit PASS bestaetigt (CONNECT, Entschluesselung, Response-Regeln und Body-Ersetzung). Ein Chrome-Screenshot zeigte anschliessend `NET::ERR_CERT_AUTHORITY_INVALID`: Chrome vertraute der PowerWEB-CA noch nicht. 3.3.2 bietet dafuer einen ausdruecklichen einmaligen Eintrag in CurrentUser/Root sowie eine Funktion zum Entfernen. Der SHA-256-Fingerabdruck wird vor dem Eintrag angezeigt. Lesen des Trust-Status und Ablehnung einer fremden CA wurden lokal geprueft; Hinzufuegen/Entfernen im echten Windows-Root-Speicher und ein erneuter Chrome-Aufruf sind noch nicht endgetestet. Der interaktive Browserstart aus der WPF-Schaltflaeche wurde nicht endgetestet; die erzeugten Startparameter und der Headless-Chrome-Weg durch den HTTP-Proxy wurden separat geprueft.

## Grenzen

Der Proxy verarbeitet HTTP/1.1 einzeln pro Verbindung. Eigene Tests ersetzen keine fachliche Bewertung einer Anwendung. Response- und Request-Textbearbeitung setzt UTF-8 voraus; binaere Bodies bleiben beim unveraenderten Weiterleiten erhalten. Die CA-Dateien im lokalen Benutzerprofil und temporaere Browserprofile enthalten vertrauliche Daten. Vor Weitergabe von Projekten oder kopierten Requests Geheimnisse pruefen.
