# PowerWEB: TLS-/SSL-Scan (Reiter 13)

Der TLS-Scanner ist eigener MIT-lizenzierter PowerShell/.NET-Code. Er baut die
TLS-Handshake-Nachrichten selbst als Bytes und liest die Serverantwort direkt
über einen `TcpClient`. Er braucht **kein OpenSSL** und kein anderes externes
Werkzeug. Der Scan beschreibt, was **dieser Host aushandelt**; er ist kein
Nachweis der Ausnutzbarkeit über das beobachtete Handshake-Verhalten hinaus.
Nur autorisierte Ziele scannen.

## Start

1. In Reiter 13 Host (Hostname, `host:port` oder eine `https`-URL) und Port
   eintragen. Leer lässt PowerWEB den Scope-Host aus Reiter 1 verwenden.
2. **Enumerate all cipher suites** bestimmt, ob je Protokoll alle akzeptierten
   Cipher per Ausschlussverfahren ermittelt werden (mehr Verbindungen) oder nur
   der jeweils vom Server bevorzugte.
3. Optional **Active vulnerability probes authorized** setzen (siehe unten).
4. **Start TLS scan**. Ergebnisse erscheinen in den Tabellen des Reiters,
   Befunde in Reiter 2, die vollständige Auswertung im exportierten Bericht.

## So arbeitet die Engine

- **Protokoll-Erkennung:** Für jede Version (SSLv3, TLS 1.0–1.3) wird ein
  ClientHello genau mit dieser Version gesendet. Antwortet der Server mit einem
  passenden ServerHello, gilt die Version als unterstützt. TLS 1.3 wird über die
  `supported_versions`-Erweiterung erkannt (auch bei einem HelloRetryRequest).
  SSLv2 wird mit einem eigenen SSLv2-ClientHello separat geprüft.
- **Cipher-Enumeration:** PowerWEB bietet zunächst alle für die Version gültigen
  Cipher an, merkt sich den vom Server gewählten, entfernt ihn aus dem Angebot
  und wiederholt das, bis der Server keinen weiteren wählt. So entsteht die Liste
  der tatsächlich akzeptierten Suites. Jede Suite wird klassifiziert: Schlüssel-
  austausch, Authentifizierung, Verschlüsselung, Bits, Forward Secrecy und
  Schwäche-Marker (RC4, 3DES, DES, EXPORT, NULL, anonym, MD5, AEAD/CBC).
- **Server-Präferenz:** Bei aktiver Enumeration wird geprüft, ob der Server eine
  eigene Cipher-Reihenfolge erzwingt (Angebot und umgekehrtes Angebot liefern
  dieselbe Wahl) oder die Client-Reihenfolge übernimmt.
- **Zertifikat:** Aus dem Certificate-Handshake (TLS ≤ 1.2) wird die Kette
  gelesen und mit `X509Certificate2`/`X509Chain` ausgewertet: Subject/Issuer,
  Schlüsselalgorithmus und -größe, Signaturalgorithmus, Gültigkeit, Rest-Tage,
  Self-Signed, Kettenvertrauen, SANs und Hostname-Abgleich (inkl. einfacher
  Wildcard). Bei **TLS-1.3-only-Hosts** ist das Zertifikat im Handshake
  verschlüsselt; PowerWEB holt es dann über einen ergänzenden `SslStream`-
  Handshake, wertet es aber mit demselben X509-Code aus.

## Abgeleitete Schwächen (immer geprüft)

Diese ergeben sich direkt aus erkannten Protokollen und Ciphern und senden keine
Angriffs-Payloads:

| Schwäche | Ableitung |
| --- | --- |
| POODLE | SSLv3 unterstützt (mit CBC) |
| BEAST | TLS 1.0 unterstützt |
| SWEET32 | 3DES-Cipher angeboten |
| FREAK / LOGJAM | EXPORT-Cipher angeboten |
| RC4 | RC4-Cipher angeboten |
| DROWN | SSLv2 unterstützt |
| Kein Forward Secrecy | nur statische Schlüsselaustausch-Cipher |
| NULL / anonym / MD5 | entsprechende Cipher angeboten |
| CRIME | Server wählt eine TLS-Kompression ≠ null |
| Secure Renegotiation | `renegotiation_info` fehlt im ServerHello |

## Aktive Prüfungen (nur mit Freigabe)

Diese senden gezielt manipulierte TLS-Records und laufen ausschließlich, wenn
**Active vulnerability probes authorized** gesetzt ist. Die Freigabe wird nach
jedem Lauf zurückgesetzt.

| Prüfung | Verfahren | Sicherheit |
| --- | --- | --- |
| Heartbleed (CVE-2014-0160) | Heartbeat-Anfrage mit übergroßer Längenangabe nach dem ServerHelloDone; eine überlange Antwort belegt den Speicher-Overread | Hoch. Zurückgelesene Bytes werden nur gezählt und sofort verworfen, nie gespeichert. |
| CCS Injection (CVE-2014-0224) | Vorzeitiges ChangeCipherSpec vor dem ClientKeyExchange; ein gepatchter Server antwortet mit `unexpected_message(10)` | Experimentell — Annahme ohne Alert ist nur ein Hinweis, manuell bestätigen. |
| TLS_FALLBACK_SCSV | ClientHello mit niedrigerer Version und SCSV; ein geschützter Server antwortet mit `inappropriate_fallback(86)` | Mittel. Nur sinnvoll, wenn mehrere Vor-1.3-Versionen unterstützt werden. |

## Bewertung (Rating)

Aus den Befunden wird eine kompakte Note A+ bis F abgeleitet: SSLv2/SSLv3, RC4,
EXPORT, NULL/anonyme Cipher, ein abgelaufenes Zertifikat oder ein bestätigter
Heartbleed setzen sie auf F; TLS 1.0/1.1, 3DES, Kompression, SHA1-Signatur,
nicht vertrauenswürdige Kette oder Hostname-Fehler begrenzen sie. Die Note ist
eine schnelle Orientierung, kein Ersatz für die Einzelbewertung der Befunde.

## Grenzen

- Das Ergebnis spiegelt die Aushandlung mit **diesem** Host wider. Ein lokaler
  Unternehmens-Proxy oder ein vorgelagertes Gerät kann Protokolle, Cipher und
  Zertifikat verändern.
- Die Cipher-Tabelle deckt alle sicherheitsrelevanten Familien ab, ist aber
  nicht die vollständige IANA-Registry. Wählt ein Server eine unbekannte Suite,
  wird sie mit ihrer ID gemeldet.
- Der TLS-1.3-Schlüsselaustausch wird mit secp256r1 angeboten. Verlangt ein
  Server ausschließlich x25519, erkennt PowerWEB 1.3 über den HelloRetryRequest,
  kann die 1.3-Cipher dann aber nicht vollständig durchzählen.
- CCS Injection und TLS_FALLBACK_SCSV sind Best-Effort und als experimentell
  gekennzeichnet. „Kein Nachweis" bedeutet nicht „sicher".
- Die Verbindungszahl je Scan ist begrenzt (Standard 250). Abbruch behält bereits
  ermittelte Ergebnisse.

## Lokale Validierung

`tests/Test-Tls.ps1` startet einen lokalen `SslStream`-Testserver mit einem
kurzlebigen, selbstsignierten Zertifikat und scannt ihn mit der Engine: Cipher-
Katalog, Protokoll- und Cipher-Enumeration, Zertifikatsauswertung, Hostname-
Abgleich, TLS-Engine-Befunde, aktive Prüfungen, Abbruch, der „No TLS"-Fall und
der Bericht-Rundlauf. Auf Windows mit WPF wird zusätzlich der Reiter 13 in der
Oberfläche geprüft. Der Test braucht kein Netzwerk und keine Fremdwerkzeuge.
