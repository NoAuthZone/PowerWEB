# PowerWEB 4.0

Part of the NoAuthZone tools — https://github.com/NoAuthZone

A self-contained web testing workbench for Windows and PowerShell, original code
under MIT. Native scan engine, manual HTTP tests, two sessions, an intercepting
proxy, table-driven tests and reports. There is no
external scan back end. Existing project findings remain readable.

Guides: [Native engine](EIGENE-ENGINE.md),
[Intruder](INTRUDER.md), [Proxy](PROXY.md), [Data table](DATATABLE.md),
[Repeater](REPEATER.md), [Sitemap, HAR and cURL](SITEMAP.md),
[TLS / SSL scan](TLS.md), [Test report](PRUEFBERICHT.md).

## Start

1. Extract the whole ZIP into its own folder.
2. Double-click `Start-PowerWEB.cmd`.
3. On **Engagement and Scan** enter a project name and, optionally, a target scope
   (needed only for the crawl, native engine and role comparison).
4. Review exclusions and limits, then **Start scan**.

Requirements: Windows, Windows PowerShell 5.1 and WPF/.NET Framework. No admin
rights in normal operation. The starter sets `-ExecutionPolicy Bypass` for its
own process only; no permanent system setting is changed. Organization policy
still applies. `PowerWEB.ps1` also launches the interface.

## The workspaces

### 1. Engagement and Scan

- Project name, target scope, additional start URLs and engagement notes.
- **The target scope is optional.** Leave it empty to work without a scope:
  Requests, Parameters, Intruder, Data table, Repeater and the proxy then accept
  and forward any target you supply. A crawl (tab 1 scan), the native engine and
  the role comparison still need a scope, because they start from and stay within
  the scope origin.
- When set, the scope binds scheme, host, port and optionally a path with its
  subpaths. `https://example.org/app/` allows `/app/page`, but neither
  `/application` nor subdomains, other ports, HTTP or foreign hosts. Query
  parameters are not an additional scope boundary. A full page path limits the
  crawler to exactly that path and its subpaths; for wider crawling use a shared
  directory path as scope and concrete pages as start URLs.
- Exclusions still apply even without a scope, so you can carve out `logout` or
  `delete` regardless. Only test targets you are authorized to test.
- Exclusions are substrings, case-insensitive, applied to decoded paths and
  queries. Default: logout, signout, delete, remove, unsubscribe. Encoded path
  separators and dot segments are rejected conservatively.
- Crawler for HTML links and redirects; no form submission, no JavaScript, no
  resource or file discovery. External targets are not requested. Fragments are
  removed and identical URLs deduplicated.
- 1 to 200 pages, depth 0 to 10, delay 0 to 10000 ms and timeout 1 to 60 s. The
  start page counts as depth 0. Queue and link evaluation are bounded.
- Passive hints about HTTP/HTTPS, certificate expiry, CSP, HSTS, MIME protection,
  frame protection, cookies, mixed content, password fields on HTTP pages and
  technical error messages.
- Optional active checks: one GET with a foreign test origin, OPTIONS and neutral
  reflection markers for up to three existing query parameters per page. Names
  that look like tokens or credentials are skipped. A reflection is **not proof of
  XSS**, and an Allow header does not prove a method is usable. A CORS hint needs
  manual validation.
- With active checks, at most six requests per visited page, without them one
  request per page. DNS, proxies and the runtime's certificate checks may trigger
  further connections.
- Cancel ends the running HTTP request as far as the runtime supports and keeps
  results already completed. DNS can take longer.

Auth headers such as `Authorization: Bearer ...` or `Cookie: ...` are held in
memory only and used inside the scope only. They are not saved. Native requests
use the cookie store of the session A/B chosen on tab 7. There is no automatic
login, token renewal or MFA handling. Expired sessions can therefore lead to
login pages or 401/403 responses.

### 2. Findings

Automatic and manual findings with risk, URL, status, source, evidence and
recommendation. Search by title, URL, risk or status. Select a row, edit it and
click **Apply finding**. For a new finding choose **Add manual finding**. Status:
Open, Confirmed, False positive, Fixed.

Automatic risk values are a first estimate and must be assessed on their merits.
Similar findings are merged by title, URL and evidence; a rescan does not reset a
status you already edited. A disappeared finding is not marked fixed
automatically.

### 3. Requests

Your own GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS requests with headers and
a UTF-8 body. State-changing methods need the checkbox in the request editor,
which is reset after sending. Your own headers override auth headers of the same
name. Connection headers such as Host and Content-Length are managed by the
runtime.

Response headers and body are visible. Known secret response headers are hidden;
response bodies themselves may still contain secrets. A response can be remembered
for comparison with the next one: status, bytes read, content equality and changed
header names are compared. This is not a semantic HTML diff. For role tests use the
A/B comparison on tab 7 or switch the auth headers deliberately and repeat the same
request.

### 4. Parameters

URL with exactly one `{{PAYLOAD}}` in the query part, your own test values one per
line (at most 50 values, up to 2048 characters each). One GET per value,
URL-encoded automatically, with the configured auth headers, exclusions, delays
and timeouts. Compared are HTTP status, header time, bytes read and verbatim
reflection. The test values are not rated automatically as SQLi, XSS or other
flaws. This area actually executes the values the tester entered.

### 5. History

Requests with method, URL, status, time, test type and errors. A row can prepare
the URL and method in the request editor. Request bodies and individual headers
are not restored from the history. Review before resending.

### 6. Manual review

An editable checklist for engagement, attack surface, transport, authentication,
sessions, roles/object rights, input validation, XSS, injection, CSRF/CORS,
business logic and wrap-up/retest. Status and evidence are saved in the project
and report. **Open** means not tested, **Reviewed** does not automatically mean
safe. The checklist is a starting point, not a complete test standard.

### 7. Native engine

An active but bounded HTTP scanner in pure PowerShell/.NET with structured
evidence: SQL error, boolean SQL response, template evaluation, HTML reflection,
redirects, header injection and CORS. Plus two separate sessions (A/B) and a role
comparison. See [EIGENE-ENGINE.md](EIGENE-ENGINE.md).

## Proxy → Repeater → Intruder

1. Set the scope on tab 1. For HTTPS, turn on **Decrypt HTTPS (MITM)** and click **Trust CA once (Windows user)**; review the SHA-256 fingerprint in the one-time confirmation. Start the proxy and click **Open browser through proxy**.
2. Select a request in proxy history and send it to **Repeater** or **Intruder**.
3. In Intruder, mark more values by selecting their text, add payloads, preview the request count, then run and inspect a selected result.

HTTPS path scopes and exclusions require proxy decryption to enforce them. The user confirmed the HTTPS MITM functional test with PASS. The one-time Windows CA trust lets Chrome accept PowerWEB certificates across the scope without individual page exceptions; it can be removed with **Remove CA trust**. See [PROXY.md](PROXY.md).

### 8. Intruder

Repeated, deliberately modified requests with your own payloads. Transfer a captured request from Proxy or Repeater, then mark positions in
the URL, headers and body with a pair of section signs, choose an attack mode
(Sniper / Battering ram / Pitchfork / Cluster bomb) and provide payload sets. See
[INTRUDER.md](INTRUDER.md).

### 9. Proxy

A local intercepting forward proxy with a dedicated browser launcher and an
optional target scope. With a scope set, only in-scope traffic is forwarded and
out-of-origin CONNECTs are blocked; with the scope left empty the proxy forwards
every request, so nothing has to be accepted per host. Route your browser through
it and modify request and response headers/body via rules or manual intercept,
then forward or drop. HTTPS
is tunnelled only for a full-origin scope without exclusions (or when no scope is set); "Decrypt HTTPS (MITM)" uses a local CA
that you trust once for the current Windows user in the Proxy tab. This trust affects other apps in that user account until removed. See [PROXY.md](PROXY.md).

### 10. Data table

Send a request repeatedly with values from a pasted table; the template references
columns as `$name`. An optional grep match/extract adds a result column. See
[DATATABLE.md](DATATABLE.md).

### 11. Repeater

Keep several named request slots side by side, each with its own last response;
edit and resend independently. Related: full resend from history and a response
line-diff on tab 3. See [REPEATER.md](REPEATER.md).

### 12. Sitemap

A host-to-path tree of every URL PowerWEB has observed — crawler, native engine,
manual requests, repeater and, while it runs, the proxy history. Select a node and
send it to **Requests**, a new **Repeater** slot or **Intruder**. **Import HAR ...**
loads a browser `.har` capture as history entries plus ready-to-edit repeater
slots. Any request in tabs 3, 10, 12 and the sitemap can be copied out as a
single-line `curl` command, and a `curl` command on the clipboard imported back
into the request editor or a new repeater slot. See [SITEMAP.md](SITEMAP.md).

### 13. TLS / SSL

A native TLS/SSL scanner in pure PowerShell/.NET: it builds raw ClientHello
records and reads the server's ServerHello directly over a `TcpClient`, so it
needs no OpenSSL or other external tool. It enumerates the offered protocol
versions (SSLv2, SSLv3, TLS 1.0/1.1/1.2/1.3) and, by elimination, the cipher
suites each version accepts, classifies them (AEAD/CBC, forward secrecy,
RC4/3DES/DES/EXPORT/NULL/anonymous/MD5), parses the certificate chain with X509
(key size, signature algorithm, validity, self-signed/trust, hostname match)
and derives a compact rating. Weaknesses such as POODLE, SWEET32, FREAK/LOGJAM,
RC4, BEAST and DROWN are derived from the observed protocols and ciphers.

Active probes (Heartbleed, CCS injection and TLS_FALLBACK_SCSV enforcement) send
crafted TLS records and therefore run only when **Active vulnerability probes
authorized** is ticked; the checkbox resets after each run. Heartbleed counts and
immediately discards any over-read bytes — leaked memory is never stored. The CCS
and fallback checks are best-effort and flagged experimental; confirm them
manually. Findings are added to tab 2 and the full result (protocols, ciphers,
certificate, vulnerabilities) is written to the exported report. The scan
reflects what this host negotiates; it is not proof of exploitability beyond the
observed handshake. See [TLS.md](TLS.md).

## Save and reports

- **Save / Load project:** JSON project with scope, scan settings, findings,
  history, run summaries, checklist and notes.
- **Export report:** HTML report, JSON project or CSV finding list.
- HTML escapes content; CSV neutralises typical formula prefixes.
- Scan errors, cancellations, remaining queue and test limits appear in the report.
- Unsaved changes trigger a save prompt on close.
- Auth headers, request bodies and full responses are not saved. **URLs including
  query values, your own parameter test values, cookie names and manual evidence
  are saved.** Review reports for secrets before sharing.
- Project files are plain unencrypted JSON, at most 20 MB on load.

## Limits

The native engine examines query parameters and selected headers. The Intruder
(tab 8) and Data table (tab 10) send tester-defined, modified requests but do not
rate the responses automatically. The proxy (tab 9) intercepts requests and
responses and modifies headers/body; with MITM on it also decrypts HTTPS. The TLS
engine (tab 13) enumerates protocols and cipher suites and inspects the
certificate, but automatic business-logic tests, automatic login/MFA handling,
extensive click sequences and OpenAPI import are not included. A complete pentest
requires manual checks.

HTTP responses are never followed automatically. In the crawler, matching redirect
targets enter the queue as their own URLs and count against the page and depth
limit. The request editor does not follow redirects.

Text responses are read up to 256 KiB (with a hint on overflow); binary content is
not. Content-Type and charset drive the analysis. HTML detection is a heuristic.
TLS certificates are validated normally by .NET/Windows; faulty connections return
errors. There is no global disabling of validation. A local corporate proxy affects
the observed certificate.

PowerWEB itself has no telemetry or automatic downloads. Only use targets within
the agreed test scope. Even GET calls can have side effects on faulty applications.

## Sources and license

PowerWEB is part of the NoAuthZone tools (https://github.com/NoAuthZone). The
original PowerWEB code is under MIT, see LICENSE. Windows, PowerShell and .NET
are system requirements with their own license terms.

## Tests and command line

The integration tests use a local test server only:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\tests\Test-PowerWEB2.ps1
```

Without the interface:

```powershell
Import-Module .\PowerWEB.Audit.psm1
$p = New-PWProject -Name 'Web assessment' -ScopeUrl 'https://example.org/app/'
$r = Invoke-PWAudit -ScopeUrl $p.ScopeUrl -MaxPages 10 -MaxDepth 2
$p.Findings = @($r.Findings)
$p.History = @($r.History)
$p.Runs = @($r.Summary)
Export-PWProjectReport -Project $p -Path "$PWD\report.html"
Save-PWProject -Project $p -Path "$PWD\project.json"
```

The former `PowerWEB.Core.psm1` remains for the simple CLI commands from version 1.
The interface uses `PowerWEB.Audit.psm1`, `PowerWEB.Scanner.psm1`,
`PowerWEB.Proxy.psm1`, `PowerWEB.Tls.psm1` (TLS/SSL scan) and `PowerWEB.Tools.psm1`
(sitemap, HAR import, cURL). The sitemap, HAR and cURL helpers are covered by
`tests/Test-Tools.ps1`; the TLS engine by `tests/Test-Tls.ps1`, which starts a
local `SslStream` test server and needs no network.

A TLS scan without the interface:

```powershell
Import-Module .\PowerWEB.Tls.psm1
$t = Invoke-PWTlsScan -Target 'example.org:443' -EnumerateCiphers
$t.Protocols | Format-Table Name, Supported
$t.Certificate | Format-List Subject, KeySize, SignatureAlgorithm, DaysLeft
$t.Summary.Rating
# add -AllowActiveVulnChecks for Heartbleed / CCS / TLS_FALLBACK_SCSV probes
```
