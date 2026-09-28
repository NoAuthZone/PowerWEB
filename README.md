# PowerWEB 3.2

A self-contained web testing workbench for Windows and PowerShell, original code
under MIT. Native scan engine, manual HTTP tests, two sessions, an intercepting
proxy, table-driven tests, reports and optional Chrome/Edge tests. There is no
external scan back end. Existing project findings remain readable.

Guides: [Native engine](EIGENE-ENGINE.md), [Browser](BROWSER.md),
[Intruder](INTRUDER.md), [Proxy](PROXY.md), [Data table](DATATABLE.md),
[Test report](PRUEFBERICHT.md).

## Start

1. Extract the whole ZIP into its own folder.
2. Double-click `Start-PowerWEB.cmd`.
3. On **Engagement and Scan** enter a project name and target scope.
4. Review exclusions and limits, then **Start scan**.

Requirements: Windows, Windows PowerShell 5.1 and WPF/.NET Framework. No admin
rights in normal operation. The starter sets `-ExecutionPolicy Bypass` for its
own process only; no permanent system setting is changed. Organization policy
still applies. `PowerWEB.ps1` also launches the interface.

## The workspaces

### 1. Engagement and Scan

- Project name, target scope, additional start URLs and engagement notes.
- The scope binds scheme, host, port and optionally a path with its subpaths.
  `https://example.org/app/` allows `/app/page`, but neither `/application` nor
  subdomains, other ports, HTTP or foreign hosts. Query parameters are not an
  additional scope boundary. A full page path limits the crawler to exactly that
  path and its subpaths; for wider crawling use a shared directory path as scope
  and concrete pages as start URLs.
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
use the cookie store of the session A/B chosen on tab 8. There is no automatic
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
A/B comparison on tab 8 or switch the auth headers deliberately and repeat the same
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

### 7. Browser

Edge or Chrome in a fresh, headless profile: DOM link discovery, a form inventory,
cookie attributes, JavaScript errors and an optional active XSS check. See
[BROWSER.md](BROWSER.md).

### 8. Native engine

An active but bounded HTTP scanner in pure PowerShell/.NET with structured
evidence: SQL error, boolean SQL response, template evaluation, HTML reflection,
redirects, header injection and CORS. Plus two separate sessions (A/B) and a role
comparison. See [EIGENE-ENGINE.md](EIGENE-ENGINE.md).

### 9. Intruder

Repeated, deliberately modified requests with your own payloads. Mark positions in
the URL, headers and body with a pair of section signs, choose an attack mode
(Sniper / Battering ram / Pitchfork / Cluster bomb) and provide payload sets. See
[INTRUDER.md](INTRUDER.md).

### 10. Proxy

A local intercepting forward proxy. Route your browser through it, modify request
headers via rules or manual intercept, then forward or drop. HTTPS (CONNECT) is
tunnelled, not decrypted in this version. See [PROXY.md](PROXY.md).

### 11. Data table

Send a request repeatedly with values from a pasted table; the template references
columns as `$name`. See [DATATABLE.md](DATATABLE.md).

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
(tab 9) and Data table (tab 11) send tester-defined, modified requests but do not
rate the responses automatically. The proxy (tab 10) intercepts HTTP and modifies
headers; HTTPS is only tunnelled there so far, not decrypted. The browser offers
DOM crawling and a limited XSS check. Automatic business-logic tests, automatic
login/MFA handling, extensive click sequences, OpenAPI import and a TLS-version
scan are not included. A complete pentest requires manual checks.

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

The original PowerWEB code is under MIT, see LICENSE. Windows, PowerShell and .NET
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
The interface uses `PowerWEB.Audit.psm1`, `PowerWEB.Scanner.psm1` and
`PowerWEB.Proxy.psm1`.
