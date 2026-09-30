# Sitemap, HAR import and cURL

Three helpers that make it faster to move requests in and out of PowerWEB. All of
them are pure data transforms in `PowerWEB.Tools.psm1`; the workbench renders and
consumes their output. Nothing here sends a request on its own — you always review
and send from the request editor, repeater or intruder, where the normal scope,
authorization and redaction rules still apply.

## Sitemap (tab 13)

A tree of every URL PowerWEB has already seen in this project, grouped host to
path:

- Sources: the crawler and native engine, your manual requests, the repeater and —
  while the proxy is running — the proxy history. Finding locations are included
  too.
- Only absolute `http`/`https` URLs are shown. A query string appears as a child
  leaf named `?...` under its path, so you can tell parameterised endpoints apart.
- The count in parentheses after a node is the number of direct children. Nodes
  with a handful of children expand automatically.
- Each node carries the **richest request PowerWEB actually observed** for that
  URL, not just the URL string. A non-`GET` node is labelled with its method
  (e.g. `[POST] login`). Sources are ranked: a proxy capture (real method,
  headers and body) beats an archived manual request, which beats a bare
  history/finding row where only the method and URL are known.

Select a node and use the buttons at the bottom. Each one reconstructs the
observed request — method, headers and body — so a POST endpoint seen through the
proxy arrives as that POST, not as an empty GET:

- **To Requests (tab 3)** — loads the request into the request editor.
- **To Repeater** — creates a new repeater slot from the request.
- **To Intruder** — loads the request into the intruder so you can mark positions.

When only the URL is known (crawler/native rows carry no headers or body), the
buttons seed a plain request for that method and the status line says so.

The tree rebuilds when a project is loaded, when a run finishes, whenever you open
the Sitemap tab, and — while the proxy is running and the tab is in view — as new
proxy traffic arrives. **Refresh** forces a rebuild at any time.

## HAR import

**Import HAR ...** on the sitemap tab reads a browser capture (`.har`, HTTP Archive
1.2, as exported by Chrome/Edge/Firefox dev tools):

- Each request becomes a **history** entry (method, URL, status, duration, type
  `HAR`).
- Up to 200 requests are also turned into ready-to-edit **repeater slots** with
  their headers and request body. Hop-by-hop and automatic headers
  (`Host`, `Content-Length`, `Connection`, `Cookie`, ...) are dropped so the
  request editor sets them itself; pseudo-headers (`:method`, ...) are skipped.
- Files larger than 50 MB are rejected.

HAR captures routinely contain session cookies and tokens. They are held in memory
as repeater slots and history only, never written into the saved project, but treat
the imported slots as sensitive while they exist.

## Copy as cURL / cURL import

Every request in the request editor (tab 3), the proxy history (tab 10), the
repeater (tab 12) and — indirectly — the sitemap can be exchanged with other tools
as a `curl` command:

- **Copy as cURL** puts a single-line command on the clipboard. Values are
  double-quoted with embedded quotes escaped. Header values are copied exactly as
  entered, including any authorization or cookie values, so paste with care.
- **From cURL** reads a `curl` command from the clipboard and fills the request
  editor (or, in the repeater, a new slot). It understands the common flags:
  `-X/--request`, `-H/--header`, `-A/--user-agent`, `-e/--referer`,
  `-b/--cookie`, the `-d/--data*` family (which imply `POST`), `--url` and a bare
  `http(s)://` argument. Line continuations (`\`, `^`, backtick) are handled, so
  multi-line commands copied from dev tools work.

A curl command imported from an arbitrary host is still subject to the project
scope when you send it — an out-of-scope target is refused at send time, exactly
like a hand-typed URL.

## Tests

`tests/Test-Tools.ps1` covers the sitemap tree structure, HAR parsing (counts,
POST body, dropped `Host` header) and a cURL build/parse round trip plus a
hand-written command with `-b`, `-A` and `-d`.
