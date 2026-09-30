# PowerWEB 4.0: Data table (tab 11)

Send a request repeatedly with values taken from a table. The request template
(URL, headers, body) references table columns as `$name`; the table's header row
names the columns and every following row is one test case, sent as its own
request. This is the friendly, spreadsheet-style companion to the Intruder.

## Placeholders

Reference a column anywhere in the URL, additional headers or body as `$name`,
where `name` matches a column header. Only defined column names are substituted;
any other `$text` is left untouched. Boundary-safe: `$id` is not matched inside
`$identifier`.

Example URL: `https://target/app/search?q=$term&id=$id`

Use **From tab 3** to copy method, URL, headers and body from the request editor.

## The table

- First non-empty line = header (column names). Names use letters, digits and
  underscore only.
- Each following line = one test case (one request).
- The separator is auto-detected per header line: **tab, then semicolon, then
  comma**, so you can paste straight from a spreadsheet.
- Lines starting with `#` are ignored.

```
term,id
admin,1
test,2
guest,3
```

## Options and limits

- **URL-encode values in the URL** (default on) encodes each value substituted
  into the URL; header and body values are inserted verbatim.
- **Max requests** 1–5000 caps the run. Each value may hold at most 2048
  characters.
- **State-changing methods** (POST/PUT/PATCH/DELETE) require the authorization
  checkbox.
- Every request runs through the same HTTP layer as the rest of PowerWEB: scope
  checking, exclusions, connection-managed header guards, delay and timeout from
  tab 1 and the active session (cookies) from tab 8. Auth headers apply; template
  headers override auth headers of the same name.

## Results

The grid shows one row per test case with the variable values, HTTP status, time
(ms), bytes read, whether any value was reflected verbatim, any error and the
(redacted) URL. Requests also appear in the history (tab 5) and the run summary
in the report.

**Reflection is not proof of exploitability.** Known auth secrets are masked in
results and history; values and URLs may still be sensitive, so review reports
before sharing.

## Local validation

`tests/Test-DataTable.ps1` checks table parsing, `$name` substitution (with
boundary safety and URL encoding), reflection and scope/exclude gating:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-DataTable.ps1
```
