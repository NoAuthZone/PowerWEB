# PowerWEB 4.0: Repeater (tab 12)

Keep several requests side by side in named **slots**, edit and resend each one
independently, and see each slot's own last response. This complements the single
request editor on tab 3.

## Slots

- **New** adds a slot (seeded with the current scope URL); **Delete** removes the
  selected one. The list on the left shows all slots.
- Selecting a slot loads its method, URL, headers, body and last response. Editing the
  fields updates that slot (captured when you switch slots or send).
- **Send** issues the slot's request via the same HTTP layer as tab 3: scope checking,
  auth headers and the active session apply, and state-changing methods need the
  slot's authorization checkbox.

Each slot keeps its **last response** in memory so you can flip between slots without
losing results. Repeater requests are logged in the history (tab 5) as type
"Repeater"; slots themselves are session-only and not saved to the project.

## Related: full resend and response diff (tab 3)

- **Open URL in request editor** (tab 5 history) now restores the **full request**
  (headers and body), not just URL and method, when the request was sent in this
  session. Older/loaded history rows fall back to URL and method only (bodies and
  headers are never persisted to the project).
- **Diff bodies** (tab 3) shows a line-by-line diff of the remembered response body vs
  the current one (`-` baseline, `+` current), instead of only "identical yes/no".

## Grep columns (Intruder and Data table)

The Intruder (tab 9) and Data table (tab 11) accept an optional **Grep match** regex
(a yes/no column: does the response body match) and a **Grep extract** regex (an
Extract column: the first capture group, or the whole match). Handy for spotting and
sorting interesting responses at a glance.
