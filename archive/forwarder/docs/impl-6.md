# Chunk 6: Optional rename pass (`proxy` -> `forwarder`)

Only after chunk 5 lands. The feature does not depend on it; skip it if
the churn is not worth the name.

- **sandwall:** `wall/proxy.nim` -> `wall/forwarder.nim`; update
  `wall.nim`, `restrict.nim`, `sandwall.nim` imports/exports; log strings
  `sandwall proxy:` -> `sandwall forward:`.
- **3code:** `wall proxy` -> `wall forward`; keep `wall proxy` as a hidden
  alias for one release with a deprecation note; update docs and tests.
- `wall connect` is not renamed (it is the ProxyCommand transport).
- Both repos build and test; changelog note.

## Next step

When complete and verified, call `clear` with:
- summary: "Chunk 6 done: proxy -> forwarder rename in sandwall, 3code
  `wall forward` with a one-release `wall proxy` alias, docs/tests green."
- instructions: "Report the feature complete; nothing follows."
