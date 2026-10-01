# History and Usage

## History aggregates

History reads token totals from `run_history_token_usage_rollup`, with one row
per run that has recorded usage. SQLite triggers update these totals in the
same transaction as each response insert, update, or delete. Repeated response
IDs replace their previous contribution instead of adding it again.

Migration `0024_run_history_token_usage_rollup.sql` calculates existing totals
once. The first startup after upgrade must finish this migration before the
service becomes available. Its duration depends on the number of recorded
responses and database storage performance. Later restarts do not recalculate
the totals. Raw history and response usage remain available.

Pagination and filters do not change. Statistics cover all matching runs,
not just the current page. Filtered statistics still scan matching run
aggregates. Text search can still require a history scan.

## Reusable Usage connections

The first Usage request for an account starts a dedicated Codex app-server
container. Later reads and reset requests reuse its initialized connection.
Results are not cached. The reset action still reads fresh usage before
checking eligibility, and failed reset requests are not replayed automatically.

Each account has one worker and one queued request. Requests for the same
account run sequentially. A page loads up to four accounts concurrently and
preserves their configured order. Usage containers do not share review sessions.
Each started account retains its container until failure or service shutdown.
The first request still pays the startup cost. RPCs retain the existing
`codex.timeout_seconds` limit.

A canceled HTTP request does not interrupt an accepted RPC. A failed RPC
invalidates its connection. The worker removes that container before starting
another. If removal fails, subsequent requests retry removal and report the
error until Docker recovers. The worker never reuses the invalid connection.

Normal scheduler exits, including single scans, shutdown signals, and errors,
wait for Usage cleanup. Shutdown rejects new Usage requests and interrupts
active RPCs. Container startup must finish before cleanup can remove its
container. Cleanup failures are logged and cause an unsuccessful process exit.
After a forced process termination, the existing startup sweep removes leftover
managed containers.

## Transcript bodies

The run detail page omits collapsed bodies larger than 16 KiB from its initial
HTML. Opening an entry loads its rendered body once. Small bodies, summaries,
messages, and command outputs remain inline. A failed load shows a retry link.
Without JavaScript, the load link opens the body directly.

`GET /api/history/{run_id}/entries/{event_id}/body` reads only the selected
persisted event. It returns safe HTML and requires the event to belong to that
run. Missing or non-expandable entries return HTTP 404. The route is available
only when the status UI is enabled, within the same trusted admin surface.
Reload the page if a backfill replaces the event IDs before a body request.

The run snapshot still reads all persisted events. The existing run JSON
endpoint still includes full bodies. Lazy body loads reduce initial HTML, not
the cost of building that snapshot.

## Regression checks

```sh
cargo test run_history --lib
cargo test usage --lib
cargo test scheduler::tests --lib
cargo test run_detail_loads_large_collapsed_bodies --lib
node --test tests/transcript_body.test.cjs
```

Usage tests exercise the production worker and HTTP page with a scripted
app-server transport. They do not measure live Docker or provider latency.
Transcript checks use real SQLite and HTTP requests. The Node check exercises
the scripts with simulated browser and fetch boundaries, not a rendered page.
