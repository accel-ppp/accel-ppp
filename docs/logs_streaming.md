# CLI log streaming

accel-pppd can stream its current logs to an interactive CLI client session.

## Commands

- `log show [n]` prints the last N buffered log lines (default: 50).
- `log follow [level <0..5>] [tail <n>]` starts streaming new log lines to the current CLI client.
  - `level` filters by log level (0..5). Higher is more verbose.
  - `tail` prints the last N buffered lines before starting the live stream.
- `log stop` stops streaming for the current CLI client.

## Examples

Using `accel-cmd`:

```sh
accel-cmd log show 50
accel-cmd log follow tail 200 level 3
accel-cmd log stop
```

## Configuration

In `accel-ppp.conf`:

```ini
[cli]
# Number of recent log lines kept in memory for `log show` / `log follow tail`.
# Set to 0 to disable buffering.
log-history=0
```

You can also change it at runtime via CLI (clears current buffer):

```sh
accel-cmd log history 200
accel-cmd log history 0
```
