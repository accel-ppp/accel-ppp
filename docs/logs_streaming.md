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

## Delivery and overload behavior

Log lines are queued per subscriber and delivered asynchronously in the
client's own I/O context, so streaming never blocks or interferes with the
threads emitting log messages.

- If a subscriber cannot keep up, queued lines are dropped and a single
  `log follow: overrun, some lines were dropped` notice is printed.
- If the client's transmit backlog keeps growing (a stalled reader), the
  subscription is dropped with `log follow: client is too slow, disabling`
  to protect the daemon's memory.
- Lines emitted between the `tail` replay and the start of the live stream
  may be missed; `tail` replay requires the history buffer to be enabled.
