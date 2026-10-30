# Spike: Seatbelt intermittently refuses the proxy connect on macOS 14

Status: open. Root cause not found; no product change yet.

## Symptom

On GitHub's `macos-14` runners (macOS 14.8), `sandbox_blocks_read_write_and_connect`
fails now and then with `proxy=unavailable (connect: PermissionDenied)`: Seatbelt
denies the sandboxed child's TCP connect to warden's own egress proxy on
`127.0.0.1:<port>`, although the profile has
`(allow network-outbound (remote ip "localhost:<port>"))` for that port. When it
happens to a real launch, the harness's request to the gateway fails.

## Data

Experiments ran on the unmerged branch `spike/macos14-proxy-eperm` (scripts in
`.github/spike/`, workflow `spike-macos-proxy.yml`).

| Experiment | macos-14 | macos-15 |
|---|---|---|
| Real `warden run probe` loop (run 41000147126) | 2 of 150 failed | not run |
| Raw `sandbox-exec` with the generated rule (runs 40999067252, 40999431030) | rare | 0 of about 1,000 |
| Delay between process start and first connect (run 41002881250) | 1 of 40 at 0 ms, 4 of 40 at 400 and 800 ms, 6 of 40 at 3.2 s | 0 at every delay |
| Large shuffled runs on four VMs (run 41004403248) | 0 of about 1,700 | 0 of about 1,600 |

- macos-15 never failed in any experiment.
- On macos-14 the rate varies a lot between runs and VMs, from 0 to about 15 %.
  Some VMs seem to be in a bad state for their whole job.
- Where it failed, the first connect of a process was refused and later connects
  from the same process succeeded.
- `(remote ip "127.0.0.1:<port>")` is rejected outright (SBPL only accepts
  `localhost` or `*` as the host), as expected.
- `(remote ip "*:<port>")` was never seen failing, but the samples are small. It is
  not an acceptable fix anyway: the child knows the port from `HTTPS_PROXY`, so it
  could reach any host listening on it.

## Hypotheses

- The `localhost` host token is matched through state that macOS 14 sets up lazily
  or refreshes, and a connect that races it is denied. This fits the failing first
  connect, the growth with delay and the clean `*:<port>` samples, but it is not
  proven.
- The cause is specific to some runner hosts, not to warden. This fits the run-to-run
  variance.

## Next steps

- Reproduce on a real macOS 14 machine, where `log stream --predicate 'sender=="Sandbox"'`
  can show the denial.
- A mitigation that does not widen the sandbox: a tiny warm-up connect to the proxy
  inside the sandbox before exec'ing the harness, retried on EPERM. This only helps if
  the failure is per process image and not per connect; test that first.
- `test(probe)` in this PR already names the failing step, so CI failures stay
  diagnosable.
