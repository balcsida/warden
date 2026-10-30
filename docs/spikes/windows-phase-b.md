# Spike: can phase B work on Windows?

Throwaway feasibility spike (branch `spike/windows-phase-b`, not for merge). Workflow: `.github/workflows/spike-windows.yml`.
Machine: GitHub `windows-2022` (Windows Server 2022, 10.0.20348), running as `runneradmin` (RID 500, full admin token, no UAC).
CI run with every step: https://github.com/balcsida/warden/actions/runs/40994957267
(an earlier full run, https://github.com/balcsida/warden/actions/runs/40994546160, gave identical results for steps 1-6).

Design under test (DESIGN §2.3/2.4 phase B): harness runs as a dedicated local user, created once by an elevated setup; firewall rules scoped to that user leave 127.0.0.1:P (egress proxy) as its only peer; the user's profile is unreadable to it.

## Results

| # | Check | Expected | Observed | Verdict |
|---|---|---|---|---|
| 1 | Create group `WardenSandboxUsers`, user `WardenSandbox`, add | works | works. user SID `S-1-5-21-…-1004`, group SID `…-1003`; runner is `…-500` | pass |
| 3 | Firewall service / profiles | on | `mpssvc` Running/Automatic; Domain, Private, Public all Enabled; `LocalPolicyModifyState` = 0 (OK, no GPO override) | pass |
| 3 | `New-NetFirewallRule -LocalUser "O:LSD:(A;;CC;;;<sid>)"` ×4 (outbound non-loopback block, inbound non-loopback block, loopback UDP block, loopback TCP block except P, codex's address strings) | created | all created; ActiveStore read-back shows the SDDL, addresses and `RemotePort=1-18079,18081-65535`; status `ProfileInactive, Enforced` | pass |
| 4a | Baseline, sandbox user, before rules: 1.1.1.1:443, example.com:443, DNS, P, Q | all work | all work | pass (control) |
| 4 | `Start-Process -Credential` | starts | starts (needs `-WorkingDirectory` the user can access). `seclogon` was **Stopped/Manual** and was started on demand by the call (Running afterwards), so no manual start needed as admin | pass |
| 4 | TCP 1.1.1.1:443 as sandbox user | blocked | blocked, 329 ms, `WSAEACCES` (10013) | pass |
| 4 | TCP example.com:443 | blocked | blocked, 4 ms, `WSAEACCES`, but name was resolved first (see next) | pass |
| 4 | DNS `Dns.GetHostAddresses("example.com")` | record | **resolves** (172.66.147.243, 104.20.23.154). Resolution is done by the DnsCache service, not by the user's process, so user-scoped rules do not see it | **leak** |
| 4 | `nslookup example.com 1.1.1.1` (direct UDP/53) | blocked | times out (non-loopback block works for UDP, silent drop) | pass |
| 4 | TCP 127.0.0.1:P (18080), reads listener's line | allowed | connected, read `HELLO-FROM-18080` | pass |
| 4 | TCP 127.0.0.1:Q (18081) | blocked | **connected, read `HELLO-FROM-18081`** | **FAIL** |
| 4 | Read `C:\Users\runneradmin\.ssh\id_test` | denied | `Access is denied` (also listing the dir) with default profile ACLs | pass |
| 4 | Write in dir granted to `WardenSandboxUsers` (icacls Modify) | allowed | wrote | pass |
| 4 | Write in dir not granted (inheritance cut on `C:\spike`) | denied | denied | pass |
| 4 | Write `C:\Windows` | denied | denied | pass |
| 4 | `whoami /groups` | record | Everyone, `WardenSandboxUsers`, BUILTIN\Users, INTERACTIVE, CONSOLE LOGON, Authenticated Users, This Organization, Local account, LOCAL, NTLM Authentication, Medium integrity. Not Administrators | info |
| 5 | Same network checks as runner | unaffected | all connect, incl. 1.1.1.1, example.com, DNS, P and Q | pass |
| 7a | Plain per-port rule for Q, user-scoped, with and without `RemoteAddress 127.0.0.1` | blocks Q | Q still connects | **FAIL** |
| 7b | Control: same Q rule for **all users**, tested as runner | blocks Q | Q still connects | **FAIL** |
| 8 | WFP filter (see below) block TCP to 127.0.0.0/8 with port ≠ P, user-scoped | blocks Q only | sandbox user: P connects, **Q blocked (`WSAEACCES`)**; runner: P and Q both connect | **pass** |
| 6a | `-RedirectStandardInput/Output/Error` to files with `-Credential` | works | works; child read `typed-by-parent` from the stdin file and wrote stdout to file | pass |
| 6b | `-NoNewWindow -Credential` | maybe rejected | accepted; child ran as sandbox user, its stdout appeared in the parent's output (inherited handles), stdin read EOF/empty | pass, see caveat |
| 6b2 | `-Credential` with no redirection | record | same as 6b; child had no console (`[Console]::WindowWidth`: "handle is invalid") | info |
| 6c | node/npm as sandbox user, without `-LoadUserProfile` | needs it? | `node -v` v22, `npm -v` 10.9 ran fine; `USERPROFILE=C:\Users\WardenSandbox` already set and the profile dir existed | pass |
| 6c | same with `-LoadUserProfile` | – | same output | no difference observed |

## Conclusions

**Works**
- Local user/group creation, secondary logon as the user, the user's token being an ordinary medium-integrity member of Users + the group.
- Per-user firewall rule scoping via `-LocalUser` SDDL works for non-loopback traffic (TCP blocked with an immediate 10013, UDP silently dropped), and does not affect the runner user.
- Deny-by-default of the real user's profile (`~\.ssh`) holds with stock ACLs; write confinement works by granting the group Modify on chosen dirs (but note `C:\` children inherit `Authenticated Users:Modify`; a workspace under `C:\` is writable by the sandbox user regardless of grants, so inheritance must be cut or the workspace must be under the user's profile).
- Plain `Start-Process -Credential` needs no profile flag for node/npm.

**Does not work**
1. **Windows Firewall rules do not filter loopback.** Not only the per-user ones: an all-users block of TCP port 18081 did not stop a loopback connect either. Codex's `…_block_loopback_tcp` / `_udp` rules (`setup_provisioning/firewall.rs`, `LOOPBACK_REMOTE_ADDRESSES = "127.0.0.0/8,::/127"`) therefore appear to be ineffective on this machine; I found no comment in codex acknowledging a loopback exemption, and its WFP filter set (`wfp/filter_specs.rs`) covers ICMP, DNS 53/853 and SMB 445 but no loopback condition. I did not verify behaviour on client Windows 10/11, so this is "true on Server 2022", not "true everywhere". The "allow only the proxy on loopback" half of phase B cannot be built from `New-NetFirewallRule`.
2. **DNS leaks through the DnsCache service.** Name resolution succeeds for the sandbox user; only direct UDP/53 is blocked. Without a proxy this does not give a channel (the follow-up TCP connect is blocked), but DNS queries are an exfiltration channel (and codex adds WFP 53/853 filters for the same reason, which would not stop DnsCache either since the query comes from another account).
3. **No real terminal.** Not demonstrated; see open questions.

**What we must do instead**
- Use WFP directly (persistent filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` in a sublayer of ours, conditions `ALE_USER_ID` = SDDL for the sandbox user + remote address in loopback + remote port ≠ P, action block). Step 8 proves this works and is user-scoped: a ~40 line P/Invoke over `fwpuclnt.dll` from PowerShell (the `FWPM_FILTER0` marshalling came out at 200 bytes and conditions at 40, matching the native layout). Rust: the `windows`/`windows-sys` crates, as codex's `wfp.rs` does. Needs admin; make the filters persistent (`FWPM_FILTER_FLAG_PERSISTENT`, which the spike did not set, so they only lasted for the session's lifetime in practice) and fixed-port, as the plan already says. The non-loopback block can stay a firewall rule (works) or move to WFP too, so there is one mechanism to verify.
- IPv6 loopback and UDP loopback filters were not tested; replicate the V6 layer and UDP condition when building it.
- DNS: either WFP-block the DnsCache path (not possible by user: the query originates in `svchost` as NetworkService) or accept it and document it as a known low-bandwidth channel; clients must send hostnames to the proxy anyway (as §2.4 says).
- Child launch: `Start-Process -Credential` is a prototype only. Real implementation uses `CreateProcessWithLogonW` or, like codex, a helper started as the sandbox user.

## Open questions / not determined

- **Interactive stdio.** CI has no console, so inheriting a real terminal (raw mode, resize, Ctrl-C) is untested. Observed: file redirection works; handle inheritance of a pipe works with `-NoNewWindow`; `CreateProcessWithLogonW` with `STARTF_USESTDHANDLES` is the usual route, but console attach/Ctrl-C delivery to a process of a different user is unverified. Codex avoids it with ConPTY plus a runner process, which would contradict DESIGN §2.3's "no PTY in warden"; needs a test on a real console.
- Password storage for the sandbox user (spike kept it in a variable; codex uses DPAPI in `.sandbox-secrets`), and whether the launcher can run as the real user while `CreateProcessWithLogonW` obtains the sandbox token (it did here, from an admin; not tried from a non-admin runner).
- Whether the sandbox user can `OpenProcess` the launcher, and what local IPC (named pipes, AF_UNIX) leaves open. Untested.
- Behaviour on client SKUs (Windows 10/11) and with Group Policy firewall settings (`LocalPolicyModifyState` was OK here).
- WFP filter persistence across reboot and cleanup on uninstall.
- Inbound blocking and `::1` were not exercised by a test.
