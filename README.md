# SSH-Guard

Real-time SSH brute-force detector and auto-blocker for Kali/Debian-based Linux systems, with a full Tkinter GUI.

SSH-Guard watches your SSH authentication log, detects brute-force attempts using a sliding-window threshold, and automatically blocks offending IPs with `iptables` — with automatic time-based unblocking, manual override controls, and a whitelist so you never lock yourself out.

This is a **defensive** tool only. It contains no attack or exploit functionality.

---

## Features

- Real-time log tailing of `/var/log/auth.log` (or `/var/log/secure`)
- Parses failed logins, invalid users, PAM auth failures, and accepted logins
- Sliding-window detection: N failed attempts within M seconds → auto-block
- Automatic `iptables`-based blocking, tagged for easy identification/cleanup
- Automatic unblock after a configurable ban duration (or permanent bans)
- Manual block / unblock of any IP from the GUI
- Whitelist support for trusted IPs (never auto-blocked)
- Persistent state via local SQLite database — survives restarts
- Dark-themed Tkinter GUI with live attempts table, blocked-IP table, and event log

---

## Requirements

- Kali Linux or any Debian-based distro
- Python 3.8+
- `python3-tk` (Tkinter)
- `iptables` (included by default on Kali)
- Root privileges (required to read the auth log and manage firewall rules)

Install Tkinter if it's missing:

```bash
sudo apt install python3-tk -y
```

---

## Installation

1. Save `ssh_guard.py` to a directory of your choice.
2. Give permission by using following command:

```bash
chmod +x ssh_guard.py
```

3. Make sure SSH server is installed and running (if you want to test locally):

```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```

No other dependencies are required — everything else is Python standard library.

---

## Usage

Run as root:

```bash
sudo python3 ssh_guard.py
```

In the GUI:

1. Review/adjust **Detection Settings** at the top:
   - **Threshold** — number of failed attempts that triggers a block
   - **Window (seconds)** — the sliding time window attempts are counted in
   - **Ban duration (seconds)** — how long a block lasts (`0` = permanent)
   - **Log file** — path to the auth log (auto-detected on startup)
2. Click **Apply** to save settings.
3. Click **▶ Start Monitoring** to begin watching the log in real time.
4. Watch attempts appear in the **Live Login Attempts** table and blocks appear in the **Blocked IPs** table.

### Manual controls

- **Block** / **Unblock** — enter any IP and block or unblock it immediately, regardless of the log.
- **Unblock Selected** — select a row in the Blocked IPs table and unblock it directly.
- **Whitelist** — add IPs (e.g. your own management IP) that should never be auto-blocked. Adding a currently-blocked IP to the whitelist unblocks it immediately.

---

## How detection works

1. SSH-Guard tails the auth log line by line as it's written.
2. Each failed login line is matched against known SSH failure patterns and the source IP is extracted.
3. Failures per IP are tracked in a sliding time window (default: 5 failures / 60 seconds).
4. Once an IP crosses the threshold, SSH-Guard inserts an `iptables` DROP rule for port 22 traffic from that IP, tagged with the comment `SSH_GUARD` for easy identification.
5. A background thread checks every 5 seconds for expired bans and removes the corresponding `iptables` rule automatically (manual blocks are exempt and must be removed by hand).

---

## Verifying it works

Basic real-time check:

```bash
# Terminal 1 — ground truth view of the raw log
sudo tail -f /var/log/auth.log

# Terminal 2 — generate failed attempts against your own machine
for i in {1..7}; do sshpass -p "wrongpass$i" ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1; done
```

Watch the GUI's **Live Login Attempts** table fill in, and once the threshold is hit, check the **Event Log** for a `🚫 BLOCKED` entry and the **Blocked IPs** table for the new entry.

Confirm the firewall rule exists:

```bash
sudo iptables -L INPUT -n --line-numbers | grep SSH_GUARD
```

For a more realistic load test, Hydra can be used against a machine/VM you own — see the tool's usage notes for an example command. Only test against systems you control.

---

## Data storage

SSH-Guard creates a SQLite database file, `ssh_guard.db`, in the same directory as the script. It stores:

- `blocked_ips` — currently blocked IPs, when they were blocked, when they expire, and why
- `whitelist` — IPs exempt from auto-blocking
- `events` — a history log of block/unblock actions

Delete this file to reset all state (blocks, whitelist, and history).

---

## Cleaning up manually

To remove a specific SSH-Guard firewall rule without the GUI:

```bash
sudo iptables -D INPUT -s <IP> -p tcp --dport 22 -m comment --comment SSH_GUARD -j DROP
```

To list all SSH-Guard rules currently active:

```bash
sudo iptables -L INPUT -n --line-numbers | grep SSH_GUARD
```

---

## Important notes

- **Always whitelist your own management/admin IP** before starting monitoring if you're connected remotely over SSH — otherwise a burst of your own failed logins (e.g. a mistyped password) could lock you out.
- SSH-Guard must run as root. Without root, it cannot reliably read `/var/log/auth.log` or modify `iptables` rules.
- Firewall rules are lost on reboot unless you persist `iptables` rules separately (e.g. with `iptables-persistent`) or keep SSH-Guard running as a service. The database itself persists regardless.
- This tool blocks by source IP on port 22 only; it does not affect other services or ports.

---

## Disclaimer

This tool is provided for educational and legitimate system-administration/defensive-security purposes only. Use it only on systems you own or are authorized to manage.
