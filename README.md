# Secure Inline Communication Channel (Linux / C)

A Linux prototype of a secure inline channel between two hosts:

```
PC1  ──►  Device1  ══════ encrypted ══════►  Device2  ──►  PC2
```

Device1 and Device2 act as inline security gateways. They establish a secure
session using a **Diffie–Hellman** handshake, then protect selected TCP/IPv4
traffic by encrypting **only the TCP payload** with **AES-256-GCM**, while
keeping the original IP and TCP headers. The end hosts (PC1, PC2) are
unaware of the encryption.

The whole topology runs inside a single Linux VM using network namespaces.

---

## Features

- **Diffie–Hellman key exchange** (RFC 7919 `ffdhe2048` group) between the devices
- **HKDF-SHA256** key derivation with a pre-shared key (PSK) to prevent man-in-the-middle attacks
- **Key confirmation** (HMAC) — the handshake fails if the devices did not derive the same keys
- **AES-256-GCM** encryption of the TCP payload only; IP and TCP headers preserved
- Authentication tag appended to the encrypted payload; **no UDP encapsulation, no custom header**
- **Unique nonce per packet** (secret salt + 64-bit counter), separate keys per direction
- **Replay protection** (64-packet sliding window)
- Receiver **verifies the tag, decrypts, restores the packet and recalculates IP and TCP checksums**
- **No protected data passes before the secure session is established**

---

## How it works

### 1. Packet selection

On each device, an `iptables` rule sends forwarded TCP packets on port 5000
to a userspace queue (`NFQUEUE`):

```
iptables -A FORWARD -p tcp -m multiport --ports 5000 -j NFQUEUE --queue-num 0
```

The `secgw` program reads packets from this queue, modifies them, and hands
them back to the kernel. If `secgw` is not running, the kernel drops the
queued packets — so no protected traffic can pass before the handshake.

### 2. Handshake (Device1 ↔ Device2)

Runs once at startup over a separate TCP control connection (port 7000):

1. Each device generates an ephemeral DH key pair (`ffdhe2048`).
2. The devices exchange public values and validate the peer's value.
3. Both compute the same shared secret.
4. HKDF-SHA256 (salt = PSK, info = label ‖ SHA-256 of both public values) derives:
   - one AES-256 key per direction,
   - one 4-byte nonce salt per direction,
   - one key-confirmation key.
5. Both sides exchange HMAC "finished" messages to confirm the keys match.

### 3. Packet protection

```
Original packet (from PC1):
[ IP header ][ TCP header ][ payload ]

On the wire (Device1 → Device2):
[ IP header ][ TCP header ][ encrypted payload ][ GCM tag (16 B) ][ counter (8 B) ]

Delivered packet (to PC2):
[ IP header ][ TCP header ][ payload ]
```

- **Nonce (12 bytes)** = secret salt (4 B, from HKDF) ‖ packet counter (8 B).
  The counter increments for every encrypted packet and is never reused; the
  sender refuses to encrypt if the counter would wrap.
- The counter is sent after the tag so the receiver can rebuild the nonce,
  even if packets are lost or reordered. It is not secret — the salt is.
- **AAD** (authenticated, not encrypted) = source IP, destination IP and the
  TCP header (checksum zeroed). This binds each payload to its connection.
- After encryption/decryption the device updates the IP total length and
  recalculates the **IP header checksum** and **TCP checksum**.
- Packets with no payload (SYN, ACK, FIN) are forwarded unchanged.

---

## Network topology

| Host | Interface | IP address | MTU |
|---|---|---|---|
| PC1 | eth0 | 10.0.1.1/24 | 1400 |
| Device1 | lan0 / wan0 | 10.0.1.254/24 / 10.0.12.1/24 | 1500 |
| Device2 | wan0 / lan0 | 10.0.12.2/24 / 10.0.2.254/24 | 1500 |
| PC2 | eth0 | 10.0.2.1/24 | 1400 |

The PCs use MTU 1400 so that a full-size packet plus the 24 bytes of
overhead (tag + counter) still fits on the 1500-byte links between the devices.

---

## Project structure

```
.
├── secgw.c             # Gateway program: NFQUEUE loop, packet parsing, encrypt/decrypt dispatch
├── crypto.c / .h       # DH handshake, HKDF, key confirmation, AES-GCM, replay window
├── pktutil.c / .h      # IPv4/TCP checksum calculation and AAD construction
├── Makefile            # Build script
├── setup_topology.sh   # Creates namespaces, links, IPs, routes and iptables rules
└── teardown.sh         # Removes the topology
```

---

## Requirements

Tested on Kali Linux (also works on Debian/Ubuntu). Requires OpenSSL 3.

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev libnetfilter-queue-dev \
                    iptables iproute2 ethtool tcpdump netcat-openbsd
```

---

## Build

```bash
make
```

This produces the `secgw` binary. `make clean` removes build files.

---

## Usage

### 1. Create the topology

```bash
sed -i 's/\r$//' *.sh *.c *.h Makefile
sudo ./setup_topology.sh
sudo ip netns exec pc1 ping -c2 10.0.2.1  #check connectivity
```

### 2. Run the demo

Open five terminals in the project directory. Run `sudo -v` in each first so
`sudo` does not prompt for a password during the demo.

| # | Role | Command |
|---|---|---|
| 1 | Device2 | `sudo ip netns exec dev2 ./secgw -r server -a 10.0.12.2 -l lan0 -k "MySecret123" -v` |
| 2 | Device1 | `sudo ip netns exec dev1 ./secgw -r client -a 10.0.12.2 -l lan0 -k "MySecret123" -v` |
| 3 | Capture between devices | `sudo ip netns exec dev1 tcpdump -l -i wan0 -nn -A 'tcp port 5000'` |
| 4 | PC2 (receiver) | `sudo ip netns exec pc2 nc -l 10.0.2.1 5000` |
| 5 | PC1 (sender) | `sudo ip netns exec pc1 nc 10.0.2.1 5000` |

Start Device2 before Device1 (Device1 retries until Device2 is ready). Both
should print:

```
[handshake] DH (ffdhe2048) complete, keys confirmed.
[+] Secure session established. Protected traffic may flow now.
```

Then type a message in terminal 5. It appears in plain text in terminal 4,
while terminal 3 shows the encrypted payload.

### 3. Clean up

Stop all programs with Ctrl+C, then run once:

```bash
sudo ./teardown.sh
```

### Command-line options

```
secgw -r client|server -a ADDR -l LAN_IFACE -k PSK [-P port] [-q queue] [-v]

  -r  role: client (Device1) or server (Device2)
  -a  server: address to listen on; client: Device2's address
  -l  interface facing the local host (e.g. lan0)
  -k  pre-shared key, same on both devices (min. 8 characters)
  -P  handshake TCP port (default 7000)
  -q  NFQUEUE number (default 0)
  -v  log every processed packet
```

To protect other ports, edit `PROTECTED_PORT` in `setup_topology.sh`
(e.g. `5000,8080`).

---

## Example output

Between the devices — encrypted, 53 bytes (29 data + 16 tag + 8 counter):

```
IP 10.0.1.1.57522 > 10.0.2.1.5000: Flags [P.], ... length 53
.....c.@*.J.7...3....\..\o..Q.3.!...P.C.D..M.."Hu.z..........
```

At PC2 — original payload restored, headers unchanged:

```
IP 10.0.1.1.57522 > 10.0.2.1.5000: Flags [P.], ... length 29
.....c.@Hello PC2, this is a secret!
```

Gateway logs:

```
Device1: [ENC] 10.0.1.1:57522 -> 10.0.2.1:5000  payload 29 -> 53 bytes
Device2: [DEC] 10.0.1.1:57522 -> 10.0.2.1:5000  payload 53 -> 29 bytes
```

---

## Testing

| Test | Method | Expected result |
|---|---|---|
| Encryption on the wire | tcpdump on `dev1 wan0` vs. `pc2 eth0` | Ciphertext between devices, plaintext at PC2 |
| No session, no data | Send before starting `secgw` | Connection fails; packets dropped |
| Wrong PSK | Start Device1 with a different `-k` | `key confirmation FAILED`, no traffic passes |
| Integrity of large transfers | Send a 2 MB random file each direction, compare `sha256sum` | Identical hashes, `rejected=0` |
| Per-packet nonce | Stop `secgw` with Ctrl+C | Stats show one counter increment per encrypted packet |

---

## Limitations

- PCs must use a reduced MTU (1400); a production system would clamp the TCP MSS instead.
- IP fragments are dropped.
- No rekeying; restart both devices to start a new session.
- The PSK is passed on the command line (visible in `ps`); a real deployment would load it from a protected file or use certificates.
- IPv4 only.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `File exists` when running setup | Run `sudo ./teardown.sh` first |
| `nfq_create_queue` fails | Another `secgw` is running in that namespace: `sudo pkill secgw` |
| tcpdump shows nothing until Ctrl+C | Add `-l` (line-buffered output) |
| Small messages work, large transfers stall | Device interfaces must be MTU 1500, PCs 1400 — re-run teardown and setup |
| Device1 keeps printing "retrying" | Start Device2 first, check the `-a` address |
| `nc: invalid option -N` | Install `netcat-openbsd` or omit `-N` |
