# Network Sniffer

This project is for academic purposes only.

## What It Does

The sniffer captures and logs traffic events for:

- HTTP (sensitive field extraction)
- HTTPS (TLS-level metadata)
- SSH
- FTP-like traffic
- SMTP-like traffic
- ICMP
- UDP
- ARP

## Quick Start

Use three terminals.

### Terminal 1: Start Test Web Server

```bash
python3 login_server.py
```

### Terminal 2: Run Sniffer

Raw capture usually needs elevated privileges.

```bash
sudo python3 sniffer.py
```

### Terminal 3: Generate Test Traffic

#### HTTP login test

You can either open:

`http://127.0.0.1:8080/test.html`

Or send a request directly:

```bash
curl -i \
  -H "Cookie: session_test=manual_cookie_abc" \
  -d "username=alice&password=secret123" \
  http://127.0.0.1:8080/login
```

#### ARP

```bash
GW=$(ip route | awk '/default/ {print $3; exit}')
ping -c 1 "$GW"
```

#### ICMP

```bash
ping -c 2 127.0.0.1
```

#### UDP (one datagram to localhost:9999)

```bash
python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'hello',('127.0.0.1',9999))"
```

#### SMTP-like traffic on port 25

```bash
python3 -c "import socket; s=socket.create_connection(('127.0.0.1',25),timeout=1); s.sendall(b'HELO local\\r\\n'); s.close()"
```

#### FTP-like traffic on port 21

```bash
python3 -c "import socket; s=socket.create_connection(('127.0.0.1',21),timeout=1); s.sendall(b'USER test\\r\\n'); s.close()"
```

#### SSH traffic

```bash
ssh -o ConnectTimeout=3 127.0.0.1
```

## Windows Notes

- In `main`, set interface to `None`.
- Uncomment mutex-related lines only if you want single-instance protection.
- Npcap is required for packet capture.

## Output

Logs are written to:

- `sniffer.log`

Just to test, they will be send to a server elsewhere