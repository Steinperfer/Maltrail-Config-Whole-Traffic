
#/home/pi/
import sys, struct, subprocess

buf = sys.stdin.buffer
out = sys.stdout.buffer

raw = buf.read(24)
if len(raw) < 24:
    # Komplett leer → SID abgelaufen
    subprocess.run(["systemctl", "stop", "maltrail"])
    subprocess.run(["/usr/local/bin/get_sid.sh"])
    subprocess.run(["systemctl", "start", "maltrail"])
    sys.exit(0)

magic, maj, min_, tz, sig, snaplen, network = struct.unpack('<IHHiIII', raw)

# Wenn Magic nicht stimmt, könnte es ein Fehlertext sein
if magic != 0xa1b2cd34:
    rest = raw + buf.read(200)
    if b"Internal communication error" in rest or b"login 0" in rest:
        subprocess.run(["systemctl", "stop", "maltrail"])
        subprocess.run(["/usr/local/bin/get_sid.sh"])
        subprocess.run(["systemctl", "start", "maltrail"])
        sys.exit(0)

# Standard PCAP Header schreiben
out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
out.flush()

packet_num = 0
while True:
    rec = buf.read(16)
    if len(rec) < 16:
        break
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rec)
    if incl_len > 65535 or incl_len < 20:
        continue
    total_len = incl_len + 8
    data = buf.read(total_len)
    if len(data) < total_len:
        break
    packet_num += 1
    ip_data = data[8:]
    if len(ip_data) < 20:
        continue
    version = ip_data[0] >> 4
    ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
    eth = b'\x00' * 12 + ethertype
    pkt = eth + ip_data
    out.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
    out.write(pkt)
    out.flush()
