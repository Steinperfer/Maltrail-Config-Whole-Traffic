import sys, struct

buf = sys.stdin.buffer
out = sys.stdout.buffer

# FritzBox Global Header (24 bytes, Little-Endian)
raw = buf.read(24)
if len(raw) < 24:
    sys.exit(1)

magic, maj, min_, tz, sig, snaplen, network = struct.unpack('<IHHiIII', raw)

# Standard PCAP Header schreiben
out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
out.flush()

packet_num = 0

while True:
    # Packet Header (16 bytes, Little-Endian)
    rec = buf.read(16)
    if len(rec) < 16:
        break
    
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rec)
    
    # Validierung
    if incl_len > 65535 or incl_len < 20:
        continue
    
    # WICHTIG: FritzBox Header (8 Bytes) + IP-Paket
    total_len = incl_len + 8
    data = buf.read(total_len)
    
    if len(data) < total_len:
        break
    
    packet_num += 1
    
    # FritzBox Header entfernen
    ip_data = data[8:]
    
    if len(ip_data) < 20:
        continue
    
    # EtherType basierend auf IP Version
    version = ip_data[0] >> 4
    ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
    
    # Ethernet Header (14 Bytes) + IP-Paket
    eth = b'\x00' * 12 + ethertype
    pkt = eth + ip_data
    
    # Standard PCAP Packet schreiben
    out.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
    out.write(pkt)
    out.flush()

sys.stderr.write(f"Processed {packet_num} packets\n")
