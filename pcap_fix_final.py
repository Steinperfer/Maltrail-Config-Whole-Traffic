#/home/pi/
#!/usr/bin/env python3
"""
pcap_fix_final.py – Router-PCAP-Bridge for Maltrail
Fixes: Race Condition on SID-Renewal
"""

import sys
import struct
import subprocess
import time
import os
import fcntl

LOCK_FILE = "/run/maltrail_sid_renewal.lock"
SID_FILE  = "/run/maltrail_sid"

def renew_sid_and_restart():
    """
    SID erneuern und Service neu starten – mit Lock gegen Doppelstart.
    Gibt True zurück wenn erfolgreich, False wenn ein anderer Prozess
    das gerade schon macht (dann einfach beenden).
    """
    try:
        lock_fd = open(LOCK_FILE, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        # Ein anderer Prozess macht das gerade – nicht doppelt starten
        sys.exit(0)

    try:
        # Service sauber stoppen und warten bis er wirklich weg ist
        subprocess.run(["systemctl", "stop", "maltrail"], check=False)

        # Sicherstellen dass alle Kindprozesse weg sind
        for _ in range(20):
            result = subprocess.run(
                ["systemctl", "is-active", "maltrail"],
                capture_output=True, text=True
            )
            if result.stdout.strip() in ("inactive", "failed", "dead"):
                break
            time.sleep(0.5)
        else:
            # Notfalls hart killen
            subprocess.run(["systemctl", "kill", "-s", "SIGKILL", "maltrail"], check=False)
            time.sleep(1)

        # Alte SID löschen damit get_sid.sh eine neue holt
        try:
            os.remove(SID_FILE)
        except FileNotFoundError:
            pass

        # Neue SID holen
        result = subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)
        if result.returncode != 0:
            # Kurz warten und nochmal versuchen
            time.sleep(3)
            subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)

        # SID-Datei muss jetzt existieren
        if not os.path.exists(SID_FILE):
            sys.exit(1)

        # Service starten
        subprocess.run(["systemctl", "start", "maltrail"], check=False)

    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        try:
            os.remove(LOCK_FILE)
        except FileNotFoundError:
            pass

    sys.exit(0)


def main():
    buf = sys.stdin.buffer
    out = sys.stdout.buffer

    # --- Header lesen ---
    raw = buf.read(24)

    # Komplett leer → SID abgelaufen
    if len(raw) < 24:
        renew_sid_and_restart()

    magic, maj, min_, tz, sig, snaplen, network = struct.unpack('<IHHiIII', raw)

    # Kein gültiges PCAP-Magic → Fehlertext vom Router
    if magic != 0xa1b2cd34:
        rest = raw + buf.read(200)
        if (b"Internal communication error" in rest
                or b"login 0" in rest
                or b"Session" in rest
                or b"error" in rest.lower()):
            renew_sid_and_restart()
        # Unbekannter Fehler – trotzdem neu starten
        renew_sid_and_restart()

    # --- Standard PCAP-Header schreiben ---
    out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    out.flush()

    # --- Pakete weiterleiten ---
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


if __name__ == "__main__":
    main()
