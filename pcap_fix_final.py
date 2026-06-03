#!/usr/bin/env python3
"""
pcap_fix_final.py – Router-PCAP-Bridge für Maltrail
- sensor.py wird intern als Subprocess verwaltet (nicht per Pipeline)
- Stirbt sensor.py (OOM beim Update) → neu starten, Pakete droppen
- Niemals selbst beenden, immer weiterlaufen
- Keine Pakete im RAM puffern
"""

import sys
import struct
import subprocess
import time
import os
import fcntl

LOCK_FILE  = "/run/maltrail_sid_renewal.lock"
SID_FILE   = "/run/maltrail_sid"
SENSOR_CMD = ["python3", "/home/pi/maltrail/sensor.py", "-r", "-"]

PCAP_HEADER = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


def start_sensor():
    """Startet sensor.py neu, schickt PCAP-Header, gibt Prozess zurück."""
    while True:
        try:
            p = subprocess.Popen(
                SENSOR_CMD,
                stdin=subprocess.PIPE,
                stdout=None,
                stderr=None
            )
            p.stdin.write(PCAP_HEADER)
            p.stdin.flush()
            return p
        except Exception:
            time.sleep(5)


def renew_sid_and_restart():
    """SID erneuern und Service neu starten – mit Lock gegen Doppelstart."""
    try:
        lock_fd = open(LOCK_FILE, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)

    try:
        subprocess.run(["systemctl", "stop", "maltrail"], check=False)

        for _ in range(20):
            r = subprocess.run(
                ["systemctl", "is-active", "maltrail"],
                capture_output=True, text=True
            )
            if r.stdout.strip() in ("inactive", "failed", "dead"):
                break
            time.sleep(0.5)
        else:
            subprocess.run(["systemctl", "kill", "-s", "SIGKILL", "maltrail"], check=False)
            time.sleep(1)

        try:
            os.remove(SID_FILE)
        except FileNotFoundError:
            pass

        r = subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)
        if r.returncode != 0:
            time.sleep(3)
            subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)

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

    # PCAP-Header vom Router lesen
    raw = buf.read(24)

    # Leer → SID abgelaufen
    if len(raw) < 24:
        renew_sid_and_restart()

    magic = struct.unpack('<I', raw[:4])[0]

    # Kein gültiges PCAP-Magic → Fehlertext vom Router
    if magic != 0xa1b2cd34:
        rest = raw + buf.read(200)
        if any(x in rest for x in [
            b"Internal communication error",
            b"login 0",
            b"Session",
        ]) or b"error" in rest.lower():
            renew_sid_and_restart()
        renew_sid_and_restart()

    # Sensor starten
    sensor = start_sensor()

    # Pakete weiterleiten
    while True:
        rec = buf.read(16)
        if len(rec) < 16:
            # curl-Stream abgebrochen → SID abgelaufen
            renew_sid_and_restart()

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rec)

        # Ungültige Paketgröße → droppen
        if incl_len > 65535 or incl_len < 20:
            continue

        total_len = incl_len + 8
        data = buf.read(total_len)
        if len(data) < total_len:
            renew_sid_and_restart()

        ip_data = data[8:]
        if len(ip_data) < 20:
            continue

        # Sensor tot? (OOM / Update) → neu starten, Paket droppen
        if sensor.poll() is not None:
            sensor = start_sensor()
            continue

        version = ip_data[0] >> 4
        ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
        eth = b'\x00' * 12 + ethertype
        pkt = eth + ip_data

        try:
            sensor.stdin.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
            sensor.stdin.write(pkt)
            sensor.stdin.flush()
        except BrokenPipeError:
            # Sensor abgestürzt → neu starten, Paket droppen
            sensor = start_sensor()
            continue
        except Exception:
            # Temporärer Fehler → droppen, weitermachen
            continue


if __name__ == "__main__":
    main()
