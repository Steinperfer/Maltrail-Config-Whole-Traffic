#!/usr/bin/env python3
"""
pcap_fix_final.py – Router-PCAP-Bridge für Maltrail
- sensor.py wird intern als Subprocess verwaltet
- BrokenPipeError → könnte Update sein → 5 Min warten, Pakete droppen
- Erst nach 5 Min Neustart von sensor.py
- Niemals selbst beenden, keine Pakete im RAM puffern
"""

import sys
import struct
import subprocess
import time
import os
import fcntl

LOCK_FILE        = "/run/maltrail_sid_renewal.lock"
SID_FILE         = "/run/maltrail_sid"
SENSOR_CMD       = ["python3", "/home/pi/maltrail/sensor.py", "-r", "-"]
PCAP_HEADER      = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
MAX_BROKEN_WAIT  = 300  # 5 Minuten warten bevor sensor neugestartet wird


def start_sensor():
    """Startet sensor.py, wartet kurz bis er bereit ist, schickt PCAP-Header."""
    while True:
        try:
            p = subprocess.Popen(
                SENSOR_CMD,
                stdin=subprocess.PIPE,
                stdout=None,
                stderr=None
            )
            time.sleep(2)  # warten bis sensor bereit ist
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
    if len(raw) < 24:
        renew_sid_and_restart()

    magic = struct.unpack('<I', raw[:4])[0]

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
    broken_since = None  # wann hat BrokenPipe angefangen

    while True:
        rec = buf.read(16)
        if len(rec) < 16:
            # curl-Stream abgebrochen → SID abgelaufen
            renew_sid_and_restart()

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', rec)

        if incl_len > 65535 or incl_len < 20:
            continue

        total_len = incl_len + 8
        data = buf.read(total_len)
        if len(data) < total_len:
            renew_sid_and_restart()

        ip_data = data[8:]
        if len(ip_data) < 20:
            continue

        # Sensor komplett tot → nur neustarten wenn timeout abgelaufen
        if sensor.poll() is not None:
            if broken_since is None:
                broken_since = time.time()
            if time.time() - broken_since > MAX_BROKEN_WAIT:
                sensor = start_sensor()
                broken_since = None
            # Paket droppen, weiter
            continue

        version = ip_data[0] >> 4
        ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
        pkt = b'\x00' * 12 + ethertype + ip_data

        try:
            sensor.stdin.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
            sensor.stdin.write(pkt)
            sensor.stdin.flush()
            broken_since = None  # Schreiben hat geklappt → reset

        except BrokenPipeError:
            # Sensor busy (Update?) → erst mal warten, Paket droppen
            if broken_since is None:
                broken_since = time.time()

            if time.time() - broken_since > MAX_BROKEN_WAIT:
                # 5 Min vorbei → sensor wirklich neu starten
                try:
                    sensor.kill()
                except Exception:
                    pass
                sensor = start_sensor()
                broken_since = None
            continue

        except Exception:
            continue


if __name__ == "__main__":
    main()
