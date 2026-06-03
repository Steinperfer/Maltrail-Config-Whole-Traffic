#!/usr/bin/env python3
"""
pcap_fix_final.py – Dauerhafte Bridge zwischen FritzBox-Capture und Maltrail-Sensor
- curl wird als Subprozess gestartet und bei SID-Ablauf neu gestartet
- sensor.py wird als Subprozess verwaltet, bei Update/BrokenPipe tolerant
- Niemals exit – läuft endlos
"""

import subprocess
import struct
import time
import sys
import os

SID_FILE        = "/run/maltrail_sid"
SENSOR_CMD      = [sys.executable, "/home/pi/maltrail/sensor.py", "-r", "-"]
PCAP_HEADER     = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
MAX_BROKEN_WAIT = 300   # 5 Min. warten bei BrokenPipe bevor Sensor neu gestartet wird


def read_sid():
    """Liest die aktuelle SID aus /run/maltrail_sid, gibt None zurück wenn nicht vorhanden."""
    try:
        with open(SID_FILE, 'r') as f:
            sid = f.read().strip()
        return sid if sid else None
    except Exception:
        return None


def start_curl(sid):
    """Startet curl mit der aktuellen SID, gibt Popen-Objekt zurück."""
    url = (
        "http://192.168.0.1/cgi-bin/capture_notimeout"
        f"?sid={sid}&capture=Start&snaplen=1600&filter=&ifaceorminor=3-0"
    )
    return subprocess.Popen(
        ["curl", "-s", "--no-buffer", url],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )


def start_sensor():
    """Startet sensor.py und sendet den PCAP-Header."""
    while True:
        try:
            p = subprocess.Popen(
                SENSOR_CMD,
                stdin=subprocess.PIPE,
                stdout=None,
                stderr=None
            )
            time.sleep(2)
            p.stdin.write(PCAP_HEADER)
            p.stdin.flush()
            return p
        except Exception:
            time.sleep(5)


def main():
    sensor = start_sensor()
    broken_since = None

    # Warte auf gültige SID
    sid = read_sid()
    while not sid:
        time.sleep(3)
        sid = read_sid()

    curl_proc = start_curl(sid)
    buf = curl_proc.stdout

    while True:
        # PCAP-Header vom Router lesen (wird bei jedem neuen Stream verworfen)
        raw = buf.read(24)
        if len(raw) < 24:
            # Stream abgebrochen → SID wahrscheinlich abgelaufen
            curl_proc.kill()
            curl_proc.wait()
            # Neue SID holen
            subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)
            time.sleep(2)
            sid = read_sid()
            if not sid:
                # Falls get_sid.sh fehlschlägt, warten und wiederholen
                time.sleep(10)
                continue
            curl_proc = start_curl(sid)
            buf = curl_proc.stdout
            continue

        magic = struct.unpack('<I', raw[:4])[0]
        if magic != 0xa1b2cd34:
            # Router sendet Fehler statt PCAP → SID abgelaufen
            rest = raw + buf.read(200)
            if any(x in rest for x in [b"Internal communication error", b"login 0", b"Session"]) or b"error" in rest.lower():
                curl_proc.kill()
                curl_proc.wait()
                subprocess.run(["/usr/local/bin/get_sid.sh"], check=False)
                time.sleep(2)
                sid = read_sid()
                if not sid:
                    time.sleep(10)
                    continue
                curl_proc = start_curl(sid)
                buf = curl_proc.stdout
                continue

        # Haupt-Paketschleife
        while True:
            rec = buf.read(16)
            if len(rec) < 16:
                # Stream unterbrochen → zurück zur äußeren Schleife (neue SID)
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

            # Sensor-Status prüfen
            if sensor.poll() is not None:
                # Sensor wirklich tot (nicht nur busy)
                if broken_since is None:
                    broken_since = time.time()
                if time.time() - broken_since > MAX_BROKEN_WAIT:
                    sensor = start_sensor()
                    broken_since = None
                continue

            version = ip_data[0] >> 4
            ethertype = b'\x86\xdd' if version == 6 else b'\x08\x00'
            pkt = b'\x00' * 12 + ethertype + ip_data

            try:
                sensor.stdin.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
                sensor.stdin.write(pkt)
                sensor.stdin.flush()
                broken_since = None
            except BrokenPipeError:
                # Sensor ist busy (Update) oder abgestürzt – warte und droppe Pakete
                if broken_since is None:
                    broken_since = time.time()
                if time.time() - broken_since > MAX_BROKEN_WAIT:
                    # Neustart nach Timeout
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
