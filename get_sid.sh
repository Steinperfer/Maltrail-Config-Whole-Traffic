/usr/local/bin/get_sid.sh
#!/bin/bash
FRITZ_IP="192.168.0.1"
PASSWORD="ROUTERPASSWORD"
SID_FILE="/run/maltrail_sid"

CHALLENGE=$(curl -s "http://${FRITZ_IP}/login_sid.lua" | grep -o '<Challenge>[^<]*' | cut -d'>' -f2)

SESSION_SID=$(curl -s -X POST "http://${FRITZ_IP}/login_sid.lua" \
  -d "response=${CHALLENGE}-$(echo -n "${CHALLENGE}-${PASSWORD}" | iconv -f UTF-8 -t UTF-16LE | md5sum | cut -d' ' -f1)" \
  -d 'username=fritz5975' \
  | grep -o '<SID>[^<]*' | cut -d'>' -f2)

# Capture mit Session SID aufrufen - FritzBox konvertiert das zur Capture SID
CAPTURE_SID=$(timeout 3 curl -s \
  -H "Authorization: AVM-SID ${SESSION_SID}" \
  "http://${FRITZ_IP}/cgi-bin/capture_notimeout?sid=${SESSION_SID}&capture=Start&snaplen=1600&filter=&ifaceorminor=3-0" \
  | head -c 100 | grep -o 'sid=[^&"]*' | head -1 | cut -d'=' -f2)

if [ -z "$CAPTURE_SID" ]; then
    CAPTURE_SID="$SESSION_SID"
fi

echo "$CAPTURE_SID" > "$SID_FILE"
chmod 644 "$SID_FILE"
echo "OK: $CAPTURE_SID"
