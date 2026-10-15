#!/usr/bin/env bash

REP="${1:-}"

case "$REP" in
    01|02|03) ;;
    *)
        echo "Aufruf: $0 01|02|03"
        exit 1
        ;;
esac

BASE="$HOME/ba-experiment/control_measurements/whonix_qubes"
RUN_DIR="$BASE/$REP"

PCAP="$RUN_DIR/capture.pcap"
STATS="$RUN_DIR/capture_stats.txt"
META="$RUN_DIR/metadata.txt"
HASH="$RUN_DIR/sha256.txt"

if [ -e "$RUN_DIR" ]; then
    echo "[FEHLER] Kontrolllauf $REP existiert bereits:"
    echo "$RUN_DIR"
    exit 1
fi

mkdir -p "$RUN_DIR"

sudo -v || exit 1

echo
echo "=========================================="
echo " Whonix-on-Qubes Kontrollmessung $REP"
echo "=========================================="
echo
echo "Voraussetzung:"
echo "  anon-whonix = Halted"
echo "  sys-whonix  = Halted"
echo "  sys-firewall und sys-net dürfen laufen."
echo
echo "Nach dem Start der Aufnahme:"
echo "  In Qubes dom0 sofort ausführen:"
echo
echo "      qvm-start sys-whonix"
echo
echo "Die Aufnahme endet automatisch nach 120 Sekunden."
echo

read -r -p "Enter drücken, wenn du bereit bist ..."

START_TIME=$(date --iso-8601=seconds)

echo
echo "[INFO] Aufnahme läuft jetzt."
echo "[INFO] Jetzt in dom0: qvm-start sys-whonix"
echo

# 120 Sekunden vollständigen Verkehr auf der transparenten Bridge aufzeichnen.
sudo timeout --signal=INT 120 \
    tcpdump -ni br0 -s 0 -w "$PCAP" \
    2> "$STATS"

RC=$?

# timeout liefert nach Ablauf normalerweise 124.
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; then
    echo "[FEHLER] tcpdump wurde unerwartet beendet (Code $RC)."
    exit 1
fi

END_TIME=$(date --iso-8601=seconds)

DROPS=$(awk '/packets dropped by kernel/ {print $1}' "$STATS" | tail -n 1)
DROPS="${DROPS:-unknown}"

# Äußere Qubes-Adresse aus den Hauptmessungen.
TEST_IP="10.0.0.38"

TEST_MAC=$(tshark -r "$PCAP" \
    -Y "ip.src == $TEST_IP" \
    -T fields -e eth.src 2>/dev/null \
    | head -n 1)

SYN_COUNT=$(tshark -r "$PCAP" \
    -Y "ip.src == $TEST_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
    -T fields -e frame.number 2>/dev/null \
    | wc -l)

{
    echo "control_series=whonix_qubes"
    echo "system=whonix_qubes"
    echo "scenario=TOR_GATEWAY_START"
    echo "repetition=$REP"
    echo "capture_start=$START_TIME"
    echo "capture_end=$END_TIME"
    echo "capture_duration_seconds=120"
    echo "test_ip=$TEST_IP"
    echo "test_mac=$TEST_MAC"
    echo "outgoing_syn_count=$SYN_COUNT"
    echo "packets_dropped=$DROPS"
    echo "network_path=sys-whonix -> sys-firewall -> sys-net -> physical Ethernet"
    echo "anon_whonix_during_capture=halted"
    echo "purpose=technical control of outer Whonix fingerprint under Qubes"
} > "$META"

sha256sum "$PCAP" > "$HASH"

echo
echo "=========================================="
echo " Kontrollmessung abgeschlossen"
echo "=========================================="
echo
echo "PCAP:            $PCAP"
echo "Test-MAC:        ${TEST_MAC:-nicht gefunden}"
echo "Ausgehende SYNs: $SYN_COUNT"
echo "Packet Drops:    $DROPS"
echo
