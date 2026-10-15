#!/bin/bash

# ------------------------------------------------------------
# Preflight-Check für die Messungen der Bachelorarbeit
#
# Das Skript prüft vor einer Messung, ob die wichtigsten
# Einstellungen des Monitoring-Rechners noch korrekt sind.
# Es verändert dabei keine Einstellungen.
# ------------------------------------------------------------

# Optional kann das Szenario übergeben werden.
# Bei IDLE darf das ausgeschaltete Testsystem noch keinen Link haben.
SCENARIO="$1"

# --- Feste Einstellungen unseres Messaufbaus ---

BRIDGE="br0"
PORT_ROUTER="enp129s0"
PORT_TESTSYSTEM="enp128s31f6"

EXPECTED_MTU="1500"

NDPI_DIR="$HOME/src/nDPI"
NDPI_READER="$NDPI_DIR/example/ndpiReader"

# Erwartete Werkzeugversionen aus der Validierungsphase
EXPECTED_NDPI_VERSION="5.0"
EXPECTED_NDPI_COMMIT="375f99ef9fb4999d778b57bbeece171b3fa9fba6"
EXPECTED_ZEEK_VERSION="8.0.9"
EXPECTED_JA4_VERSION="v1.0.0"
EXPECTED_P0F_VERSION="3.09b-3build2"
EXPECTED_TSHARK_VERSION="4.2.2"
EXPECTED_TCPDUMP_VERSION="4.99.4"

# Mindestwert für freien Speicherplatz.
# Unterhalb davon wird nur gewarnt.
MIN_FREE_GB=20


# --- Zähler für das Endergebnis ---

ERRORS=0
WARNINGS=0


# Kleine Hilfsfunktionen für eine übersichtlichere Ausgabe

ok() {
    echo "[OK]   $1"
}

warning() {
    echo "[WARN] $1"
    WARNINGS=$((WARNINGS + 1))
}

error() {
    echo "[FEHLER] $1"
    ERRORS=$((ERRORS + 1))
}


echo
echo "=========================================="
echo " Preflight-Check Bachelorarbeit"
echo "=========================================="
echo


# ------------------------------------------------------------
# 1. sudo-Berechtigung einmalig holen
# ------------------------------------------------------------

echo "--- sudo ---"

if sudo -v; then
    ok "sudo-Berechtigung vorhanden"
else
    error "sudo-Berechtigung konnte nicht bestätigt werden"
fi

echo


# ------------------------------------------------------------
# 2. Prüfen, ob die benötigten Programme vorhanden sind
# ------------------------------------------------------------

echo "--- Programme ---"

for PROGRAM in tcpdump tshark zeek p0f ethtool bridge zkg; do
    if command -v "$PROGRAM" >/dev/null 2>&1; then
        ok "$PROGRAM gefunden"
    else
        error "$PROGRAM wurde nicht gefunden"
    fi
done

if [ -x "$NDPI_READER" ]; then
    ok "ndpiReader gefunden"
else
    error "ndpiReader wurde unter $NDPI_READER nicht gefunden"
fi

echo


# ------------------------------------------------------------
# 3. Bridge und Netzwerkschnittstellen prüfen
# ------------------------------------------------------------

echo "--- Bridge und Schnittstellen ---"

if ip link show "$BRIDGE" >/dev/null 2>&1; then
    ok "$BRIDGE vorhanden"
else
    error "$BRIDGE nicht vorhanden"
fi

if ip link show "$PORT_ROUTER" >/dev/null 2>&1; then
    ok "$PORT_ROUTER vorhanden"
else
    error "$PORT_ROUTER nicht vorhanden"
fi

if ip link show "$PORT_TESTSYSTEM" >/dev/null 2>&1; then
    ok "$PORT_TESTSYSTEM vorhanden"
else
    error "$PORT_TESTSYSTEM nicht vorhanden"
fi


# Prüfen, ob die Bridge UP ist

if ip link show "$BRIDGE" 2>/dev/null | grep -q "UP"; then
    ok "$BRIDGE ist UP"
else
    error "$BRIDGE ist nicht UP"
fi


# Die transparente Bridge soll selbst keine IP-Adresse besitzen.

if [ -z "$(ip -o addr show dev "$BRIDGE" 2>/dev/null)" ]; then
    ok "$BRIDGE hat keine IP-Adresse"
else
    error "$BRIDGE besitzt eine IP-Adresse"
fi


# Beide Ethernet-Ports müssen Mitglied von br0 sein.

if ip link show "$PORT_ROUTER" 2>/dev/null | grep -q "master $BRIDGE"; then
    ok "$PORT_ROUTER ist Mitglied von $BRIDGE"
else
    error "$PORT_ROUTER ist nicht Mitglied von $BRIDGE"
fi

if ip link show "$PORT_TESTSYSTEM" 2>/dev/null | grep -q "master $BRIDGE"; then
    ok "$PORT_TESTSYSTEM ist Mitglied von $BRIDGE"
else
    error "$PORT_TESTSYSTEM ist nicht Mitglied von $BRIDGE"
fi


# Beide Ports sollen Daten weiterleiten.
# Prüfen, ob an den Ethernet-Ports ein physischer Link besteht.
# Beim IDLE-Szenario darf der Testsystem-Port ohne Link sein,
# da das Testsystem zu diesem Zeitpunkt ausgeschaltet sein kann.

for INTERFACE in "$PORT_ROUTER" "$PORT_TESTSYSTEM"; do

    CARRIER=$(cat "/sys/class/net/$INTERFACE/carrier" 2>/dev/null)

    if [ "$CARRIER" = "1" ]; then
        ok "$INTERFACE hat einen physischen Link"

        if bridge link 2>/dev/null \
            | grep "$INTERFACE" \
            | grep -q "state forwarding"; then

            ok "$INTERFACE steht auf forwarding"
        else
            error "$INTERFACE hat Link, steht aber nicht auf forwarding"
        fi

    else
        if [ "$SCENARIO" = "IDLE" ] && [ "$INTERFACE" = "$PORT_TESTSYSTEM" ]; then
            warning "$INTERFACE hat noch keinen Link (bei ausgeschaltetem Testsystem für IDLE zulässig)"
        else
            error "$INTERFACE hat keinen physischen Link (LAN-Kabel prüfen)"
        fi
    fi

done

echo


# ------------------------------------------------------------
# 4. MTU prüfen
# ------------------------------------------------------------

echo "--- MTU ---"

for INTERFACE in "$BRIDGE" "$PORT_ROUTER" "$PORT_TESTSYSTEM"; do

    MTU=$(cat "/sys/class/net/$INTERFACE/mtu" 2>/dev/null)

    if [ "$MTU" = "$EXPECTED_MTU" ]; then
        ok "$INTERFACE: MTU $MTU"
    else
        error "$INTERFACE: MTU ist $MTU statt $EXPECTED_MTU"
    fi

done

echo


# ------------------------------------------------------------
# 5. Offloading der beiden physischen Netzwerkkarten prüfen
#
# TSO, GSO, GRO und LRO sollen auf dem Monitoring-Rechner
# deaktiviert sein, damit die aufgezeichneten Pakete möglichst
# unverändert im PCAP erscheinen.
# ------------------------------------------------------------

echo "--- Offloading ---"

for INTERFACE in "$PORT_ROUTER" "$PORT_TESTSYSTEM"; do

    echo "$INTERFACE:"

    for FEATURE in \
        tcp-segmentation-offload \
        generic-segmentation-offload \
        generic-receive-offload \
        large-receive-offload
    do

        STATUS=$(ethtool -k "$INTERFACE" 2>/dev/null \
            | grep "^$FEATURE:" \
            | awk '{print $2}')

        if [ "$STATUS" = "off" ]; then
            ok "$FEATURE = off"
        else
            error "$INTERFACE: $FEATURE ist nicht off"
        fi

    done

done

echo


# ------------------------------------------------------------
# 6. Werkzeugversionen prüfen
#
# Damit während der gesamten Messreihe mit demselben
# Softwarestand gearbeitet wird.
# ------------------------------------------------------------

echo "--- Werkzeugversionen ---"


# nDPI

NDPI_VERSION=$(git -C "$NDPI_DIR" describe --tags --always 2>/dev/null)
NDPI_COMMIT=$(git -C "$NDPI_DIR" rev-parse HEAD 2>/dev/null)

if [ "$NDPI_VERSION" = "$EXPECTED_NDPI_VERSION" ]; then
    ok "nDPI Version $NDPI_VERSION"
else
    error "nDPI Version ist $NDPI_VERSION statt $EXPECTED_NDPI_VERSION"
fi

if [ "$NDPI_COMMIT" = "$EXPECTED_NDPI_COMMIT" ]; then
    ok "nDPI Commit stimmt"
else
    error "nDPI Commit hat sich geändert"
fi


# Zeek

ZEEK_VERSION=$(zeek --version 2>/dev/null | awk '{print $3}')

if [ "$ZEEK_VERSION" = "$EXPECTED_ZEEK_VERSION" ]; then
    ok "Zeek Version $ZEEK_VERSION"
else
    error "Zeek Version ist $ZEEK_VERSION statt $EXPECTED_ZEEK_VERSION"
fi


# JA4

JA4_VERSION=$(zkg --user list 2>/dev/null \
    | grep 'zeek/foxio/ja4' \
    | sed -n 's/.*installed: \([^)]*\).*/\1/p')

if [ "$JA4_VERSION" = "$EXPECTED_JA4_VERSION" ]; then
    ok "JA4 Version $JA4_VERSION"
else
    error "JA4 Version ist $JA4_VERSION statt $EXPECTED_JA4_VERSION"
fi


# p0f

P0F_VERSION=$(dpkg-query -W -f='${Version}' p0f 2>/dev/null)

if [ "$P0F_VERSION" = "$EXPECTED_P0F_VERSION" ]; then
    ok "p0f Version $P0F_VERSION"
else
    error "p0f Version ist $P0F_VERSION statt $EXPECTED_P0F_VERSION"
fi


# TShark

TSHARK_VERSION=$(tshark --version 2>/dev/null \
    | head -n 1 \
    | awk '{print $3}')

if [ "$TSHARK_VERSION" = "$EXPECTED_TSHARK_VERSION" ]; then
    ok "TShark Version $TSHARK_VERSION"
else
    error "TShark Version ist $TSHARK_VERSION statt $EXPECTED_TSHARK_VERSION"
fi


# tcpdump

TCPDUMP_VERSION=$(tcpdump --version 2>/dev/null \
    | head -n 1 \
    | awk '{print $3}')

if [ "$TCPDUMP_VERSION" = "$EXPECTED_TCPDUMP_VERSION" ]; then
    ok "tcpdump Version $TCPDUMP_VERSION"
else
    error "tcpdump Version ist $TCPDUMP_VERSION statt $EXPECTED_TCPDUMP_VERSION"
fi

echo


# ------------------------------------------------------------
# 7. Zeitsynchronisation prüfen
# ------------------------------------------------------------

echo "--- Zeitsynchronisation ---"

NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)

if [ "$NTP_SYNC" = "yes" ]; then
    ok "Systemzeit ist synchronisiert"
else
    warning "Systemzeit wird nicht als synchronisiert gemeldet"
fi

echo


# ------------------------------------------------------------
# 8. Freien Speicherplatz prüfen
# ------------------------------------------------------------

echo "--- Speicherplatz ---"

FREE_GB=$(df -BG "$HOME/ba-experiment" \
    | awk 'NR==2 {gsub("G","",$4); print $4}')

if [ "$FREE_GB" -ge "$MIN_FREE_GB" ]; then
    ok "$FREE_GB GB freier Speicherplatz"
else
    warning "Nur noch $FREE_GB GB frei"
fi

echo


# ------------------------------------------------------------
# Ergebnis
# ------------------------------------------------------------

echo "=========================================="
echo " Ergebnis"
echo "=========================================="

echo "Fehler:    $ERRORS"
echo "Warnungen: $WARNINGS"
echo

if [ "$ERRORS" -eq 0 ]; then
    echo "PRECHECK BESTANDEN"
    exit 0
else
    echo "PRECHECK NICHT BESTANDEN"
    echo "Vor einer offiziellen Messung müssen die Fehler geprüft werden."
    exit 1
fi
