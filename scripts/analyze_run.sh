#!/bin/bash

# ------------------------------------------------------------
# Analyse-Skript für die Messungen der Bachelorarbeit
#
# Aufruf:
#   ./analyze_run.sh RUN_ORDNER
#
# Beispiel:
#   ./analyze_run.sh ~/ba-experiment/measurements/ubuntu/WEB/01
#
# Für einen Pretest zum Beispiel:
#   ./analyze_run.sh ~/ba-experiment/pretests/capture_script_test/ubuntu/WEB/01
#
# Das Skript:
# - prüft, ob PCAP und Metadaten vorhanden sind
# - überprüft den gespeicherten SHA-256-Hash
# - liest System, Szenario, IP und MAC aus metadata.txt
# - führt nDPI aus
# - führt p0f aus
# - führt Zeek mit JA4 aus
# - extrahiert JA4T-Werte des Testsystems
# - extrahiert wichtige TCP-SYN-Merkmale mit TShark
# - speichert die Ergebnisse getrennt im analysis-Ordner
# ------------------------------------------------------------


# ------------------------------------------------------------
# Feste Einstellungen
# ------------------------------------------------------------

NDPI_DIR="$HOME/src/nDPI"
NDPI_READER="$NDPI_DIR/example/ndpiReader"

# Zeek liegt bei unserer Installation unter /opt/zeek/bin.
# Der Pfad wird hier zusätzlich gesetzt, damit das Skript
# unabhängig von der aktuell geöffneten Shell funktioniert.
export PATH="/opt/zeek/bin:$PATH"

# Auch die mit zkg installierten Zeek-Pakete sollen gefunden
# werden. Dazu gehört insbesondere das JA4-Paket.
if command -v zkg >/dev/null 2>&1; then
    eval "$(zkg --user env)"
fi


# ------------------------------------------------------------
# Run-Ordner übernehmen
# ------------------------------------------------------------

RUN_DIR="$1"


if [ -z "$RUN_DIR" ]; then
    echo
    echo "Verwendung:"
    echo "  $0 RUN_ORDNER"
    echo
    echo "Beispiel:"
    echo "  $0 ~/ba-experiment/measurements/ubuntu/WEB/01"
    echo
    exit 1
fi


# Einen eventuell vorhandenen Schrägstrich am Ende entfernen.

RUN_DIR="${RUN_DIR%/}"


# ------------------------------------------------------------
# Benötigte Dateien
# ------------------------------------------------------------

PCAP_FILE="$RUN_DIR/capture.pcap"
METADATA_FILE="$RUN_DIR/metadata.txt"
SHA_FILE="$RUN_DIR/sha256.txt"

ANALYSIS_DIR="$RUN_DIR/analysis"

# Für die Werkzeuganalyse wird aus dem vollständigen Roh-PCAP
# eine Arbeitskopie erstellt, die nur Ethernet-Verkehr enthält,
# der dem Testsystem anhand seiner MAC-Adresse zugeordnet werden kann.
FILTERED_PCAP="$ANALYSIS_DIR/testhost.pcap"

NDPI_OUTPUT="$ANALYSIS_DIR/ndpi"
P0F_OUTPUT="$ANALYSIS_DIR/p0f"
ZEEK_OUTPUT="$ANALYSIS_DIR/zeek"
TSHARK_OUTPUT="$ANALYSIS_DIR/tshark"

ANALYSIS_INFO="$ANALYSIS_DIR/analysis_info.txt"


echo
echo "=========================================="
echo " Analyse eines Messlaufs"
echo "=========================================="
echo


# ------------------------------------------------------------
# Prüfen, ob der Run-Ordner vorhanden ist
# ------------------------------------------------------------

if [ ! -d "$RUN_DIR" ]; then
    echo "[FEHLER] Run-Ordner wurde nicht gefunden:"
    echo "$RUN_DIR"
    exit 1
fi


# ------------------------------------------------------------
# PCAP und Metadaten prüfen
# ------------------------------------------------------------

if [ ! -f "$PCAP_FILE" ]; then
    echo "[FEHLER] capture.pcap wurde nicht gefunden."
    exit 1
fi


if [ ! -f "$METADATA_FILE" ]; then
    echo "[FEHLER] metadata.txt wurde nicht gefunden."
    exit 1
fi


if [ ! -f "$SHA_FILE" ]; then
    echo "[FEHLER] sha256.txt wurde nicht gefunden."
    exit 1
fi


# ------------------------------------------------------------
# Informationen aus metadata.txt lesen
# ------------------------------------------------------------

SYSTEM=$(grep '^system=' "$METADATA_FILE" | cut -d= -f2-)
SCENARIO=$(grep '^scenario=' "$METADATA_FILE" | cut -d= -f2-)
REPETITION=$(grep '^repetition=' "$METADATA_FILE" | cut -d= -f2-)
TEST_IP=$(grep '^test_ipv4=' "$METADATA_FILE" | cut -d= -f2-)
TEST_MAC=$(grep '^test_mac=' "$METADATA_FILE" | cut -d= -f2-)
RUN_STATUS=$(grep '^status=' "$METADATA_FILE" | cut -d= -f2-)


echo "System:       $SYSTEM"
echo "Szenario:     $SCENARIO"
echo "Wiederholung: $REPETITION"
echo "IPv4:         $TEST_IP"
echo "MAC:          $TEST_MAC"
echo "Run-Status:   $RUN_STATUS"
echo


# ------------------------------------------------------------
# Prüfen, ob eine Test-IP vorhanden ist
# ------------------------------------------------------------

if [ -z "$TEST_IP" ] || [ "$TEST_IP" = "unknown" ]; then
    echo "[FEHLER] Keine gültige IPv4-Adresse in metadata.txt gefunden."
    exit 1
fi

# Für die Filterung des Testsystem-Verkehrs wird zusätzlich
# die während der Messung bestimmte MAC-Adresse benötigt.

if [ -z "$TEST_MAC" ] || [ "$TEST_MAC" = "unknown" ]; then
    echo "[FEHLER] Keine gültige MAC-Adresse in metadata.txt gefunden."
    exit 1
fi

# ------------------------------------------------------------
# Integrität des PCAPs prüfen
#
# Bevor die Analyse beginnt, wird kontrolliert, ob sich die
# Roh-PCAP-Datei seit ihrer Erstellung verändert hat.
# ------------------------------------------------------------

echo "------------------------------------------"
echo " SHA-256-Prüfung"
echo "------------------------------------------"
echo


if (cd "$RUN_DIR" && sha256sum -c sha256.txt); then
    echo "[OK] PCAP-Integrität bestätigt."
else
    echo
    echo "[FEHLER] SHA-256-Prüfung fehlgeschlagen."
    echo "Analyse wird nicht durchgeführt."
    exit 1
fi


# ------------------------------------------------------------
# Prüfen, ob die benötigten Programme vorhanden sind
# ------------------------------------------------------------

echo
echo "------------------------------------------"
echo " Programme prüfen"
echo "------------------------------------------"
echo


for PROGRAM in tshark p0f zeek zeek-cut; do

    if command -v "$PROGRAM" >/dev/null 2>&1; then
        echo "[OK] $PROGRAM gefunden"
    else
        echo "[FEHLER] $PROGRAM wurde nicht gefunden"
        exit 1
    fi

done


if [ -x "$NDPI_READER" ]; then
    echo "[OK] ndpiReader gefunden"
else
    echo "[FEHLER] ndpiReader wurde nicht gefunden:"
    echo "$NDPI_READER"
    exit 1
fi


# ------------------------------------------------------------
# Schutz vor versehentlichem Überschreiben einer Analyse
# ------------------------------------------------------------

# capture_run.sh erstellt bereits einen leeren analysis-Ordner.
# Deshalb wird nur geprüft, ob darin schon Analyseergebnisse
# vorhanden sind.

if [ -d "$ANALYSIS_DIR" ] &&
   [ -n "$(find "$ANALYSIS_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]; then

    echo
    echo "[FEHLER] Im analysis-Ordner befinden sich bereits Dateien:"
    echo "$ANALYSIS_DIR"
    echo
    echo "Es wird nichts überschrieben."
    exit 1
fi


# ------------------------------------------------------------
# Ausgabeordner erstellen
# ------------------------------------------------------------

mkdir -p "$NDPI_OUTPUT"
mkdir -p "$P0F_OUTPUT"
mkdir -p "$ZEEK_OUTPUT"
mkdir -p "$TSHARK_OUTPUT"

# ============================================================
# Verkehr des Testsystems filtern
# ============================================================

echo
echo "=========================================="
echo " Testsystem-Verkehr filtern"
echo "=========================================="
echo

echo "MAC-Adresse des Testsystems: $TEST_MAC"
echo


# Das ursprüngliche capture.pcap bleibt unverändert.
# Für die Analyse wird eine abgeleitete PCAP-Datei erstellt.
#
# eth.addr erfasst Pakete, bei denen die MAC-Adresse des
# Testsystems entweder Quell- oder Zieladresse ist.
#
# Dadurch werden unter anderem IPv4- und IPv6-Verkehr sowie
# vom Testsystem erzeugter Broadcast- und Multicast-Verkehr
# berücksichtigt, während Verkehr anderer LAN-Geräte
# weitgehend ausgeschlossen wird.

tshark \
    -r "$PCAP_FILE" \
    -Y "eth.addr == $TEST_MAC" \
    -F pcap \
    -w "$FILTERED_PCAP"


if [ $? -ne 0 ] || [ ! -s "$FILTERED_PCAP" ]; then
    echo
    echo "[FEHLER] Gefilterte PCAP-Datei konnte nicht erstellt werden."
    exit 1
fi


FILTERED_SHA256=$(sha256sum "$FILTERED_PCAP" | awk '{print $1}')


echo
echo "[OK] Testsystem-PCAP erstellt:"
echo "$FILTERED_PCAP"
echo

ANALYSIS_START=$(date -Is)


# Status der einzelnen Werkzeuge.
# Diese Werte werden am Ende in analysis_info.txt gespeichert.

NDPI_STATUS="not_run"
P0F_STATUS="not_run"
ZEEK_STATUS="not_run"
JA4T_STATUS="not_run"
TSHARK_STATUS="not_run"


# ============================================================
# 1. nDPI
# ============================================================

echo
echo "=========================================="
echo " nDPI"
echo "=========================================="
echo


# -i gibt die PCAP-Datei an.
# -v 2 erzeugt eine ausführlichere Ausgabe, damit auch
# Fingerprint-Informationen später ausgewertet werden können.

"$NDPI_READER" \
    -i "$FILTERED_PCAP" \
    -v 2 \
    > "$NDPI_OUTPUT/ndpi_verbose.txt" \
    2>&1


if [ $? -eq 0 ]; then
    NDPI_STATUS="ok"
    echo "[OK] nDPI-Analyse abgeschlossen."
else
    NDPI_STATUS="failed"
    echo "[FEHLER] nDPI meldete einen Fehler."
fi

# ------------------------------------------------------------
# nDPI TCP-Fingerprints des Testsystems zusammenfassen
# ------------------------------------------------------------

if [ "$NDPI_STATUS" = "ok" ]; then

    {
        printf "count\ttcp_fingerprint\tclassification\n"

        grep "TCP $TEST_IP:" "$NDPI_OUTPUT/ndpi_verbose.txt" \
            | grep -o 'TCP Fingerprint: [^]]*' \
            | sed 's/^TCP Fingerprint: //' \
            | sort \
            | uniq -c \
            | awk '
                {
                    count=$1
                    split($2, parts, "/")
                    print count "\t" parts[1] "\t" parts[2]
                }
            '

    } > "$NDPI_OUTPUT/os_fingerprints.tsv"

    echo "[OK] nDPI-Fingerprint-Zusammenfassung erstellt."

fi

# ============================================================
# 2. p0f
# ============================================================

echo
echo "=========================================="
echo " p0f"
echo "=========================================="
echo


# p0f analysiert die bereits vorhandene PCAP-Datei offline.
# Die normale Konsolenausgabe und das p0f-Log werden getrennt
# gespeichert.

p0f \
    -r "$FILTERED_PCAP" \
    -o "$P0F_OUTPUT/p0f.log" \
    > "$P0F_OUTPUT/p0f_console.txt" \
    2>&1


if [ $? -eq 0 ]; then
    P0F_STATUS="ok"
    echo "[OK] p0f-Analyse abgeschlossen."
else
    P0F_STATUS="failed"
    echo "[FEHLER] p0f meldete einen Fehler."
fi

# ------------------------------------------------------------
# p0f Betriebssystem-Fingerprints des Testsystems
# zusammenfassen
# ------------------------------------------------------------

if [ "$P0F_STATUS" = "ok" ]; then

    {
        printf "count\tos\tparams\traw_sig\n"

        grep "mod=syn|cli=$TEST_IP/" "$P0F_OUTPUT/p0f.log" \
            | awk -F'|' '
                {
                    os=$5
                    params=$7
                    raw_sig=$8

                    sub(/^os=/, "", os)
                    sub(/^params=/, "", params)
                    sub(/^raw_sig=/, "", raw_sig)

                    print os "\t" params "\t" raw_sig
                }
            ' \
            | sort \
            | uniq -c \
            | awk '
                {
                    count=$1
                    sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")
                    print count "\t" $0
                }
            '

    } > "$P0F_OUTPUT/os_fingerprints.tsv"

    echo "[OK] p0f-Fingerprint-Zusammenfassung erstellt."

fi

# ============================================================
# 3. Zeek und JA4
# ============================================================

echo
echo "=========================================="
echo " Zeek / JA4"
echo "=========================================="
echo


# Zeek schreibt seine Logdateien immer in das aktuelle
# Arbeitsverzeichnis. Deshalb wechseln wir für diesen Schritt
# in den eigenen Zeek-Ausgabeordner.
#
# "packages" lädt die über zkg installierten Pakete,
# darunter das JA4-Paket.

(
    cd "$ZEEK_OUTPUT" || exit 1

    zeek \
        -Cr "$FILTERED_PCAP" \
        packages \
        > zeek_console.txt \
        2>&1
)


if [ $? -eq 0 ]; then
    ZEEK_STATUS="ok"
    echo "[OK] Zeek-Analyse abgeschlossen."
else
    ZEEK_STATUS="failed"
    echo "[FEHLER] Zeek meldete einen Fehler."
fi


# ------------------------------------------------------------
# JA4T aus conn.log extrahieren
#
# Wir interessieren uns hier nur für Verbindungen, deren
# Ursprung das bekannte Testsystem ist.
# ------------------------------------------------------------

if [ "$ZEEK_STATUS" = "ok" ] &&
   [ -f "$ZEEK_OUTPUT/conn.log" ]; then

    {
        printf "orig_h\tresp_h\tja4t\n"

        zeek-cut id.orig_h id.resp_h ja4t \
            < "$ZEEK_OUTPUT/conn.log" \
            | awk -v ip="$TEST_IP" '$1 == ip'

    } > "$ZEEK_OUTPUT/ja4t.tsv"


    # Prüfen, ob neben der Kopfzeile mindestens ein echter
    # JA4T-Fingerprint vorhanden ist. "(empty)" wird dabei
    # nicht als Fingerprint gewertet.

    if tail -n +2 "$ZEEK_OUTPUT/ja4t.tsv" \
        | awk -F'\t' '$3 != "(empty)" && $3 != "" {print $3}' \
        | grep -q .; then

        JA4T_STATUS="ok"
        echo "[OK] JA4T-Ausgabe erstellt."

        # Gleiche Fingerprints werden zusammengefasst.
        # Dadurch lässt sich später direkt erkennen, wie häufig
        # ein JA4T-Fingerprint im Messlauf aufgetreten ist.

        {
            printf "count\tja4t\n"

            tail -n +2 "$ZEEK_OUTPUT/ja4t.tsv" \
                | awk -F'\t' '$3 != "(empty)" && $3 != "" {print $3}' \
                | sort \
                | uniq -c \
                | awk '
                    {
                        count=$1
                        $1=""
                        sub(/^[[:space:]]+/, "")
                        print count "\t" $0
                    }
                '

        } > "$ZEEK_OUTPUT/ja4t_summary.tsv"

        echo "[OK] JA4T-Zusammenfassung erstellt."

    else

        JA4T_STATUS="no_data"

        # Auch wenn kein Fingerprint vorhanden ist, wird eine
        # Datei mit Kopfzeile angelegt. Das erleichtert später
        # die automatisierte Auswertung aller Messläufe.

        printf "count\tja4t\n" \
            > "$ZEEK_OUTPUT/ja4t_summary.tsv"

        echo "[WARN] Keine JA4T-Fingerprints gefunden."

    fi

else

    JA4T_STATUS="failed"
    echo "[WARN] JA4T konnte nicht aus conn.log extrahiert werden."

fi

# ============================================================
# 4. TShark
# ============================================================

echo
echo "=========================================="
echo " TShark"
echo "=========================================="
echo


# Es werden ausgehende TCP-SYN-Pakete des Testsystems
# betrachtet. Diese Merkmale sind für das passive
# Betriebssystem-Fingerprinting besonders interessant.
#
# Ausgegeben werden unter anderem:
# - TTL
# - TCP Window
# - MSS
# - Window Scale
# - Reihenfolge bzw. Rohwert der TCP-Optionen

tshark \
    -r "$FILTERED_PCAP" \
    -Y "ip.src==$TEST_IP && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields \
    -E header=y \
    -E separator=$'\t' \
    -E quote=n \
    -e frame.number \
    -e frame.time_epoch \
    -e ip.src \
    -e ip.dst \
    -e ip.ttl \
    -e tcp.flags \
    -e tcp.window_size_value \
    -e tcp.options.mss_val \
    -e tcp.options.wscale.shift \
    -e tcp.options \
    > "$TSHARK_OUTPUT/syn_features.tsv" \
    2> "$TSHARK_OUTPUT/tshark_errors.txt"


if [ $? -eq 0 ]; then
    TSHARK_STATUS="ok"
    echo "[OK] TShark-Auswertung abgeschlossen."
else
    TSHARK_STATUS="failed"
    echo "[FEHLER] TShark meldete einen Fehler."
fi

# ------------------------------------------------------------
# TCP-SYN-Merkmale des Testsystems zusammenfassen
# ------------------------------------------------------------

if [ "$TSHARK_STATUS" = "ok" ]; then

    {
        printf "count\tttl\twindow\tmss\twscale\toptions_pattern\n"

        # syn_features.tsv enthält weiterhin für jedes einzelne
        # SYN-Paket den vollständigen und unveränderten Hexwert
        # der TCP-Optionen.
        #
        # Für diese zusätzliche Zusammenfassung werden lediglich
        # die variablen Werte innerhalb der TCP-Timestamp-Option
        # abstrahiert. Optionstypen und Reihenfolge bleiben erhalten.

        tail -n +2 "$TSHARK_OUTPUT/syn_features.tsv" \
            | awk -F'\t' '
                NF >= 10 {
                    print $5 "\t" $7 "\t" $8 "\t" $9 "\t" $10
                }
            ' \
            | sed -E 's/080a[0-9A-Fa-f]{16}/080a<TIMESTAMP>/g' \
            | sort \
            | uniq -c \
            | awk '
                {
                    count=$1
                    sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")
                    print count "\t" $0
                }
            '

    } > "$TSHARK_OUTPUT/syn_summary.tsv"


    if [ "$(wc -l < "$TSHARK_OUTPUT/syn_summary.tsv")" -gt 1 ]; then
        echo "[OK] TShark-SYN-Zusammenfassung erstellt."
    else
        echo "[WARN] Keine ausgehenden TCP-SYN-Pakete gefunden."
    fi

fi

# ============================================================
# Analyseinformationen speichern
# ============================================================

ANALYSIS_END=$(date -Is)


cat > "$ANALYSIS_INFO" <<EOF
system=$SYSTEM
scenario=$SCENARIO
repetition=$REPETITION

test_ipv4=$TEST_IP
test_mac=$TEST_MAC

source_pcap=capture.pcap
analysis_pcap=testhost.pcap
analysis_filter=eth.addr == $TEST_MAC
analysis_pcap_sha256=$FILTERED_SHA256

analysis_start=$ANALYSIS_START
analysis_end=$ANALYSIS_END

ndpi_status=$NDPI_STATUS
p0f_status=$P0F_STATUS
zeek_status=$ZEEK_STATUS
ja4t_status=$JA4T_STATUS
tshark_status=$TSHARK_STATUS
EOF


# ------------------------------------------------------------
# Abschluss
# ------------------------------------------------------------

echo
echo "=========================================="
echo " Analyse abgeschlossen"
echo "=========================================="
echo
echo "nDPI:   $NDPI_STATUS"
echo "p0f:    $P0F_STATUS"
echo "Zeek:   $ZEEK_STATUS"
echo "JA4T:   $JA4T_STATUS"
echo "TShark: $TSHARK_STATUS"
echo
echo "Ergebnisse:"
echo "$ANALYSIS_DIR"
echo
