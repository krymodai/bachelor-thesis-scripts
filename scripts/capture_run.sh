#!/bin/bash

# ------------------------------------------------------------
# Capture-Skript für die Messungen der Bachelorarbeit
#
# Aufruf:
#   ./capture_run.sh SYSTEM SZENARIO WIEDERHOLUNG
#
# Beispiel:
#   ./capture_run.sh tails WEB 01
#
# Das Skript:
# - prüft die Eingaben
# - führt den Preflight-Check aus
# - erstellt den richtigen Messordner
# - startet und beendet tcpdump
# - gibt die Zeitpunkte für das Szenario vor
# - speichert wichtige Ereignisse
# - speichert die tcpdump-Statistik
# - bestimmt die IP- und MAC-Adresse des Testsystems
# - berechnet den SHA-256-Hash des PCAPs
# - erstellt metadata.txt
# - ergänzt run_index.tsv
# ------------------------------------------------------------


# ------------------------------------------------------------
# Feste Einstellungen
# ------------------------------------------------------------

BASE_DIR="$HOME/ba-experiment"

MEASUREMENTS_DIR="$BASE_DIR/measurements"
METADATA_DIR="$BASE_DIR/metadata"

PREFLIGHT="$BASE_DIR/scripts/preflight_check.sh"

BRIDGE="br0"

# Lokales IPv4-Netz des Versuchsaufbaus.
# Der Punkt muss für grep escaped werden.
LAB_PREFIX_REGEX='^10\.0\.0\.'

# IP-Adresse des Routers.
# Diese soll später nicht als Testsystem vorgeschlagen werden.
ROUTER_IP="10.0.0.138"

# Beim IDLE-Szenario wird etwas länger aufgezeichnet.
# Für die spätere Auswertung können dann die ersten
# 300 Sekunden ab dem ersten Verkehr des Testsystems
# verwendet werden.
# Dauer der eigentlichen Leerlaufphase,
# nachdem das System vollständig gestartet wurde.
IDLE_SECONDS=300


# ------------------------------------------------------------
# Eingaben übernehmen
# ------------------------------------------------------------

SYSTEM=$(echo "$1" | tr '[:upper:]' '[:lower:]')
SCENARIO=$(echo "$2" | tr '[:lower:]' '[:upper:]')
REPETITION="$3"


# Es müssen alle drei Angaben vorhanden sein.

if [ -z "$SYSTEM" ] || [ -z "$SCENARIO" ] || [ -z "$REPETITION" ]; then
    echo
    echo "Verwendung:"
    echo "  $0 SYSTEM SZENARIO WIEDERHOLUNG"
    echo
    echo "Beispiel:"
    echo "  $0 tails WEB 01"
    echo
    exit 1
fi


# ------------------------------------------------------------
# Testsystem prüfen
#
# Das hier ist der bekannte Ground Truth.
# Das Skript versucht NICHT, das Betriebssystem zu erkennen.
# ------------------------------------------------------------

case "$SYSTEM" in
    windows10|ubuntu|tails|whonix|qubes)
        ;;
    *)
        echo "Unbekanntes Testsystem: $SYSTEM"
        echo "Erlaubt: windows10, ubuntu, tails, whonix, qubes"
        exit 1
        ;;
esac


# ------------------------------------------------------------
# Szenario prüfen
# ------------------------------------------------------------

case "$SCENARIO" in
    IDLE|WEB|DOWNLOAD|CONT)
        ;;
    *)
        echo "Unbekanntes Szenario: $SCENARIO"
        echo "Erlaubt: IDLE, WEB, DOWNLOAD, CONT"
        exit 1
        ;;
esac


# ------------------------------------------------------------
# Wiederholung prüfen
# ------------------------------------------------------------

case "$REPETITION" in
    1|01)
        REPETITION="01"
        ;;
    2|02)
        REPETITION="02"
        ;;
    3|03)
        REPETITION="03"
        ;;
    *)
        echo "Wiederholung muss 01, 02 oder 03 sein."
        exit 1
        ;;
esac


# ------------------------------------------------------------
# Namen und Dateien für diesen Lauf festlegen
# ------------------------------------------------------------

RUN_ID="${SYSTEM}_${SCENARIO}_${REPETITION}"

RUN_DIR="$MEASUREMENTS_DIR/$SYSTEM/$SCENARIO/$REPETITION"

PCAP_FILE="$RUN_DIR/capture.pcap"
CAPTURE_STATS="$RUN_DIR/capture_stats.txt"
METADATA_FILE="$RUN_DIR/metadata.txt"
EVENTS_FILE="$RUN_DIR/events.tsv"
SHA_FILE="$RUN_DIR/sha256.txt"

RUN_INDEX="$METADATA_DIR/run_index.tsv"


echo
echo "=========================================="
echo " Messung: $RUN_ID"
echo "=========================================="
echo


# ------------------------------------------------------------
# Schutz vor versehentlichem Überschreiben
# ------------------------------------------------------------

if [ -e "$RUN_DIR" ]; then
    echo "[FEHLER] Der Messordner existiert bereits:"
    echo "$RUN_DIR"
    echo
    echo "Es wird nichts überschrieben."
    exit 1
fi


# ------------------------------------------------------------
# Preflight-Check
# ------------------------------------------------------------

echo "Preflight-Check wird durchgeführt ..."
echo

"$PREFLIGHT" "$SCENARIO"

if [ $? -ne 0 ]; then
    echo
    echo "[FEHLER] Preflight-Check nicht bestanden."
    echo "Messung wird nicht gestartet."
    exit 1
fi


# ------------------------------------------------------------
# Ordner für diesen Messlauf erstellen
# ------------------------------------------------------------

mkdir -p "$RUN_DIR/analysis"
mkdir -p "$METADATA_DIR"

echo
echo "[OK] Messordner erstellt:"
echo "$RUN_DIR"


# ------------------------------------------------------------
# Ereignisprotokoll vorbereiten
#
# Darin werden wichtige Zeitpunkte gespeichert, zum Beispiel
# der Start eines Webseitenaufrufs oder der Beginn des Streams.
# ------------------------------------------------------------

printf "timestamp\tevent\n" > "$EVENTS_FILE"


log_event() {
    printf "%s\t%s\n" "$(date -Is)" "$1" >> "$EVENTS_FILE"
}

# Diese Funktion wird verwendet, wenn bereits ein bestimmter
# Zeitstempel vorhanden ist. Dadurch kann derselbe Zeitpunkt
# in events.tsv und metadata.txt gespeichert werden.

log_event_at() {
    printf "%s\t%s\n" "$1" "$2" >> "$EVENTS_FILE"
}

# ------------------------------------------------------------
# Vorbereitung je nach Szenario
# ------------------------------------------------------------

echo
echo "------------------------------------------"
echo " Vorbereitung"
echo "------------------------------------------"

case "$SCENARIO" in

    IDLE)
        echo "Das Testsystem soll ausgeschaltet sein."
        echo "Das LAN-Kabel zwischen Monitoring-PC und Testsystem"
        echo "soll bereits angeschlossen sein."
        echo
        echo "Die Router-Seite der Bridge muss verbunden sein."
        ;;

    WEB)
        echo "Browser bitte vollständig neu starten."
        echo
        echo "Firefox:"
        echo "Private Sitzung verwenden."
        echo
        echo "Tails / Whonix:"
        echo "Vorgesehene Tor-Browser-Sitzung verwenden."
        echo
        echo "Noch keine der fünf Messseiten öffnen."
        ;;

    DOWNLOAD)
        echo "Browser bitte vorbereiten."
        echo
        echo "Die Download-Datei noch NICHT herunterladen."
        echo
        echo "Download:"
        echo "https://cdn.truefilesize.com/test/test-50mb.bin"
        ;;

    CONT)
        echo "Vimeo bitte VOR der Messung vorbereiten:"
        echo
        echo "https://vimeo.com/1084537"
        echo
        echo "- eventuelle Bot-Prüfung bereits erledigen"
        echo "- Big Buck Bunny auf 00:00 stellen"
        echo "- Qualität fest auf 720p stellen"
        echo "- Video pausieren"
        ;;

esac


echo
read -r -p "Wenn alles vorbereitet ist, Enter drücken ... "


# ------------------------------------------------------------
# Capture starten
# ------------------------------------------------------------

echo
echo "Starte tcpdump auf $BRIDGE ..."

sudo tcpdump \
    -i "$BRIDGE" \
    -nn \
    -s 0 \
    -w "$PCAP_FILE" \
    2> "$CAPTURE_STATS" &

TCPDUMP_PID=$!

# Zeitpunkt unmittelbar nach dem Start von tcpdump festhalten.
CAPTURE_START=$(date -Is)

sleep 2

if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    echo
    echo "[FEHLER] tcpdump konnte nicht gestartet werden."
    echo
    cat "$CAPTURE_STATS"
    exit 1
fi


log_event_at "$CAPTURE_START" "capture_start"

echo "[OK] Capture läuft."
echo


# ------------------------------------------------------------
# Funktion zum sauberen Beenden von tcpdump
# ------------------------------------------------------------

stop_capture() {

    if [ -n "$TCPDUMP_PID" ] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        sudo kill -INT "$TCPDUMP_PID" 2>/dev/null
        wait "$TCPDUMP_PID" 2>/dev/null
    fi

    TCPDUMP_PID=""
}


# Falls das Skript mit Strg+C abgebrochen wird, soll tcpdump
# nicht im Hintergrund weiterlaufen.

cleanup() {

    if [ -n "$TCPDUMP_PID" ]; then
        echo
        echo "Skript wurde abgebrochen. tcpdump wird beendet."
        stop_capture
    fi
}


trap cleanup INT TERM


# ------------------------------------------------------------
# Szenario durchführen
# ------------------------------------------------------------

case "$SCENARIO" in


    # ========================================================
    # IDLE
    # ========================================================

    IDLE)

        echo
        echo "=========================================="
        echo " JETZT TESTSYSTEM EINSCHALTEN"
        echo "=========================================="
        echo

        log_event "testsystem_start_prompt"

        echo "Das Hochfahren und die notwendige Anmeldung"
        echo "dürfen jetzt normal durchgeführt werden."
        echo
        echo "Sobald das System vollständig gestartet ist"
        echo "und die normale Desktop-/Arbeitsumgebung bereit ist,"
        echo "am Monitoring-System Enter drücken."
        echo
        echo "Danach beginnt die eigentliche Leerlaufphase."
        echo

        read -r -p "System vollständig gestartet und bereit? Dann hier Enter drücken ... "

        log_event "idle_start"

        echo
        echo "=========================================="
        echo " LEERLAUFPHASE GESTARTET"
        echo "=========================================="
        echo
        echo "Ab jetzt $IDLE_SECONDS Sekunden keine"
        echo "Benutzeraktivität am Testsystem durchführen."
        echo

        sleep "$IDLE_SECONDS"

        log_event "idle_end"

        echo
        echo "Leerlaufphase beendet."
        ;;


    # ========================================================
    # WEB
    # ========================================================

    WEB)

        echo
        echo "10 Sekunden allgemeiner Vorlauf ..."
        sleep 10


        # ----------------------------------------------------
        # Debian
        # ----------------------------------------------------

        echo
        echo "=========================================="
        echo "1 von 5: Debian"
        echo "=========================================="
        echo
        echo "Adresse am Testsystem eintippen,"
        echo "aber noch NICHT aufrufen:"
        echo
        echo "https://www.debian.org/"
        echo

        read -r -p "Wenn die Adresse fertig eingegeben ist, hier im Monitoring-System Enter drücken. Dann erfolgt ein 3-sekündiger Countdown, an dessen Ende du die Website aufrufen sollst ... "

        echo
        echo "3 ..."
        sleep 1
        echo "2 ..."
        sleep 1
        echo "1 ..."
        sleep 1

        echo
        echo ">>> JETZT WEBSITE AUFRUFEN <<<"
        echo

        log_event "web_debian"

        sleep 15


        # ----------------------------------------------------
        # kernel.org
        # ----------------------------------------------------

        echo
        echo "=========================================="
        echo "2 von 5: kernel.org"
        echo "=========================================="
        echo
        echo "Adresse am Testsystem eintippen,"
        echo "aber noch NICHT aufrufen:"
        echo
        echo "https://www.kernel.org/"
        echo

        read -r -p "Wenn die Adresse fertig eingegeben ist, hier im Monitoring-System Enter drücken. Dann erfolgt ein 3-sekündiger Countdown, an dessen Ende du die Website aufrufen sollst ... "

        echo
        echo "3 ..."
        sleep 1
        echo "2 ..."
        sleep 1
        echo "1 ..."
        sleep 1

        echo
        echo ">>> JETZT WEBSITE AUFRUFEN <<<"
        echo

        log_event "web_kernel"

        sleep 15


        # ----------------------------------------------------
        # Wikipedia
        # ----------------------------------------------------

        echo
        echo "=========================================="
        echo "3 von 5: Wikipedia"
        echo "=========================================="
        echo
        echo "Adresse am Testsystem eintippen,"
        echo "aber noch NICHT aufrufen:"
        echo
        echo "https://www.wikipedia.org/"
        echo

        read -r -p "Wenn die Adresse fertig eingegeben ist, hier im Monitoring-System Enter drücken. Dann erfolgt ein 3-sekündiger Countdown, an dessen Ende du die Website aufrufen sollst ... "

        echo
        echo "3 ..."
        sleep 1
        echo "2 ..."
        sleep 1
        echo "1 ..."
        sleep 1

        echo
        echo ">>> JETZT WEBSITE AUFRUFEN <<<"
        echo

        log_event "web_wikipedia"

        sleep 15


        # ----------------------------------------------------
        # Mozilla
        # ----------------------------------------------------

        echo
        echo "=========================================="
        echo "4 von 5: Mozilla"
        echo "=========================================="
        echo
        echo "Adresse am Testsystem eintippen,"
        echo "aber noch NICHT aufrufen:"
        echo
        echo "https://www.mozilla.org/"
        echo

        read -r -p "Wenn die Adresse fertig eingegeben ist, hier im Monitoring-System Enter drücken. Dann erfolgt ein 3-sekündiger Countdown, an dessen Ende du die Website aufrufen sollst ... "

        echo
        echo "3 ..."
        sleep 1
        echo "2 ..."
        sleep 1
        echo "1 ..."
        sleep 1

        echo
        echo ">>> JETZT WEBSITE AUFRUFEN <<<"
        echo

        log_event "web_mozilla"

        sleep 15


        # ----------------------------------------------------
        # W3C
        # ----------------------------------------------------

        echo
        echo "=========================================="
        echo "5 von 5: W3C"
        echo "=========================================="
        echo
        echo "Adresse am Testsystem eintippen,"
        echo "aber noch NICHT aufrufen:"
        echo
        echo "https://www.w3.org/"
        echo

        read -r -p "Wenn die Adresse fertig eingegeben ist, hier im Monitoring-System Enter drücken. Dann erfolgt ein 3-sekündiger Countdown, an dessen Ende du die Website aufrufen sollst ... "

        echo
        echo "3 ..."
        sleep 1
        echo "2 ..."
        sleep 1
        echo "1 ..."
        sleep 1

        echo
        echo ">>> JETZT WEBSITE AUFRUFEN <<<"
        echo

        log_event "web_w3c"

        sleep 15


        echo
        echo "Alle fünf Webseiten wurden aufgerufen."
        echo "10 Sekunden Nachlauf ..."

        sleep 10
        ;;

    # ========================================================
    # DOWNLOAD
    # ========================================================

    DOWNLOAD)

        echo
        echo "10 Sekunden Vorlauf ..."
        sleep 10

        echo
        echo "=========================================="
        echo " JETZT DOWNLOAD STARTEN"
        echo "=========================================="
        echo
        echo "https://cdn.truefilesize.com/test/test-50mb.bin"
        echo

        log_event "download_start_prompt"

        read -r -p "Wenn der Download vollständig abgeschlossen ist, Enter drücken ... "

        log_event "download_complete"

        echo
        echo "10 Sekunden Nachlauf ..."
        sleep 10
        ;;


    # ========================================================
    # CONT
    # ========================================================

    CONT)

        echo
        echo "10 Sekunden Vorlauf ..."
        sleep 10

        echo
        echo "=========================================="
        echo " JETZT PLAY"
        echo "=========================================="
        echo

        log_event "stream_play"

        sleep 180

        echo
        echo "=========================================="
        echo " JETZT PAUSE"
        echo "=========================================="
        echo

        log_event "stream_pause"

        echo "10 Sekunden Nachlauf ..."
        sleep 10
        ;;

esac


# ------------------------------------------------------------
# Capture beenden
# ------------------------------------------------------------

echo
echo "Capture wird beendet ..."

stop_capture

CAPTURE_END=$(date -Is)

log_event_at "$CAPTURE_END" "capture_end"

trap - INT TERM

echo "[OK] Capture beendet."


# ------------------------------------------------------------
# PCAP dem normalen Benutzer zuordnen
#
# tcpdump wurde mit sudo gestartet. Deshalb gehört die Datei
# zuerst root. Danach wird sie wieder dem normalen Benutzer
# zugeordnet.
# ------------------------------------------------------------

sudo chown "$USER:$(id -gn)" "$PCAP_FILE" 2>/dev/null

sync


# ------------------------------------------------------------
# tcpdump-Statistik anzeigen und auslesen
# ------------------------------------------------------------

echo
echo "------------------------------------------"
echo " tcpdump-Statistik"
echo "------------------------------------------"
echo

cat "$CAPTURE_STATS"


PACKETS_CAPTURED=$(grep -E '^[0-9]+ packets captured' "$CAPTURE_STATS" \
    | tail -n 1 \
    | awk '{print $1}')

PACKETS_RECEIVED=$(grep -E '^[0-9]+ packets received by filter' "$CAPTURE_STATS" \
    | tail -n 1 \
    | awk '{print $1}')

PACKETS_DROPPED=$(grep -E '^[0-9]+ packets dropped by kernel' "$CAPTURE_STATS" \
    | tail -n 1 \
    | awk '{print $1}')


# Falls eine der Zahlen nicht gefunden wurde, wird "unknown"
# eingetragen.

[ -z "$PACKETS_CAPTURED" ] && PACKETS_CAPTURED="unknown"
[ -z "$PACKETS_RECEIVED" ] && PACKETS_RECEIVED="unknown"
[ -z "$PACKETS_DROPPED" ] && PACKETS_DROPPED="unknown"


# ------------------------------------------------------------
# IP- und MAC-Adresse des Testsystems bestimmen
#
# Das Betriebssystem selbst ist bereits bekannt, weil es beim
# Start des Skripts angegeben wurde.
#
# Hier wird nur bestimmt, welche IPv4- und MAC-Adresse dieses
# Testsystem während des jeweiligen Messlaufs verwendet hat.
# ------------------------------------------------------------

echo
echo "------------------------------------------"
echo " IP- und MAC-Adresse des Testsystems"
echo "------------------------------------------"
echo


CANDIDATES_FILE="$RUN_DIR/ip_candidates.txt"


# Zuerst werden lokale IPv4-Adressen gesucht, von denen
# ausgehende TCP-SYN-Pakete stammen.

tshark -r "$PCAP_FILE" \
    -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src' \
    -T fields \
    -e ip.src 2>/dev/null \
    | grep "$LAB_PREFIX_REGEX" \
    | grep -v "^$ROUTER_IP$" \
    | sort -u \
    > "$CANDIDATES_FILE"


CANDIDATE_COUNT=$(wc -l < "$CANDIDATES_FILE")


# Falls über TCP-SYN kein Kandidat gefunden wurde, werden
# allgemein lokale IPv4-Quelladressen betrachtet.

if [ "$CANDIDATE_COUNT" -eq 0 ]; then

    tshark -r "$PCAP_FILE" \
        -Y 'ip.src' \
        -T fields \
        -e ip.src 2>/dev/null \
        | grep "$LAB_PREFIX_REGEX" \
        | grep -v "^$ROUTER_IP$" \
        | sort -u \
        > "$CANDIDATES_FILE"

    CANDIDATE_COUNT=$(wc -l < "$CANDIDATES_FILE")

fi


# ------------------------------------------------------------
# Genau ein Kandidat:
# IP-Adresse automatisch übernehmen.
# ------------------------------------------------------------

if [ "$CANDIDATE_COUNT" -eq 1 ]; then

    TEST_IP=$(cat "$CANDIDATES_FILE")

    echo "[OK] IPv4-Adresse automatisch bestimmt: $TEST_IP"


# ------------------------------------------------------------
# Mehrere Kandidaten:
# Auswahl durch den Benutzer.
#
# Das ist absichtlich keine automatische Betriebssystem-
# Erkennung. Der Benutzer kennt das verwendete Testsystem und
# kann bei Bedarf dessen aktuelle IP-Adresse prüfen.
# ------------------------------------------------------------

elif [ "$CANDIDATE_COUNT" -gt 1 ]; then

    echo "Mehrere mögliche IPv4-Adressen wurden gefunden:"
    echo

    nl -w2 -s') ' "$CANDIDATES_FILE"

    echo
    read -r -p "Nummer der IPv4-Adresse des Testsystems eingeben: " CHOICE

    TEST_IP=$(sed -n "${CHOICE}p" "$CANDIDATES_FILE")


    # Falls eine ungültige Nummer eingegeben wurde, kann die
    # Adresse noch manuell eingegeben werden.

    if [ -z "$TEST_IP" ]; then
        echo
        echo "Ungültige Auswahl."
        read -r -p "IPv4-Adresse des Testsystems manuell eingeben: " TEST_IP
    fi


# ------------------------------------------------------------
# Kein Kandidat:
# IP-Adresse manuell eingeben.
# ------------------------------------------------------------

else

    echo "IPv4-Adresse konnte nicht automatisch bestimmt werden."
    echo
    read -r -p "IPv4-Adresse des Testsystems eingeben: " TEST_IP

fi


# MAC-Adresse zur ausgewählten IPv4-Adresse aus dem PCAP lesen.

TEST_MAC=$(tshark -r "$PCAP_FILE" \
    -Y "ip.src==$TEST_IP" \
    -T fields \
    -e eth.src 2>/dev/null \
    | sed '/^$/d' \
    | head -n 1)


[ -z "$TEST_MAC" ] && TEST_MAC="unknown"


echo
echo "[OK] IPv4: $TEST_IP"
echo "[OK] MAC:  $TEST_MAC"


# Die temporäre Kandidatenliste wird danach nicht mehr benötigt.

rm -f "$CANDIDATES_FILE"


# ------------------------------------------------------------
# SHA-256 des Roh-PCAPs berechnen
# ------------------------------------------------------------

PCAP_SHA256=$(sha256sum "$PCAP_FILE" | awk '{print $1}')

echo "$PCAP_SHA256  capture.pcap" > "$SHA_FILE"

echo
echo "[OK] SHA-256 des PCAPs erstellt."


# ------------------------------------------------------------
# Gespeicherten SHA-256-Hash überprüfen
#
# sha256.txt enthält den erwarteten Hash und den Dateinamen.
# Die Prüfung wird im Messordner durchgeführt, damit
# "capture.pcap" dort direkt gefunden wird.
# ------------------------------------------------------------

if (cd "$RUN_DIR" && sha256sum -c sha256.txt); then

    HASH_CHECK="ok"
    echo "[OK] SHA-256-Prüfung erfolgreich."

else

    HASH_CHECK="failed"
    echo "[FEHLER] SHA-256-Prüfung fehlgeschlagen."

fi

# ------------------------------------------------------------
# Status des Messlaufs bestimmen
# ------------------------------------------------------------

STATUS="valid"
OBSERVATION="none"

# Eine fehlgeschlagene Integritätsprüfung macht den Lauf
# für die Hauptauswertung ungültig.

if [ "$HASH_CHECK" != "ok" ]; then
    STATUS="invalid"
fi

# Packet Drops sollen bei den offiziellen Messungen nicht
# vorkommen. Wenn Drops vorhanden sind, wird der Lauf als
# ungültig markiert und soll wiederholt werden.

if [ "$PACKETS_DROPPED" = "unknown" ]; then

    STATUS="invalid"

elif [ "$PACKETS_DROPPED" -gt 0 ]; then

    STATUS="invalid"

fi


# Bedien- oder Ablaufprobleme können nicht immer automatisch
# erkannt werden. Deshalb gibt es dafür eine kurze Nachfrage.

echo
read -r -p "Gab es einen Bedien- oder Ablauf-Fehler? [j/N]: " PROCEDURE_ERROR


if [[ "$PROCEDURE_ERROR" = "j" || "$PROCEDURE_ERROR" = "J" ]]; then
    STATUS="invalid"
fi


# ------------------------------------------------------------
# Besondere Beobachtungen
#
# Reales Verhalten wie CAPTCHA, Buffering oder langsames Laden
# macht einen technisch korrekten Lauf nicht automatisch
# ungültig.
# ------------------------------------------------------------

echo
echo "Gab es eine besondere Beobachtung?"
echo
echo "0 = keine"
echo "1 = CAPTCHA / Bot-Prüfung"
echo "2 = Buffering beim Streaming"
echo "3 = ungewöhnlich langsamer Seitenaufruf"
echo "4 = sonstiges"
echo

read -r -p "Auswahl [0]: " OBS_CHOICE


case "$OBS_CHOICE" in

    1)
        OBSERVATION="captcha_or_bot_check"
        ;;

    2)
        OBSERVATION="stream_buffering"
        ;;

    3)
        OBSERVATION="slow_page_load"
        ;;

    4)
        read -r -p "Kurze Beschreibung: " OBSERVATION
        ;;

    *)
        OBSERVATION="none"
        ;;

esac


# Wenn kein eigentlicher Fehler vorliegt, aber eine besondere
# Beobachtung gemacht wurde, wird der Lauf als
# valid_observation gekennzeichnet.

if [ "$STATUS" = "valid" ] && [ "$OBSERVATION" != "none" ]; then
    STATUS="valid_observation"
fi


# ------------------------------------------------------------
# metadata.txt erstellen
# ------------------------------------------------------------

cat > "$METADATA_FILE" <<EOF
run_id=$RUN_ID
system=$SYSTEM
scenario=$SCENARIO
repetition=$REPETITION

capture_start=$CAPTURE_START
capture_end=$CAPTURE_END

monitor_interface=$BRIDGE
test_ipv4=$TEST_IP
test_mac=$TEST_MAC

packets_captured=$PACKETS_CAPTURED
packets_received=$PACKETS_RECEIVED
packets_dropped=$PACKETS_DROPPED

pcap_sha256=$PCAP_SHA256
pcap_hash_check=$HASH_CHECK

preflight=pass
status=$STATUS
observation=$OBSERVATION
EOF


# ------------------------------------------------------------
# Zentralen run_index.tsv anlegen oder ergänzen
# ------------------------------------------------------------

if [ ! -f "$RUN_INDEX" ]; then

    printf "run_id\tsystem\tscenario\trepetition\tcapture_start\tipv4\tmac\tpackets_captured\tpackets_dropped\tstatus\tobservation\n" \
        > "$RUN_INDEX"

fi


printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$RUN_ID" \
    "$SYSTEM" \
    "$SCENARIO" \
    "$REPETITION" \
    "$CAPTURE_START" \
    "$TEST_IP" \
    "$TEST_MAC" \
    "$PACKETS_CAPTURED" \
    "$PACKETS_DROPPED" \
    "$STATUS" \
    "$OBSERVATION" \
    >> "$RUN_INDEX"


# ------------------------------------------------------------
# Abschluss
# ------------------------------------------------------------

echo
echo "=========================================="
echo " Messung abgeschlossen"
echo "=========================================="
echo
echo "Run:          $RUN_ID"
echo "Status:       $STATUS"
echo "IPv4:         $TEST_IP"
echo "MAC:          $TEST_MAC"
echo "Pakete:       $PACKETS_CAPTURED"
echo "Packet Drops: $PACKETS_DROPPED"
echo
echo "PCAP:"
echo "$PCAP_FILE"
echo
echo "Metadaten:"
echo "$METADATA_FILE"
echo
