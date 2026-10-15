#!/bin/bash

# ------------------------------------------------------------
# Zusammenführung der Analyseergebnisse der Bachelorarbeit
#
# Standardaufruf:
#   ./collect_results.sh
#
# Dann werden die offiziellen Messungen aus
#   ~/ba-experiment/measurements
# gelesen und die Ergebnisse unter
#   ~/ba-experiment/results
# gespeichert.
#
# Für einen Test kann auch ein anderer Quell- und Zielordner
# angegeben werden:
#
#   ./collect_results.sh QUELLORDNER ZIELORDNER
#
# Beispiel für die Pretests:
#
#   ./collect_results.sh \
#     ~/ba-experiment/pretests/capture_script_test \
#     ~/ba-experiment/pretests/collected_results
#
#
# Erzeugte Dateien:
#
#   results_by_run.tsv
#       Eine Zeile pro Messlauf.
#
#   results_long.tsv
#       Eine Zeile pro tatsächlich vorkommendem
#       Fingerprint bzw. Merkmalsmuster.
#
# Dieses Skript führt KEINE neue PCAP-Analyse durch.
# Es sammelt ausschließlich bereits erzeugte Ergebnisse.
# ------------------------------------------------------------


# ------------------------------------------------------------
# Verzeichnisse
# ------------------------------------------------------------

BASE_DIR="$HOME/ba-experiment"

SOURCE_DIR="${1:-$BASE_DIR/measurements}"
RESULTS_DIR="${2:-$BASE_DIR/results}"

RESULTS_BY_RUN="$RESULTS_DIR/results_by_run.tsv"
RESULTS_LONG="$RESULTS_DIR/results_long.tsv"


echo
echo "=========================================="
echo " Ergebnisse zusammenführen"
echo "=========================================="
echo
echo "Quelle:"
echo "$SOURCE_DIR"
echo
echo "Ziel:"
echo "$RESULTS_DIR"
echo


# ------------------------------------------------------------
# Quellordner prüfen
# ------------------------------------------------------------

if [ ! -d "$SOURCE_DIR" ]; then
    echo "[FEHLER] Quellordner wurde nicht gefunden:"
    echo "$SOURCE_DIR"
    exit 1
fi


# ------------------------------------------------------------
# Ergebnisordner anlegen
# ------------------------------------------------------------

mkdir -p "$RESULTS_DIR"


# ------------------------------------------------------------
# Hilfsfunktion zum Lesen von key=value-Dateien
#
# Sie wird sowohl für metadata.txt als auch für
# analysis_info.txt verwendet.
# ------------------------------------------------------------

get_value() {

    KEY="$1"
    FILE="$2"

    if [ ! -f "$FILE" ]; then
        return
    fi

    awk -v key="$KEY" '
        index($0, key "=") == 1 {
            sub("^[^=]*=", "")
            print
            exit
        }
    ' "$FILE"
}


# ------------------------------------------------------------
# Hilfsfunktion:
# Eine bestimmte Spalte einer TSV-Datei zusammenführen.
#
# Falls innerhalb eines Runs mehrere verschiedene Fingerprints
# vorhanden sind, werden sie mit " ; " getrennt.
#
# Dadurch geht in results_by_run.tsv keine Abweichung verloren.
# Die vollständig strukturierte Darstellung steht zusätzlich
# in results_long.tsv.
# ------------------------------------------------------------

join_column() {

    FILE="$1"
    COLUMN="$2"

    if [ ! -f "$FILE" ]; then
        return
    fi

    awk -F'\t' -v col="$COLUMN" '
        NR > 1 && $col != "" {

            if (result != "") {
                result = result " ; "
            }

            result = result $col
        }

        END {
            print result
        }
    ' "$FILE"
}


# ------------------------------------------------------------
# Kopfzeile: eine Zeile pro Run
# ------------------------------------------------------------

printf '%s\n' \
"run_id	system	scenario	repetition	run_status	observation	analysis_present	ndpi_status	p0f_status	zeek_status	ja4t_status	tshark_status	ndpi_fingerprint	ndpi_classification	ndpi_count	p0f_os	p0f_params	p0f_raw_sig	p0f_count	ja4t	ja4t_count	ttl	window	mss	wscale	options_pattern	syn_count" \
> "$RESULTS_BY_RUN"


# ------------------------------------------------------------
# Kopfzeile: vollständige Long-Darstellung
#
# Je nach Werkzeug sind nur die jeweils relevanten Spalten
# befüllt.
# ------------------------------------------------------------

printf '%s\n' \
"run_id	system	scenario	repetition	run_status	tool	count	fingerprint	classification	params	raw_sig	ttl	window	mss	wscale	options_pattern" \
> "$RESULTS_LONG"


# ------------------------------------------------------------
# Zähler
# ------------------------------------------------------------

RUN_COUNT=0
ANALYZED_COUNT=0


# ============================================================
# Alle Messläufe suchen
# ============================================================

while IFS= read -r -d '' METADATA_FILE; do

    RUN_DIR=$(dirname "$METADATA_FILE")
    ANALYSIS_DIR="$RUN_DIR/analysis"
    ANALYSIS_INFO="$ANALYSIS_DIR/analysis_info.txt"

    NDPI_FILE="$ANALYSIS_DIR/ndpi/os_fingerprints.tsv"
    P0F_FILE="$ANALYSIS_DIR/p0f/os_fingerprints.tsv"
    JA4T_FILE="$ANALYSIS_DIR/zeek/ja4t_summary.tsv"
    TSHARK_FILE="$ANALYSIS_DIR/tshark/syn_summary.tsv"


    # --------------------------------------------------------
    # Grundinformationen des Runs
    # --------------------------------------------------------

    RUN_ID=$(get_value "run_id" "$METADATA_FILE")
    SYSTEM=$(get_value "system" "$METADATA_FILE")
    SCENARIO=$(get_value "scenario" "$METADATA_FILE")
    REPETITION=$(get_value "repetition" "$METADATA_FILE")
    RUN_STATUS=$(get_value "status" "$METADATA_FILE")
    OBSERVATION=$(get_value "observation" "$METADATA_FILE")


    # Falls in einer älteren Testdatei keine run_id gespeichert
    # wurde, wird sie aus den bekannten Feldern erzeugt.

    if [ -z "$RUN_ID" ]; then
        RUN_ID="${SYSTEM}_${SCENARIO}_${REPETITION}"
    fi


    # Tabs würden die TSV-Struktur beschädigen.
    # Deshalb werden sie in der freien Beobachtung durch
    # Leerzeichen ersetzt.

    OBSERVATION=$(printf "%s" "$OBSERVATION" | tr '\t\r\n' '   ')


    # --------------------------------------------------------
    # Prüfen, ob dieser Run bereits analysiert wurde
    # --------------------------------------------------------

    if [ -f "$ANALYSIS_INFO" ]; then

        ANALYSIS_PRESENT="yes"
        ANALYZED_COUNT=$((ANALYZED_COUNT + 1))

        NDPI_STATUS=$(get_value "ndpi_status" "$ANALYSIS_INFO")
        P0F_STATUS=$(get_value "p0f_status" "$ANALYSIS_INFO")
        ZEEK_STATUS=$(get_value "zeek_status" "$ANALYSIS_INFO")
        JA4T_STATUS=$(get_value "ja4t_status" "$ANALYSIS_INFO")
        TSHARK_STATUS=$(get_value "tshark_status" "$ANALYSIS_INFO")

    else

        ANALYSIS_PRESENT="no"

        NDPI_STATUS=""
        P0F_STATUS=""
        ZEEK_STATUS=""
        JA4T_STATUS=""
        TSHARK_STATUS=""

    fi


    # ========================================================
    # Kompakte Werte für results_by_run.tsv
    # ========================================================

    NDPI_FP=$(join_column "$NDPI_FILE" 2)
    NDPI_CLASS=$(join_column "$NDPI_FILE" 3)
    NDPI_COUNT=$(join_column "$NDPI_FILE" 1)

    P0F_OS=$(join_column "$P0F_FILE" 2)
    P0F_PARAMS=$(join_column "$P0F_FILE" 3)
    P0F_RAW=$(join_column "$P0F_FILE" 4)
    P0F_COUNT=$(join_column "$P0F_FILE" 1)

    JA4T=$(join_column "$JA4T_FILE" 2)
    JA4T_COUNT=$(join_column "$JA4T_FILE" 1)

    TTL=$(join_column "$TSHARK_FILE" 2)
    WINDOW=$(join_column "$TSHARK_FILE" 3)
    MSS=$(join_column "$TSHARK_FILE" 4)
    WSCALE=$(join_column "$TSHARK_FILE" 5)
    OPTIONS=$(join_column "$TSHARK_FILE" 6)
    SYN_COUNT=$(join_column "$TSHARK_FILE" 1)


    # --------------------------------------------------------
    # Eine Zeile für diesen Run schreiben
    # --------------------------------------------------------

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$RUN_ID" \
        "$SYSTEM" \
        "$SCENARIO" \
        "$REPETITION" \
        "$RUN_STATUS" \
        "$OBSERVATION" \
        "$ANALYSIS_PRESENT" \
        "$NDPI_STATUS" \
        "$P0F_STATUS" \
        "$ZEEK_STATUS" \
        "$JA4T_STATUS" \
        "$TSHARK_STATUS" \
        "$NDPI_FP" \
        "$NDPI_CLASS" \
        "$NDPI_COUNT" \
        "$P0F_OS" \
        "$P0F_PARAMS" \
        "$P0F_RAW" \
        "$P0F_COUNT" \
        "$JA4T" \
        "$JA4T_COUNT" \
        "$TTL" \
        "$WINDOW" \
        "$MSS" \
        "$WSCALE" \
        "$OPTIONS" \
        "$SYN_COUNT" \
        >> "$RESULTS_BY_RUN"


    # ========================================================
    # results_long.tsv
    # ========================================================


    # --------------------------------------------------------
    # nDPI
    # --------------------------------------------------------

    if [ -f "$NDPI_FILE" ]; then

        tail -n +2 "$NDPI_FILE" |
        while IFS=$'\t' read -r COUNT FP CLASSIFICATION; do

            [ -z "$COUNT" ] && continue

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$RUN_ID" \
                "$SYSTEM" \
                "$SCENARIO" \
                "$REPETITION" \
                "$RUN_STATUS" \
                "ndpi" \
                "$COUNT" \
                "$FP" \
                "$CLASSIFICATION" \
                "" \
                "" \
                "" \
                "" \
                "" \
                "" \
                "" \
                >> "$RESULTS_LONG"

        done

    fi


    # --------------------------------------------------------
    # p0f
    # --------------------------------------------------------

    if [ -f "$P0F_FILE" ]; then

        tail -n +2 "$P0F_FILE" |
        while IFS=$'\t' read -r COUNT OS PARAMS RAW_SIG; do

            [ -z "$COUNT" ] && continue

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$RUN_ID" \
                "$SYSTEM" \
                "$SCENARIO" \
                "$REPETITION" \
                "$RUN_STATUS" \
                "p0f" \
                "$COUNT" \
                "" \
                "$OS" \
                "$PARAMS" \
                "$RAW_SIG" \
                "" \
                "" \
                "" \
                "" \
                "" \
                >> "$RESULTS_LONG"

        done

    fi


    # --------------------------------------------------------
    # JA4T
    # --------------------------------------------------------

    if [ -f "$JA4T_FILE" ]; then

        tail -n +2 "$JA4T_FILE" |
        while IFS=$'\t' read -r COUNT FP; do

            [ -z "$COUNT" ] && continue

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$RUN_ID" \
                "$SYSTEM" \
                "$SCENARIO" \
                "$REPETITION" \
                "$RUN_STATUS" \
                "ja4t" \
                "$COUNT" \
                "$FP" \
                "" \
                "" \
                "" \
                "" \
                "" \
                "" \
                "" \
                "" \
                >> "$RESULTS_LONG"

        done

    fi


    # --------------------------------------------------------
    # TShark
    # --------------------------------------------------------

    if [ -f "$TSHARK_FILE" ]; then

        tail -n +2 "$TSHARK_FILE" |
        while IFS=$'\t' read -r COUNT TTL_VALUE WINDOW_VALUE MSS_VALUE WSCALE_VALUE OPTIONS_VALUE; do

            [ -z "$COUNT" ] && continue

            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$RUN_ID" \
                "$SYSTEM" \
                "$SCENARIO" \
                "$REPETITION" \
                "$RUN_STATUS" \
                "tshark" \
                "$COUNT" \
                "" \
                "" \
                "" \
                "" \
                "$TTL_VALUE" \
                "$WINDOW_VALUE" \
                "$MSS_VALUE" \
                "$WSCALE_VALUE" \
                "$OPTIONS_VALUE" \
                >> "$RESULTS_LONG"

        done

    fi


    RUN_COUNT=$((RUN_COUNT + 1))

done < <(
    find "$SOURCE_DIR" \
        -type f \
        -name metadata.txt \
        -print0 \
        | sort -z
)


# ============================================================
# Abschluss
# ============================================================

echo
echo "=========================================="
echo " Zusammenführung abgeschlossen"
echo "=========================================="
echo
echo "Gefundene Runs:     $RUN_COUNT"
echo "Analysierte Runs:   $ANALYZED_COUNT"
echo
echo "Run-Übersicht:"
echo "$RESULTS_BY_RUN"
echo
echo "Vollständige Long-Darstellung:"
echo "$RESULTS_LONG"
echo
