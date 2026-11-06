#
# Test        : PROC-9002
# Description : Process Integrity Risk Scoring and Reporting
#

Register --test-no PROC-9002 --os Linux --weight L --network NO --category security --description "Process Integrity Risk Scoring and Reporting"

if [ "${SKIPTEST}" -eq 0 ]; then

    PROC_DIR="${ROOTDIR}proc"
    CPU_THRESHOLD=80
    SCORE=0
    REPORT_DIR="/var/log"
    REPORT_FILE="${REPORT_DIR}/lynis-proc9002-$(date '+%Y%m%d_%H%M%S').log"

    # Create timestamped report
    if ! : > "${REPORT_FILE}" 2>/dev/null; then
        REPORT_FILE="/tmp/lynis-proc9002-$(date '+%Y%m%d_%H%M%S').log"
        : > "${REPORT_FILE}" 2>/dev/null
    fi

    # Log information in Lynis and custom report
    PROC9002_LOG() {
        LogText "PROC-9002: $1"

        if [ -n "${REPORT_FILE}" ] && [ -w "${REPORT_FILE}" ]; then
            printf '%s\n' "$1" >> "${REPORT_FILE}"
        fi
    }

    # Calculate weighted risk points
    PROC9002_POINTS() {
        local count="$1"
        local weight="$2"
        local cap="$3"
        local points

        points=$((count * weight))

        if [ "${points}" -gt "${cap}" ]; then
            points="${cap}"
        fi

        echo "${points}"
    }

    # Report header
    PROC9002_LOG "=========================================="
    PROC9002_LOG "LINUX PROCESS INTEGRITY AUDIT - PROC-9002"
    PROC9002_LOG "Host: $(hostname)"
    PROC9002_LOG "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    PROC9002_LOG "CPU threshold: ${CPU_THRESHOLD}%"
    PROC9002_LOG "=========================================="

    # 1. Zombie processes
    ZOMBIES=$(${PSBINARY} -eo stat= | \
        ${AWKBINARY} '$1 ~ /^Z/ {c++} END {print c+0}')

    ZOMBIE_POINTS=$(PROC9002_POINTS "${ZOMBIES}" 5 15)
    SCORE=$((SCORE + ZOMBIE_POINTS))

    if [ "${ZOMBIES}" -eq 0 ]; then
        ZOMBIE_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 zombie process check (PASS)" --result "${STATUS_NOT_FOUND}" --color GREEN
    else
        ZOMBIE_STATUS="WARN"
        Display --indent 2 --text "- PROC-9002 zombie process check (WARN)" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9002 "Investigate zombie processes detected by the process risk audit"
    fi

    PROC9002_LOG "Zombie processes: ${ZOMBIES} | Status: ${ZOMBIE_STATUS} | Points: ${ZOMBIE_POINTS}"

    # 2. Processes adopted by PID 1 (informational only)
    PID1_COUNT=$(${PSBINARY} -eo ppid= | \
        ${AWKBINARY} '$1 == 1 {c++} END {print c+0}')

    PROC9002_LOG "Processes adopted by PID 1: ${PID1_COUNT} (informational; not scored)"

    Display --indent 2 --text "- PROC-9002 PID 1 process count (informational)" --result "${STATUS_DONE}" --color WHITE

    # 3. Temporary and shared-memory executable checks
    TMP_COUNT=0
    SHM_COUNT=0
    DELETED_COUNT=0

    for exe in "${PROC_DIR}"/[0-9]*/exe; do
        [ -L "$exe" ] || continue

        pid=${exe#"${PROC_DIR}"/}
        pid=${pid%/exe}

        target=$(readlink "$exe" 2>/dev/null) || continue

        case "$target" in
            /tmp/*|/var/tmp/*)
                TMP_COUNT=$((TMP_COUNT + 1))
                PROC9002_LOG "Temporary executable: PID=${pid} PATH=${target}"
                ;;
            /dev/shm/*)
                SHM_COUNT=$((SHM_COUNT + 1))
                PROC9002_LOG "Shared-memory executable: PID=${pid} PATH=${target}"
                ;;
        esac

        case "$target" in
            *" (deleted)")
                DELETED_COUNT=$((DELETED_COUNT + 1))
                PROC9002_LOG "Deleted executable: PID=${pid} PATH=${target}"
                ;;
        esac
    done

    # Score /tmp and /var/tmp findings
    TMP_POINTS=$(PROC9002_POINTS "${TMP_COUNT}" 20 40)
    SCORE=$((SCORE + TMP_POINTS))

    if [ "${TMP_COUNT}" -eq 0 ]; then
        TMP_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 /tmp and /var/tmp executable check (PASS)" --result "${STATUS_NOT_FOUND}" --color GREEN
    else
        TMP_STATUS="FAIL"
        Display --indent 2 --text "- PROC-9002 /tmp and /var/tmp executable check (FAIL)" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9002 "Investigate executables running from /tmp or /var/tmp"
    fi

    PROC9002_LOG "/tmp and /var/tmp executables: ${TMP_COUNT} | Status: ${TMP_STATUS} | Points: ${TMP_POINTS}"

    # Score /dev/shm findings
    SHM_POINTS=$(PROC9002_POINTS "${SHM_COUNT}" 30 40)
    SCORE=$((SCORE + SHM_POINTS))

    if [ "${SHM_COUNT}" -eq 0 ]; then
        SHM_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 /dev/shm executable check (PASS)" --result "${STATUS_NOT_FOUND}" --color GREEN
    else
        SHM_STATUS="FAIL"
        Display --indent 2 --text "- PROC-9002 /dev/shm executable check (FAIL)" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9002 "Investigate executables running from /dev/shm"
    fi

    PROC9002_LOG "/dev/shm executables: ${SHM_COUNT} | Status: ${SHM_STATUS} | Points: ${SHM_POINTS}"

    # 4. Deleted executable references
    DELETED_POINTS=$(PROC9002_POINTS "${DELETED_COUNT}" 25 40)
    SCORE=$((SCORE + DELETED_POINTS))

    if [ "${DELETED_COUNT}" -eq 0 ]; then
        DELETED_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 deleted executable check (PASS)" --result "${STATUS_NOT_FOUND}" --color GREEN
    else
        DELETED_STATUS="FAIL"
        Display --indent 2 --text "- PROC-9002 deleted executable check (FAIL)" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9002 "Investigate running processes with deleted executable references"
    fi

    PROC9002_LOG "Deleted executable references: ${DELETED_COUNT} | Status: ${DELETED_STATUS} | Points: ${DELETED_POINTS}"

    # 5. High CPU usage
    CPU_COUNT=$(${PSBINARY} -eo pcpu= | \
        ${AWKBINARY} -v t="${CPU_THRESHOLD}" '$1 >= t {c++} END {print c+0}')

    CPU_POINTS=$(PROC9002_POINTS "${CPU_COUNT}" 10 20)
    SCORE=$((SCORE + CPU_POINTS))

    if [ "${CPU_COUNT}" -eq 0 ]; then
        CPU_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 high CPU usage check (PASS)" --result "${STATUS_OK}" --color GREEN
    else
        CPU_STATUS="WARN"
        Display --indent 2 --text "- PROC-9002 high CPU usage check (WARN)" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9002 "Investigate processes using at least 80 percent CPU"
    fi

    PROC9002_LOG "Processes at or above ${CPU_THRESHOLD}% CPU: ${CPU_COUNT} | Status: ${CPU_STATUS} | Points: ${CPU_POINTS}"

    # 6. Overall score and risk classification
    if [ "${SCORE}" -gt 100 ]; then
        SCORE=100
    fi

    if [ "${SCORE}" -eq 0 ]; then
        RATING="LOW"
        OVERALL_STATUS="PASS"
        Display --indent 2 --text "- PROC-9002 overall risk rating: LOW (PASS)" --result "${STATUS_OK}" --color GREEN
    elif [ "${SCORE}" -lt 40 ]; then
        RATING="MEDIUM"
        OVERALL_STATUS="WARN"
        Display --indent 2 --text "- PROC-9002 overall risk rating: MEDIUM (WARN)" --result "${STATUS_WARNING}" --color YELLOW
    else
        RATING="HIGH"
        OVERALL_STATUS="FAIL"
        Display --indent 2 --text "- PROC-9002 overall risk rating: HIGH (FAIL)" --result "${STATUS_WARNING}" --color RED
        ReportSuggestion PROC-9002 "Review the PROC-9002 process integrity risk report and investigate high-risk findings"
    fi

    # 7. Final summary
    PROC9002_LOG "=========================================="
    PROC9002_LOG "AUDIT SUMMARY"
    PROC9002_LOG "Risk score: ${SCORE}/100"
    PROC9002_LOG "Risk rating: ${RATING}"
    PROC9002_LOG "Overall status: ${OVERALL_STATUS}"
    PROC9002_LOG "Report file: ${REPORT_FILE}"
    PROC9002_LOG "=========================================="

    Display --indent 2 --text "- PROC-9002 risk score: ${SCORE}/100 (${RATING})" --result "${OVERALL_STATUS}" --color GREEN

fi