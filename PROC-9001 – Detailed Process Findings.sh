#
# Test        : PROC-9001
# Description : Detailed Linux Process Integrity Audit
#

Register --test-no PROC-9001 --os Linux --weight L --network NO --category security --description "Detailed Linux Process Integrity Audit"

if [ "${SKIPTEST}" -eq 0 ]; then

    PROC_DIR="${ROOTDIR}proc"

    # 1. Check zombie processes
    ZOMBIES=$(${PSBINARY} -eo pid=,ppid=,stat=,user=,comm= | \
        ${AWKBINARY} '$3 ~ /^Z/ {print "PID="$1" PPID="$2" USER="$4" CMD="$5}')

    ZOMBIE_COUNT=$(printf '%s\n' "${ZOMBIES}" | \
        ${AWKBINARY} 'NF {c++} END {print c+0}')

    LogText "PROC-9001: Zombie processes found: ${ZOMBIE_COUNT}"

    if [ "${ZOMBIE_COUNT}" -gt 0 ]; then
        LogText "PROC-9001: Zombie process details: ${ZOMBIES}"
        Display --indent 2 --text "- Checking zombie processes with details" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9001 "Investigate the zombie processes recorded in the Lynis log"
    else
        Display --indent 2 --text "- Checking zombie processes with details" --result "${STATUS_NOT_FOUND}" --color GREEN
    fi

    # 2. Check processes adopted by PID 1
    PID1_DETAILS=$(${PSBINARY} -eo pid=,ppid=,user=,comm= | \
        ${AWKBINARY} '$2 == 1 {print "PID="$1" USER="$3" CMD="$4}')

    PID1_COUNT=$(printf '%s\n' "${PID1_DETAILS}" | \
        ${AWKBINARY} 'NF {c++} END {print c+0}')

    LogText "PROC-9001: Processes adopted by PID 1: ${PID1_COUNT}"
    LogText "PROC-9001: PID 1 process details: ${PID1_DETAILS}"

    Display --indent 2 --text "- Counting processes adopted by PID 1 (informational)" --result "${STATUS_DONE}" --color WHITE

    # 3. Check executables running from temporary directories
    TMP_COUNT=0

    for exe in "${PROC_DIR}"/[0-9]*/exe; do
        [ -L "$exe" ] || continue

        pid=${exe#"${PROC_DIR}"/}
        pid=${pid%/exe}

        target=$(readlink "$exe" 2>/dev/null) || continue

        case "$target" in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                DETAILS=$(${PSBINARY} -p "$pid" -o ppid=,user=,comm= 2>/dev/null)

                LogText "PROC-9001: Temporary executable: PID=${pid} DETAILS=${DETAILS} PATH=${target}"

                TMP_COUNT=$((TMP_COUNT + 1))
                ;;
        esac
    done

    LogText "PROC-9001: Temporary directory executable count: ${TMP_COUNT}"

    if [ "${TMP_COUNT}" -gt 0 ]; then
        Display --indent 2 --text "- Checking temporary directory executables with details" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9001 "Investigate executable processes running from temporary directories"
    else
        Display --indent 2 --text "- Checking temporary directory executables with details" --result "${STATUS_NOT_FOUND}" --color GREEN
    fi

    # 4. Check deleted executable processes
    DELETED_COUNT=0

    for exe in "${PROC_DIR}"/[0-9]*/exe; do
        [ -L "$exe" ] || continue

        pid=${exe#"${PROC_DIR}"/}
        pid=${pid%/exe}

        target=$(readlink "$exe" 2>/dev/null) || continue

        case "$target" in
            *" (deleted)")
                DETAILS=$(${PSBINARY} -p "$pid" -o ppid=,user=,comm= 2>/dev/null)

                LogText "PROC-9001: Deleted executable: PID=${pid} DETAILS=${DETAILS} PATH=${target}"

                DELETED_COUNT=$((DELETED_COUNT + 1))
                ;;
        esac
    done

    LogText "PROC-9001: Deleted executable count: ${DELETED_COUNT}"

    if [ "${DELETED_COUNT}" -gt 0 ]; then
        Display --indent 2 --text "- Checking deleted executable processes with details" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9001 "Investigate processes using deleted executable files"
    else
        Display --indent 2 --text "- Checking deleted executable processes with details" --result "${STATUS_NOT_FOUND}" --color GREEN
    fi

    # 5. Check high CPU usage
    CPU_DETAILS=$(${PSBINARY} -eo pid=,pcpu=,comm= | \
        ${AWKBINARY} '$2 >= 80 {print "PID="$1" CPU="$2"% CMD="$3}')

    CPU_COUNT=$(printf '%s\n' "${CPU_DETAILS}" | \
        ${AWKBINARY} 'NF {c++} END {print c+0}')

    LogText "PROC-9001: High CPU process count: ${CPU_COUNT}"
    LogText "PROC-9001: High CPU process details: ${CPU_DETAILS}"

    if [ "${CPU_COUNT}" -gt 0 ]; then
        Display --indent 2 --text "- Checking high CPU processes with details" --result "${STATUS_WARNING}" --color YELLOW
        ReportSuggestion PROC-9001 "Investigate processes using at least 80 percent CPU"
    else
        Display --indent 2 --text "- Checking high CPU processes with details" --result "${STATUS_OK}" --color GREEN
    fi

fi