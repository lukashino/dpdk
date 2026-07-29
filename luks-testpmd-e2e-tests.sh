#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# luks-testpmd-e2e-tests.sh - End-to-end flow parser test suite for testpmd
#
# Runs flow rule command files against testpmd and checks for parser errors.
# Supports local build/, global system install, or side-by-side comparison.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Defaults ---
PCI_ADDR="0000:c4:00.0"
PCI_SLOT="3b:00"
NET_DEV="ens3f0np0"
VF_BDF_0="0000:c4:00.2"
VF_BDF_1="0000:c4:00.3"
REPR="[0-1]"
RXQ=4
TXQ=4
EXTRA_EAL=""
EXTRA_PMD=""
TESTPMD_BUILD="${SCRIPT_DIR}/build/app/dpdk-testpmd"
TESTPMD_GLOBAL="$(command -v dpdk-testpmd 2>/dev/null)"
TESTPMD=""  # resolved later
COLOR=auto  # auto, always, never
TEST_DIR="${SCRIPT_DIR}"

# --- Colors ---
_setup_colors() {
    if [[ "$COLOR" == "never" ]] || { [[ "$COLOR" == "auto" ]] && ! [[ -t 1 ]]; }; then
        RED="" GRN="" YEL="" BLD="" RST=""
    else
        RED=$'\033[1;31m' GRN=$'\033[1;32m' YEL=$'\033[1;33m'
        BLD=$'\033[1m'    RST=$'\033[0m'
    fi
}

# --- Helpers ---
die()  { echo "${RED}ERROR:${RST} $*" >&2; exit 1; }
info() { echo "${BLD}==${RST} $*"; }
pass() { echo "  ${GRN}PASS${RST}  $1"; }
fail() { echo "  ${RED}FAIL${RST}  $1"; }
skip() { echo "  ${YEL}SKIP${RST}  $1"; }

usage() {
    cat <<'EOF'
Usage: luks-testpmd-e2e-tests.sh [OPTIONS] [TEST...]

Run flow parser end-to-end tests against testpmd.

Options:
  -b, --build             Use build/ testpmd only (default)
  -g, --global            Use globally installed dpdk-testpmd only
  -c, --compare           Run both and compare results side-by-side
  -B, --binary PATH       Use a specific testpmd binary
  -p, --prep              Run device preparation (SR-IOV, switchdev) and exit
  --check-prep            Check if device is ready (exit 0 if yes)
  -l, --list              List available test files
  -v, --verbose           Show full testpmd output for each test
  -q, --quiet             Only show failures and summary
  --pci ADDR              PCI address (default: 0000:3b:00.0)
  --rxq N                 Number of RX queues (default: 4)
  --txq N                 Number of TX queues (default: 4)
  --color MODE            auto, always, never (default: auto)
  -h, --help              Show this help

Test selection:
  With no TEST arguments, all cmds-claude-*.txt and cmds*.txt files are run.
  Specify one or more test names (with or without cmds-claude- prefix and .txt
  suffix) to run specific tests:

    ./luks-testpmd-e2e-tests.sh rss-queues jump-groups
    ./luks-testpmd-e2e-tests.sh cmds-claude-vxlan-encap-decap.txt
    ./luks-testpmd-e2e-tests.sh cmds.txt cmds-configs.txt

Examples:
  # Check device readiness and prepare if needed
  sudo ./luks-testpmd-e2e-tests.sh --prep

  # Run all tests against build/ testpmd
  sudo ./luks-testpmd-e2e-tests.sh

  # Run specific tests against global testpmd
  sudo ./luks-testpmd-e2e-tests.sh -g rss-queues vxlan-encap-decap

  # Compare build/ vs global testpmd on all tests
  sudo ./luks-testpmd-e2e-tests.sh --compare

  # Quick iteration: test new cmd file with global testpmd
  sudo ./luks-testpmd-e2e-tests.sh -g cmds-new-feature.txt
EOF
    exit 0
}

# --- Device preparation ---
check_prep() {
    local ok=0

    # Check SR-IOV VFs
    local numvfs
    numvfs=$(cat "/sys/class/net/${NET_DEV}/device/sriov_numvfs" 2>/dev/null)
    if [[ "$numvfs" -lt 2 ]]; then
        echo "  sriov_numvfs = ${numvfs:-0} (need >= 2)"
        ok=1
    fi

    # Check switchdev mode
    local eswitch
    eswitch=$(devlink dev eswitch show "pci/${PCI_ADDR}" 2>/dev/null)
    if ! echo "$eswitch" | grep -q "mode switchdev"; then
        echo "  eswitch mode is not switchdev"
        ok=1
    fi

    # Check VF BDFs are bound
    if [[ ! -d "/sys/bus/pci/devices/${VF_BDF_0}/net" ]]; then
        echo "  ${VF_BDF_0} not bound"
        ok=1
    fi
    if [[ ! -d "/sys/bus/pci/devices/${VF_BDF_1}/net" ]]; then
        echo "  ${VF_BDF_1} not bound"
        ok=1
    fi

    # Check PF net device exists
    if [[ ! -d "/sys/class/net/${NET_DEV}" ]]; then
        echo "  ${NET_DEV} not found"
        ok=1
    fi

    return $ok
}

do_prep() {
    [[ $(id -u) -eq 0 ]] || die "Device preparation requires root (use sudo)"

    info "Checking if preparation is needed..."
    if check_prep >/dev/null 2>&1; then
        info "Device already prepared"
        devlink dev eswitch show "pci/${PCI_ADDR}"
        ip link show | grep -E "${NET_DEV}|_rep"
        return 0
    fi

    info "Creating 2 SR-IOV VFs on ${NET_DEV}..."
    echo 2 > "/sys/class/net/${NET_DEV}/device/sriov_numvfs" \
        || die "Failed to create VFs"

    info "Unbinding VFs for switchdev transition..."
    echo "${VF_BDF_0}" > /sys/bus/pci/drivers/mlx5_core/unbind 2>/dev/null
    echo "${VF_BDF_1}" > /sys/bus/pci/drivers/mlx5_core/unbind 2>/dev/null

    info "Setting eswitch to switchdev mode..."
    devlink dev eswitch set "pci/${PCI_ADDR}" mode switchdev \
        || die "Failed to set switchdev mode"

    info "Rebinding VFs..."
    echo "${VF_BDF_0}" > /sys/bus/pci/drivers/mlx5_core/bind \
        || die "Failed to bind ${VF_BDF_0}"
    echo "${VF_BDF_1}" > /sys/bus/pci/drivers/mlx5_core/bind \
        || die "Failed to bind ${VF_BDF_1}"

    # Brief settle time for udev
    sleep 1

    info "Device preparation complete:"
    devlink dev eswitch show "pci/${PCI_ADDR}"
    ip link show | grep -E "${NET_DEV}|_rep"
}

# --- Test runner ---
resolve_test_file() {
    local name="$1"

    # Exact path
    [[ -f "$name" ]] && { echo "$name"; return 0; }

    # In test dir, exact
    [[ -f "${TEST_DIR}/${name}" ]] && { echo "${TEST_DIR}/${name}"; return 0; }

    # With .txt suffix
    [[ -f "${TEST_DIR}/${name}.txt" ]] && { echo "${TEST_DIR}/${name}.txt"; return 0; }

    # With cmds-claude- prefix
    [[ -f "${TEST_DIR}/cmds-claude-${name}.txt" ]] && {
        echo "${TEST_DIR}/cmds-claude-${name}.txt"; return 0
    }

    # With cmds- prefix
    [[ -f "${TEST_DIR}/cmds-${name}.txt" ]] && {
        echo "${TEST_DIR}/cmds-${name}.txt"; return 0
    }

    return 1
}

# Return short display name from a test file path
test_name() {
    basename "$1" .txt
}

kill_testpmd() {
    if pkill -9 -f dpdk-testpmd 2>/dev/null; then
        # Wait for hugepage/lock cleanup only if we killed something
        sleep 1
    fi
}

# Extract DPDK version from a testpmd binary without hanging.
# EAL --version prints the version but does NOT exit, so we must use
# --no-pci to skip slow PCI scanning, /dev/null for immediate EOF on
# stdin, and timeout as a safety net.  Older DPDK (< 24.x) lacks
# --version, so fall back to the RPM package version.
get_testpmd_version() {
    local binary="$1" ver
    ver=$(timeout 5 "$binary" --no-pci --version 2>&1 < /dev/null \
        | grep -oP "DPDK [0-9][0-9.]*" | head -1)
    if [[ -z "$ver" ]]; then
        ver=$(rpm -qf "$binary" 2>/dev/null \
            | grep -oP "dpdk-\K[0-9][0-9.]*" | head -1)
        [[ -n "$ver" ]] && ver="DPDK ${ver}"
    fi
    echo "$ver"
}

# Parse per-test overrides from a "# TESTPMD: key=val ..." header comment.
# Supported keys: pci_opts  (extra PCI devargs, e.g. dv_flow_en=2)
#                 no_repr   (omit representor config)
#                 rxq, txq  (override queue counts)
parse_test_opts() {
    local cmdfile="$1"
    _topt_pci_opts=""
    _topt_no_repr=0
    _topt_rxq=${RXQ}
    _topt_txq=${TXQ}

    local header
    header=$(head -1 "$cmdfile")
    if [[ "$header" != "# TESTPMD:"* ]]; then
        return
    fi
    local opts="${header#\# TESTPMD:}"
    local tok
    for tok in $opts; do
        case "$tok" in
            pci_opts=*) _topt_pci_opts="${tok#pci_opts=}" ;;
            no_repr)    _topt_no_repr=1 ;;
            rxq=*)      _topt_rxq="${tok#rxq=}" ;;
            txq=*)      _topt_txq="${tok#txq=}" ;;
        esac
    done
}

# Run a single test file. Sets globals: _test_ok, _test_creates, _test_errors
run_one() {
    local binary="$1" cmdfile="$2"
    local name
    name=$(test_name "$cmdfile")

    _test_ok=1
    _test_creates=0
    _test_errors=""

    if [[ ! -x "$binary" ]]; then
        _test_ok=0
        _test_errors="binary not found: ${binary}"
        return
    fi

    kill_testpmd

    # Read per-test overrides
    parse_test_opts "$cmdfile"

    local pci_dev="${PCI_ADDR}"
    [[ -n "$_topt_pci_opts" ]] && pci_dev="${pci_dev},${_topt_pci_opts}"
    [[ $_topt_no_repr -eq 0 ]] && pci_dev="${pci_dev},representor=${REPR}"

    local output
    # Feed /dev/null to stdin so testpmd exits after processing the
    # cmdline file instead of blocking on "Press enter to exit".
    output=$("$binary" \
        -a "${pci_dev}" \
        -l 0,1 ${EXTRA_EAL} \
        -- --rxq=${_topt_rxq} --txq=${_topt_txq} ${EXTRA_PMD} \
        --cmdline-file "$cmdfile" 2>&1 < /dev/null)
    local rc=$?

    # Check for hard crash first
    if echo "$output" | grep -qE 'Segmentation fault|SIGBUS|PANIC'; then
        _test_ok=0
        _test_errors="CRASH detected"
        return
    fi

    # Check for device probe failures — no point checking flow results
    if echo "$output" | grep -qE 'No probed ethernet devices|Bus.*probe failed'; then
        _test_ok=0
        _test_errors="device probe failed (check verbs/mlx5_ib)"
        return
    fi

    # Capture parser errors (command syntax failures) — these fail the test
    _test_errors=$(echo "$output" | grep -E \
        'unhandled flow parser|unknown parser token|Bad arguments' || true)

    # Count successful flow operations (anchored to testpmd flow output)
    _test_creates=$(echo "$output" | grep -cE \
        'Flow rule #|validated|Flow [0-9]+ destroyed|Flow dump finished|COUNT|dequeued|Pattern template #[0-9]+ created|Actions template #[0-9]+ created|Template table #[0-9]+ created|Configure flows on port' || true)

    # Count PMD warnings (HW rejected the rule — parsed OK but unsupported)
    _test_pmd_warns=$(echo "$output" | grep -cE \
        'port_flow_complain|Caught PMD error' || true)

    if [[ -n "$_test_errors" ]]; then
        _test_ok=0
    fi

    if [[ "$VERBOSE" -eq 1 ]]; then
        echo "$output" | grep -E '\[.*\.txt\]' | head -40
        echo ""
    fi
}

list_tests() {
    info "Available test files in ${TEST_DIR}:"
    local f name
    for f in "${TEST_DIR}"/cmds-claude-*.txt "${TEST_DIR}"/cmds.txt "${TEST_DIR}"/cmds-configs.txt; do
        [[ -f "$f" ]] || continue
        name=$(test_name "$f")
        # Count flow operations in the file
        local ops
        ops=$(grep -cE '^flow (create|validate|destroy|flush|dump|list|query)' "$f")
        printf "  %-40s (%d flow ops)\n" "$name" "$ops"
    done
}

run_suite() {
    local binary="$1" label="$2"
    shift 2
    local files=("$@")
    local n_pass=0 n_fail=0 n_skip=0 n_total=${#files[@]}

    info "Running ${n_total} tests with ${label}"
    echo ""

    local f name
    for f in "${files[@]}"; do
        name=$(test_name "$f")

        run_one "$binary" "$f"

        if [[ $_test_ok -eq 1 ]]; then
            n_pass=$((n_pass + 1))
            if [[ "$QUIET" -ne 1 ]]; then
                local _info="${_test_creates} ops"
                [[ $_test_pmd_warns -gt 0 ]] && _info="${_info}, ${_test_pmd_warns} HW unsupported"
                pass "${name}  (${_info})"
            fi
        else
            n_fail=$((n_fail + 1))
            fail "${name}"
            if [[ -n "$_test_errors" ]]; then
                echo "$_test_errors" | head -5 | sed 's/^/         /'
            fi
        fi
    done

    kill_testpmd

    echo ""
    local summary="${n_pass} passed"
    [[ $n_fail -gt 0 ]] && summary="${summary}, ${RED}${n_fail} failed${RST}"
    [[ $n_skip -gt 0 ]] && summary="${summary}, ${n_skip} skipped"
    info "${label}: ${summary} (${n_total} total)"

    return $n_fail
}

run_compare() {
    local files=("$@")
    local n_total=${#files[@]}
    local n_match=0 n_differ=0

    info "Comparing build/ vs global testpmd on ${n_total} tests"
    echo ""

    printf "  %-40s  %-10s  %s\n" "TEST" "BUILD" "GLOBAL"
    printf "  %-40s  %-10s  %s\n" "----" "-----" "------"

    local f name
    for f in "${files[@]}"; do
        name=$(test_name "$f")

        run_one "$TESTPMD_BUILD" "$f"
        local build_ok=$_test_ok build_ops=$_test_creates

        run_one "$TESTPMD_GLOBAL" "$f"
        local global_ok=$_test_ok global_ops=$_test_creates

        local b_plain g_plain b_color g_color
        if [[ $build_ok -eq 1 ]]; then
            b_plain="PASS(${build_ops})"
            b_color="${GRN}PASS${RST}(${build_ops})"
        else
            b_plain="FAIL"
            b_color="${RED}FAIL${RST}"
        fi
        if [[ $global_ok -eq 1 ]]; then
            g_plain="PASS(${global_ops})"
            g_color="${GRN}PASS${RST}(${global_ops})"
        else
            g_plain="FAIL"
            g_color="${RED}FAIL${RST}"
        fi

        local match_mark=""
        if [[ $build_ok -eq $global_ok ]]; then
            n_match=$((n_match + 1))
        else
            n_differ=$((n_differ + 1))
            match_mark="  ${YEL}<< DIFFERS${RST}"
        fi

        # Use plain width for padding, then print colored string
        local b_pad g_pad
        b_pad=$((10 - ${#b_plain}))
        g_pad=$((10 - ${#g_plain}))
        [[ $b_pad -lt 0 ]] && b_pad=0
        [[ $g_pad -lt 0 ]] && g_pad=0
        printf "  %-40s  %s%*s  %s%*s%s\n" "$name" "$b_color" "$b_pad" "" "$g_color" "$g_pad" "" "$match_mark"
    done

    kill_testpmd

    echo ""
    info "Comparison: ${n_match} match, ${n_differ} differ (${n_total} total)"

    return $n_differ
}

# --- Collect test files ---
collect_test_files() {
    local user_tests=("$@")
    local files=()

    if [[ ${#user_tests[@]} -eq 0 ]]; then
        # Default: all cmds-claude-*.txt plus cmds.txt and cmds-configs.txt
        local f
        for f in "${TEST_DIR}"/cmds-claude-*.txt; do
            [[ -f "$f" ]] && files+=("$f")
        done
        for f in "${TEST_DIR}"/cmds.txt "${TEST_DIR}"/cmds-configs.txt; do
            [[ -f "$f" ]] && files+=("$f")
        done
    else
        local t resolved
        for t in "${user_tests[@]}"; do
            resolved=$(resolve_test_file "$t") \
                || die "Test not found: $t"
            files+=("$resolved")
        done
    fi

    if [[ ${#files[@]} -eq 0 ]]; then
        die "No test files found"
    fi

    echo "${files[@]}"
}

# --- Main ---
main() {
    local mode="build"  # build, global, compare
    local do_prep_flag=0
    local do_check_prep=0
    local do_list=0
    VERBOSE=0
    QUIET=0
    local user_tests=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -b|--build)    mode=build; shift ;;
            -g|--global)   mode=global; shift ;;
            -c|--compare)  mode=compare; shift ;;
            -B|--binary)   mode=custom; TESTPMD="$2"; shift 2 ;;
            -p|--prep)     do_prep_flag=1; shift ;;
            --check-prep)  do_check_prep=1; shift ;;
            -l|--list)     do_list=1; shift ;;
            -v|--verbose)  VERBOSE=1; shift ;;
            -q|--quiet)    QUIET=1; shift ;;
            --pci)         PCI_ADDR="$2"; shift 2 ;;
            --rxq)         RXQ="$2"; shift 2 ;;
            --txq)         TXQ="$2"; shift 2 ;;
            --color)       COLOR="$2"; shift 2 ;;
            -h|--help)     _setup_colors; usage ;;
            -*)            die "Unknown option: $1 (try --help)" ;;
            *)             user_tests+=("$1"); shift ;;
        esac
    done

    _setup_colors

    # --check-prep: just test and exit
    if [[ $do_check_prep -eq 1 ]]; then
        if check_prep; then
            echo "${GRN}Device ready${RST}"
            exit 0
        else
            echo "${RED}Device not ready${RST}"
            exit 1
        fi
    fi

    # --prep: prepare device and exit
    if [[ $do_prep_flag -eq 1 ]]; then
        do_prep
        exit $?
    fi

    # --list: show tests and exit
    if [[ $do_list -eq 1 ]]; then
        list_tests
        exit 0
    fi

    # Must be root to run testpmd
    [[ $(id -u) -eq 0 ]] || die "Tests require root (use sudo)"

    # Check device readiness, auto-prep if needed
    if ! check_prep >/dev/null 2>&1; then
        info "${YEL}Device not ready — running preparation...${RST}"
        do_prep
        if ! check_prep >/dev/null 2>&1; then
            die "Device still not ready after preparation"
        fi
    fi

    # Resolve testpmd binary
    case "$mode" in
        build)
            TESTPMD="$TESTPMD_BUILD"
            [[ -x "$TESTPMD" ]] || die "Build testpmd not found: ${TESTPMD}\n  Run: meson setup build && ninja -C build"
            ;;
        global)
            TESTPMD="${TESTPMD_GLOBAL}"
            [[ -n "$TESTPMD" && -x "$TESTPMD" ]] \
                || die "Global dpdk-testpmd not found in PATH"
            ;;
        compare)
            [[ -x "$TESTPMD_BUILD" ]] \
                || die "Build testpmd not found: ${TESTPMD_BUILD}"
            [[ -n "$TESTPMD_GLOBAL" && -x "$TESTPMD_GLOBAL" ]] \
                || die "Global dpdk-testpmd not found in PATH"
            ;;
        custom)
            [[ -x "$TESTPMD" ]] || die "Binary not found: ${TESTPMD}"
            ;;
    esac

    # Kill any leftover testpmd
    kill_testpmd

    # Collect test files
    local files_str
    files_str=$(collect_test_files "${user_tests[@]}")
    local files
    read -ra files <<< "$files_str"

    echo ""

    # Run
    local rc=0
    case "$mode" in
        build)
            run_suite "$TESTPMD_BUILD" "build/ testpmd ($(get_testpmd_version "$TESTPMD_BUILD"))" "${files[@]}"
            rc=$?
            ;;
        global)
            run_suite "$TESTPMD_GLOBAL" "global testpmd ($(get_testpmd_version "$TESTPMD_GLOBAL"))" "${files[@]}"
            rc=$?
            ;;
        compare)
            run_compare "${files[@]}"
            rc=$?
            ;;
        custom)
            run_suite "$TESTPMD" "custom testpmd ($TESTPMD)" "${files[@]}"
            rc=$?
            ;;
    esac

    exit $rc
}

main "$@"
