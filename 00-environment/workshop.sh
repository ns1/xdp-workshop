#!/usr/bin/env bash

# Get the current directory name for the script itself so we know where we are on
# the filesystem, regardless of where we are exectured from
SCRIPT_DIRECTORY=$(dirname $(readlink -f $0))

# Source our environment and common functionality.
source ${SCRIPT_DIRECTORY}/workshop.env
source ${SCRIPT_DIRECTORY}/../common/common.sh

declare -a ACTIONS=(setup teardown exec shell alias)

function script_usage() {
    cat <<EOF
Usage: $(basename $0) [global options] [action] [options]

This script handles managing and configuring our workshop test environment,
including how we will be testing and maipulating the various tutorials.

Global Options:
    -p|--plain  Disable colorized output.
    -x|--debug  Enable debug output.
    -h|--help   Display this help message.

Actions:
    setup       This action will run through and setup our test environment for the workshop.
    teardown    This action will teardown the test environment completely.
    exec        Execute a given command inside the network namespace setup in the test environment.
    shell       Enter a shell inside the network namespace setup in the test environment.
    alias       Used to create a convenience alias 'xdp' for managing the test environment.
EOF
    die
}

function setup_usage() {
    cat <<EOF
Usage: $(basename ${BASH_SOURCE[0]}) [global options] setup [options]

The 'setup' action will handle configuring the base test environment to enable developing, debugging,
and testing the various tutorials in this workshop.

Global Options:
    -p|--plain  Disable colorized output.
    -x|--debug  Enable debug output.

Options:
    -n|--name       The namespace of the virtual test nics. [default: '${NIC_NAMESPACE}']
    -4|--v4-prefix  The address to assign to the primary virtual test nic. [default: '${NIC_PREFIX_V4}']
    -m|--v4-mask    The net mask for the addresses assigned to the virtual test nic's. [default: '${NIC_MASK_V4}']
    -6|--v6-prefix  The address to assign to the secondary virtual test nic. [default: '${NIC_PREFIX_V6}']
    -a|--v6-mask    The net mask for the addresses assigned to the virtual test nic's. [default: '${NIC_MASK_V6}']
    -h|--help       Display this help message.
EOF
    return 1
}

function setup() {
    while [[ ${1} ]]; do
        case "${1}" in
            -n|--name)       NIC_NAMESPACE="${2}";  shift ;;
            -4|--v4-prefix)  NIC_PREFIX_V4="${2}";  shift ;;
            -m|--v4-mask)    NIC_MASK_V4="${2}";    shift ;;
            -6|--v6-prefix)  NIC_PREFIX_V6="${2}";  shift ;;
            -a|--v6-mask)    NIC_MASK_V6="${2}";    shift ;;

            -h|--help)       setup_usage; return $? ;;
            *)               error "Unknown option specified '${1}'"; setup_usage; return $? ;;
        esac
        shift;
    done

    PRIMARY_NIC_NAME="${NIC_NAMESPACE}0"
    SECONDARY_NIC_NAME="${NIC_NAMESPACE}1"

    info "Creating network namespace '${NIC_NAMESPACE}' and bridging ${PRIMARY_NIC_NAME} locally to ${SECONDARY_NIC_NAME} inside the namespace."

    ip netns add ${NIC_NAMESPACE}
    ip link add ${PRIMARY_NIC_NAME} type veth peer name ${SECONDARY_NIC_NAME} netns ${NIC_NAMESPACE}

    PRIMARY_NIC_ADDR="${NIC_PREFIX_V4/%.0/.1}"
    PRIMARY_NIC_ADDR_V6="${NIC_PREFIX_V6/%::/::1}"

    info "Assigning ${PRIMARY_NIC_ADDR}/${NIC_MASK_V4} and ${PRIMARY_NIC_ADDR_V6}/${NIC_MASK_V6} to ${PRIMARY_NIC_NAME} locally."
    ip addr add ${PRIMARY_NIC_ADDR}/${NIC_MASK_V4} dev ${PRIMARY_NIC_NAME}
    ip addr add ${PRIMARY_NIC_ADDR_V6}/${NIC_MASK_V6} dev ${PRIMARY_NIC_NAME}
    ip link set ${PRIMARY_NIC_NAME} up

    SECONDARY_NIC_ADDR="${NIC_PREFIX_V4/%.0/.2}"
    SECONDARY_NIC_ADDR_V6="${NIC_PREFIX_V6/%::/::2}"

    info "Assigning ${SECONDARY_NIC_ADDR}/${NIC_MASK_V4} and ${SECONDARY_NIC_ADDR_V6}/${NIC_MASK_V6} to ${SECONDARY_NIC_NAME} inside '${NIC_NAMESPACE}' namespace."
    ip netns exec ${NIC_NAMESPACE} ip addr add ${SECONDARY_NIC_ADDR}/${NIC_MASK_V4} dev ${SECONDARY_NIC_NAME}
    ip netns exec ${NIC_NAMESPACE} ip addr add ${SECONDARY_NIC_ADDR_V6}/${NIC_MASK_V6} dev ${SECONDARY_NIC_NAME}
    ip netns exec ${NIC_NAMESPACE} ip link set ${SECONDARY_NIC_NAME} up
    ip netns exec ${NIC_NAMESPACE} ip route add default via ${PRIMARY_NIC_ADDR} dev ${SECONDARY_NIC_NAME}

    info "Interface configuration complete."
    echo ""

    info "Local interface details:"
    ip a s ${PRIMARY_NIC_NAME}
    echo ""

    info "Remote interface details:"
    ip netns exec ${NIC_NAMESPACE} ip a s ${SECONDARY_NIC_NAME}

    return 0
}

function teardown_usage() {
    cat <<EOF
Usage: $(basename ${BASH_SOURCE[0]}) [global options] teardown [options]

The 'teardown' action will completely destroy the base test environment.

Global Options:
    -p|--plain  Disable colorized output.
    -x|--debug  Enable debug output.

Options:
    -n|--name   The namespace of the virtual test nics. [default: '${NIC_NAMESPACE}']
    -h|--help   Display this help message.
EOF
    return 1
}

function teardown() {
    while [[ ${1} ]]; do
        case "${1}" in
            -n|--name)   NIC_NAMESPACE="${2}"; shift ;;

            -h|--help)   teardown_usage; return $? ;;
            *)           error "Unknown option specified '${1}'"; teardown_usage; return $? ;;
        esac
        shift;
    done

    ip netns del ${NIC_NAMESPACE}

    return 0
}

function exec_usage() {
    cat <<EOF
Usage: $(basename ${BASH_SOURCE[0]}) [global options] exec [options] -- [command]

The 'exec' action will execute the command provided inside the configured network namespace.

Global Options:
    -p|--plain  Disable colorized output.
    -x|--debug  Enable debug output.

Options:
    -n|--name   The namespace of the virtual test nics. [default: '${NIC_NAMESPACE}']
    -h|--help   Display this help message.
EOF
    return 1
}

function exec() {
    while [[ ${1} ]]; do
        case "${1}" in
            -n|--name)  NIC_NAMESPACE="${2}"; shift ;;

            -h|--help)  exec_usage; return $? ;;
            --)         shift; break ;;
            *)          break ;;
        esac
        shift;
    done

    info "Executing '${@}' inside namespace '${NIC_NAMESPACE}'."
    ip netns exec ${NIC_NAMESPACE} ${@}

    return 0
}

function shell_usage() {
    cat <<EOF
Usage: $(basename ${BASH_SOURCE[0]}) [global options] shell [options]

The 'shell' action will start a shell inside the configured network namespace.

Global Options:
    -p|--plain  Disable colorized output.
    -x|--debug  Enable debug output.

Options:
    -n|--name   The namespace of the virtual test nics. [default: '${NIC_NAMESPACE}']
    -h|--help   Display this help message.
EOF
    return 1
}

function shell() {
    while [[ ${1} ]]; do
        case "${1}" in
            -n|--name)  NIC_NAMESPACE="${2}"; shift ;;

            -h|--help)  shell_usage; return $? ;;
            --)         shift; break ;;
            *)          break ;;
        esac
        shift;
    done

    info "Entering shell inside namespace '${NIC_NAMESPACE}'."
    ip netns exec ${NIC_NAMESPACE} bash
    debug "Exiting shell inside namespace '${NIC_NAMESPACE}'."

    return 0
}

function alias() {
    local sudo=""

    if [ "$EUID" -ne "0" ]; then
        warn "Adding sudo to the alias, since the alias command was run as a non-root user."
        sudo="sudo "
    fi

    local al="alias xdp='${sudo}$(readlink -e "${SCRIPT_DIRECTORY}/workshop.sh")'"
    echo ${al}
    return 0
}

function main() {
    debug "Running action '${ACTION}' with arguments '${@}'"

    ${ACTION} ${@}
    return $?
}

# If the script is run with no arguments print overall script usage and exit.
if [[ $# -lt 1 ]]; then
    script_usage
fi

# Global option and action parsing
while [[ ${1} ]]; do
    # Check to see if this argument is one of the available actions of this script.
    if [[ " ${ACTIONS[@]} " =~ " ${1} " ]]; then
        ACTION="${1}"
        shift
        break
    fi

    # Check to see if this argument is one of the available global options of this script.
    case "${1}" in
        -p|--plain)  USE_COLOR="false"; setup_color ;;
        -x|--debug)  DEBUG="true" ;;
        -h|--help)   script_usage ;;
        *)           error "Unknown global option or action '${1}'"; script_usage ;;
    esac
    shift;
done

# We must have a valid action specified in order to run anything so error if its not set properly.
if [[ ${ACTION} == "" ]]; then
    error "Must specify an action to use this script"
    script_usage
fi

# Run the main function of the script and then exit with its return code.
main ${@}
die $?
