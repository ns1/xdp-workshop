#!/usr/bin/env bash

function setup_color() {
    if [[ $USE_COLOR == "true" ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        BLUE='\033[0;34m'
        YELLOW='\033[1;33m'
        NC='\033[0m' # No Color
    else
        RED=''
        GREEN=''
        BLUE=''
        YELLOW=''
        NC=''
    fi
}

function die() {
    exit ${1:-1}
}

function error() {
    echo -e "${RED}[ERROR]${NC} ${@}" >&2
}

function fatal() {
    echo -e "${RED}[FATAL]${NC} ${@}" >&2
    die
}

function info() {
    echo -e "${GREEN}[INFO]${NC} ${@}"
}

function warn() {
    echo -e "${YELLOW}[WARNING]${NC} ${@}" >&2
}

function debug() {
    if [[ ${DEBUG} != "false" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} ${@}" >&2
    fi
}

setup_color
