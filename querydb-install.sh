#!/usr/bin/env bash
set -o errexit
set -o pipefail
set -o nounset
set -eu

if [ "$(uname)" = 'Darwin' ]; then
  # Get script location
  # https://unix.stackexchange.com/a/96238
  if [ "${BASH_SOURCE:-x}" != 'x' ]; then
    this_script=$BASH_SOURCE
  elif [ "${ZSH_VERSION:-x}" != 'x' ]; then
    setopt function_argzero
    this_script=$0
  elif eval '[[ -n ${.sh.file} ]]' 2>/dev/null; then
    eval 'this_script=${.sh.file}'
  else
    echo 1>&2 "Unsupported shell. Please use bash, ksh93, or zsh."
    exit 2
  fi
  relative_directory=$(dirname "$this_script")
  SCRIPT_ABS_DIR=$(cd "$relative_directory" && pwd)
else
  SCRIPT_ABS_PATH=$(readlink -f "$0")
  SCRIPT_ABS_DIR=$(dirname "$SCRIPT_ABS_PATH")
fi

# Check if required tools are installed
check_installed() {
  if ! type "$1" > /dev/null; then
    echo "Please ensure you have $1 installed."
    exit 1
  fi
}

# Set JOERN_INSTALL_DIR with default value, allowing an override via script argument
DEFAULT_JOERN_INSTALL_DIR="$PWD/joern-cli/target/universal/stage"
JOERN_INSTALL_DIR="${1:-$DEFAULT_JOERN_INSTALL_DIR}"

# Ensure JOERN_INSTALL_DIR exists
if [ ! -d "$JOERN_INSTALL_DIR" ]; then
  echo "Error: Joern installation directory '$JOERN_INSTALL_DIR' does not exist."
  exit 1
fi

echo "Building the plugin"
sbt querydb/createDistribution
readonly QUERYDB_ZIP=$PWD/querydb/target/querydb.zip

echo "Installing plugin in $JOERN_INSTALL_DIR"
pushd "$JOERN_INSTALL_DIR" > /dev/null
  ./joern --remove-plugin querydb
  ./joern --add-plugin "$QUERYDB_ZIP"
popd > /dev/null

echo "Plugin installed successfully."