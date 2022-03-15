#!/bin/bash
echo Downloading testssl....
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
repository="https://github.com/drwetter/testssl.sh.git"

git clone --depth 1 "$repository"