#!/bin/bash

set -eo pipefail

set -x

LIBXJWT_VERSION="1.0.1"
LIBXJWT_HASH="e2dec5ffe9d9db69eb66ed9596afd83dfaefed515a9ba7cf32a2e785c4cb14cb"
LIBXJWT_URL="https://github.com/ScaleFT/libxjwt/archive/v${LIBXJWT_VERSION}.tar.gz"

DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi

cd "${DIR}"
cd ..

download_and_hash() {
    local FILE_HASH=""
    local LOCAL_TAR="${1}"
    local FETCH_URL="${2}"
    local EXPECT_HASH="${3}"

    if [ ! -f "${LOCAL_TAR}" ]; then
        echo "Downloading ${FETCH_URL} to ${LOCAL_TAR}"
        curl -L -s -o "${LOCAL_TAR}" "${FETCH_URL}"
    else 
        echo "Existing tar found: ${LOCAL_TAR}"
    fi

    FILE_HASH=$(openssl dgst -sha256 "${LOCAL_TAR}" | sed 's/^.* //')
    if [ "${FILE_HASH}" != "${EXPECT_HASH}" ]; then
        echo "error: calculated hash ${FILE_HASH} != expected hash: ${EXPECT_HASH} for ${LOCAL_TAR}"
        exit 1
    else 
        echo "sha256 checksum matches"
    fi
}


rm -rf  "${DIR}/build"
mkdir -p "${DIR}/build"

LIBXJWT_LOCAL_TAR="${DIR}/build/libxjwt.tar.gz"
LIBXJWT_INST_DIR="${DIR}/build/local-libxjwt"
download_and_hash "${LIBXJWT_LOCAL_TAR}" "${LIBXJWT_URL}" "${LIBXJWT_HASH}"

cd "${DIR}"
cd ..
tar -xz -f "${LIBXJWT_LOCAL_TAR}" -C "${DIR}/build"
cd "${DIR}/build/libxjwt-${LIBXJWT_VERSION}"

scons

scons destdir="${LIBXJWT_INST_DIR}" install

cd "${DIR}"
cd ..

scons APXS=/usr/bin/apxs with_libxjwt="${LIBXJWT_INST_DIR}"
