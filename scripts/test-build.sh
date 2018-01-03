#!/bin/bash

set -eo pipefail

set -x

LIBXJWT_VERSION="1.0.2"
LIBXJWT_HASH="267f922cd8e8e357032763b8a31ad771e9622db6c202b88d107c9d74acc2867c"
LIBXJWT_URL="https://github.com/ScaleFT/libxjwt/releases/download/v${LIBXJWT_VERSION}/libxjwt-${LIBXJWT_VERSION}.tar.gz"



DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi

DIR=`readlink -f "${DIR}"`

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

mkdir -p "${LIBXJWT_INST_DIR}"

cd "${DIR}"
cd ..
tar -xz -f "${LIBXJWT_LOCAL_TAR}" -C "${DIR}/build"
cd "${DIR}/build/libxjwt-${LIBXJWT_VERSION}"

./configure
make
make DESTDIR="${LIBXJWT_INST_DIR}" install

cd "${DIR}"
cd ..

MOD_INST_DIR="${DIR}/build/local-apache-module"

./buildconf.sh
./configure --with-apxs=/usr/bin/apxs --with-xjwt="${LIBXJWT_INST_DIR}/usr/local"
make
make DESTDIR="${MOD_INST_DIR}" install