#!/bin/bash
# Copyright (C) 2025 Avi Brender.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, either version 3 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.


# This is a quick and dirty script to parse an mfg.dat file from a BGW210-700 and print out the contents to the console.
# It doesn't do as much sanity checking as the Go code, but it should work as long as openssl, dd and xxd are installed.

set -e

FILE=${1:-"mfg.dat"} # Read file from the first argument, otherwise assume `mfg.dat` in current dir.

FILE_SIZE=$(( 256 * 1024 )) # mfg.dat is 256k.
OFFSET=$(( -0x4000 ))
CERT_STORE_START=$(( FILE_SIZE + OFFSET ))

HEADER_SIZE=5*4 # The header is 5x 4-byte words.

READ_WORD_SKIP_START=$(( CERT_STORE_START - 4)) # Subtract 4 because we start at #1 instead of 0.
read_word(){
  local WORD_NUM=$1

  HEX_NUMBER=$(dd status=none if="${FILE}" bs=1 count=4 skip=$((READ_WORD_SKIP_START + (4 * WORD_NUM))) | xxd -p)
  echo $((0x$HEX_NUMBER)) # Convert to decimal
}

if [ ! -r "$FILE" ]; then
  echo "Cannot read file ${FILE}"
  exit 1
fi

ACTUAL_SIZE=$(cat "${FILE}" | wc -c)
if [ ${ACTUAL_SIZE} -ne ${FILE_SIZE} ]; then
    echo "mfg.dat file is ${ACTUAL_SIZE} bytes, expected ${FILE_SIZE} bytes"
    exit 1
fi

# Verify the magic numbers are correct.
MAGIC1=$(read_word 1)
MAGIC2=$(read_word 2)
if [[ ${MAGIC1} -ne $((0x0E0C0A08)) ]] || [[ ${MAGIC2} -ne $((0x02040607)) ]]; then
  echo "Unknown magic numbers - expected 0x0E0C0A08 and 0x02040607"
  exit 1
fi

NUMBER_OF_ENTRIES=$(read_word 4)
if [[ ${NUMBER_OF_ENTRIES} -gt 10 ]] ; then
  echo "Found suspiciously large number of entries: ${NUMBER_OF_ENTRIES}"
  exit
fi

echo "Number of entries: ${NUMBER_OF_ENTRIES}"
echo

RAW_DATA_START=$(( CERT_STORE_START + HEADER_SIZE + (NUMBER_OF_ENTRIES * 4 * 4) )) # Offset (in bytes) where the raw data starts.
START_WORD_OF_ENTRIES=6
for (( i=0; i<NUMBER_OF_ENTRIES; i++ ))
do
  ENTRY_OFFSET=$(( START_WORD_OF_ENTRIES + (i * 4) ))

  # Read the entry.
  ENTRY_RAW_DATA_OFFSET=$(read_word ENTRY_OFFSET)
  ENTRY_RAW_DATA_LENGTH=$(read_word $(( ENTRY_OFFSET + 1 )) )
  ENTRY_TYPE=$(read_word $(( ENTRY_OFFSET + 2 )) )

  if [[ ${ENTRY_TYPE} -eq 2 ]]; then
    echo "################## FOUND CLIENT CERTIFICATE ####################"

    DEVICE_CERT_PEM=$(dd status=none if="${FILE}" bs=1 count=${ENTRY_RAW_DATA_LENGTH} skip=$((RAW_DATA_START + ENTRY_RAW_DATA_OFFSET)) | openssl x509 -inform DER -outform PEM)
    echo -n "Certificate Subject: "; echo "${DEVICE_CERT_PEM}" | openssl x509 -inform PEM -noout -subject;
    echo -n "Certificate Issuer:  "; echo "${DEVICE_CERT_PEM}" | openssl x509 -inform PEM -noout -issuer; echo
    echo "${DEVICE_CERT_PEM}"
    echo
  fi

  if [[ ${ENTRY_TYPE} -eq 3 ]]; then
    echo "################## FOUND CA CERTIFICATE ########################"

    CA_PEM=$(dd status=none if="${FILE}" bs=1 count=${ENTRY_RAW_DATA_LENGTH} skip=$((RAW_DATA_START + ENTRY_RAW_DATA_OFFSET)) | openssl x509 -inform DER -outform PEM)
    echo -n "Certificate Subject: "; echo "${CA_PEM}" | openssl x509 -inform PEM -noout -subject;
    echo -n "Certificate Issuer:  "; echo "${CA_PEM}" | openssl x509 -inform PEM -noout -issuer; echo
    echo "${CA_PEM}"
    echo
  fi

  if [[ ${ENTRY_TYPE} -eq 4 ]]; then
    echo "################## FOUND ENCRYPTED PRIVATE KEY #################"
    # There are 2x 4-byte words before the encrypted key.
    PREAMBLE_LEN=2*4

    dd status=none if="${FILE}" bs=1 count=$((ENTRY_RAW_DATA_LENGTH - PREAMBLE_LEN)) skip=$((RAW_DATA_START + ENTRY_RAW_DATA_OFFSET + PREAMBLE_LEN)) | \
        openssl aes-128-cbc -d -K "8C02E49C55BAE56C4BE552B50B41D69F" -iv "2F79D4173A155E3BD079DE4C81719D3C" -nopad | openssl ec -inform DER -outform PEM
    echo
  fi
done