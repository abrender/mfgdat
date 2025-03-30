#!/bin/bash
# Copyright (C) 2025 Avi Brender.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, either version 3 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.


# The purpose of this script is to create fake `mfg.dat` files to be used as test data for testing & verifying the
# functionality of the code in this repo.

set -e

mac_address="02:01:02:03:04:05"
serial_number="123ABC-P67AB2DR253311"

ca_dir=$(mktemp -d -t fake_ca.XXXXX) || exit 1

echo "Fake CA directory: ${ca_dir}"
echo

pushd ${ca_dir} > /dev/null

# Create root CA key
openssl genrsa -quiet -out rootCA.key 2048

# Create root CA certificate
openssl req -quiet -x509 -new -nodes -key rootCA.key -sha256 -days 10950 -out rootCA.crt -outform DER -subj "/CN=FakeTemporaryRootCA"

# Create intermediate CA key
openssl genrsa -quiet -out intermediateCA.key 2048

# Create intermediate CA CSR
openssl req -quiet -new -key intermediateCA.key -out intermediateCA.csr -subj "/CN=FakeTemporaryIntermediateCA"

# Sign the intermediate CA CSR with the root CA
openssl x509 -req -in intermediateCA.csr -CA rootCA.crt -CAkey rootCA.key -CAserial rootCA.srl -CAcreateserial -out intermediateCA.crt -outform DER -days 10949 -sha256 > /dev/null

# Verify the intermediate CA certificate
openssl verify -CAfile rootCA.crt intermediateCA.crt > /dev/null

# Create device key
openssl genrsa -quiet -out device.key 1024

# Create device CSR
openssl req -quiet -new -key device.key -out device.csr -subj "/CN={$mac_address}/serialNumber=${serial_number}"

# Sign the device CSR with the intermediate CA.
openssl x509 -req -in device.csr -CA intermediateCA.crt -CAkey intermediateCA.key -out device.crt -outform DER -days 365 -sha1 > /dev/null

# Encrypt the device key.
openssl rsa -in device.key -outform der | openssl aes-128-cbc -e -K "8C02E49C55BAE56C4BE552B50B41D69F" -iv "2F79D4173A155E3BD079DE4C81719D3C" -out device.key.encrypted

device_crt_len=$(cat device.crt | wc -c)
encrypted_device_key_len=$(cat device.key.encrypted | wc -c)
root_ca_crt_len=$(cat rootCA.crt | wc -c)
intermediate_ca_crt_len=$(cat intermediateCA.crt | wc -c)

header_len_bytes=$((5 * 4)) # 2 unknown words + length word + entry_count word + empty word.
num_entries=4
entries_len_bytes=$((${num_entries} * 4 * 4)) # 4 entries of 4x 4-byte words each.
encrypted_device_key_preamble_len=$((2 * 4)) # There are 2 unknown words before the encrypted device key.
raw_data_len_bytes=$((encrypted_device_key_preamble_len + encrypted_device_key_len + device_crt_len + root_ca_crt_len + intermediate_ca_crt_len))
total_len_bytes=$((header_len_bytes + entries_len_bytes + raw_data_len_bytes))

# Create fake mfg.dat-fake file
dd status=none if=/dev/zero of=mfg.dat-fake bs=256k count=1

# Magic Numbers
MAGIC="0E0C0A08"
MAGIC+="02040607"
echo "${MAGIC}" | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=8 seek=$((0x3C000))

# Length
printf '%08X' ${total_len_bytes} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((0x3C008))
# Number of entries
printf '%08X' ${num_entries} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((0x3C00C))

raw_data_start=$((0x3C000 + header_len_bytes + entries_len_bytes))
raw_data_offset=0
entry_seek=$((0x3C014))

# Entry #1 (Encrypted private key)
entry_len=$((encrypted_device_key_len + encrypted_device_key_preamble_len))
printf '%08X' ${raw_data_offset} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 0))
printf '%08X' ${entry_len} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 4))
printf '%08X' 4 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 8))
printf '%08X' 1 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 12))
# The encrypted private key entry has 2 leading words before the encrypted raw data. The first word is 0x01, the second
# is 0 (which does not have to be set, because the entire file is filled with zeros).
printf '%08X' 1 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((raw_data_start + raw_data_offset))
dd status=none conv=notrunc if=device.key.encrypted of=mfg.dat-fake bs=1 count=$((entry_len - encrypted_device_key_preamble_len)) seek=$((raw_data_start + raw_data_offset + encrypted_device_key_preamble_len))
entry_seek=$((entry_seek += 4*4))
raw_data_offset=$((raw_data_offset + entry_len))

# Entry #2 (Device certificate)
entry_len=${device_crt_len}
printf '%08X' ${raw_data_offset} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 0))
printf '%08X' ${entry_len} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 4))
printf '%08X' 2 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 8))
printf '%08X' 0 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 12))

dd status=none conv=notrunc if=device.crt of=mfg.dat-fake bs=1 count=${entry_len} seek=$((raw_data_start + raw_data_offset))
entry_seek=$((entry_seek += 4*4))
raw_data_offset=$((raw_data_offset + entry_len))

# Entry #3 (Intermediate CA certificate)
entry_len=${intermediate_ca_crt_len}
printf '%08X' ${raw_data_offset} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 0))
printf '%08X' ${entry_len} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 4))
printf '%08X' 3 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 8))
printf '%08X' 0 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 12))
dd status=none conv=notrunc if=intermediateCA.crt of=mfg.dat-fake bs=1 count=${entry_len} seek=$((raw_data_start + raw_data_offset))
entry_seek=$((entry_seek += 4*4))
raw_data_offset=$((raw_data_offset + entry_len))

# Entry #4 (Root CA certificate)
entry_len=${root_ca_crt_len}
printf '%08X' ${raw_data_offset} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 0))
printf '%08X' ${entry_len} | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 4))
printf '%08X' 3 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 8))
printf '%08X' 0 | xxd -r -p | dd status=none conv=notrunc of=mfg.dat-fake bs=1 count=4 seek=$((entry_seek + 12))
dd status=none conv=notrunc if=rootCA.crt of=mfg.dat-fake bs=1 count=${entry_len} seek=$((raw_data_start + raw_data_offset))
entry_seek=$((entry_seek += 4*4))
raw_data_offset=$((raw_data_offset + entry_len))

# Cleanup
rm rootCA.{crt,key,srl} intermediateCA.{csr,crt,key} device.{csr,crt,key,key.encrypted}

popd > /dev/null

mv ${ca_dir}/mfg.dat-fake ./

echo
echo "Created mfg.dat-fake in the current working directory."

rmdir ${ca_dir}

echo
echo "Done."
