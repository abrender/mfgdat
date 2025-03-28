# Certificate extraction tool

## Instructions
The latest Linux, Mac & Windows binaries can be found [here](https://github.com/abrender/mfgdat/releases).

To build & run the decoder tool, follow these steps:
1) Install Go (https://go.dev/doc/install)
1) Clone this repo
2) `go run main.go </full/path/to/mfg.dat>`.  The path to `mfg.dat` is optional. If the filename is not provided then the decoder tool searches the current directory for a file named `mfg.dat`.

## Supported devices
This code has only been tested on `mfg.dat` files from **BGW210-700** gateways.

# `mfg.dat` Certificate storage format details

*Note*: This information was deduced from an `mfg.dat` file belonging to a `BGW210-700` gateway device. The details below may be different for other models.

### Location
The certificate section begins at `-0x4000` (-16,384) bytes from the end of `mfg.dat`. Given an `mfg.dat` of size 256k (`0x40000`), the certificate section begins at `0x40000 + (-0x4000) = 0x3C000`.

### Format
The header and entries are encoded in 4-byte words, with the MSB (most significant byte) stored at the smallest memory address ([big endian](https://en.wikipedia.org/wiki/Endianness)).

| Starting Address | Length | Details               |
| -- | -- |-----------------------|
| `0x3C000` | 5 words | [Header](#header)     |
| `0x3C014` | (4 words) x (number_of_entries) | [Entries](#entries)   |
| `0x3C014 + (16 x number_of_entries)` | variable | [Raw data](#raw-data) |

#### Header
The header contains metadata information about the certificate section and entries. Each field is a 4-byte word.

| Word | Value             | Details                                                                                                                                                                                                         |
|------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | Unknown           | 
| 2    | Unknown           | 
| 3    | Length            | Length of the certificate section, in *bytes*. This is relative to the start of the certificate section (at `0x3C000`), therefore the first 2 (unknown) words and this length field are included in the length. | 
| 4    | Number of entries | Number of entries in the certificate section                                                                                                                                                                    |
| 5    | Unknown           | Unknown. Set to `0x0`                                                                                                                                                                                           |

#### Entries
Entries contains metadata about the type of entry and where to locate the entry's raw data.

Each entry is composed of 4x 4-byte words as described in the table below.

| Word | Value   | Details                                                                                                                                                                                                                              |
|------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | Offset  | Starting address for the entry's raw data. The offset is in *bytes* relative to the certificate sections's [Raw data](#raw-data) starting address.                                                                                   |
| 2    | Length  | Length, in *bytes*, of the entry's raw data.                                                                                                                                                                                         |
| 3    | Type    | *2* = X509 Client Certificate in ASN.1 DER format.<BR>*3* = X509 CA Certificates (Intermediate and Root certificates) in ASN.1 DER format.<BR>*4* = AES-128 [Encrypted Private Key](#encrypted-private-key) in PKCS8 ASN.1 DER form. |
| 4    | Unknown | Set to `1` for the encrypted private key, `0` otherwise.                                                                                                                                                                             |

#### Encrypted Private Key
The device's private key is contained in a single [entry](#entries) of type `4` which points to a section of [raw data](#raw-data) that is laid out as follows:

| Word | Value                 | Details                                                                                                               |
|------|-----------------------|-----------------------------------------------------------------------------------------------------------------------|
| 1    | Unknown               | The value must be `1`                                                                                                 |
| 2    | Unknown               | Maybe a length                                                                                                        |
| 3+   | Encrypted Private Key | [AES-128](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encrypted private key, in PKCS8 ASN.1 DER form. |

The encrypted private device key can be decrypted using the following AES-128 parameters:
* Key: `0x8C 0x02 0xE4 0x9C 0x55 0xBA 0xE5 0x6C 0x4B 0xE5 0x52 0xB5 0x0B 0x41 0xD6 0x9F`
* IV: `0x2F 0x79 0xD4 0x17 0x3A 0x15 0x5E 0x3B 0xD0 0x79 0xDE 0x4C 0x81 0x71 0x9D 0x3C`

#### Raw Data
Certificate [entries](#entries) point to raw data contained in this section.
