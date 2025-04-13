# Certificate extraction tool
The tools and information in this repository are used to extract the device certificates and key from `mfg.dat` &
`calibration_01.bin` files of BGW gateway devices. The certificates and key can be used to configure [EAP](https://en.wikipedia.org/wiki/Extensible_Authentication_Protocol)
authentication between a network gateway and an AT&T ONT device.

## Instructions
* <ins>Method #1</ins>: **Use a pre-built release binary**. Download and unzip the latest Linux, Mac or Windows binary from a release: [here](https://github.com/abrender/mfgdat/releases). 
      Place the binary application and an `mfg.dat` or `calibration_01.bin` file into the same folder and run the application. The application
      will create a `.tar.gz` file containing the key, certificates and example `wpa_supplicant.conf` file.
  * If the `mfg.dat` or `calibration_01.bin` file is in a different directory or has a different file name then the full
    path to the file can be passed as the first argument to the program.
    Example: `$ decoder-windows-amd64 path/to/my/mfg.dat`
* <ins>Method #2</ins>: **Build & run the Go code**. Ensure that you have Go installed (https://go.dev/doc/install).
  ```
  git clone https://github.com/abrender/mfgdat.git
  cd mfgdat
  go get .
  go run . path/to/my/mfg.dat
  ```
* <ins>Method #3</ins>. **Bash script**. This method only works with BGW210-700 devices.
      Download and run the [parse-mfg-dat.sh](https://github.com/abrender/mfgdat/blob/main/parse-mfg-dat.sh) script from this repository.
      The script will output the device key, certificates and MAC address to the console.
      The [wpa_supplicant.conf.template](https://github.com/abrender/mfgdat/blob/main/wpa_supplicant.conf.template) file can be used as a template for creating your own configuration file.
      If there are multiple CA certificates (this is likely) then they can all be appended and placed into the same file.

## Supported devices
This code supports the following devices models:
* BGW210-700
* BGW320-500
* BGW320-505
* BGW620-700

# Certificate storage format details

### Location
* <ins>`mfg.dat`</ins>:
The certificate section begins at `-0x4000` (-16,384) bytes from the end of `mfg.dat`.
Given an `mfg.dat` of size 256k (`0x40000`), the certificate section begins at `0x40000 + (-0x4000) = 0x3C000`.

* <ins>`calibration_01.bin`</ins>: The certificate section begins at the start of the file.

### Format
The header and entries are encoded in 4-byte words, with the MSB (most significant byte) stored at the smallest memory address ([big endian](https://en.wikipedia.org/wiki/Endianness)).

| Starting Address                     | Length                          | Details               |
|--------------------------------------|---------------------------------|-----------------------|
| `0x3C000`                            | 5 words                         | [Header](#header)     |
| `0x3C014`                            | (4 words) x (number_of_entries) | [Entries](#entries)   |
| `0x3C014 + (16 x number_of_entries)` | variable                        | [Raw data](#raw-data) |

#### Header
The header contains metadata information about the certificate section and entries. Each field is a 4-byte word.

| Word | Value             | Details                                                                                                                                                                                                       |
|------|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | Magic             | Always: `0x0E0C0A08`                                                                                                                                                                                          |
| 2    | Magic             | Always: `0x02040607`                                                                                                                                                                                          |
| 3    | Length            | Length of the certificate section, in *bytes*. This is relative to the start of the certificate section (at `0x3C000`), therefore the first 2 (magic) words and this length field are included in the length. | 
| 4    | Number of entries | Number of entries in the certificate section                                                                                                                                                                  |
| 5    | Unknown           | Unknown. Set to `0x0`                                                                                                                                                                                         |

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
The device's private key is contained in a single [entry](#entries) of type `4` which points to a section of [raw data](#raw-data).

For BGW210-700 devices, the raw data is laid out as follows:

| Word | Value                 | Details                                                                                                                                                                                                                                       |
|------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1    | Unknown               | The value must be `1`                                                                                                                                                                                                                         |
| 2    | Unknown               | Maybe a length                                                                                                                                                                                                                                |
| 3+   | Encrypted Private Key | [AES-128](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encrypted private key, in PKCS8 ASN.1 DER form.                                                                                                                         |

For all other models, the raw data is the [AES-128](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encrypted private key, in PKCS8 ASN.1 DER form.

Information on decrypting the keys can be found in the source code.

#### Raw Data
Certificate [entries](#entries) point to raw data contained in this section.

## Credit
Credit to rss (@rssor) and d (@slush0_) of 8311 for information about the private key decryption.

## Resources
- [extract_bgw_certs](https://github.com/rssor/extract_bgw_certs/) Python version authored by @rssor & @slush0_ from 8311.
- [mfg_dat_decode](https://www.devicelocksmith.com/2018/12/eap-tls-credentials-decoder-for-nvg-and.html) the original closed-source implementation from devicelocksmith, with support for all but the BGW620-700
- [0x888e/certs](https://github.com/0x888e/certs) software-only method to get the necessary files out of a BGW210 or BGW320