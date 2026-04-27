# Pico ATECC Forensic Acquisition System

## Project Overview

This project provides autonomous forensic data acquisition using the Raspberry Pi Pico W.

The system uses USB HID keystroke injection to deploy a payload, collect volatile telemetry, encrypt the collected data with the ATECC608A secure element, store the encrypted output on an SD card, and expose a TLS-enabled retrieval server.

---

## Folder Structure

```text
pico_atecc/
├── atecc_script/
│   ├── aes/
│   ├── hal/
│   ├── init/
│   ├── password/
│   ├── session_gen/
│   ├── sign_cert/
│   └── com_channel/
│       ├── cdc/
│       └── channel/
│           ├── aes/
│           ├── base64/
│           ├── pico_auth/
│           └── session/
│               ├── session_end/
│               ├── session_handle/
│               └── session_secure/
├── telemetry/
├── user_auth/
├── external_lib/
│   ├── cryptoauthlib/
│   └── no-OS-FatFS-SD-SPI-RPi-Pico/
├── led/
├── rubber_exec/
├── sd_card/
├── usb_desc/
├── webserver_pico/
│   ├── auth/
│   ├── core/
│   ├── parse/
│   ├── response/
│   ├── upload/
│   └── webserver/
├── wifi/
├── main.c
├── payload.py
└── CMakeLists.txt
```

---

## Directory Reference

### `pico_atecc/`

Root firmware project directory.

---

### `atecc_script/`

Contains cryptographic, provisioning, secure-session, and communication logic for the ATECC608A hardware secure element.

| Folder | Purpose |
|---|---|
| `aes/` | AES encryption/decryption helpers and secure-element AES workflows. |
| `hal/` | Hardware Abstraction Layer for Pico-to-ATECC I²C communication. |
| `init/` | Initialization routines for waking, configuring, and preparing the secure element. |
| `password/` | Password hashing, validation, and password-derived key operations. |
| `session_gen/` | Secure session-key generation for encrypted telemetry streams and secure channels. |
| `sign_cert/` | ECDSA certificate signing and signature generation through the secure element. |
| `com_channel/` | Structured communication layer for authenticated and encrypted data exchange. |

#### `atecc_script/com_channel/`

| Folder | Purpose |
|---|---|
| `cdc/` | USB-CDC serial-over-USB transport for debugging or data transfer. |
| `channel/` | Logical secure-messaging channel layers. |

#### `atecc_script/com_channel/channel/`

| Folder | Purpose |
|---|---|
| `aes/` | AES helper utilities for encrypted channel messages. |
| `base64/` | Base64 encoder/decoder utilities for packet encoding. |
| `pico_auth/` | Authentication layer for identity verification and secure handshakes. |
| `session/` | Secure-session lifecycle, protocol handling, and key management. |

#### `atecc_script/com_channel/channel/session/`

| Folder | Purpose |
|---|---|
| `session_end/` | Secure session teardown and sensitive-data cleanup. |
| `session_handle/` | Protocol handling, packet control, and session state machines. |
| `session_secure/` | Session key management, rotation, and encryption material handling. |

---

### `telemetry/`

Telemetry pipeline for collecting, packaging, encrypting, and decrypting telemetry streams.

Main responsibilities:

- Produces encrypted telemetry packets.
- Provides streaming decryption for downloaded telemetry data.

---

### `user_auth/`

Implements user-authentication logic for verifying investigator credentials.

---

### `external_lib/`

Contains third-party dependencies used by the firmware.

| Folder | Purpose |
|---|---|
| `cryptoauthlib/` | Microchip CryptoAuthLib support for ATECC secure-element devices. |
| `no-OS-FatFS-SD-SPI-RPi-Pico/` | FAT filesystem and SD-card support for the Raspberry Pi Pico. |

---

### `led/`

Implements LED-based system status indicators.

Example status states:

- Initialization
- Error
- Telemetry activity
- Server active

---

### `rubber_exec/`

Implements the USB HID keystroke-injection engine.

Used to automate:

- Payload download
- Scripted keystroke execution
- Forensic collection trigger flow

---

### `sd_card/`

Provides SD-card hardware configuration and storage access.

Main responsibilities:

- SPI interface configuration
- Low-level read/write routines
- Filesystem binding

---

### `usb_desc/`

Contains USB descriptor definitions for HID and USB-CDC functionality.

Defines TinyUSB configuration such as:

- VID / PID
- HID report descriptors
- Endpoint structure

---

### `webserver_pico/`

Embedded TLS web server for encrypted data retrieval.

| Folder | Purpose |
|---|---|
| `auth/` | Authentication for webserver clients. |
| `core/` | HTTP routing, TLS session management, and connection handling. |
| `parse/` | HTTP request parsing. |
| `response/` | HTTP response construction and transmission. |
| `upload/` | Upload handling for configuration files, certificates, and provisioning materials. |
| `webserver/` | High-level webserver orchestration. |

---

### `wifi/`

Handles Wi-Fi networking, connection management, and LWIP configuration.

---

## Root-Level Files

| File | Purpose |
|---|---|
| `main.c` | Central firmware orchestrator. |
| `payload.py` | Host-side payload script. |
| `CMakeLists.txt` | Project build configuration. |

---

## ATECC608A Setup Script Instructions

Manually copy the setup-script logic into `main.c`, then run the provisioning functions in the order implied by the filenames.

This configures:

- Key slots
- SlotConfig rules
- KeyConfig rules
- Security policies

> **Important:** Provision the secure element before locking the configuration zone.

### SlotConfig & KeyConfig Reference

Little-endian values are shown below.

| Slot | SlotConfig | KeyConfig | Meaning |
|---:|---:|---:|---|
| 0 | `0x6483` | `0x0013` | Private ECC, signing, encrypted PrivWrite, GenKey, NoRead. |
| 1 | `0x2083` | `0x0013` | Private ECC, signing, GenKey only. |
| 2 | `0x6487` | `0x0013` | Private ECC, signing, and ECDH. |
| 3 | `0x208F` | `0x0013` | Private ECC, signing, and ECDH with write-next behavior. |
| 4-8 | `0x0000` | `0x001C` | Development data read/write slots. |
| 9-10 | `0x448F` | `0x0018` | Production AES-128 slots. |
| 11 | `0x008F` | `0x0018` | Development AES-128 slot. |
| 12 | `0x0000` | `0x001C` | Clear data slot. |
| 13-15 | `0x448F` | `0x001C` | Secret write-only encrypted slots. |

---

## Build

```bash
mkdir build
cd build
cmake ..
make
```

Expected output:

```text
pico_atecc.uf2
```

---

## Flashing

1. Hold **BOOTSEL**.
2. Connect the Pico W to the host machine.
3. Copy `pico_atecc.uf2` to the mounted Pico volume.

---

## Runtime Flow

```text
HID keystroke injection
        ↓
Payload execution on target
        ↓
Telemetry capture
        ↓
Hardware-encrypted storage
        ↓
TLS webserver retrieval
```

---

## Testing Notes

Recommended test areas:

- HID execution verification
- Secure-element provisioning
- SD-card integrity
- HTTPS/TLS functionality
