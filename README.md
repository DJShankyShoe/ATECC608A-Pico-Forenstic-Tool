# README.md

## Project Overview

This system provides autonomous forensic data acquisition using the Raspberry Pi Pico W.  
It automatically deploys a payload using HID keystroke injection, collects volatile telemetry, encrypts everything using the ATECC608A secure element, stores the results on an SD card, and hosts a secure TLS server for retrieval.

Below is a **folder‑level explanation**, including **all child folders** and their roles.

---

# Folder Structure (With Explanations)

## **pico_atecc/**  
Root firmware project.

---

## **atecc_script/**  
Implements all cryptographic, provisioning, secure‑session, and communication features for the ATECC608A hardware secure element.

### **aes/**  
Implements AES‑based operations (encryption/decryption helpers, secure‑element AES workflows).

### **hal/**  
Hardware Abstraction Layer for Pico‑to‑ATECC I²C communication.

### **init/**  
Initialization routines for waking, configuring, and preparing the secure element.

### **password/**  
Handles password hashing, validation, and password‑derived key operations.

### **session_gen/**  
Generates secure session keys used for encrypting telemetry streams or securing channels.

### **sign_cert/**  
Handles ECDSA certificate signing and cryptographic signature generation through the secure element.

### **com_channel/**  
Implements a structured communication layer for authenticated & encrypted data exchange.

#### **cdc/**  
Provides USB‑CDC (serial‑over‑USB) transport channel for debugging or data transfer.

#### **channel/**  
Contains all logical channel layers used for secure messaging.

##### **aes/**  
Helper utilities used when AES operations are needed in channel messages.

##### **base64/**  
Base64 encoder/decoder utilities for packet encoding.

##### **pico_auth/**  
Authentication layer enforcing identity verification and secure handshake.

##### **session/**  
All logic related to secure sessions.

###### **session_end/**  
Graceful and secure teardown of sessions, including wiping sensitive data.

###### **session_handle/**  
Implements protocol handling, managing state machines and packet control.

###### **session_secure/**  
Key management for secure sessions (key rotation, encryption material, etc.)

---

## **telemetry/**  
Telemetry pipeline responsible for collecting, packaging, and decrypting telemetry streams.

- Produces encrypted telemetry packets  
- Provides streaming decryption for downloaded data  

---

## **user_auth/**  
Implements user‑authentication logic for verifying investigator credentials.

---

## **external_lib/**  
Contains external, third‑party dependencies needed by other components.

### **cryptoauthlib/**  
Vendor cryptographic library support for Microchip ATECC devices.

### **no‑OS‑FatFS‑SD‑SPI‑RPi‑Pico/**  
Third‑party FAT filesystem used to manage SD‑card storage.

---

## **led/**  
Implements LED‑based system status indicators (initialization, error, telemetry, server‑active).

---

## **rubber_exec/**  
Implements the USB HID keystroke injection engine (“Rubber Ducky” behavior).

Used to:
- Automate payload download  
- Execute scripted keystrokes  
- Trigger forensic collection on the target  

---

## **sd_card/**  
SD card hardware configuration and storage interface.

Responsibilities:
- SPI interface to SD card  
- Low‑level read/write routines  
- Filesystem binding  

---

## **usb_desc/**  
USB descriptor definitions for HID and USB‑CDC functionality.

Contains all TinyUSB descriptor and configuration files that define:
- VID / PID  
- HID report descriptors  
- Endpoint structure  

---

## **webserver_pico/**  
Embedded TLS web server for encrypted data retrieval.

### **auth/**  
Authentication for webserver clients.

### **core/**  
HTTP server core: routing, TLS session management, connection handling.

### **parse/**  
Parses incoming HTTP requests.

### **response/**  
Builds and sends HTTP responses to the client.

### **upload/**  
Handles file uploads (config files, certificates, provisioning materials).

### **webserver/**  
Defines high‑level orchestration for the webserver.

---

## **wifi/**  
Wi‑Fi networking, connection management, and LWIP configuration.

---

## **root‑level files**  
- **main.c** – Central orchestrator  
- **payload.py** – Host-side payload script  
- **CMakeLists.txt** – Build configuration  

---

# ATECC608A Setup Script Instructions

You must **manually copy** the setup script logic into `main.c` and run the provisioning functions **in the order implied by the filenames**.

This configures:
- Key slots  
- SlotConfig rules  
- KeyConfig rules  
- Security policies  

### SlotConfig & KeyConfig Reference (Little‑Endian)

| Slot | SlotConfig | KeyConfig | Meaning |
|------|------------|-----------|---------|
| 0 | 0x6483 | 0x0013 | Private ECC, Signing, PrivWrite enc, GenKey, NoRead |
| 1 | 0x2083 | 0x0013 | Private ECC, Signing, GenKey only |
| 2 | 0x6487 | 0x0013 | Private ECC, Sign + ECDH |
| 3 | 0x208F | 0x0013 | Private ECC, Sign + ECDH(write-next) |
| 4–8 | 0x0000 | 0x001C | Data R/W (development) |
| 9–10 | 0x448F | 0x0018 | AES‑128 production | 
| 11 | 0x008F | 0x0018 | AES‑128 development |
| 12 | 0x0000 | 0x001C | Data‑clear |
| 13–15 | 0x448F | 0x001C | Secret write‑only (encrypted) |

Provision BEFORE locking the configuration zone.

---

# Build

```
mkdir build
cd build
cmake ..
make
```

Yields:  
`pico_atecc.uf2`

---

# Flashing

1. Hold **BOOTSEL**  
2. Connect Pico W  
3. Copy the UF2 file to the mounted volume  

---

# Runtime Flow

1. HID keystroke injection  
2. Payload execution on target  
3. Telemetry capture  
4. Hardware‑encrypted storage  
5. TLS webserver retrieval  

---

# Testing Notes

- HID execution verification  
- Secure‑element provisioning  
- SD card integrity  
- HTTPS functionality  

---
