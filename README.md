# RFID Password Vault (CircuitPython)

This project turns a Raspberry Pi Pico and an RC522 RFID module into a secure, hardware-based password manager. It differentiates itself by storing **encrypted credentials (usernames and passwords) directly on the RFID cards**, ensuring the device itself holds no sensitive database.

To enhance security, the system uses **Anti-Cloning UID Binding** and a **Custom Magic Header** to validate cards before processing.

## Key Features

*   **Dual Mode Storage**: Supports two types of credentials:
    *   **Password Only**: Classic mode. Types password + Enter.
    *   **Username + Password**: Types Username + Tab + Password + Enter.
*   **Anti-Cloning Security**: Encryption keys are dynamically derived from the unique card UID and a device-specific `MASTER_SECRET`. If a card is cloned to a new tag with a different UID, the derived key will be incorrect, and the data will decrypt to garbage.
*   **Magic Header Validation**: The system uses distinct headers to identify card types:
    *   `PfId`: Password Only
    *   `PfUs`: Username + Password
*   **On-Card Storage**: Credentials travel with the user, not the reader.
*   **Universal Support (Custom Driver)**: I include a **custom implementation of the MFRC522 driver** (`lib/mfrc522.py`) specifically modified to support **NTAG 215** chips (and other 7-byte UID tags) alongside standard Mifare Classic 1KB cards.
*   **Plug & Play**: Acts as a standard USB HID Keyboard.

## Hardware Requirements

*   **Raspberry Pi Pico** (or other RP2040 board)
*   **MFRC522 RFID Module**
*   **NTAG 215** or **Mifare Classic 1KB** cards/fobs
*   Wires & Breadboard

## Wiring

| MFRC522 Pin | Pico Pin | Function |
| :--- | :--- | :--- |
| **SDA (SS)** | GP17 | Chip Select (CS) |
| **SCK** | GP18 | SPI Clock |
| **MOSI** | GP19 | SPI TX |
| **MISO** | GP16 | SPI RX |
| **RST** | GP22 | Reset |
| **3.3V** | 3V3 (OUT) | Power |
| **GND** | GND | Ground |

## Installation

1.  **Install CircuitPython**: Flash the latest CircuitPython firmware to your Raspberry Pi Pico.
2.  **Install Libraries**: Copy the `lib` folder from this repository to your Pico. This is **critical** as it contains the custom `mfrc522.py` driver needed for NTAG support.
    *   Also ensure you have `adafruit_hid` and `busio` installed.
3.  **Copy Code**: Copy `code.py` to the root of the drive.

## Configuration

Open `code.py` and configure your **Master Secret**. This is the core of the security system.

```python
# --- Security Config ---
# CHANGE THIS to a unique secret for your device!
MASTER_SECRET = b"SuperSecretKey123" 
```

*   **MASTER_SECRET**: This key is mixed with the Card UID to generate the encryption keystream.
*   **Effect**: A card written with one device's secret cannot be read by another device with a different secret.

## Usage

### Reading via USB (HID Mode)
Just tap a programmed card.
1.  **Detect**: Reader scans UID.
2.  **Verify**: Checks for Magic Header (`PfId` or `PfUs`).
3.  **Decrypt**: Uses (UID + Master Secret) to unlock the payload.
4.  **Type**:
    *   **Password Only**: Types `password` -> `Enter`.
    *   **Username + Password**: Types `username` -> `Tab` -> `password` -> `Enter`.

### Management Console (Serial)
Connect to the Pico's serial console to manage cards.

*   `write <password>`:
    *   Writes a **Password Only** tag (Header: `PfId`).
*   `write <username> <password>`:
    *   Writes a **Username + Password** tag (Header: `PfUs`).
    *   *Note: Total length of "username + password + 1" must be <= 44 bytes.*
*   `wipe`: Unlocks and fills the data area with zeros.
