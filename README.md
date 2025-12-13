# RFID Password Vault (CircuitPython)

This project turns a Raspberry Pi Pico and an RC522 RFID module into a secure, hardware-based password manager. It differentiates itself by storing **encrypted credentials (usernames and passwords) directly on the RFID cards**, ensuring the device itself holds no sensitive database.

To enhance security, the system uses **Anti-Cloning UID Binding** and a **Custom Magic Header** to validate cards before processing.

## Key Features

*   **Multiple Storage Modes**: Supports three types of data:
    *   **Password Only**: Classic mode. Types password + Enter.
    *   **Username + Password**: Types Username + Tab + Password + Enter.
    *   **Advanced Macros**: Rubber Ducky-style macros with key sequences, combinations, and delays.
    *   **TOTP Authenticator**: Stores 2FA secrets and types the current 6-digit code (Time-based One-Time Password).
*   **Web Management Interface**: Modern, browser-based UI for managing cards without serial console access. Features real-time status updates, formatted read results, and intuitive forms for writing credentials or macros.
*   **Multi-Sector/Page Support**: Uses chained storage across multiple blocks/pages for large data:
    *   **Mifare 1K**: Up to ~660 bytes (44 data blocks × 15 bytes)
    *   **NTAG215**: Up to ~393 bytes (131 user pages × 3 bytes)
    *   Automatically chains across sectors/pages with continuation flags
*   **Anti-Cloning Security**: Encryption keys are dynamically derived from the unique card UID and a device-specific `MASTER_SECRET`. If a card is cloned to a new tag with a different UID, the derived key will be incorrect, and the data will decrypt to garbage.
*   **Magic Header Validation**: The system uses distinct headers to identify card types:
    *   `PfId`: Password Only
    *   `PfUs`: Username + Password
    *   `PfMc`: Advanced Macro
    *   `Pf2F`: TOTP Authenticator
*   **On-Card Storage**: Credentials and macros travel with the user, not the reader.
*   **Universal Support (Custom Driver)**: I include a **custom implementation of the MFRC522 driver** (`lib/mfrc522.py`) specifically modified to support **NTAG 215** chips (and other 7-byte UID tags) alongside standard Mifare Classic 1KB cards.
*   **Dual Interface**: Both serial console and web UI for maximum flexibility.
*   **Plug & Play**: Acts as a standard USB HID Keyboard.

## Hardware Requirements

*   **Raspberry Pi Pico** (or other RP2040 board with CircuitPython Wi-Fi support)
*   **MFRC522 RFID Module**
*   **NTAG 215** or **Mifare Classic 1KB** cards/fobs
*   Wires & Breadboard
*   **Wi-Fi Network** (optional, required for Web UI functionality)

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
    *   Also ensure you have `adafruit_hid`, `adafruit_httpserver`, and `busio` installed.
3.  **Copy Code**: Copy `code.py` to the root of the drive.
4.  **Copy Web UI**: Copy `index.html` to the root of the drive (required for the web interface).
5.  **Configure Wi-Fi** (optional, for Web UI): Create `settings.toml` in the root and add your Wi-Fi credentials:
    ```toml
    SSID = "your-wifi-network-name"
    PASS = "your-wifi-password"
    ```

## Configuration

### Master Secret

Open `code.py` and configure your **Master Secret**. This is the core of the security system.

```python
# --- Security Config ---
# CHANGE THIS to a unique secret for your device!
MASTER_SECRET = b"SuperSecretKey123" 
```

*   **MASTER_SECRET**: This key is mixed with the Card UID to generate the encryption keystream.
*   **Effect**: A card written with one device's secret cannot be read by another device with a different secret.

### Wi-Fi Configuration (for Web UI)

To enable the Web UI, configure your Wi-Fi credentials in `settings.toml`:

```toml
SSID = "your-wifi-network-name"
PASS = "your-wifi-password"
WIFI_ENABLED = 1
WEBUI_ENABLED = 1
```

*   **WIFI_ENABLED**: Set to 1 to enable Wi-Fi connection (required for TOTP/NTP).
*   **WEBUI_ENABLED**: Set to 1 to enable the Web UI.
*   **Effect**:
    *   If `WIFI_ENABLED=1` and `WEBUI_ENABLED=0`: Device connects to Wi-Fi for time sync, but Web UI is disabled (Secure 2FA Mode).
    *   If `WEBUI_ENABLED=1`: Device connects to Wi-Fi and starts the Web UI at `http://<device-ip>/`.
If you dont want to use wifi or your device does not support it set WEBUI_ENABLED to 0.

The device will automatically connect to Wi-Fi on boot and display its IP address in the serial console. The Web UI will be available at `http://<device-ip>/`.

## Usage

### Reading via USB (HID Mode)
Just tap a programmed card.
1.  **Detect**: Reader scans UID.
2.  **Verify**: Checks for Magic Header (`PfId`, `PfUs`, or `PfMc`).
3.  **Decrypt**: Uses (UID + Master Secret) to unlock the payload.
4.  **Execute**:
    *   **Password Only**: Types `password` -> `Enter`.
    *   **Username + Password**: Types `username` -> `Tab` -> `password` -> `Enter`.
    *   **Macro**: Parses and executes the macro sequence (key presses, combinations, delays, etc.).
    *   **TOTP**: Calculates current 2FA code (HMAC-SHA1) and types it.

### Web Management Interface

The device includes a modern web-based management interface that runs on the Pico itself. This allows you to manage your RFID cards through any web browser without needing serial console access.

#### Accessing the Web UI

1.  **Configure Wi-Fi**: Set up your Wi-Fi credentials in `settings.toml` (see Configuration section).
2.  **Power on the device**: The device will connect to Wi-Fi automatically and print its IP address to the serial console.
3.  **Open your browser**: Navigate to `http://<device-ip>/` (e.g., `http://192.168.1.100/`).

#### Web UI Features

The Web UI provides an intuitive interface for all card management operations:

*   **Write Credentials**: 
    *   **Password Only**: Write a simple password card
    *   **Username + Password**: Write username and password combination
    *   **Advanced Macro**: Write Rubber Ducky-style macros with full syntax support
    *   **TOTP Authenticator**: Write Base32 2FA secrets (e.g., from Google Authenticator)
*   **Read Cards**: Inspect card contents without executing them
    *   Displays card type, UID, and formatted data
    *   For macros, shows parsed command breakdown
*   **Wipe Cards**: Securely erase card data
*   **Real-time Status**: Live status updates showing device state and operation results
*   **Read Results Display**: Formatted JSON output showing card contents

#### Using the Web UI

1.  **Writing a Card**:
    *   Select the card type (Password Only, Username + Password, or Advanced Macro)
    *   Enter your credentials or macro text
    *   Click "Burn to Card"
    *   Scan your RFID card when prompted (status will change to "Waiting for card...")
    *   The card will be written and encrypted automatically

2.  **Reading a Card**:
    *   Click "Read Card"
    *   Scan the card when prompted
    *   Results will appear in the "Read Result" panel, showing:
        *   Card UID
        *   Card type
        *   Decrypted data
        *   For macros: parsed command breakdown

3.  **Wiping a Card**:
    *   Click "Wipe Card"
    *   Scan the card when prompted
    *   All data will be erased from the card

The Web UI automatically detects when cards are scanned and updates the status in real-time. All operations use the same encryption and security features as the serial console.

### Management Console (Serial)
Connect to the Pico's serial console to manage cards.

#### Basic Commands

*   `write <password>`:
    *   Writes a **Password Only** tag (Header: `PfId`).
    *   Uses legacy single-block mode for small data (< 44 bytes).
*   `write <username> <password>`:
    *   Writes a **Username + Password** tag (Header: `PfUs`).
    *   Uses legacy single-block mode for small data (< 44 bytes).
*   `read`:
    *   Reads and displays card contents without executing.
    *   Shows card type, UID, data content, and for macros, a parsed command breakdown.
    *   Useful for debugging and verification.
    *   **Example Usage:**
        ```
        > read
        Scan card to READ contents (will not execute)...
        [Scan card]
        ==================================================
        Card UID: ['0x4', '0xce', '0xfa', '0xdf', '0x78', '0x0', '0x0']
        Card Type: Advanced Macro
        Macro Length: 16 characters
        Macro Content:
        --------------------------------------------------
        hello{KEY:ENTER}
        --------------------------------------------------
        Parsed Commands: 2
          1. TEXT: "hello"
          2. KEY: ENTER
        ==================================================
        ```
*   `wipe`:
    *   Wipes all data from the card (detects and clears chained data automatically).
*   `webui <on/off>`:
    *   Enable or disable the Web UI.
    *   **Note**: `webui off` disables the server but **leaves Wi-Fi connected** to maintain time sync for TOTP.
*   `wifi <on/off>`:
    *   Enable or disable Wi-Fi.
    *   **Note**: `wifi off` disconnects Wi-Fi AND stops the Web UI (since it requires network).
    *   **Example Usage:**
        ```
        > wifi on
        WiFi connected successfully.
        ```

#### Advanced Macro Commands

*   `macro <macro_text>`:
    *   Writes an **Advanced Macro** tag (Header: `PfMc`).
    *   Automatically uses chained storage mode for any size data.
    *   Supports Rubber Ducky-style syntax with key sequences, combinations, and delays.

*   `totp <base32_secret>`:
    *   Writes a **TOTP Authenticator** tag (Header: `Pf2F`).
    *   Stores the secret (Base32) and generates codes on scan.
    *   **Note**: Requires Wi-Fi to sync time via NTP.

### Reading Card Contents

The `read` command allows you to inspect card contents without executing them. This is useful for:
*   Verifying what data is stored on a card
*   Debugging macro syntax
*   Checking card type and encryption status
*   Viewing parsed macro commands

**Usage:**
1. Type `read` in the serial console
2. Scan the card when prompted
3. View the formatted output showing card details

**Example Outputs:**

**Password Card:**
```
> read
Scan card to READ contents (will not execute)...
==================================================
Card UID: ['0x4', '0xce', '0xfa', '0xdf', '0x78', '0x0', '0x0']
Card Type: Password Only (Legacy)
Password: mypassword123
Length: 13 characters
==================================================
```

**Username + Password Card:**
```
> read
Scan card to READ contents (will not execute)...
==================================================
Card UID: ['0x4', '0xce', '0xfa', '0xdf', '0x78', '0x0', '0x0']
Card Type: Username + Password
Username: myuser
Password: mypass123
Total Length: 17 characters
==================================================
```

**Macro Card:**
```
> read
Scan card to READ contents (will not execute)...
==================================================
Card UID: ['0x4', '0xce', '0xfa', '0xdf', '0x78', '0x0', '0x0']
Card Type: Advanced Macro
Macro Length: 28 characters
Macro Content:
--------------------------------------------------
sudo apt update{KEY:ENTER}{DELAY:2000}sudo apt upgrade -y{KEY:ENTER}
--------------------------------------------------
Parsed Commands: 5
  1. TEXT: "sudo apt update"
  2. KEY: ENTER
  3. DELAY: 2000ms
  4. TEXT: "sudo apt upgrade -y"
  5. KEY: ENTER
==================================================
```

### Storage Capacity

The system automatically selects the appropriate storage mode:

*   **Legacy Mode** (< 44 bytes): Single block/page storage
    *   Mifare: 3 blocks (48 bytes total, 44 bytes payload)
    *   NTAG: 12 pages (48 bytes total, 44 bytes payload)
*   **Chained Mode** (≥ 44 bytes or explicit macro): Multi-block/page storage
    *   Mifare 1K: Up to 44 data blocks = ~660 bytes payload
    *   NTAG215: Up to 131 user pages = ~393 bytes payload

## Rubber Ducky Macro Format

The system supports advanced macros similar to USB Rubber Ducky scripts. Macros can include plain text, key presses, key combinations, and delays.

### Macro Syntax

Macros use a simple command format with curly braces `{}`:

*   **Plain Text**: Type text directly (e.g., `hello world`)
*   **Single Keys**: `{KEY:ENTER}`, `{KEY:TAB}`, `{KEY:SPACE}`, etc.
*   **Key Combinations**: `{COMBO:CTRL+C}`, `{COMBO:ALT+TAB}`, `{COMBO:SHIFT+F10}`, etc.
*   **Delays**: `{DELAY:500}` (milliseconds)
*   **Explicit Strings**: `{STRING:text}` (useful after commands)

### Supported Keys

#### Navigation Keys
*   `ENTER`, `TAB`, `SPACE`, `BACKSPACE`, `DELETE`, `ESCAPE`
*   `UP`, `DOWN`, `LEFT`, `RIGHT` (arrow keys)
*   `HOME`, `END`, `PAGE_UP`, `PAGE_DOWN`, `INSERT`

#### Function Keys
*   `F1` through `F12`

#### Modifiers (for combinations)
*   `CTRL` / `CONTROL`
*   `SHIFT`
*   `ALT`
*   `GUI` / `WINDOWS` / `CMD`

### Macro Examples

#### Simple Password Entry
```
macro mypassword123{KEY:ENTER}
```
Types the password and presses Enter.

#### Copy and Paste
```
macro {COMBO:CTRL+C}{DELAY:100}{COMBO:CTRL+V}
```
Copies selected text, waits 100ms, then pastes it.

#### Command with Delays
```
macro sudo apt update{KEY:ENTER}{DELAY:2000}sudo apt upgrade -y{KEY:ENTER}
```
Runs `sudo apt update`, waits 2 seconds, then runs `sudo apt upgrade -y`.

#### Username + Tab + Password
```
macro myuser{KEY:TAB}mypass{KEY:ENTER}
```
Types username, presses Tab, types password, presses Enter.

#### Complex Sequence
```
macro {COMBO:ALT+TAB}{DELAY:500}Hello World{KEY:ENTER}
```
Switches windows (Alt+Tab), waits 500ms, types "Hello World", presses Enter.

#### Multi-line Command
```
macro cd /home/user{KEY:ENTER}{DELAY:500}ls -la{KEY:ENTER}
```
Changes directory, waits, then lists files.

### Writing Macros

1. Connect to the Pico's serial console (e.g., using `screen`, `minicom`, or Arduino IDE Serial Monitor).
2. Type: `macro <your_macro_text>`
3. Press Enter.
4. Scan your RFID card when prompted.
5. The macro is stored encrypted on the card.

**Example:**
```
> macro sudo systemctl restart sshd{KEY:ENTER}
Scan card to BURN macro (28 bytes)
WARNING: existing cards must be wiped or overwritten.
[Scan card...]
Write Success (NTAG Macro/Chained)!
```

### Reading Macros

Simply scan the programmed card. The system will:
1. Detect the macro header (`PfMc`)
2. Decrypt the macro data
3. Parse the macro commands
4. Execute them as keyboard input

The macro executes immediately when the card is scanned, so be careful with macros that perform destructive actions!

### Tips for Writing Macros

*   **Test First**: Test macros in a safe environment before using them on important systems.
*   **Use Delays**: Add delays (`{DELAY:500}`) between commands if the target system is slow to respond.
*   **Escape Sequences**: For special characters, use key combinations or explicit strings.
*   **Length Limits**: Remember storage limits (660 bytes for Mifare, 393 bytes for NTAG215).
*   **Backward Compatibility**: Legacy password/username cards continue to work alongside macro cards.

## Hardware 2FA (TOTP)

The device can act as a physical 2FA token (like a programmable hardware token).

1.  **Get Secret**: When setting up 2FA on a website, look for the "enter key manually" option to get the Base32 secret (e.g., `JBSWY3DPEHPK3PXP`).
2.  **Write Card**:
    *   **Web UI**: Select "TOTP Authenticator", paste the secret, and click Burn.
    *   **Serial**: Run `totp JBSWY3DPEHPK3PXP`.
3.  **Usage**: When prompted for a 2FA code, scan the card. The device will calculate the current code and type it.


### Prerequisites
*   **Wi-Fi Connection**: The Pico **MUST** be connected to Wi-Fi to synchronize its internal clock via NTP. Without accurate time, generated codes will be rejected by the service.
*   **Configuration**: Ensure `settings.toml` has valid `SSID` and `PASS`. Set `WIFI_ENABLED = 1`. `WEBUI_ENABLED` can be 0 if you want 2FA without the management interface.

### Troubleshooting
*   **Code Rejected?**:
    *   Check if the Pico has synced time (look for "TOTP: Time synced!" in serial output on boot).
    *   Wait for the next 30-second window and try again.
*   **"Time Sync Failed"**: Check your Wi-Fi credentials in `settings.toml`.
*   **Generic Error**: Ensure the secret was valid Base32 (A-Z, 2-7).

### Security
The TOTP secret is stored **encrypted** on the card using the same UID-binding mechanism as passwords. Use the `MASTER_SECRET` in `code.py` to ensure only your reader can generate codes from your cards.


