import board
import busio
import digitalio
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
import mfrc522
import time
import supervisor
import sys
import json
import wifi
import socketpool
import os
import sys

# Ensure lib directory is in path
if "lib" not in sys.path:
    sys.path.append("lib")

from adafruit_httpserver import Server, Request, Response
import rtc
import adafruit_ntp
import adafruit_hashlib as hashlib
import struct

# --- Setup ---
sck = board.GP18
mosi = board.GP19
miso = board.GP16
cs = board.GP17
rst = board.GP22

reader = mfrc522.MFRC522(sck, mosi, miso, rst, cs)

kbd = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

# --- Wi-Fi & WebUI Setup ---
# Read WebUI enabled flag (default to False if not set)
# Supports: 1/0 (integer), true/false (boolean), or "true"/"false" (string)
# Supports: 1/0 (integer), true/false (boolean), or "true"/"false" (string)
webui_enabled = False
wifi_enabled = False

def parse_bool_env(key, default=False):
    try:
        val = os.getenv(key)
        if val is not None:
            if isinstance(val, bool):
                return val
            elif isinstance(val, (int, float)):
                return bool(val)
            else:
                return str(val).lower().strip() in ("true", "1", "yes", "on")
    except Exception:
        pass
    return default

webui_enabled = parse_bool_env("WEBUI_ENABLED", False)
wifi_enabled = parse_bool_env("WIFI_ENABLED", False)
# If WebUI is enabled, WiFi must be enabled essentially (but we treat them as separate flags for startup intent)
# We won't force wifi_enabled=True here, but we will ensure WiFi connects if WebUI is requested.


ssid = os.getenv("SSID")
password = os.getenv("PASS")

# Global variables for web UI state
pool = None
server = None
wifi_connected = False

def connect_wifi():
    """Connect to WiFi if not already connected"""
    global wifi_connected, ssid, password
    
    if not ssid or not password:
        print("WiFi: SSID or PASS not configured in settings.toml")
        return False
        
    if wifi_connected and wifi.radio.ipv4_address:
        return True
        
    print(f"WiFi: Connecting to {ssid}...")
    try:
        wifi.radio.connect(ssid, password)
        # Wait for connection
        max_retries = 20
        retry_count = 0
        while not wifi.radio.ipv4_address and retry_count < max_retries:
            time.sleep(0.5)
            retry_count += 1
        
        if wifi.radio.ipv4_address:
            print(f"WiFi: Connected! IP: {wifi.radio.ipv4_address}")
            wifi_connected = True
            return True
        else:
            print("WiFi: Connection timeout")
            return False
    except Exception as e:
        print(f"WiFi: Connection failed: {e}")
        return False

def disconnect_wifi():
    """Disconnect WiFi"""
    global wifi_connected
    if wifi_connected:
        try:
            wifi.radio.stop_station()
            print("WiFi: Disconnected")
        except Exception as e:
            print(f"WiFi: Error disconnecting: {e}")
        wifi_connected = False

def start_web_server():
    """Start the WebUI server (requires WiFi)"""
    global pool, server, wifi_connected
    
    if server is not None:
        print("WebUI: Server already running")
        return True
        
    if not wifi_connected or not wifi.radio.ipv4_address:
        print("WebUI: Cannot start - WiFi not connected")
        if not connect_wifi():
            return False
            
    try:
        pool = socketpool.SocketPool(wifi.radio)
        server = Server(pool, "/static", debug=True)
        setup_web_routes()
        server.start(str(wifi.radio.ipv4_address))
        print(f"WebUI: Server started at http://{wifi.radio.ipv4_address}/")
        return True
    except Exception as e:
        print(f"WebUI: Failed to start server: {e}")
        return False

def stop_web_server():
    """Stop the WebUI server"""
    global pool, server
    
    if server is not None:
        try:
            server.stop()
            print("WebUI: Server stopped")
        except Exception as e:
            print(f"WebUI: Error stopping server: {e}")
        server = None
    
    if pool is not None:
        pool = None

def url_decode(encoded):
    """
    Decodes a URL-encoded string.
    """
    res = []
    i = 0
    length = len(encoded)
    while i < length:
        char = encoded[i]
        if char == '+':
            res.append(' ')
            i += 1
        elif char == '%' and i + 2 < length:
            try:
                hex_val = encoded[i+1:i+3]
                res.append(chr(int(hex_val, 16)))
                i += 3
            except Exception:
                res.append('%')
                i += 1
        else:
            res.append(char)
            i += 1
    return "".join(res)

def parse_form_data(body):
    """Simple parser for x-www-form-urlencoded data"""
    data = {}
    try:
        query_string = body.decode("utf-8")
        pairs = query_string.split("&")
        for pair in pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                data[key] = url_decode(value)
    except Exception:
        pass
    return data

def setup_web_routes():
    """Setup all web server routes"""

    @server.route("/")
    def base(request: Request):
        try:
            with open("index.html", "r") as f:
                html = f.read()
                return Response(request, html, content_type="text/html")
        except Exception as e:
             return Response(request, f"Error loading UI: {e}", content_type="text/plain")

    @server.route("/write", methods=["POST"])
    def write_card_web(request: Request):
        global current_state, pending_data, pending_header, last_web_status
        
        data = parse_form_data(request.body)
        
        card_type = data.get("type", "pass")
        username = data.get("username", "")
        password = data.get("password", "")
        macro_text = data.get("macro_text", "")
        
        print(f"WebUI Write Request: type={card_type}, user='{username}', pass='{password}'")
        
        if card_type == "user":
            pending_data = f"{username}\n{password}"
            pending_header = MAGIC_HEADER_USER
        elif card_type == "macro":
            pending_data = macro_text
            pending_header = MAGIC_HEADER_MACRO
        elif card_type == "totp":
            pending_data = data.get("totp_secret", "").replace(" ", "").upper()
            pending_header = MAGIC_HEADER_TOTP
        else:
            pending_data = password
            pending_header = MAGIC_HEADER_PASS
            
        current_state = STATE_WRITE_WAIT
        type_name = {"pass": "password", "user": "username+password", "macro": "macro", "totp": "totp"}.get(card_type, "data")
        last_web_status = f"Waiting for card to write ({type_name})..."
        print(f"WebUI: Ready to write ({card_type})")
        
        return Response(request, "Device is READY. Scan card to WRITE.", content_type="text/plain")

    @server.route("/wipe", methods=["POST"])
    def wipe_card_web(request: Request):
        global current_state, last_web_status
        current_state = STATE_WIPE_WAIT
        last_web_status = "Waiting for card to wipe..."
        print("WebUI: Ready to wipe")
        return Response(request, "Device is READY. Scan card to WIPE.", content_type="text/plain")

    @server.route("/read", methods=["POST"])
    def read_card_web(request: Request):
        global current_state, last_web_status, last_read_result
        current_state = STATE_READ_WAIT
        last_web_status = "Waiting for card to read..."
        last_read_result = None # Clear previous result
        print("WebUI: Ready to read")
        return Response(request, "Device is READY. Scan card to READ.", content_type="text/plain")

    @server.route("/status", methods=["GET"])
    def get_status(request: Request):
        global last_web_status, last_read_result
        status_data = {
            "status": last_web_status,
            "read_result": last_read_result
        }
        return Response(request, json.dumps(status_data), content_type="application/json")




# --- RFID Config ---
# --- RFID Config ---
# Sector 1 blocks: 4, 5, 6 (Data), 7 (Trailer - Keys)
SECTOR_BLOCKS = [4, 5, 6]
# NTAG Pages: 4 bytes each. We need 48 bytes -> 12 pages.
# Start at Page 4 (User Memory). Ends at Page 15.
NTAG_START_PAGE = 4
NTAG_PAGES = 12 

# Common Default Keys
KNOWN_KEYS = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], # Factory Default
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], # Blank / Null
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], # NXP / Madigan
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], # NFC Forum
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A]
]

# --- Security Config ---
# CHANGE THIS to a unique secret for your device!
MASTER_SECRET = b"SuperSecretKey123" 
MAGIC_HEADER_PASS = b"PfId" # Password-RFID ID (Legacy/Default)
MAGIC_HEADER_USER = b"PfUs" # Password-RFID User+Pass
MAGIC_HEADER_MACRO = b"PfMc" # Password-RFID Macro
MAGIC_HEADER_TOTP = b"Pf2F" # Password-RFID TOTP

# Continuation flags for chained blocks/pages
CONTINUE_FLAG = 0xFF  # Continue to next block/page
END_FLAG = 0x00       # End of data

# Storage limits
MIFARE_MAX_BLOCKS = 44  # Usable data blocks (excluding trailers and reserved)
NTAG_MAX_PAGES = 131    # User memory pages (pages 4-134)

TYPE_UNKNOWN = 0
TYPE_PASS = 1
TYPE_USER = 2
TYPE_MACRO = 3
TYPE_TOTP = 4
TYPE_TOTP = 4

# Keycode name mapping for macro parser
KEYCODE_MAP = {
    'ENTER': Keycode.ENTER,
    'TAB': Keycode.TAB,
    'SPACE': Keycode.SPACE,
    'BACKSPACE': Keycode.BACKSPACE,
    'DELETE': Keycode.DELETE,
    'ESCAPE': Keycode.ESCAPE,
    'UP': Keycode.UP_ARROW,
    'DOWN': Keycode.DOWN_ARROW,
    'LEFT': Keycode.LEFT_ARROW,
    'RIGHT': Keycode.RIGHT_ARROW,
    'HOME': Keycode.HOME,
    'END': Keycode.END,
    'PAGE_UP': Keycode.PAGE_UP,
    'PAGE_DOWN': Keycode.PAGE_DOWN,
    'INSERT': Keycode.INSERT,
    'F1': Keycode.F1, 'F2': Keycode.F2, 'F3': Keycode.F3, 'F4': Keycode.F4,
    'F5': Keycode.F5, 'F6': Keycode.F6, 'F7': Keycode.F7, 'F8': Keycode.F8,
    'F9': Keycode.F9, 'F10': Keycode.F10, 'F11': Keycode.F11, 'F12': Keycode.F12,
}

MODIFIER_MAP = {
    'CTRL': Keycode.CONTROL,
    'CONTROL': Keycode.CONTROL,
    'SHIFT': Keycode.SHIFT,
    'ALT': Keycode.ALT,
    'GUI': Keycode.GUI,
    'WINDOWS': Keycode.GUI,
    'CMD': Keycode.GUI,
}

def derive_key(uid, length=48):
    """
    Derives a simple encryption key from the UID and Master Secret.
    Returns a bytearray of the specified length.
    """
    # Simple mixer: Just repeat/XOR UID + Secret to make a keystream
    # Let's make a stream generator seed.
    seed = 0
    for b in uid:
        seed = (seed * 31 + b) & 0xFFFF
    
    for b in MASTER_SECRET:
        seed = (seed * 31 + b) & 0xFFFF
        
    # Generate pseudo-random keystream based on seed
    key_stream = bytearray(length)
    state = seed
    for i in range(length):
        # Linear Congruential Generator (LCG) - primitive but deterministic
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        key_stream[i] = (state >> 16) & 0xFF
        
    # DEBUG: Print key hash
    # print(f"DEBUG: Key[{len(key_stream)}]: {list(key_stream[:5])}...")
    return key_stream

def xor_crypt(data, key_stream):
    """XORs data with key_stream."""
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key_stream[i % len(key_stream)]
    return out

# --- TOTP & Time Logic ---
def sync_time():
    """Syncs usage RTC via NTP if Wi-Fi is connected."""
    global wifi_connected
    if not wifi_connected or not pool:
        print("TOTP: Cannot sync time (No Wi-Fi)")
        return False
        
    print("TOTP: Syncing time via NTP...")
    try:
        ntp = adafruit_ntp.NTP(pool, tz_offset=0)
        rtc.RTC().datetime = ntp.datetime
        print(f"TOTP: Time synced! Current UTC: {time.time()}")
        return True
    except Exception as e:
        print(f"TOTP: Time sync failed: {e}")
        return False

def base32_decode(encoded):
    """Simple Base32 decoder (RFC 4648)"""
    # Standard Base32 alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    padding = "="
    
    encoded = encoded.upper().rstrip(padding)
    res_bits = 0
    res_buffer = 0
    output = bytearray()
    
    for char in encoded:
        if char not in alphabet:
            continue
        val = alphabet.index(char)
        res_buffer = (res_buffer << 5) | val
        res_bits += 5
        while res_bits >= 8:
            res_bits -= 8
            output.append((res_buffer >> res_bits) & 0xFF)
            
    return output

def hmac_sha1(key, msg):
    """
    Standard HMAC-SHA1 implementation using adafruit_hashlib
    """
    block_size = 64
    
    if len(key) > block_size:
        # If key is longer than block_size, hash it first
        h = hashlib.sha1()
        h.update(key)
        key = h.digest()
        
    if len(key) < block_size:
        # Pad key with zeros
        key = key + b'\x00' * (block_size - len(key))
        
    # Inner and Outer pads
    o_key_pad = bytearray(x ^ 0x5c for x in key)
    i_key_pad = bytearray(x ^ 0x36 for x in key)
    
    # Inner hash
    h_inner = hashlib.sha1()
    h_inner.update(i_key_pad)
    h_inner.update(msg)
    inner_digest = h_inner.digest()
    
    # Outer hash
    h_outer = hashlib.sha1()
    h_outer.update(o_key_pad)
    h_outer.update(inner_digest)
    return h_outer.digest()

def generate_totp(secret_base32):
    """
    Generates the current 6-digit TOTP code.
    """
    try:
        # Decode secret
        secret_bytes = base32_decode(secret_base32)
        
        # Use time_ns() to avoid 32-bit float precision loss
        try:
             now_ns = time.time_ns()
             now = now_ns // 1000000000
        except AttributeError:
             now = int(time.time())

        # DEBUG: Print time to see if it's advancing
        print(f"DEBUG: TOTP UnixTime={now}")
        
        # Calculate counter
        counter = now // 30
        print(f"DEBUG: TOTP Counter={counter}")
        
        # Pack counter into 8 bytes (big endian)
        msg = struct.pack(">Q", counter)
        
        # HMAC-SHA1
        digest = hmac_sha1(secret_bytes, msg)
        
        # Truncate
        offset = digest[-1] & 0x0F
        code_int = ((digest[offset] & 0x7F) << 24 |
                    (digest[offset + 1] & 0xFF) << 16 |
                    (digest[offset + 2] & 0xFF) << 8 |
                    (digest[offset + 3] & 0xFF))
        
        # Modulo
        code_int_val = code_int % 1000000
        # Manual zfill since .zfill isn't in all CircuitPython builds
        code_str = str(code_int_val)
        while len(code_str) < 6:
            code_str = "0" + code_str
        return code_str
        
    except Exception as e:
        print(f"TOTP Generation Error: {e}")
        return "000000"

# --- Macro Parser and Executor ---
def parse_macro(macro_text):
    """
    Parse macro text into a list of commands.
    Format supports:
    - Plain text: typed as-is
    - {KEY:name} - press a single key (e.g., {KEY:ENTER})
    - {COMBO:modifier+key} - key combination (e.g., {COMBO:CTRL+C})
    - {DELAY:ms} - delay in milliseconds (e.g., {DELAY:500})
    - {STRING:text} - explicitly type text
    
    Returns a list of command dictionaries.
    """
    commands = []
    i = 0
    text_buffer = []
    
    while i < len(macro_text):
        if macro_text[i] == '{':
            # Flush any pending text
            if text_buffer:
                commands.append({'type': 'TEXT', 'value': ''.join(text_buffer)})
                text_buffer = []
            
            # Find closing brace
            end_brace = macro_text.find('}', i)
            if end_brace == -1:
                # Malformed, treat rest as text
                text_buffer.append(macro_text[i:])
                break
            
            # Extract command
            cmd_str = macro_text[i+1:end_brace]
            i = end_brace + 1
            
            # Parse command
            if ':' in cmd_str:
                cmd_type, cmd_value = cmd_str.split(':', 1)
                cmd_type = cmd_type.strip().upper()
                cmd_value = cmd_value.strip()
                
                if cmd_type == 'KEY':
                    commands.append({'type': 'KEY', 'value': cmd_value.upper()})
                elif cmd_type == 'COMBO':
                    commands.append({'type': 'COMBO', 'value': cmd_value.upper()})
                elif cmd_type == 'DELAY':
                    try:
                        delay_ms = int(cmd_value)
                        commands.append({'type': 'DELAY', 'value': delay_ms})
                    except ValueError:
                        pass  # Invalid delay, skip
                elif cmd_type == 'STRING':
                    commands.append({'type': 'TEXT', 'value': cmd_value})
            else:
                # Invalid command format, treat as text
                text_buffer.append('{' + cmd_str + '}')
        else:
            text_buffer.append(macro_text[i])
            i += 1
    
    # Flush remaining text
    if text_buffer:
        commands.append({'type': 'TEXT', 'value': ''.join(text_buffer)})
    
    return commands

def execute_macro(commands):
    """
    Execute a list of macro commands.
    """
    for cmd in commands:
        cmd_type = cmd['type']
        cmd_value = cmd['value']
        
        if cmd_type == 'TEXT':
            # Type text
            layout.write(cmd_value)
            
        elif cmd_type == 'KEY':
            # Press single key
            if cmd_value in KEYCODE_MAP:
                kbd.press(KEYCODE_MAP[cmd_value])
                kbd.release_all()
            else:
                # Try to find keycode by name (case-insensitive search)
                keycode_name = None
                for name, keycode in KEYCODE_MAP.items():
                    if name.upper() == cmd_value.upper():
                        keycode_name = name
                        break
                
                if keycode_name:
                    kbd.press(KEYCODE_MAP[keycode_name])
                    kbd.release_all()
                else:
                    # Unknown key, skip
                    print(f"Unknown key: {cmd_value}")
            
        elif cmd_type == 'COMBO':
            # Key combination (e.g., CTRL+C, ALT+TAB)
            parts = cmd_value.split('+')
            if len(parts) >= 2:
                modifiers = []
                key_name = None
                
                for part in parts[:-1]:
                    part = part.strip().upper()
                    if part in MODIFIER_MAP:
                        modifiers.append(MODIFIER_MAP[part])
                
                key_name = parts[-1].strip().upper()
                
                if modifiers and key_name in KEYCODE_MAP:
                    # Press modifiers + key
                    keys_to_press = modifiers + [KEYCODE_MAP[key_name]]
                    kbd.press(*keys_to_press)
                    kbd.release_all()
                elif key_name in KEYCODE_MAP:
                    # Just the key, no modifiers
                    kbd.press(KEYCODE_MAP[key_name])
                    kbd.release_all()
                else:
                    print(f"Unknown combo: {cmd_value}")
            else:
                # Single key in combo format, treat as KEY
                if cmd_value in KEYCODE_MAP:
                    kbd.press(KEYCODE_MAP[cmd_value])
                    kbd.release_all()
            
        elif cmd_type == 'DELAY':
            # Delay in milliseconds
            time.sleep(cmd_value / 1000.0)
        
        # Small delay between commands for reliability
        time.sleep(0.01)

def is_ntag(uid):
    return len(uid) == 7

# --- NTAG Specifics ---
def read_ntag_chunks(start_page, num_pages):
    """Reads NTAG pages. Note: Each read returns 16 bytes (4 pages)."""
    data = []
    # We need to read 'num_pages' (4 bytes each).
    # Since read(addr) returns 4 pages (16 bytes), we can read in strides of 4.
    
    for p in range(start_page, start_page + num_pages, 4):
        # Read returns 16 bytes (Pages p, p+1, p+2, p+3)
        chunk = reader.read(p)
        if chunk is None:
             return None
        data.extend(chunk)
        
    # If we read more than needed (e.g. asked for 12, read 16), truncate?
    # Actually 12 pages = 48 bytes = 3 strides of 4. Perfect match.
    return data[:num_pages*4]

def write_ntag_chunks(start_page, data):
    """Writes bytes to NTAG. Data must be multiple of 4."""
    # Split into 4-byte pages
    for i in range(0, len(data), 4):
        page_addr = start_page + (i // 4)
        page_data = data[i : i+4]
        if len(page_data) < 4:
            page_data = list(page_data) + [0]*(4-len(page_data))
            
        stat = reader.write_ntag(page_addr, list(page_data))
        if stat != reader.OK:
            return False
    return True

def write_mifare_chained(uid, start_block, encrypted_data):
    """
    Write encrypted data to chained Mifare blocks starting from start_block.
    Data should already be encrypted. Splits into 15-byte chunks with continuation flags.
    Flags are stored as metadata (not encrypted).
    Uses special encoding for last chunk: 0x00 = end with 15 bytes, 0x01-0x0F = end with 1-15 bytes.
    Authenticates sectors as needed when crossing boundaries.
    Returns True on success, False on error.
    """
    # Split encrypted data into 15-byte chunks (16 bytes - 1 byte for flag)
    chunks = []
    for i in range(0, len(encrypted_data), 15):
        chunk = encrypted_data[i:i+15]
        chunks.append(chunk)
    
    if not chunks:
        return False
    
    current_block = start_block
    current_sector = get_sector_from_block(current_block)
    
    # Authenticate first sector
    if not auth_sector(uid, sector=current_sector):
        return False
    
    for i, chunk in enumerate(chunks):
        # Determine continuation flag
        is_last = (i == len(chunks) - 1)
        
        if is_last:
            # Last chunk: encode how many bytes are real
            # 0x00 = end with full 15 bytes, 0x01-0x0F = end with 1-15 bytes
            if len(chunk) == 15:
                flag = END_FLAG  # 0x00 = end, full 15 bytes
            else:
                flag = len(chunk)  # 0x01-0x0F = end with that many bytes
        else:
            flag = CONTINUE_FLAG  # 0xFF = continue
        
        # Pad chunk to 15 bytes if needed (for writing)
        chunk_padded = list(chunk) + [0] * (15 - len(chunk))
        
        # Create block data: 15 bytes encrypted payload + 1 byte flag (metadata)
        block_data = chunk_padded + [flag]
        
        # Write block
        stat = reader.write(current_block, block_data)
        if stat != reader.OK:
            reader.stop_crypto1()
            return False
        
        # If not last chunk, prepare for next block
        if not is_last:
            next_block = get_next_data_block(current_block)
            next_sector = get_sector_from_block(next_block)
            
            # If crossing sector boundary, authenticate new sector
            if next_sector != current_sector:
                reader.stop_crypto1()  # Stop crypto for current sector
                if not auth_sector(uid, sector=next_sector):
                    return False
                current_sector = next_sector
            
            current_block = next_block
            
            # Safety check
            if current_block >= 64:
                reader.stop_crypto1()
                return False
    
    reader.stop_crypto1()
    return True

def write_ntag_chained(start_page, encrypted_data):
    """
    Write encrypted data to chained NTAG pages starting from start_page.
    Data should already be encrypted. Splits into 3-byte chunks with continuation flags.
    Flags are stored as metadata (not encrypted).
    Uses special encoding for last chunk: 0x00 = end with 3 bytes, 0x01-0x03 = end with 1-3 bytes.
    Returns True on success, False on error.
    """
    # Split encrypted data into 3-byte chunks (4 bytes - 1 byte for flag)
    chunks = []
    for i in range(0, len(encrypted_data), 3):
        chunk = encrypted_data[i:i+3]
        chunks.append(chunk)
    
    if not chunks:
        return False
    
    current_page = start_page
    
    for i, chunk in enumerate(chunks):
        # Determine continuation flag
        is_last = (i == len(chunks) - 1)
        
        if is_last:
            # Last chunk: encode how many bytes are real
            # 0x00 = end with full 3 bytes, 0x01-0x03 = end with 1-3 bytes
            if len(chunk) == 3:
                flag = END_FLAG  # 0x00 = end, full 3 bytes
            else:
                flag = len(chunk)  # 0x01, 0x02, or 0x03 = end with that many bytes
        else:
            flag = CONTINUE_FLAG  # 0xFF = continue
        
        # Pad chunk to 3 bytes if needed (for writing)
        chunk_padded = list(chunk) + [0] * (3 - len(chunk))
        
        # Create page data: 3 bytes encrypted payload + 1 byte flag (metadata)
        page_data = chunk_padded + [flag]
        
        # Write page
        stat = reader.write_ntag(current_page, page_data)
        if stat != reader.OK:
            return False
        
        # Move to next page if not last
        if not is_last:
            current_page += 1
            
            # Safety check
            if current_page > 134:
                return False
    
    return True

# --- Mifare Specifics ---
def get_sector_from_block(block_addr):
    """Returns the sector number for a given block address."""
    return block_addr // 4

def get_trailer_block(sector):
    """Returns the trailer block address for a given sector."""
    return (sector * 4) + 3

def is_trailer_block(block_addr):
    """Check if a block address is a trailer block."""
    return (block_addr % 4) == 3

def get_next_data_block(block_addr):
    """Get the next data block, skipping trailer blocks."""
    next_block = block_addr + 1
    if is_trailer_block(next_block):
        next_block += 1  # Skip trailer, go to next sector
    return next_block

def auth_sector(uid, sector=None, block_addr=None):
    """
    Authenticate a Mifare sector.
    If sector is provided, uses that sector's trailer block.
    If block_addr is provided, determines sector from block.
    If neither provided, defaults to sector 1 (legacy behavior).
    """
    if sector is None:
        if block_addr is not None:
            sector = get_sector_from_block(block_addr)
        else:
            sector = 1  # Default to sector 1 for backward compatibility
    
    trailer_block = get_trailer_block(sector)
    
    # Try all known keys
    for i, key in enumerate(KNOWN_KEYS):
        status = reader.auth(reader.AUTHENT1A, trailer_block, key, uid)
        if status == reader.OK:
            return True
        else:
            reader.stop_crypto1()  
    return False

def auth_sector_by_block(uid, block_addr):
    """Helper to authenticate sector containing the given block address."""
    sector = get_sector_from_block(block_addr)
    return auth_sector(uid, sector=sector)

def read_mifare_chained(uid, start_block, max_blocks=MIFARE_MAX_BLOCKS):
    """
    Read chained Mifare blocks starting from start_block.
    Checks continuation flags and authenticates sectors as needed.
    Returns concatenated data or None on error.
    """
    data = []
    current_block = start_block
    current_sector = get_sector_from_block(current_block)
    blocks_read = 0
    
    # Authenticate first sector
    if not auth_sector(uid, sector=current_sector):
        print(f"DEBUG: Auth failed for sector {current_sector}")
        return None
    
    while blocks_read < max_blocks:
        # Read current block
        block_data = reader.read(current_block)
        if block_data is None:
            print(f"DEBUG: Failed to read block {current_block}")
            reader.stop_crypto1()
            return None
        
        # Extract continuation flag (last byte)
        continuation_flag = block_data[15]
        # Extract data (first 15 bytes)
        block_payload = block_data[:15]
        
        print(f"DEBUG: Block {current_block}: flag=0x{continuation_flag:02X}, data_len={len(data)}")
        
        # Check if we should continue
        if continuation_flag == CONTINUE_FLAG:
            # Continue to next block - add all 15 bytes
            data.extend(block_payload)
            blocks_read += 1
        elif continuation_flag == END_FLAG:
            # End with full 15 bytes
            print(f"DEBUG: Found END_FLAG at block {current_block} (full 15 bytes)")
            data.extend(block_payload)
            reader.stop_crypto1()
            return data
        elif 1 <= continuation_flag <= 15:
            # End with partial bytes (1-15)
            bytes_to_take = continuation_flag
            print(f"DEBUG: Found end flag {continuation_flag} at block {current_block} ({bytes_to_take} bytes)")
            data.extend(block_payload[:bytes_to_take])
            reader.stop_crypto1()
            return data
        else:
            # Invalid flag, treat as end (but take what we have)
            print(f"DEBUG: Invalid flag 0x{continuation_flag:02X} at block {current_block}, stopping")
            data.extend(block_payload)
            reader.stop_crypto1()
            return data
        
        # Move to next block
        next_block = get_next_data_block(current_block)
        next_sector = get_sector_from_block(next_block)
        
        # If crossing sector boundary, authenticate new sector
        if next_sector != current_sector:
            reader.stop_crypto1()  # Stop crypto for current sector
            if not auth_sector(uid, sector=next_sector):
                print(f"DEBUG: Auth failed for next sector {next_sector}")
                return None
            current_sector = next_sector
        
        current_block = next_block
        
        # Safety check: don't exceed card limits
        if current_block >= 64:  # Mifare 1K has 64 blocks (0-63)
            print(f"DEBUG: Reached block limit")
            reader.stop_crypto1()
            return data
    
    print(f"DEBUG: Reached max blocks limit")
    reader.stop_crypto1()
    return data

def read_ntag_chained(start_page, max_pages=NTAG_MAX_PAGES):
    """
    Read chained NTAG pages starting from start_page.
    Checks continuation flags in last byte of each page.
    Uses special encoding: 0xFF = continue, 0x00 = end with 3 bytes, 0x01-0x03 = end with 1-3 bytes.
    Returns concatenated data or None on error.
    """
    data = []
    current_page = start_page
    pages_read = 0
    
    while pages_read < max_pages:
        # Read 4 pages at a time (reader.read returns 16 bytes = 4 pages)
        # But we need to check each page individually
        base_page = (current_page // 4) * 4  # Align to 4-page boundary
        chunk = reader.read(base_page)
        if chunk is None:
            print(f"DEBUG: Failed to read NTAG page {base_page}")
            return None
        
        # Extract the specific page we need
        page_offset = current_page % 4
        page_data = chunk[page_offset * 4 : (page_offset + 1) * 4]
        
        # Extract continuation flag (last byte of page)
        continuation_flag = page_data[3]
        # Extract data (first 3 bytes)
        page_payload = page_data[:3]
        
        print(f"DEBUG: Page {current_page}: flag=0x{continuation_flag:02X}, data_len={len(data)}")
        
        # Check if we should continue
        if continuation_flag == CONTINUE_FLAG:
            # Continue to next page - add all 3 bytes
            data.extend(page_payload)
            pages_read += 1
            current_page += 1
        elif continuation_flag == END_FLAG:
            # End with full 3 bytes
            print(f"DEBUG: Found END_FLAG at page {current_page} (full 3 bytes)")
            data.extend(page_payload)
            return data
        elif continuation_flag in [1, 2, 3]:
            # End with partial bytes (1-3)
            bytes_to_take = continuation_flag
            print(f"DEBUG: Found end flag {continuation_flag} at page {current_page} ({bytes_to_take} bytes)")
            data.extend(page_payload[:bytes_to_take])
            return data
        else:
            # Invalid flag, treat as end (but take what we have)
            print(f"DEBUG: Invalid flag 0x{continuation_flag:02X} at page {current_page}, stopping")
            data.extend(page_payload)
            return data
        
        # Safety check: don't exceed card limits
        if current_page > 134:  # NTAG215 pages 0-134
            print(f"DEBUG: Reached page limit")
            return data
    
    print(f"DEBUG: Reached max pages limit")
    return data

def write_card_data(uid, text_data, header=MAGIC_HEADER_PASS):
    print("Writing to card...")
    
    # 1. Prepare Plaintext
    b_data = text_data.encode('utf-8')
    
    # If header is MACRO, always use macro mode (even if small)
    is_macro = (header == MAGIC_HEADER_MACRO)
    
    # ALWAYS use chained mode to prevent read ambiguity
    # This ensures consistency with the reader which prefers chained mode
    use_chained = True
    
    if use_chained:
        # Macro mode - use chained storage
        # Calculate max storage
        if is_ntag(uid):
            # NTAG: 3 bytes per page, max 131 pages = 393 bytes payload
            max_payload = 393
        else:
            # Mifare: 15 bytes per block, max 44 blocks = 660 bytes payload
            max_payload = 660
        
        if len(b_data) > max_payload:
            b_data = b_data[:max_payload]
            print(f"Warning: Data truncated to {max_payload} bytes")
        
        # Use provided header for chained data (do not force macro)
        # Previously we forced MAGIC_HEADER_MACRO here, but we want to preserve types
        payload = list(header) + list(b_data)
        print(f"DEBUG: Writing chained data: {len(b_data)} bytes, header: {header}")
    else:
        # Legacy mode - single block/page
        if len(b_data) > 44:
            b_data = b_data[:44]  # Truncate
        payload = list(header) + list(b_data) + [0] * (44 - len(b_data))
        print(f"DEBUG: Writing legacy data: {len(b_data)} bytes, header: {header}")
    
    # 2. Encrypt
    key_stream = derive_key(uid, length=len(payload))
    encrypted_data = xor_crypt(payload, key_stream)
    
    if is_ntag(uid):
        if use_chained:
            # NTAG Chained Write
            if write_ntag_chained(NTAG_START_PAGE, encrypted_data):
                print("Write Success (NTAG Macro/Chained)!")
                return True
            else:
                print("Write Failed (NTAG Error)")
                return False
        else:
            # NTAG Legacy Write
            if write_ntag_chunks(NTAG_START_PAGE, encrypted_data):
                print("Write Success (NTAG Secure)!")
                return True
            else:
                print("Write Failed (NTAG Error)")
                return False
            
    else:
        if use_chained:
            # Mifare Chained Write
            if write_mifare_chained(uid, SECTOR_BLOCKS[0], encrypted_data):
                print("Write Success (Mifare Macro/Chained)!")
                return True
            else:
                print("Write Failed (Mifare Error)")
                return False
        else:
            # Mifare Legacy Write
            if not auth_sector(uid):
                print("Auth Failed! Write aborted.")
                return False
                
            for i, block_addr in enumerate(SECTOR_BLOCKS):
                chunk = encrypted_data[i*16 : (i+1)*16]
                stat = reader.write(block_addr, list(chunk))
                if stat != reader.OK:
                    print(f"Error writing block {block_addr}")
                    reader.stop_crypto1()
                    return False
                    
            reader.stop_crypto1()
            print("Write Success (Mifare Secure)!")
            return True

def decrypt_and_parse(uid, raw_data):
    """
    Helper to decrypt and check header.
    Returns (card_type, content) or (TYPE_UNKNOWN, None)
    """
    if not raw_data or len(raw_data) < 4:
        return (TYPE_UNKNOWN, None)
        
    try:
        # Decrypt
        key_stream = derive_key(uid, length=len(raw_data))
        decrypted_data = xor_crypt(raw_data, key_stream)
        
        # Check Magic Header
        card_type = TYPE_UNKNOWN
        payload_start = 0
        
        header = decrypted_data[:4]
        if header == MAGIC_HEADER_PASS:
            card_type = TYPE_PASS
            payload_start = 4
        elif header == MAGIC_HEADER_USER:
            card_type = TYPE_USER
            payload_start = 4
        elif header == MAGIC_HEADER_MACRO:
            card_type = TYPE_MACRO
            payload_start = 4
        elif header == MAGIC_HEADER_TOTP:
            card_type = TYPE_TOTP
            payload_start = 4
        else:
            # Invalid header
            return (TYPE_UNKNOWN, None)
            
        # Strip Header
        payload = decrypted_data[payload_start:]
        
        # Decode
        if card_type == TYPE_MACRO or card_type == TYPE_TOTP:
            # Macro/TOTP data - return all bytes until null (or end)
            final_chars = []
            for b in payload:
                if b == 0:
                    break
                final_chars.append(chr(b))
            final_str = "".join(final_chars)
            return (card_type, final_str)
        else:
            # Legacy mode - stop at first null
            final_chars = []
            for b in payload:
                if b == 0:
                    break
                final_chars.append(chr(b))
            final_str = "".join(final_chars)
            return (card_type, final_str)
            
    except Exception as e:
        print(f"Decryption Error: {e}")
        return (TYPE_UNKNOWN, None)

def read_card_data(uid):
    """
    Robust read function.
    1. Try Chained Read -> Decrypt -> Check Header.
    2. If invalid, Try Legacy Read -> Decrypt -> Check Header.
    """
    
    # --- Attempt 1: Chained Mode ---
    print("DEBUG: Attempting Chained Read...")
    raw_chained = None
    if is_ntag(uid):
        raw_chained = read_ntag_chained(NTAG_START_PAGE)
    else:
        raw_chained = read_mifare_chained(uid, SECTOR_BLOCKS[0])
        
    if raw_chained:
        res_type, res_data = decrypt_and_parse(uid, raw_chained)
        if res_type != TYPE_UNKNOWN:
            print(f"DEBUG: Chained Read Successful (Type {res_type})")
            return (res_type, res_data)
        else:
            print("DEBUG: Chained Read yielded invalid header. Trying Legacy...")
    
    # --- Attempt 2: Legacy Mode ---
    print("DEBUG: Attempting Legacy Read...")
    raw_legacy = []
    
    if is_ntag(uid):
        raw_legacy = read_ntag_chunks(NTAG_START_PAGE, NTAG_PAGES)
    else:
        # Mifare
        current_sector = get_sector_from_block(SECTOR_BLOCKS[0])
        # Re-authenticate for legacy read (in case previous auth state is mixed)
        reader.stop_crypto1()
        if not auth_sector(uid, sector=current_sector):
             print("DEBUG: Legacy Auth Failed")
             return (TYPE_UNKNOWN, None)
             
        for block_addr in SECTOR_BLOCKS:
            block_data = reader.read(block_addr)
            if block_data is not None:
                raw_legacy.extend(block_data)
            else:
                 print(f"DEBUG: Legacy read error at block {block_addr}")
                 return (TYPE_UNKNOWN, None)
        reader.stop_crypto1()
        
    if raw_legacy:
        res_type, res_data = decrypt_and_parse(uid, raw_legacy)
        if res_type != TYPE_UNKNOWN:
            print(f"DEBUG: Legacy Read Successful (Type {res_type})")
            return (res_type, res_data)
            
    print("DEBUG: All read attempts failed or data invalid.")
    return (TYPE_UNKNOWN, None)

def wipe_card(uid):
    # First, try to read chained data to find all used blocks/pages
    used_blocks = []
    used_pages = []
    
    if is_ntag(uid):
        # Try to read chained data to find used pages
        current_page = NTAG_START_PAGE
        while current_page <= 134:
            base_page = (current_page // 4) * 4
            chunk = reader.read(base_page)
            if chunk is None:
                break
            
            page_offset = current_page % 4
            page_data = chunk[page_offset * 4 : (page_offset + 1) * 4]
            continuation_flag = page_data[3]
            
            used_pages.append(current_page)
            
            if continuation_flag == END_FLAG:
                break
            if continuation_flag != CONTINUE_FLAG:
                break
            
            current_page += 1
        
        # Wipe all used pages
        if used_pages:
            for page in used_pages:
                zeros_page = [0] * 4
                reader.write_ntag(page, zeros_page)
            print(f"NTAG Wiped ({len(used_pages)} pages).")
        else:
            # Fallback: wipe legacy range
            zeros = [0] * 48
            if write_ntag_chunks(NTAG_START_PAGE, zeros):
                print("NTAG Wiped (legacy).")
            else:
                print("NTAG Wipe Failed.")
                return False
        return True
    else:
        # Try to read chained data to find used blocks
        current_block = SECTOR_BLOCKS[0]
        current_sector = get_sector_from_block(current_block)
        
        if not auth_sector(uid, sector=current_sector):
            print("Auth Failed! Wipe aborted.")
            return False
        
        while current_block < 64:
            block_data = reader.read(current_block)
            if block_data is None:
                reader.stop_crypto1()
                break
            
            continuation_flag = block_data[15]
            used_blocks.append(current_block)
            
            if continuation_flag == END_FLAG:
                reader.stop_crypto1()
                break
            if continuation_flag != CONTINUE_FLAG:
                reader.stop_crypto1()
                break
            
            # Move to next block
            next_block = get_next_data_block(current_block)
            next_sector = get_sector_from_block(next_block)
            
            if next_sector != current_sector:
                reader.stop_crypto1()
                if not auth_sector(uid, sector=next_sector):
                    break
                current_sector = next_sector
            
            current_block = next_block
        
        # Wipe all used blocks
        if used_blocks:
            zeros_block = [0] * 16
            for block_addr in used_blocks:
                sector = get_sector_from_block(block_addr)
                if not auth_sector(uid, sector=sector):
                    print(f"Auth Failed for sector {sector}! Wipe incomplete.")
                    reader.stop_crypto1()
                    return False
                reader.write(block_addr, zeros_block)
            reader.stop_crypto1()
            print(f"Card Wiped ({len(used_blocks)} blocks).")
        else:
            # Fallback: wipe legacy blocks
            if not auth_sector(uid):
                print("Auth Failed! Wipe aborted.")
                return False
                
            zeros_block = [0] * 16
            for block_addr in SECTOR_BLOCKS:
                reader.write(block_addr, zeros_block)
                
            reader.stop_crypto1()
            print("Card Wiped (legacy).")
        return True

# --- State Machine ---
# Initialize WebUI if enabled
# --- State Machine ---

# 1. Handle WiFi Startup
if wifi_enabled or webui_enabled:
    if connect_wifi():
        sync_time()
else:
    print("WiFi: Disabled in settings.toml")

# 2. Handle WebUI Startup (only if specifically enabled)
if webui_enabled:
    if wifi_connected:
        start_web_server()
    else:
        print("WebUI: Could not start (WiFi failed)")
else:
    if wifi_enabled: 
        print("WebUI: Disabled (WiFi is ON for Time Sync/2FA)")
    else:
        print("WebUI: Disabled")

STATE_IDLE = 0
STATE_WRITE_WAIT = 1
STATE_WIPE_WAIT = 2
STATE_READ_WAIT = 3

current_state = STATE_IDLE
pending_data = ""
pending_header = MAGIC_HEADER_PASS
last_web_status = "Device Ready"
last_read_result = None

print("Ready (Secure On-Card Storage Mode).")
print("Type 'write <pass>' or 'write <user> <pass>' to burn credentials.")
print("Large data (>44 bytes) automatically uses macro/chained mode.")

def process_command(cmd):
    global current_state, pending_data, pending_header, webui_enabled
    parts = cmd.split()
    if not parts: return
    
    op = parts[0].lower()
    
    if op == "write":
        if len(parts) < 2:
            print("Usage: write <password> OR write <username> <password>")
        else:
            if len(parts) == 2:
                # Password only
                pending_data = parts[1]
                pending_header = MAGIC_HEADER_PASS
            else:
                # Username + Password
                pending_data = parts[1] + "\n" + " ".join(parts[2:])
                pending_header = MAGIC_HEADER_USER
                
            current_state = STATE_WRITE_WAIT
            print(f"Scan card to BURN credentials")
            print("WARNING: existing cards must be wiped or overwritten.")
            
    elif op == "macro":
        if len(parts) < 2:
            print("Usage: macro <macro_text>")
            print("Writes a macro with advanced key sequences (Rubber Ducky style).")
            print("Supports up to ~660 bytes (Mifare) or ~393 bytes (NTAG215).")
            print("")
            print("Macro Format:")
            print("  Plain text: typed as-is")
            print("  {KEY:ENTER} - press Enter key")
            print("  {KEY:TAB} - press Tab key")
            print("  {COMBO:CTRL+C} - key combination (Ctrl+C)")
            print("  {COMBO:ALT+TAB} - key combination (Alt+Tab)")
            print("  {DELAY:500} - delay 500 milliseconds")
            print("  {STRING:text} - explicitly type text")
            print("")
            print("Examples:")
            print("  macro Hello{KEY:ENTER}")
            print("  macro {COMBO:CTRL+C}{DELAY:100}{COMBO:CTRL+V}")
            print("  macro sudo apt update{KEY:ENTER}{DELAY:2000}sudo apt upgrade -y{KEY:ENTER}")
        else:
            # Join all parts after "macro" as the macro text
            pending_data = " ".join(parts[1:])
            pending_header = MAGIC_HEADER_MACRO
            current_state = STATE_WRITE_WAIT
            print(f"Scan card to BURN macro ({len(pending_data.encode('utf-8'))} bytes)")
            print(f"Scan card to BURN macro ({len(pending_data.encode('utf-8'))} bytes)")
            print("WARNING: existing cards must be wiped or overwritten.")

    elif op == "totp":
        if len(parts) < 2:
            print("Usage: totp <base32_secret>")
            print("Writes a 2FA secret to the card.")
        else:
            pending_data = parts[1].replace(" ", "").upper()
            pending_header = MAGIC_HEADER_TOTP
            current_state = STATE_WRITE_WAIT
            print(f"Scan card to BURN TOTP Secret")
            
    elif op == "wipe":
        current_state = STATE_WIPE_WAIT
        print("Scan card to WIPE...")
        
    elif op == "read":
        current_state = STATE_READ_WAIT
        print("Scan card to READ contents (will not execute)...")
        
    elif op == "webui":
        if len(parts) < 2:
            status = "enabled" if (webui_enabled and server is not None) else "disabled"
            print(f"WebUI is currently {status}")
            if server is not None and wifi_connected:
                print(f"WebUI URL: http://{wifi.radio.ipv4_address}/")
            print("Usage: webui <on|off>")
        else:
            action = parts[1].lower()
            if action in ("on", "enable", "start"):
                if webui_enabled and server is not None:
                    print("WebUI is already enabled")
                else:
                    webui_enabled = True
                    # Ensure WiFi is up
                    if not wifi_connected:
                         if connect_wifi():
                             sync_time()
                    
                    if start_web_server():
                        print("WebUI enabled successfully")
                    else:
                        print("WebUI enable failed")
                        
            elif action in ("off", "disable", "stop"):
                if server is None:
                    print("WebUI is already disabled")
                else:
                    stop_web_server()
                    # We do NOT disconnect WiFi here, as per user request (WebUI toggle only affects WebUI)
                    webui_enabled = False
                    print("WebUI disabled (WiFi remains active)")
            else:
                print("Usage: webui <on|off>")

    elif op == "wifi":
        if len(parts) < 2:
            status = "connected" if wifi_connected else "disconnected"
            print(f"WiFi is currently {status}")
            if wifi_connected:
                print(f"IP: {wifi.radio.ipv4_address}")
            print("Usage: wifi <on|off>")
        else:
            action = parts[1].lower()
            if action in ("on", "enable", "start"):
                if wifi_connected:
                    print("WiFi is already connected")
                else:
                    wifi_enabled = True
                    if connect_wifi():
                        print("WiFi connected successfully")
                        sync_time()
                        # If WebUI was supposed to be on, start it now? 
                        # User said "wifi should toggle both" -> implying if I turn WiFi on, maybe WebUI should come on if it was enabled?
                        # "the wifi should toggle both"
                        # Interpretation: 
                        # wifi off -> wifi disconnects AND webui stops.
                        # wifi on -> wifi connects... does webui start? 
                        # "if wifi is started up it should check the webui flag" -> YES.
                        if webui_enabled:
                            start_web_server()
                    else:
                        print("WiFi connection failed")
                        
            elif action in ("off", "disable", "stop"):
                if not wifi_connected:
                    print("WiFi is already disconnected")
                else:
                    # wifi off -> disable both
                    stop_web_server()
                    disconnect_wifi()
                    wifi_enabled = False
                    # Note: we don't necessarily set webui_enabled = False permanently, 
                    # but the server is stopped. If we run "wifi on" later, it checks webui_enabled flag.
                    print("WiFi disconnected (WebUI stopped)")
            else:
                print("Usage: wifi <on|off>")
        
    elif op == "help":
        print("Commands:")
        print("  write <pass>              - Write password only")
        print("  write <user> <pass>        - Write username + password")
        print("  macro <macro_text>        - Write advanced macro (Rubber Ducky style)")
        print("  read                      - Read card contents (display only, no execution)")
        print("  wipe                      - Wipe card data")
        print("  totp <secret>             - Write TOTP 2FA secret")
        print("  totp <secret>             - Write TOTP 2FA secret")
        print("  webui <on|off>            - Enable/disable web interface (leaves WiFi on)")
        print("  wifi <on|off>             - Enable/disable WiFi (disabling kills WebUI too)")
        print("")
        print("Macro Format (use {KEY:name}, {COMBO:mod+key}, {DELAY:ms}):")
        print("  Example: macro Hello{KEY:ENTER}{COMBO:CTRL+C}")
        print("  Type 'macro' without arguments for detailed help.")
        print("")
        print("Large data (>44 bytes) automatically uses macro/chained storage.")
        
    elif op == "status":
        # Return current status for web UI
        status_data = {
            "state": current_state,
            "state_name": {
                STATE_IDLE: "Idle",
                STATE_WRITE_WAIT: "Waiting for card (Write)",
                STATE_WIPE_WAIT: "Waiting for card (Wipe)",
                STATE_READ_WAIT: "Waiting for card (Read)"
            }.get(current_state, "Unknown"),
            "last_status_message": last_web_status,
            "last_read_result": last_read_result
        }
        print(f"STATUS_RESULT:{json.dumps(status_data)}")
        
    else:
        print("Unknown command. Type 'help' for usage.")

# Input Buffer
serial_buf = ""

while True:
    try:

        # 0. Poll Web Server (if enabled)
        if server is not None:
            try:
                server.poll()
            except Exception as e:
                print(f"Web Server Error: {e}")

        # 1. Check Serial
        while supervisor.runtime.serial_bytes_available:
            c = sys.stdin.read(1)
            if c == '\n' or c == '\r':
                if serial_buf:
                    process_command(serial_buf)
                    serial_buf = ""
            else:
                serial_buf += c
                
        # 2. Check RFID
        (stat, tag_type) = reader.request(reader.REQIDL)
        
        if stat == reader.OK:
            (stat, uid) = reader.anticoll()
            
            if stat == reader.OK:
                # IMPORTANT: We must SELECT the card before Auth/Read/Write
                if reader.select_tag(uid) != reader.OK:
                    # Error selecting?
                    # print("Failed to select tag.")
                    time.sleep(0.5)
                    continue
                    
                h_id = [hex(x) for x in uid]
                
                if current_state == STATE_WRITE_WAIT:
                    # WRITE Mode
                    if write_card_data(uid, pending_data, pending_header):
                        last_web_status = "Write Success!"
                    else:
                        last_web_status = "Write Failed!"
                    current_state = STATE_IDLE
                    time.sleep(1.0)
                    
                elif current_state == STATE_WIPE_WAIT:
                    # WIPE Mode
                    if wipe_card(uid):
                        last_web_status = "Card Wiped!"
                    else:
                        last_web_status = "Wipe Failed!"
                    current_state = STATE_IDLE
                    time.sleep(1.0)
                    
                elif current_state == STATE_READ_WAIT:
                    # READ Mode (display only, no execution)
                    (c_type, c_data) = read_card_data(uid)
                    
                    # Build structured data for web UI
                    read_result = {
                        "uid": h_id,
                        "type": c_type,
                        "type_name": "",
                        "data": c_data if c_data else None,
                        "username": None,
                        "password": None,
                        "macro_commands": None
                    }
                    
                    if c_type == TYPE_PASS and c_data:
                        read_result["type_name"] = "Password Only (Legacy)"
                        read_result["password"] = c_data
                        read_result["length"] = len(c_data)
                        
                    elif c_type == TYPE_USER and c_data:
                        read_result["type_name"] = "Username + Password"
                        if "\n" in c_data:
                            uname, pword = c_data.split("\n", 1)
                            read_result["username"] = uname
                            read_result["password"] = pword
                            read_result["length"] = len(c_data)
                        else:
                            read_result["data"] = c_data
                            read_result["warning"] = "Malformed User Data (missing newline)"
                            
                    elif c_type == TYPE_MACRO and c_data:
                        read_result["type_name"] = "Advanced Macro"
                        read_result["length"] = len(c_data)
                        # Try to parse and show command breakdown
                        try:
                            commands = parse_macro(c_data)
                            read_result["macro_commands"] = commands
                        except Exception as e:
                            read_result["macro_parse_error"] = str(e)
                            
                            read_result["macro_parse_error"] = str(e)
                    
                    elif c_type == TYPE_TOTP and c_data:
                        read_result["type_name"] = "TOTP Authenticator"
                        read_result["length"] = len(c_data)
                        read_result["totp_secret"] = c_data
                        # Preview code
                        read_result["totp_preview"] = generate_totp(c_data)

                    elif c_type == TYPE_UNKNOWN:
                        read_result["type_name"] = "Unknown/Empty"
                        read_result["error"] = "No valid data found on card. (Card may be blank, corrupted, or use different encryption)"
                    else:
                        read_result["type_name"] = "Unknown"
                        read_result["raw_data"] = repr(c_data) if c_data else None
                    
                    # Store for WebUI
                    last_read_result = read_result
                    last_web_status = "Read Complete"
                    current_state = STATE_IDLE

                    # Output JSON for web UI parsing (with special marker)
                    json_output = json.dumps(read_result)
                    print(f"READ_RESULT:{json_output}")
                    
                    # Also output human-readable format for console
                    print("=" * 50)
                    print(f"Card UID: {h_id}")
                    if read_result["type_name"]:
                        print(f"Card Type: {read_result['type_name']}")
                    if read_result.get("password"):
                        print(f"Password: {read_result['password']}")
                    if read_result.get("username"):
                        print(f"Username: {read_result['username']}")
                    if read_result.get("length"):
                        print(f"Length: {read_result['length']} characters")
                    if read_result.get("data") and c_type == TYPE_MACRO:
                        print(f"Macro Content:")
                        print("-" * 50)
                        print(read_result["data"])
                        print("-" * 50)
                        if read_result.get("macro_commands"):
                            print(f"Parsed Commands: {len(read_result['macro_commands'])}")
                            for i, cmd in enumerate(read_result["macro_commands"], 1):
                                cmd_type = cmd.get('type', 'UNKNOWN')
                                cmd_value = cmd.get('value', '')
                                if cmd_type == 'TEXT':
                                    preview = cmd_value[:30] + "..." if len(cmd_value) > 30 else cmd_value
                                    print(f"  {i}. TEXT: \"{preview}\"")
                                elif cmd_type == 'KEY':
                                    print(f"  {i}. KEY: {cmd_value}")
                                elif cmd_type == 'COMBO':
                                    print(f"  {i}. COMBO: {cmd_value}")
                                elif cmd_type == 'DELAY':
                                    print(f"  {i}. DELAY: {cmd_value}ms")
                    if read_result.get("totp_secret"):
                        print(f"TOTP Secret: {read_result['totp_secret']}")
                        print(f"Current Code: {read_result['totp_preview']}")
                    if read_result.get("error"):
                        print(read_result["error"])
                    if read_result.get("warning"):
                        print(f"Warning: {read_result['warning']}")
                    print("=" * 50)
                    
                    time.sleep(1.0)
                    
                else:
                    # READ / AUTH Mode
                    # print("Reading card...")
                    (c_type, c_data) = read_card_data(uid)
                    
                    if c_type == TYPE_PASS and c_data:
                        print(f"Card {h_id}: Password found (Legacy)!")
                        layout.write(c_data)
                        time.sleep(0.3)
                        kbd.send(Keycode.ENTER)
                        time.sleep(2.0)
                        
                    elif c_type == TYPE_USER and c_data:
                        print(f"Card {h_id}: User+Pass found!")
                        # Split by newline
                        if "\n" in c_data:
                            uname, pword = c_data.split("\n", 1)
                            layout.write(uname)
                            kbd.send(Keycode.TAB)
                            time.sleep(0.3)
                            layout.write(pword.strip())
                            time.sleep(0.3)
                            kbd.send(Keycode.ENTER)
                        else:
                            # Fallback if corrupt
                            print("Error: Malformed User Data")
                            
                        time.sleep(2.0)
                    elif c_type == TYPE_MACRO and c_data:
                        print(f"Card {h_id}: Macro found!")
                        print(f"Macro content: {c_data[:100]}...")
                        # Parse and execute macro
                        try:
                            commands = parse_macro(c_data)
                            print(f"Parsed {len(commands)} macro commands")
                            execute_macro(commands)
                            print("Macro execution completed")
                        except Exception as e:
                            print(f"Macro execution error: {e}")
                            import traceback
                            traceback.print_exception(e)
                            # Fallback: try to type as plain text
                            print("Falling back to plain text typing")
                            layout.write(c_data)
                        time.sleep(2.0)
                        print(f"Card {h_id}: Macro detected but data is empty or None")
                        print(f"c_data value: {repr(c_data)}")

                    elif c_type == TYPE_TOTP and c_data:
                        print(f"Card {h_id}: TOTP Secret found!")
                        # Generate and Type
                        code = generate_totp(c_data)
                        if code != "000000":
                            print(f"Type Code: {code}")
                            layout.write(code)
                            time.sleep(0.3)
                            kbd.send(Keycode.ENTER)
                        else:
                            print("Error generating TOTP")
                        time.sleep(2.0)
                    else:
                        # print(f"Card {h_id}: No valid password found")
                        time.sleep(0.5)
                
        time.sleep(0.01)
    except Exception as e:
        print(f"Runtime Error: {e}")
        time.sleep(1.0) # Prevent tight loop crash loop

