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

# --- Setup ---
sck = board.GP18
mosi = board.GP19
miso = board.GP16
cs = board.GP17
rst = board.GP22

reader = mfrc522.MFRC522(sck, mosi, miso, rst, cs)

kbd = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

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
MAGIC_HEADER = b"PfId" # Password-RFID ID

def derive_key(uid):
    """
    Derives a simple encryption key from the UID and Master Secret.
    Returns a bytearray of same length as data blocks (16 bytes).
    """
    # Simple mixer: Just repeat/XOR UID + Secret to make a keystream
    # We want a 16-byte key for block operations or just a stream.
    # Let's make a stream generator seed.
    seed = 0
    for b in uid:
        seed = (seed * 31 + b) & 0xFFFF
    
    for b in MASTER_SECRET:
        seed = (seed * 31 + b) & 0xFFFF
        
    # Generate pseudo-random keystream based on seed
    key_stream = bytearray(48) # Enough for 3 blocks
    state = seed
    for i in range(48):
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

# --- Mifare Specifics ---
def auth_sector(uid):
    # Try all known keys
    for i, key in enumerate(KNOWN_KEYS):
        status = reader.auth(reader.AUTHENT1A, 4, key, uid)
        if status == reader.OK:
            return True
        else:
            reader.stop_crypto1()  
    return False

def write_card_password(uid, password):
    print("Writing to card...")
    
    # 1. Prepare Plaintext
    b_pass = password.encode('utf-8')
    if len(b_pass) > 44:
        b_pass = b_pass[:44] # Truncate
        
    # Pad with 0
    payload = list(MAGIC_HEADER) + list(b_pass) + [0] * (44 - len(b_pass))
    
    # 2. Encrypt
    key_stream = derive_key(uid)
    encrypted_data = xor_crypt(payload, key_stream)
    
    if is_ntag(uid):
        # NTAG Write
        if write_ntag_chunks(NTAG_START_PAGE, encrypted_data):
            print("Write Success (NTAG Secure)!")
            return True
        else:
            print("Write Failed (NTAG Error)")
            return False
            
    else:
        # Mifare Write
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

def read_card_password(uid):
    raw_data = []
    
    if is_ntag(uid):
        # NTAG Read
        raw_data = read_ntag_chunks(NTAG_START_PAGE, NTAG_PAGES)
        if raw_data is None:
            # print("DEBUG: NTAG Read Failed")
            return None
    else:
        # Mifare Read
        if not auth_sector(uid):
            # print("DEBUG: Auth Failed in read_card_password") 
            return None
            
        for block_addr in SECTOR_BLOCKS:
            block_data = reader.read(block_addr)
            if block_data is None:
                reader.stop_crypto1()
                # print(f"DEBUG: Read returned None for block {block_addr}")
                return None
            raw_data.extend(block_data)
            
        reader.stop_crypto1()
    
    # Decrypt
    key_stream = derive_key(uid)
    decrypted_data = xor_crypt(raw_data, key_stream)
    
    # Check Magic Header
    if decrypted_data[:4] != MAGIC_HEADER:
        return None
        
    # Strip Header
    payload = decrypted_data[4:]
    
    # Decode
    try:
        final_chars = []
        for b in payload:
            if b == 0:
                break
            final_chars.append(chr(b))
            
        final_str = "".join(final_chars)
        return final_str
    except Exception as e:
        print(f"Decryption Error: {repr(e)}")
        return None

def wipe_card(uid):
    zeros = [0] * 48
    
    if is_ntag(uid):
        if write_ntag_chunks(NTAG_START_PAGE, zeros):
             print("NTAG Wiped.")
             return True
        print("NTAG Wipe Failed.")
        return False
    else:
        if not auth_sector(uid):
            print("Auth Failed! Wipe aborted.")
            return False
            
        zeros_block = [0] * 16
        for block_addr in SECTOR_BLOCKS:
            reader.write(block_addr, zeros_block)
            
        reader.stop_crypto1()
        print("Card Wiped.")
        return True

# --- State Machine ---
STATE_IDLE = 0
STATE_WRITE_WAIT = 1
STATE_WIPE_WAIT = 2

current_state = STATE_IDLE
pending_password = ""

print("Ready (Secure On-Card Storage Mode).")
print("Type 'write <pass>' to burn a password.")

def process_command(cmd):
    global current_state, pending_password
    parts = cmd.split()
    if not parts: return
    
    op = parts[0].lower()
    
    if op == "write":
        if len(parts) < 2:
            print("Usage: write <password>")
        else:
            pending_password = " ".join(parts[1:])
            current_state = STATE_WRITE_WAIT
            print(f"Scan card to BURN password")
            print("WARNING: existing cards must be wiped or overwritten.")
            
    elif op == "wipe":
        current_state = STATE_WIPE_WAIT
        print("Scan card to WIPE Sector 1...")
        
    elif op == "help":
        print("Commands: write <pass>, wipe")
        
    else:
        print("Unknown command.")

# Input Buffer
serial_buf = ""

while True:
    try:
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
                    write_card_password(uid, pending_password)
                    current_state = STATE_IDLE
                    time.sleep(1.0)
                    
                elif current_state == STATE_WIPE_WAIT:
                    # WIPE Mode
                    wipe_card(uid)
                    current_state = STATE_IDLE
                    time.sleep(1.0)
                    
                else:
                    # READ / AUTH Mode
                    # print("Reading card...")
                    passwd = read_card_password(uid)
                    if passwd:
                        print(f"Card {h_id}: Password found!")
                        layout.write(passwd)
                        kbd.send(Keycode.ENTER)
                        time.sleep(2.0)
                    else:
                        # print(f"Card {h_id}: No valid password found")
                        time.sleep(0.5)
                
        time.sleep(0.01)
    except Exception as e:
        print(f"Runtime Error: {e}")
        time.sleep(1.0) # Prevent tight loop crash loop

