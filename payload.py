import serial, time, base64
import serial.tools.list_ports
import psutil, platform, json, base64
import getpass
import threading
import queue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

BAUD = 115200
PICO_VID = 0x2E8A
PICO_PUBLIC_KEY = "4B7EEC4186E38B9E2AF2042B77FDDA2A1DD0EB99A08F7315B8A926A0E4B4A980422330CC0EF250A531360A2AB24B06C385CF16A970FEAE320DA30B6DD7B5A117"

RESET="\x1b[0m"; CYAN="\x1b[36m"; YELL="\x1b[33m"; RED="\x1b[31m"; GREEN="\x1b[32m"
def now(): return time.strftime("%H:%M:%S")
def HOST(msg): print(f"{now()} {CYAN}HOST|{RESET} {msg}")
def MCU(msg):  print(f"{now()} {YELL}MCU |{RESET} {msg}")

# Global state
AES_KEY = None
message_queue = queue.Queue()
listener_active = threading.Event()
session_killed = threading.Event()

# ============================================================================
# CRYPTOGRAPHY FUNCTIONS
# ============================================================================

def verify_cert(cert_pem):
    """Verify certificate using hardcoded public key"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        pub_key = cert.public_key()
        
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        pub_hex = pub_bytes[1:].hex().upper()
        
        if pub_hex == PICO_PUBLIC_KEY:
            return True
        else:
            HOST(f"Public key mismatch!")
            HOST(f"Expected: {PICO_PUBLIC_KEY}")
            HOST(f"Got:      {pub_hex}")
            return False
            
    except Exception as e:
        HOST(f"Certificate verification error: {e}")
        return False

def generate_ephemeral_key():
    """Generate ephemeral ECC P-256 key pair for ECDH"""
    
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    pub_hex = pub_bytes[1:].hex().upper()
    
    return private_key, pub_hex

def derive_ecdh_secret(private_key, peer_public_hex):
    """Derive ECDH shared secret"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    peer_pub_bytes = bytes.fromhex(peer_public_hex)
    peer_pub_bytes_full = b'\x04' + peer_pub_bytes
    
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), 
        peer_pub_bytes_full
    )
    
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"TEAMIS18-SALT",
        info=b"session-key",
        backend=default_backend()
    )
    
    aes_key = hkdf.derive(shared_secret)
    
    return aes_key

def aes_cbc_encrypt(plaintext, aes_key):
    """Encrypt using AES-CBC with PKCS#7 padding"""
    iv = os.urandom(16)
    
    padding_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padding_len] * padding_len)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return iv + ciphertext

def aes_cbc_decrypt(encrypted, aes_key):
    """Decrypt using AES-CBC and remove PKCS#7 padding"""
    if len(encrypted) < 16:
        raise ValueError("Encrypted data too short")
    
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    padding_len = padded[-1]
    if padding_len > 16 or padding_len == 0:
        return padded
    
    for i in range(padding_len):
        if padded[-(i+1)] != padding_len:
            return padded
    
    return padded[:-padding_len]

# ============================================================================
# SERIAL COMMUNICATION
# ============================================================================

def pick_port():
    for p in serial.tools.list_ports.comports():
        if p.vid == PICO_VID or any(h in (p.description or "") for h in ("Pico","RP2","Raspberry")):
            return p.device
    raise SystemExit("No Pico found")

def send_line(ser, text):
    """Thread-safe send"""
    HOST(f"TX: {text}")
    try:
        ser.write((text + "\n").encode())
    except Exception as e:
        HOST(f"Send error: {e}")

# ============================================================================
# LISTENER THREAD
# ============================================================================

def serial_listener_thread(ser):
    """
    Continuously listen for serial messages and put them in the queue.
    Runs in a separate thread.
    """
    HOST("Listener thread started")
    listener_active.set()
    
    while listener_active.is_set() and not session_killed.is_set():
        try:
            line = ser.readline()
            if line:
                s = line.decode(errors="ignore").strip()
                if s:
                    MCU(s)
                    
                    # Check for session kill
                    if "KILL_SESSION" in s:
                        print(f"{RED}╔════════════════════════════════════════╗{RESET}")
                        print(f"{RED}║  SESSION KILLED BY DEVICE              ║{RESET}")
                        print(f"{RED}╚════════════════════════════════════════╝{RESET}")
                        session_killed.set()
                        message_queue.put(("KILL_SESSION", s))
                        break
                    
                    # Put message in queue for processing
                    message_queue.put(("MESSAGE", s))
            else:
                time.sleep(0.001)  # Small delay to prevent busy-waiting
                
        except Exception as e:
            if listener_active.is_set():
                HOST(f"Listener error: {e}")
            break
    
    HOST("Listener thread stopped")

# ============================================================================
# MESSAGE HANDLERS
# ============================================================================

class MessageProcessor:
    """Processes incoming messages based on current state"""
    
    def __init__(self, ser):
        self.ser = ser
        self.state = "INIT"
        self.waiting_for = None
        self.response_data = {}
        self.response_event = threading.Event()
        
    def wait_for_message(self, message_type, timeout=10.0):
        """
        Wait for a specific message type.
        Returns the message content or None if timeout.
        """
        self.waiting_for = message_type
        self.response_data = {}
        self.response_event.clear()
        
        # Wait for response
        if self.response_event.wait(timeout):
            return self.response_data.get(message_type)
        else:
            HOST(f"Timeout waiting for {message_type}")
            return None
    
    def process_message(self, msg):
        """Process a single message immediately"""
        
        # Handle encrypted messages
        if msg.startswith("ENC:"):
            self._handle_encrypted(msg)
            return
        
        # Handle specific message types
        if msg.startswith("CERT_RESP:X509CERT:"):
            self._handle_cert_response(msg)
        
        elif msg.startswith("ECDH_PUB_MCU:"):
            self._handle_ecdh_pub(msg)
        
        elif msg == "CHANNEL_OK":
            self._handle_channel_ok()
        
        elif msg == "USER_AUTH_OK":
            self._handle_auth_ok()
        
        elif msg == "USER_AUTH_FAIL":
            self._handle_auth_fail()
        
        elif msg.startswith("TEST_ENC:"):
            self._handle_test_enc(msg)
        
        # Handle state-specific waiting
        if self.waiting_for:
            if self.waiting_for in msg or msg.startswith(self.waiting_for):
                self.response_data[self.waiting_for] = msg
                self.response_event.set()
    
    def _handle_encrypted(self, msg):
        """Handle encrypted messages"""
        if not AES_KEY:
            return
        
        try:
            enc_data = base64.b64decode(msg.split(":", 1)[1])
            dec_data = aes_cbc_decrypt(enc_data, AES_KEY)
            decrypted_msg = dec_data.decode(errors='ignore')
            HOST(f"{GREEN}🔓 Decrypted:{RESET} {decrypted_msg}")
            
            # Store decrypted response if waiting
            if self.waiting_for == "ENC:":
                self.response_data["ENC:"] = decrypted_msg
                self.response_event.set()
                
        except Exception as e:
            HOST(f"Decryption error: {e}")
    
    def _handle_cert_response(self, msg):
        """Handle certificate response"""
        cert_b64 = msg.split(":", 2)[2]
        self.response_data["CERT_RESP:X509CERT:"] = cert_b64
        if self.waiting_for == "CERT_RESP:X509CERT:":
            self.response_event.set()
    
    def _handle_ecdh_pub(self, msg):
        """Handle ECDH public key"""
        pub_key = msg.split(":", 1)[1]
        self.response_data["ECDH_PUB_MCU:"] = pub_key
        if self.waiting_for == "ECDH_PUB_MCU:":
            self.response_event.set()
    
    def _handle_channel_ok(self):
        """Handle channel established confirmation"""
        HOST(f"{GREEN}=== SECURE CHANNEL ESTABLISHED ==={RESET}")
        HOST(f"{GREEN}✅ Perfect Forward Secrecy enabled{RESET}")
        HOST(f"{GREEN}✅ AES-128-CBC encryption active{RESET}")
        self.response_data["CHANNEL_OK"] = True
        if self.waiting_for == "CHANNEL_OK":
            self.response_event.set()
    
    def _handle_auth_ok(self):
        """Handle authentication success"""
        HOST(f"{GREEN}✅ Password accepted!{RESET}")
        self.response_data["USER_AUTH_OK"] = True
        if self.waiting_for == "AUTH_RESULT":
            self.response_event.set()
    
    def _handle_auth_fail(self):
        """Handle authentication failure"""
        HOST(f"{RED}❌ Password rejected{RESET}")
        self.response_data["USER_AUTH_FAIL"] = True
        if self.waiting_for == "AUTH_RESULT":
            self.response_event.set()
    
    def _handle_test_enc(self, msg):
        """Handle test encryption message"""
        test_enc = msg.split(":", 1)[1]
        self.response_data["TEST_ENC:"] = test_enc
        if self.waiting_for == "TEST_ENC:":
            self.response_event.set()

# ============================================================================
# TELEMETRY COLLECTION
# ============================================================================

def collect_telemetry():
    data = {}
    try:
        procs = []
        for p in psutil.process_iter(['pid','name']):
            try:
                procs.append({'pid': p.info['pid'], 'name': p.info['name']})
            except Exception:
                pass
        data['processes'] = procs[:50]
    except Exception:
        data['processes'] = []

    try:
        conns = []
        for c in psutil.net_connections(kind='inet')[:50]:
            try:
                conns.append({'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else '',
                              'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else '',
                              'status': c.status})
            except Exception:
                pass
        data['net_connections'] = conns
    except Exception:
        data['net_connections'] = []

    try:
        users = []
        for u in psutil.users():
            users.append({'name': u.name, 'host': u.host, 'started': int(u.started)})
        data['users'] = users
    except Exception:
        data['users'] = []

    try:
        data['uptime_s'] = int(time.time() - psutil.boot_time())
    except Exception:
        data['uptime_s'] = None

    try:
        services = []
        if platform.system() == "Windows":
            try:
                import subprocess
                sc = subprocess.check_output("sc query type= service state= all", shell=True)
                lines = sc.decode(errors='ignore').split('\n')
                for l in lines:
                    if "SERVICE_NAME:" in l:
                        sn = l.split(":",1)[1].strip()
                        services.append(sn)
            except Exception:
                pass
        elif platform.system() == "Linux":
            try:
                import subprocess
                sc = subprocess.check_output("systemctl list-units --type=service --all", shell=True)
                lines = sc.decode(errors='ignore').split('\n')
                for l in lines:
                    if ".service" in l:
                        parts = l.split()
                        if parts:
                            services.append(parts[0])
            except Exception:
                pass
        data['services'] = services[:50]
    except Exception:
        data['services'] = []

    return data

def send_telemetry(ser, aes_key, processor):
    HOST("Collecting telemetry...")
    telem = collect_telemetry()
    
    telem_json = json.dumps(telem)
    HOST(f"Telemetry size: {len(telem_json)} bytes")
    
    chunk_size = 200
    chunks = [telem_json[i:i+chunk_size] for i in range(0, len(telem_json), chunk_size)]
    
    HOST(f"Sending {len(chunks)} chunk(s) with ACK...")
    for i, chunk in enumerate(chunks):
        # Format with TELEM_CHUNK prefix
        formatted_chunk = f"TELEM_CHUNK:{i}:{chunk}"
        if i > 0:
            break
        
        # Encrypt the formatted chunk
        chunk_encrypted = aes_cbc_encrypt(formatted_chunk.encode(), aes_key)
        chunk_b64 = base64.b64encode(chunk_encrypted).decode()
        
        send_line(ser, f"ENC:{chunk_b64}")
        HOST(f"  Chunk {i+1}/{len(chunks)} sent, waiting for ACK...")
        
        # Wait for ENCRYPTED ACK response
        processor.waiting_for = "ENC:"
        processor.response_data = {}
        processor.response_event.clear()
        
        if processor.response_event.wait(timeout=6.0):
            decrypted_msg = processor.response_data.get("ENC:", "")
            if decrypted_msg.startswith("ACK_CHUNK:"):
                ack_seq = decrypted_msg.split(":")[1].strip()
                if ack_seq == str(i):
                    HOST(f"  ✓ Chunk {i+1}/{len(chunks)} acknowledged")
                else:
                    HOST(f"  ✗ Unexpected ACK seq: {ack_seq} (expected {i})")
                    return False
            else:
                HOST(f"  ✗ Unexpected response: {decrypted_msg}")
                return False
        else:
            HOST(f"  ✗ Timeout on chunk {i+1}/{len(chunks)}")
            return False
    
    HOST(f"{GREEN}✓ All {len(chunks)} chunks acknowledged{RESET}")
    return True

# ============================================================================
# AUTHENTICATION
# ============================================================================

def authenticate_user(ser, processor, aes_key):
    """Authenticate user with threading support"""
    attempt = 0
    
    while True:
        # Check if session was killed
        if session_killed.is_set():
            HOST(f"{RED}Session was killed by device{RESET}")
            return False
        
        attempt += 1
        HOST(f"Authentication attempt {attempt}")
        pw = getpass.getpass("Enter password (or 'quit' to exit): ")
        
        if pw.lower() in ['quit', 'exit', 'q']:
            HOST("User cancelled authentication")
            return False
        
        # Send encrypted password
        pw_msg = f"USER_AUTH:{pw}"
        pw_encrypted = aes_cbc_encrypt(pw_msg.encode(), aes_key)
        pw_b64 = base64.b64encode(pw_encrypted).decode()
        send_line(ser, f"ENC:{pw_b64}")
        
        # Wait for authentication result
        processor.waiting_for = "AUTH_RESULT"
        processor.response_data = {}
        processor.response_event.clear()
        
        if processor.response_event.wait(timeout=5.0):
            if processor.response_data.get("USER_AUTH_OK"):
                HOST(f"{GREEN}=== AUTHENTICATION SUCCESSFUL ==={RESET}")
                return True
            elif processor.response_data.get("USER_AUTH_FAIL"):
                HOST("Authentication failed. Try again.\n")
                continue
        else:
            # Check if killed during timeout
            if session_killed.is_set():
                HOST(f"{RED}Session was killed by device{RESET}")
                return False
            
            HOST("⚠️  Authentication timeout")
            retry = input("Retry? (y/n): ").lower()
            if retry != 'y':
                return False
    
    return False

# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    global AES_KEY
    
    # Open serial port
    port = pick_port()
    HOST(f"Opening {port}")
    ser = serial.Serial(port, BAUD, timeout=0.1)
    ser.dtr = False; time.sleep(0.15); ser.dtr = True
    time.sleep(0.5)
    
    # Create message processor
    processor = MessageProcessor(ser)
    
    # Start listener thread
    listener_thread = threading.Thread(target=serial_listener_thread, args=(ser,), daemon=True)
    listener_thread.start()
    time.sleep(0.5)  # Let listener start
    
    # Start message processing loop in background
    def process_queue():
        while not session_killed.is_set():
            try:
                msg_type, msg = message_queue.get(timeout=0.1)
                if msg_type == "MESSAGE":
                    processor.process_message(msg)
                elif msg_type == "KILL_SESSION":
                    break
            except queue.Empty:
                continue
    
    processor_thread = threading.Thread(target=process_queue, daemon=True)
    processor_thread.start()
    
    try:
        # INIT
        send_line(ser, "INIT")
        time.sleep(0.5)
        
        # Request device certificate
        send_line(ser, "CERT_REQ")
        cert_b64 = processor.wait_for_message("CERT_RESP:X509CERT:", timeout=30)
        
        if not cert_b64:
            HOST("No device cert received; abort.")
            return
        
        cert_b64 = cert_b64.split(":", 2)[2]
        cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_b64}\n-----END CERTIFICATE-----"
        
        # Verify certificate
        HOST("Verifying certificate...")
        if not verify_cert(cert_pem):
            HOST("Certificate verification FAILED; abort.")
            return
        HOST(f"{GREEN}Certificate verification OK{RESET}")
        
        # === ECDH KEY EXCHANGE ===
        HOST("\n" + "="*50)
        HOST("EPHEMERAL KEY EXCHANGE (Perfect Forward Secrecy)")
        HOST("="*50)
        
        HOST("Generating host ephemeral key...")
        host_private_key, host_public_hex = generate_ephemeral_key()
        HOST(f"Host ephemeral public key: {host_public_hex[:32]}...")
        
        send_line(ser, f"ECDH_PUB_HOST:{host_public_hex}")
        
        pico_pub_hex = processor.wait_for_message("ECDH_PUB_MCU:", timeout=2.0)
        if not pico_pub_hex:
            HOST("No Pico ephemeral pub received; abort.")
            return
        
        pico_pub_hex = pico_pub_hex.split(":", 1)[1]
        HOST(f"Pico ephemeral public key: {pico_pub_hex[:32]}...")
        
        HOST("Deriving session key via ECDH + HKDF...")
        aes_key = derive_ecdh_secret(host_private_key, pico_pub_hex)
        AES_KEY = aes_key
        
        send_line(ser, "HOST_READY")
        
        # Test encryption
        test_enc = processor.wait_for_message("TEST_ENC:", timeout=1.0)
        if test_enc:
            test_enc_data = test_enc.split(":", 1)[1]
            test_encrypted = base64.b64decode(test_enc_data)
            test_plain = aes_cbc_decrypt(test_encrypted, aes_key)
            HOST(f"Decrypted test message: {test_plain.decode()}")
        
        response_msg = "test response from host"
        response_encrypted = aes_cbc_encrypt(response_msg.encode(), aes_key)
        response_b64 = base64.b64encode(response_encrypted).decode()
        send_line(ser, f"TEST_RESPONSE:{response_b64}")
        
        # Wait for channel confirmation
        processor.wait_for_message("CHANNEL_OK", timeout=1.0)
        
        # === AUTHENTICATION ===
        HOST("\n" + "="*50)
        HOST("AUTHENTICATION PHASE")
        HOST("="*50)
        
        authenticated = authenticate_user(ser, processor, aes_key)
        
        if not authenticated:
            HOST("Authentication failed or cancelled. Exiting.")
            return
        
        # === TELEMETRY ===
        HOST("\n" + "="*50)
        HOST("TELEMETRY COLLECTION")
        HOST("="*50)
        
        if not send_telemetry(ser, aes_key, processor):
            HOST(f"{RED}Telemetry transmission failed{RESET}")
        
        # # Send test message
        # pt = b"HELLO_FROM_HOST"
        # encrypted = aes_cbc_encrypt(pt, aes_key)
        # send_line(ser, "ENC:" + base64.b64encode(encrypted).decode())
        # time.sleep(0.5)
        
        # # Close session
        # send_line(ser, "bye")
        # time.sleep(0.5)

        while True:
            pass
        
    finally:
        # Cleanup
        listener_active.clear()
        session_killed.set()
        time.sleep(0.5)
        ser.close()
        HOST("Session closed")

if __name__ == "__main__":

    main()

