# Digital-Chakravyuha-3.0
import os
import logging
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
from functools import wraps

# Corporate-grade logging configuration
t_logging = logging.getLogger('ChakravyuhaLogger')
t_logging.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
t_logging.addHandler(ch)

#############################
# Layer 1: Perimeter Defense #
#############################
class PerimeterDefense:
    def __init__(self):
        self.allowed_ips = os.getenv('ALLOWED_IPS', '127.0.0.1').split(',')

    def ip_whitelist(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            if client_ip not in self.allowed_ips:
                t_logging.warning(f"Blocked access from unauthorized IP: {client_ip}")
                return jsonify({'error': 'Access denied'}), 403
            return func(*args, **kwargs)
        return wrapper

############################
# Layer 2: Application Defense #
############################
class ApplicationDefense:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        return self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_payload(self, ciphertext: bytes) -> bytes:
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

############################
# Layer 3: Data-at-Rest Defense #
############################
class DataDefense:
    def __init__(self, key: bytes):
        self.key = key
        self.backend = default_backend()
        self.iv = os.urandom(16)

    def encrypt_data(self, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        return self.iv + encryptor.update(data) + encryptor.finalize()

    def decrypt_data(self, token: bytes) -> bytes:
        iv = token[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(token[16:]) + decryptor.finalize()

############################
# Layer 4: AI Integrity Defense #
############################
class AIIntegrityDefense:
    def __init__(self):
        self.anomaly_threshold = 0.7  # placeholder

    def monitor_behavior(self, metrics: dict) -> bool:
        # Placeholder for real anomaly detection (e.g. ML model inference)
        score = sum(metrics.values()) / len(metrics)
        if score > self.anomaly_threshold:
            t_logging.error("Anomaly detected in AI subsystem: metrics score {}".format(score))
            return False
        return True

############################
# Orchestrator & API Gateway #
############################
app = Flask(__name__)

# Key generation & rotation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Initialize defenses
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keys()
perimeter = PerimeterDefense()
app_defense = ApplicationDefense(PRIVATE_KEY, PUBLIC_KEY)
data_defense = DataDefense(os.urandom(32))
ai_defense = AIIntegrityDefense()

@app.route('/secure-endpoint', methods=['POST'])
@perimeter.ip_whitelist
def secure_endpoint():
    # Decrypt incoming payload
    try:
        encrypted = request.get_data()
        plaintext = app_defense.decrypt_payload(encrypted)
    except Exception as e:
        t_logging.error(f"Decryption failed: {str(e)}")
        return jsonify({'error': 'Invalid payload'}), 400

    # Business logic placeholder
d
    # Monitor AI metrics
    metrics = {'cpu': 0.2, 'memory': 0.3}  # example
    if not ai_defense.monitor_behavior(metrics):
        return jsonify({'error': 'AI integrity breach'}), 500

    # Process and respond
    response_data = b"Processing complete"
    encrypted_response = app_defense.encrypt_payload(response_data)
    return encrypted_response, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context=('cert.pem', 'key.pem'))

Extra Code to protect the system
import os
import logging
import time
from functools import wraps
from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import jwt
from collections import defaultdict

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger("ChakravyuhaSecure")

# --- Flask App ---
app = Flask(__name__)

# --- Security Configurations ---
ALLOWED_IPS = set(os.environ.get('ALLOWED_IPS', '127.0.0.1').split(','))
JWT_SECRET = os.environ.get('JWT_SECRET', 'supersecretjwtkey')
AES_KEY = os.environ.get('DATA_AES_KEY', os.urandom(32)).encode() if isinstance(os.environ.get('DATA_AES_KEY', None), str) else os.urandom(32)

# RSA Key loading (use secrets manager in production)
PRIVATE_KEY_PEM = os.environ.get('PRIVATE_KEY_PEM')
if PRIVATE_KEY_PEM:
    PRIVATE_KEY = serialization.load_pem_private_key(PRIVATE_KEY_PEM.encode(), password=None)
else:
    PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=4096)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# --- Rate Limiting ---
rate_limit = defaultdict(list)
RATE_LIMIT = 100  # requests per minute

def rate_limiter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        times = rate_limit[ip]
        times[:] = [t for t in times if now - t < 60]
        if len(times) >= RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for {ip}")
            abort(429)
        times.append(now)
        return func(*args, **kwargs)
    return wrapper

# --- IP Whitelisting ---
def ip_whitelist(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        if ip not in ALLOWED_IPS:
            logger.warning(f"Blocked unauthorized IP: {ip}")
            abort(403)
        return func(*args, **kwargs)
    return wrapper

# --- JWT Authentication ---
def require_jwt(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            abort(401)
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if payload.get('exp', 0) < time.time():
                abort(401)
        except Exception as e:
            logger.warning("JWT auth failed")
            abort(401)
        return func(*args, **kwargs)
    return wrapper

# --- Encryption Helpers ---
def encrypt_data(data: bytes) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct

def decrypt_data(token: bytes) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    nonce = token[:12]
    return aesgcm.decrypt(nonce, token[12:], None)

def encrypt_payload(plaintext: bytes) -> bytes:
    return PUBLIC_KEY.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_payload(ciphertext: bytes) -> bytes:
    return PRIVATE_KEY.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- Endpoints ---
@app.route('/secure-endpoint', methods=['POST'])
@ip_whitelist
@require_jwt
@rate_limiter
def secure_endpoint():
    try:
        encrypted = request.get_data()
        plaintext = decrypt_payload(encrypted)
    except Exception:
        logger.error("Payload decryption failed")
        return jsonify({'error': 'Invalid encrypted payload'}), 400

    # Example AI anomaly detection (replace with real logic)
    metrics = {'cpu': 0.2, 'memory': 0.3}
    if max(metrics.values()) > 0.8:
        logger.error("AI anomaly detected")
        return jsonify({'error': 'AI integrity breach'}), 500

    response_data = b"Processing complete"
    try:
        encrypted_response = encrypt_payload(response_data)
    except Exception:
        logger.error("Response encryption failed")
        return jsonify({'error': 'Encryption error'}), 500
    return encrypted_response, 200

@app.route('/generate-jwt', methods=['POST'])
@ip_whitelist
def generate_jwt():
    # Simple JWT for demo; include user info as needed and set expiration
    payload = {
        'user': request.remote_addr,
        'exp': int(time.time()) + 3600  # 1 hour expiry
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({'token': token})

# --- Main ---
if __name__ == '__main__':
    # Use Gunicorn or uWSGI behind NGINX in production, not Flask's server
    app.run(host='0.0.0.0', port=8443, ssl_context=('cert.pem', 'key.pem'))
