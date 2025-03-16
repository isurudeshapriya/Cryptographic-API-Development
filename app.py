from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

app = Flask(__name__)

# Dictionary to store generated keys
keys = {}

# Function to fix Base64 padding issues
def add_padding(base64_str):
    missing_padding = len(base64_str) % 4
    if missing_padding:
        base64_str += '=' * (4 - missing_padding)
    return base64_str

# 🔑 Key Generation Endpoint
@app.route('/generate-key', methods=['POST'])
def generate_key():
    data = request.json
    key_type = data.get("key_type", "AES")
    key_size = data.get("key_size", 256)

    if key_type != "AES" or key_size != 256:
        return jsonify({"error": "Only AES-256 is supported"}), 400

    key = get_random_bytes(32)
    key_id = str(len(keys) + 1)
    keys[key_id] = key

    return jsonify({
        "key_id": key_id,
        "key_value": base64.b64encode(key).decode()
    })

# 🔒 Encryption Endpoint
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    key_id = data.get("key_id")
    plaintext = data.get("plaintext")

    if key_id not in keys:
        return jsonify({"error": "Invalid key ID"}), 400

    key = keys[key_id]
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    encrypted_data = base64.b64encode(nonce + ciphertext).decode('utf-8')

    return jsonify({"ciphertext": encrypted_data})

# 🔓 Decryption Endpoint (Fixed Base64 Padding Issue)
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    key_id = data.get("key_id")
    ciphertext = data.get("ciphertext")

    if key_id not in keys:
        return jsonify({"error": "Invalid key ID"}), 400

    key = keys[key_id]

    try:
        # Fix Base64 padding
        ciphertext = add_padding(ciphertext)
        decoded_ciphertext = base64.b64decode(ciphertext)

        nonce, encrypted_data = decoded_ciphertext[:16], decoded_ciphertext[16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        return jsonify({"plaintext": decrypted_data.decode()})
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

# 🔍 Hash Generation Endpoint
@app.route('/generate-hash', methods=['POST'])
def generate_hash():
    data = request.json
    message = data.get("data")
    algorithm = data.get("algorithm", "SHA-256")

    if algorithm == "SHA-256":
        hash_value = hashlib.sha256(message.encode()).digest()
    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    return jsonify({
        "hash_value": base64.b64encode(hash_value).decode(),
        "algorithm": algorithm
    })

# ✅ Hash Verification Endpoint
@app.route('/verify-hash', methods=['POST'])
def verify_hash():
    data = request.json
    original_message = data.get("data")
    provided_hash = data.get("hash_value")
    algorithm = data.get("algorithm", "SHA-256")

    try:
        provided_hash = base64.b64decode(add_padding(provided_hash))
    except Exception:
        return jsonify({"error": "Invalid Base64 encoding"}), 400

    if algorithm == "SHA-256":
        computed_hash = hashlib.sha256(original_message.encode()).digest()
    else:
        return jsonify({"error": "Unsupported algorithm"}), 400

    is_valid = provided_hash == computed_hash

    return jsonify({
        "is_valid": is_valid,
        "message": "Hash matches the data." if is_valid else "Hash does not match!"
    })

if __name__ == '__main__':
    app.run(debug=True)
