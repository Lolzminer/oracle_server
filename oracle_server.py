from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import threading

app = Flask(__name__)

# Replace these with your actual AES key and IV (hex strings)
KEY_HEX = "00112233445566778899aabbccddeeff"
IV_HEX = "0102030405060708090a0b0c0d0e0f10"

KEY = binascii.unhexlify(KEY_HEX)
IV = binascii.unhexlify(IV_HEX)

@app.route('/check_padding', methods=['POST'])
def check_padding():
    try:
        ciphertext_b64 = request.json.get('ciphertext')
        ciphertext = binascii.a2b_base64(ciphertext_b64)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        plaintext = cipher.decrypt(ciphertext)
        unpad(plaintext, AES.block_size)
        return jsonify({'valid_padding': True}), 200
    except Exception:
        return jsonify({'valid_padding': False}), 403

def run_server():
    app.run(host='127.0.0.1', port=5000)

if __name__ == "__main__":
    run_server()
