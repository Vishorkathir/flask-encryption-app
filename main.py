import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS, cross_origin
import sqlite3
import hashlib
from cryptography.fernet import Fernet
import requests

app = Flask(__name__)
cors = CORS(app)

def init_db():
    if not os.path.exists('database'):
        os.makedirs('database')
    
    conn = sqlite3.connect('database/devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, secret TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (device_id TEXT, encrypted_message TEXT)''')
    conn.commit()
    conn.close()


def generate_key():
    try:
        with open("encryption_key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("encryption_key.key", "wb") as key_file:
            key_file.write(key)
        print("Encryption key generated and saved.")
        return key


def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()


def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())


def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()


@app.route('/register', methods=['POST'])
@cross_origin() 
def register_device():
    # print(request.form)
    device_id = request.json['device_id']
    secret = request.json['secret']
    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()
    
    conn = sqlite3.connect('database/devices.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO devices (device_id, secret) VALUES (?, ?)", (device_id, hashed_secret))
        conn.commit()
        response = {"message": f"Device {device_id} registered successfully."}
    except sqlite3.IntegrityError:
        response = {"error": f"Device {device_id} is already registered."}
    finally:
        conn.close()
    return jsonify(response)


@app.route('/authenticate', methods=['POST'])
@cross_origin() 
def authenticate_device():
    device_id = request.json['device_id']
    secret = request.json['secret']
    hashed_secret = hashlib.sha256(secret.encode()).hexdigest()

    conn = sqlite3.connect('database/devices.db')
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE device_id = ? AND secret = ?", (device_id, hashed_secret))
    result = c.fetchone()
    conn.close()
    
    if result:
        response = jsonify({
            "message": f"Device {device_id} authenticated successfully.",
            "device_id": device_id,
            "success": True
        }), 200
    else:
        response = jsonify({
            "message": "Authentication failed.",
            "success": False
        }), 404
    return response

@app.route('/messages/<device_id>', methods=['GET'])
@cross_origin()
def get_messages(device_id):
    conn = sqlite3.connect('database/devices.db')
    c = conn.cursor()
    c.execute("SELECT encrypted_message FROM messages WHERE device_id = ?", (device_id,))
    messages = c.fetchall()
    conn.close()
    
    decrypted_messages = []
    for msg in messages:
        try:
            decrypted = decrypt_message(msg[0].encode())
            decrypted_messages.append(decrypted)
        except Exception as e:
            print(f"Error decrypting message: {e}")
            continue
    
    return jsonify({
        "messages": decrypted_messages
    })

@app.route('/send', methods=['POST'])
@cross_origin() 
def send_message():
    device_id = request.json['device_id']
    message = request.json['message']
    encrypted_message = encrypt_message(message)

    conn = sqlite3.connect('database/devices.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (device_id, encrypted_message) VALUES (?, ?)", (device_id, encrypted_message.decode()))
    conn.commit()
    conn.close()
    res = requests.post('http://127.0.0.1:5001/receive', json = {"message": "Message encrypted and sent successfully.", "encrypted_message": encrypted_message.decode(), "device_id":device_id})
    return jsonify({"message": f"{res.json()['message']}"})

@app.route('/')
@cross_origin() 
def home():
    return render_template('index.html')

if __name__ == "__main__":
    init_db()
    generate_key()
    app.run(debug=True)