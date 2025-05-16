from flask import Flask, request, render_template, send_file, flash
from Crypto.Cipher import Salsa20, ChaCha20
from Crypto.Hash import HMAC, SHA256
import os
import io
from google.cloud import storage
from pymongo import MongoClient
import time

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')  # Use environment variable for secret key

# Google Cloud Storage Configuration
GCS_BUCKET_NAME = os.getenv('GCS_BUCKET_NAME', 'shobi12345')  # Replace with your GCS bucket name
GCS_CLIENT = storage.Client()

# MongoDB Atlas Configuration
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://kavyaspare2:pe6NUkid764vOHso@mycluster.8x5nu.mongodb.net/?retryWrites=true&w=majority&appName=MyCluster')
client = MongoClient(MONGODB_URI)
db = client['test']
collection = db['images']

def encrypt_image(image_data, key, algorithm='chacha20'):
    if algorithm == 'salsa20':
        nonce = os.urandom(8)  # Salsa20 uses an 8-byte nonce
        cipher = Salsa20.new(key=key, nonce=nonce)
        encrypted_data = cipher.encrypt(image_data)  # Encrypt the image data

        # Use HMAC-SHA256 for authentication with Salsa20
        h = HMAC.new(key, digestmod=SHA256)
        h.update(encrypted_data)
        mac = h.digest()

        return nonce + mac + encrypted_data  # Prepend nonce and MAC to encrypted data

    else:  # Default to ChaCha20
        nonce = os.urandom(12)  # ChaCha20 uses a 12-byte nonce
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted_data = cipher.encrypt(image_data)  # Encrypt the image data

        # Use HMAC-SHA256 for authentication with ChaCha20 too for consistency
        h = HMAC.new(key, digestmod=SHA256)
        h.update(encrypted_data)
        mac = h.digest()

        return nonce + mac + encrypted_data  # Prepend nonce and MAC to encrypted data

def decrypt_image(encrypted_data, key, algorithm='chacha20'):
    if algorithm == 'salsa20':
        nonce = encrypted_data[:8]  # Extract the nonce for Salsa20
        mac = encrypted_data[8:40]  # Extract the MAC (32 bytes for SHA256)
        cipher_text = encrypted_data[40:]  # The actual encrypted data
    else:  # Default to ChaCha20
        nonce = encrypted_data[:12]  # Extract the nonce for ChaCha20
        mac = encrypted_data[12:44]  # Extract the MAC (32 bytes for SHA256)
        cipher_text = encrypted_data[44:]  # The actual encrypted data

    # Verify the MAC
    h = HMAC.new(key, digestmod=SHA256)
    h.update(cipher_text)
    try:
        h.verify(mac)  # This will raise an exception if the MAC is invalid
    except ValueError:
        raise ValueError("MAC verification failed: data may have been tampered with")

    # Create the cipher object for decryption
    if algorithm == 'salsa20':
        cipher = Salsa20.new(key=key, nonce=nonce)
    else:  # Default to ChaCha20
        cipher = ChaCha20.new(key=key, nonce=nonce)

    # Decrypt the data
    decrypted_data = cipher.decrypt(cipher_text)  # Decrypt the image data
    return decrypted_data

def upload_to_gcs(file_data, file_name):
    bucket = GCS_CLIENT.bucket(GCS_BUCKET_NAME)
    blob = bucket.blob(file_name)
    blob.upload_from_string(file_data)
    blob.make_public()  # Make the file publicly accessible
    return blob.public_url

def store_url_in_mongodb(url):
    collection.insert_one({"image_url": url})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    key = request.form['key'].encode('utf-8')[:32]  # Ensure key is 32 bytes
    algorithm = request.form.get('algorithm', 'chacha20') # Get the selected algorithm
    image_data = file.read()
    encrypted_data = encrypt_image(image_data, key, algorithm)

    # Upload to GCS and get the URL
    file_name = f"encrypted_image_{int(time.time())}.enc"  # Unique file name
    url = upload_to_gcs(encrypted_data, file_name)

    # Store URL in MongoDB
    store_url_in_mongodb(url)

    flash('Image encrypted and uploaded successfully!', 'success')
    return send_file(io.BytesIO(encrypted_data), mimetype='application/octet-stream', as_attachment=True,
                     download_name='encrypted_image.enc')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    key = request.form['key'].encode('utf-8')[:32]  # Ensure key is 32 bytes
    algorithm = request.form.get('algorithm', 'chacha20')  # Get the selected algorithm
    encrypted_data = file.read()
    decrypted_data = decrypt_image(encrypted_data, key, algorithm)
    return send_file(io.BytesIO(decrypted_data), mimetype='image/png', as_attachment=True,
                     download_name='decrypted_image.png')

@app.route('/decrypt_from_gcs', methods=['POST'])
def decrypt_from_gcs():
    gcs_url = request.form['gcs_url']
    key = request.form['key'].encode('utf-8')[:32]  # Ensure key is 32 bytes
    algorithm = request.form.get('algorithm', 'chacha20')  # Get the selected algorithm

    # Download the encrypted file from GCS
    file_name = gcs_url.split('/')[-1]
    bucket_name = GCS_BUCKET_NAME

    try:
        bucket = GCS_CLIENT.bucket(bucket_name)
        blob = bucket.blob(file_name)
        encrypted_data = blob.download_as_bytes()
        decrypted_data = decrypt_image(encrypted_data, key, algorithm)
        return send_file(io.BytesIO(decrypted_data), mimetype='image/png', as_attachment=True,
                         download_name='decrypted_image.png')
    except Exception as e:
        flash(f'Error retrieving or decrypting image: {str(e)}', 'error')
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)