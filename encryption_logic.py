import base64

def encrypt_message(message):
    base64_bytes = base64.b64encode(message.encode("ascii"))
    encrypted_message = base64_bytes.decode("ascii")
    return encrypted_message

def decrypt_message(message):
    try:
        base64_bytes = base64.b64decode(message.encode("ascii"))
        decrypted_message = base64_bytes.decode("ascii")
        return decrypted_message
    except base64.binascii.Error:
        raise ValueError("Invalid Base64 encoded message")
