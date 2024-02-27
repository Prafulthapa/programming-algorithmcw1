import unittest
from encryption_logic import encrypt_message, decrypt_message

class TestEncryptionLogic(unittest.TestCase):
    def test_encrypt_decrypt(self):
        original_message = "Hello, this is a testing."
        encrypted_message = encrypt_message(original_message)
        decrypted_message = decrypt_message(encrypted_message)

        self.assertEqual(original_message, decrypted_message)

if __name__ == '__main__':
    unittest.main()
