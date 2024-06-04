import os

def generate_key_iv():
  key = os.urandom(32)  # AES-256
  iv = os.urandom(16)   # AES block size
  return key, iv