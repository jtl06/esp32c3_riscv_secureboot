#!/usr/bin/env python3
import struct
import hashlib
import sys
from ecdsa import VerifyingKey, BadSignatureError
from ecdsa.util import sigdecode_string

# Constants
SBC_HEADER_MAGIC = 0x53424331
HEADER_FORMAT = "<III32s64s" # magic, size, version, hash, sig
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def verify_image(image_path, public_key_path):
    print(f"Verifying {image_path} with {public_key_path}...")
    
    with open(image_path, "rb") as f:
        data = f.read()
        
    if len(data) < HEADER_SIZE:
        print("Error: File too small.")
        return False
        
    header_bytes = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]
    
    magic, img_size, img_version, img_hash, sig = struct.unpack(HEADER_FORMAT, header_bytes)
    
    # 1. Verify Magic
    if magic != SBC_HEADER_MAGIC:
        print(f"Error: Invalid Magic 0x{magic:08X}")
        return False
        
    # 2. Verify Size
    if len(payload) != img_size:
        print(f"Error: Size mismatch. Header says {img_size}, got {len(payload)}")
        return False
        
    # 3. Verify Hash
    sha256 = hashlib.sha256()
    sha256.update(payload)
    calc_hash = sha256.digest()
    
    if calc_hash != img_hash:
        print("Error: Hash mismatch.")
        print(f"  Header: {img_hash.hex()}")
        print(f"  Calc:   {calc_hash.hex()}")
        return False
        
    print("Hash verified.")
    
    # 4. Verify Signature
    # The C code verifies the signature against the hash of the header fields (magic, size, ver, hash)
    # Reconstruct the data that was signed
    signed_data = struct.pack("<III32s", magic, img_size, img_version, img_hash)
    
    with open(public_key_path, "rb") as f:
        vk = VerifyingKey.from_pem(f.read())
        
    try:
        # sigdecode_string expects raw bytes (64 bytes for P-256)
        vk.verify(sig, signed_data, sigdecode=sigdecode_string)
        print("Signature verified.")
        return True
    except BadSignatureError:
        print("Error: Invalid Signature.")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: verify_image.py <image> <public_key>")
        sys.exit(1)
        
    if verify_image(sys.argv[1], sys.argv[2]):
        print("SUCCESS: Image is valid.")
        sys.exit(0)
    else:
        print("FAILURE: Image is invalid.")
        sys.exit(1)
