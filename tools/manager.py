#!/usr/bin/env python3
import argparse
import struct
import hashlib
import os
import sys
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from ecdsa.util import sigencode_string

# Constants
SBC_HEADER_MAGIC = 0x53424331
HEADER_FORMAT = "<III32s64s" # magic, size, version, hash, sig
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def generate_keys(args):
    print("Generating ECDSA P-256 keys...")
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key
    
    with open(args.private_key, "wb") as f:
        f.write(sk.to_pem())
    print(f"Private key saved to {args.private_key}")
    
    with open(args.public_key, "wb") as f:
        f.write(vk.to_pem())
    print(f"Public key saved to {args.public_key}")

def sign_binary(args):
    print(f"Signing binary {args.input}...")
    
    if not os.path.exists(args.input):
        print(f"Error: Input file {args.input} not found.")
        return

    with open(args.input, "rb") as f:
        data = f.read()
    
    img_size = len(data)
    img_version = args.version
    
    # Compute SHA-256 hash of the image
    sha256 = hashlib.sha256()
    sha256.update(data)
    img_hash = sha256.digest()
    
    # Sign the hash
    with open(args.private_key, "rb") as f:
        sk = SigningKey.from_pem(f.read())
    
    # Sign the header fields (magic + size + version + img_hash)
    # This matches the verification logic in the bootloader
    to_sign = struct.pack("<III32s", SBC_HEADER_MAGIC, img_size, img_version, img_hash)
    
    # Sign the hash deterministically (RFC6979)
    # sigencode_string returns r + s as raw bytes (64 bytes for P-256)
    sig = sk.sign(to_sign, sigencode=sigencode_string, hashfunc=hashlib.sha256)
    if len(sig) != 64:
        print(f"Warning: Signature length is {len(sig)}, expected 64.")

    # Create header
    # struct pack expects bytes for 's' format
    header = struct.pack(HEADER_FORMAT, 
                         SBC_HEADER_MAGIC,
                         img_size,
                         img_version,
                         img_hash,
                         sig)
    
    # Pad to 64KB (0x10000) to ensure the app binary starts at a 64KB aligned address
    # This is required for ESP32-C3 MMU mapping of IROM/DROM segments.
    padding_len = 0x10000 - HEADER_SIZE
    padding = b'\xFF' * padding_len

    output_filename = args.output if args.output else args.input + ".signed"
    
    with open(output_filename, "wb") as f:
        f.write(header)
        f.write(padding)
        f.write(data)
        
    print(f"Signed binary saved to {output_filename}")
    print(f"  Magic: 0x{SBC_HEADER_MAGIC:08X}")
    print(f"  Size:  {img_size}")
    print(f"  Ver:   {img_version}")
    print(f"  Hash:  {img_hash.hex()}")

def upload_binary(args):
    print(f"Mocking upload of {args.binary} to port {args.port}...")
    # In a real scenario, we would use pyserial to talk to the bootloader
    # or use esptool to flash it to a specific partition.
    print("Upload complete (mock).")

def main():
    parser = argparse.ArgumentParser(description="Secure Boot Manager Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Generate Keys
    parser_gen = subparsers.add_parser("generate-keys", help="Generate ECDSA keys")
    parser_gen.add_argument("--private-key", default="private.pem", help="Output private key file")
    parser_gen.add_argument("--public-key", default="public.pem", help="Output public key file")
    parser_gen.set_defaults(func=generate_keys)
    
    # Sign Binary
    parser_sign = subparsers.add_parser("sign", help="Sign a binary")
    parser_sign.add_argument("input", help="Input binary file")
    parser_sign.add_argument("--private-key", default="private.pem", help="Private key for signing")
    parser_sign.add_argument("--version", type=int, default=1, help="Image version")
    parser_sign.add_argument("--output", help="Output signed binary")
    parser_sign.set_defaults(func=sign_binary)
    
    # Upload
    parser_upload = subparsers.add_parser("upload", help="Upload binary")
    parser_upload.add_argument("binary", help="Signed binary file")
    parser_upload.add_argument("--port", default="/dev/ttyUSB0", help="Serial port")
    parser_upload.set_defaults(func=upload_binary)
    
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
