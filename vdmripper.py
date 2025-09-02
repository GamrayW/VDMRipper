import os
import io
import re
import sys
import json
import hashlib
import argparse

from mplua_parse import commial_parse


parser = argparse.ArgumentParser(
            prog='VDMRipper',
            description='Extract entries from VDM files'
        )
parser.add_argument('filename')
parser.add_argument(
            '-e',
            '--extract',
            required=True,
            choices=["lua"],
            help="Extract files"
    )
parser.add_argument(
            '-o',
            '--output',
            default="output",
            help="Output directory"
    )

args = parser.parse_args()

if not os.path.isfile(args.filename):
    print(f"Error: {args.filename} does not seem to be a file on the filesystem.")
    sys.exit(1)

SIG_TYPES = {}
with open("sig_types.json", "r") as f:
    SIG_TYPES = json.load(f)

os.makedirs(args.output, exist_ok=True)

current_threat = ""
count = 0
unknown_threat_count = 0
with open(args.filename, "rb") as f:
    while True:
        header = f.read(4)
        if len(header) < 4:
            sys.exit(0) 
        
        sig_type = header[0]
        size_low = header[1]
        size_high = int.from_bytes(header[2:4], byteorder='little')
        sig_size = size_low | (size_high << 8)
        
        value_data = f.read(sig_size)
        if len(value_data) < sig_size:
            print(f"Warning: Expected {sig_size} bytes but got {len(value_data)}")
            sys.exit(1)
        
        if sig_type == SIG_TYPES["SIGNATURE_TYPE_THREAT_BEGIN"]:
            threat = value_data.decode('utf-8', errors='replace')
            pattern = r'[a-zA-Z0-9!@#$%^&*()\-_=+\[\]{};:\'",.<>/?|\\]{4,}'
            matches = re.findall(pattern, threat)
            if matches:
                threat_name = max(matches, key=len)
            else:
                unknown_threat_count += 1
                threat_name = f"UnknownThreat{unknown_threat_count}"
            continue

        if args.extract == "lua" and sig_type == SIG_TYPES["SIGNATURE_TYPE_LUASTANDALONE"]:
            threat_dir = os.path.join(args.output, threat_name.replace('/', '-'))
            os.makedirs(threat_dir, exist_ok=True)
            metadata, mplua = value_data.split(b'\x1bLua')
            mplua = b"\x1bLua" + mplua
            hashed = hashlib.md5(mplua).hexdigest()
            luac_filename = os.path.join(threat_dir, hashed + ".luac")
            metadata_filename = os.path.join(threat_dir, hashed + ".meta")
            commial_parse(io.BytesIO(mplua), luac_filename)
            with open(metadata_filename, "wb") as out_metadata:
                out_metadata.write(metadata)

            count += 1
            print(f"Ripped {hashed} (total {count})", end="\r")
            
print("\nDone")
        
        