import os
import io
import re
import sys
import json
import hashlib
import argparse
import subprocess

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
            choices=["lua", "vfs", "friendly_files"],
            help="Extract files"
    )
parser.add_argument(
            '-o',
            '--output',
            default="output",
            help="Output directory"
    )

parser.add_argument(
            '--luadec',
            help="Luadec binary path to decompile luac files (use -e lua)"
    )

args = parser.parse_args()

if not os.path.isfile(args.filename):
    print(f"Error: {args.filename} does not seem to be a file on the filesystem.")
    sys.exit(1)

SIG_TYPES = {}
with open("sig_types.json", "r") as f:
    SIG_TYPES = json.load(f)

FRIENDLIES = [
    SIG_TYPES["SIGNATURE_TYPE_FRIENDLYFILE_SHA256"], 
    SIG_TYPES["SIGNATURE_TYPE_FRIENDLYFILE_SHA512"]
    ]

os.makedirs(args.output, exist_ok=True)

current_threat = ""
count = 0
unknown_threat_count = 0
with open(args.filename, "rb") as vdm_file:
    while True:
        header = vdm_file.read(4)
        if len(header) < 4:
            break
        
        sig_type = header[0]
        size_low = header[1]
        size_high = int.from_bytes(header[2:4], byteorder='little')
        sig_size = size_low | (size_high << 8)
        
        value_data = vdm_file.read(sig_size)
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


            if args.luadec is not None:
                decompiled_file = luac_filename.replace('.luac', '.lua')
                outfile = open(decompiled_file, "w")
                subprocess.run([args.luadec, luac_filename], 
                                stdout=outfile, stderr=subprocess.DEVNULL)
                outfile.close()
                # Sometimes the file is not found
                if os.path.exists(luac_filename):
                    os.remove(luac_filename)

            count += 1
            print(f"Ripped {hashed} (total {count})", end="\r")

        if args.extract == "vfs" and sig_type == SIG_TYPES["SIGNATURE_TYPE_VFILE"]:
            data_stream = io.BytesIO(value_data)
            offset_to_filename = int.from_bytes(data_stream.read(4), byteorder='little')
            time_data = data_stream.read(offset_to_filename - 4)  # we leave room to retrieve file size
            file_size = int.from_bytes(data_stream.read(4), byteorder='little')
            unknown = data_stream.read(8)
            filename = data_stream.read(0x224).decode("utf-16-le").split('\x00')[0]
            file_content = data_stream.read(file_size)
            if len(file_content) != file_size:
                print(f"Fatal missmatch, expected {file_size} bytes but only got {len(file_content)}")
                quit()

            filename_unix = filename.replace("\\\\", '/').replace("\\", '/').replace(':', '')
            full_path = os.path.join(args.output, filename_unix)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "wb") as out_vfile:
                out_vfile.write(file_content + "\n")

            count += 1
            print(f"Ripped {os.path.basename(full_path)} (total: {count}) {' '*20}", end=f"\r")

        if args.extract == "friendly_files":
            if sig_type in FRIENDLIES:
                ext = [".sha256", ".sha512"][FRIENDLIES.index(sig_type)]  # hacky, do better
                path = os.path.join(args.output, threat_name.replace('/', '-') + ext)
                with open(path, "a") as friend_file:
                    friend_file.write(value_data.hex() + '\n')

                count += 1
                print(f"Ripped signature {value_data.hex()} (total: {count}) {' '*20}", end="\r")

print(f"\nDone, ripped a total of {count} files")
        
        