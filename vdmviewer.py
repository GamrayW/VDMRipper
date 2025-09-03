import os
import sys
import json
import argparse

from colorama import Fore, Style, init

parser = argparse.ArgumentParser(
                prog='VDMViewer',
                description='Display VDM files in hex (like xxd | less) and coloring'
            )
parser.add_argument('filename', help="The target VDM file")
parser.add_argument(
                '-o',
                '--offset', 
                type=int, 
                default=500, 
                help="Number of entries to display (500 default)"
            )
parser.add_argument(
                '-f',
                '--filter',
                help='Filter the output by type of sig_entry (ex: "Lua", "luastandalone" will only show SIGNATURE_TYPE_LUASTANDALONE entries)'
            )
parser.add_argument(
                '-t',
                '--threat',
                default="",
                help='Threat type filter (ex: "Win32/BlowSearch", will only show entries from threats matching the provided name)'
            )

args = parser.parse_args()

if not os.path.isfile(args.filename):
        print(f"Error: {args.filename} does not seem to be a file on the filesystem.")
        sys.exit(1)

init()
COLORS = [Fore.LIGHTBLUE_EX, Fore.LIGHTMAGENTA_EX, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE]
SIG_TYPES = {}
with open("sig_types.json", "r") as f:
    SIG_TYPES = json.load(f)

filter_type = 0
if args.filter is not None:
    if args.filter.startswith("SIGNATURE"):
        filter_type = SIG_TYPES.get(args.filter.upper())
        if filter_type is None:
            print(f"No match for sig_type: \"{args.filter}\"")
            sys.exit(1)
    else:
        sig_type = [key for key in SIG_TYPES.keys() if args.filter.upper() in key]
        if len(sig_type) > 1:
            print(f"Too many match for sig_type: \"{args.filter}\" (try using full name ?)")
            print('\t' + '\n\t'.join(sig_type))
            sys.exit(1)
        if len(sig_type) == 0:
            print(f"No match for sig_type: \"{args.filter}\"")
            sys.exit(1)

        filter_type = SIG_TYPES[sig_type[0]]

hex_buffer = ''
ascii_buffer = ''
buffer_size = 0
offset = 0
sig_count = 1
color_index = 0
current_threat = b""

with open(args.filename, 'rb') as f:
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
        
        if filter_type != 0 and sig_type != filter_type:
            offset += len(header + value_data)
            continue
        if sig_type == 0x5C:
            current_color = Fore.GREEN
            current_threat = value_data
        elif sig_type == 0x5D:
            current_color = Fore.RED
        else:
            color_index += 1
            current_color = COLORS[color_index % len(COLORS)]
        
        if sig_count % args.offset == 0:
            if input(":") == 'q':
                sys.exit(0)
        
        complete_data = header + value_data        
        for byte in complete_data:
            hex_buffer += f'{current_color}{byte:02x}'
            
            if 32 <= byte <= 126:
                ascii_buffer += f'{current_color}{chr(byte)}'
            else:
                ascii_buffer += f'{current_color}.'
            
            buffer_size += 1
            if buffer_size % 2 == 0:
                hex_buffer += ' '
            
            if buffer_size == 16:
                if args.threat.encode() in current_threat:
                    print(f"{offset:08x}: {hex_buffer}{Style.RESET_ALL} {ascii_buffer}{Style.RESET_ALL}")
                    sig_count += 1
                hex_buffer = ''
                ascii_buffer = ''
                buffer_size = 0
                offset += 0x10
        

    if buffer_size > 0:
        padding = (16 - buffer_size) * 3
        if buffer_size % 2 == 1:
            padding += 1
        print(f"{offset:08x}: {hex_buffer}{' ' * padding}{Style.RESET_ALL} {ascii_buffer}{Style.RESET_ALL}")

print(f"Found {sig_count} match")
