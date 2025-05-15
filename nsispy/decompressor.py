# This file is part of nsispy.
#
# nsispy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nsispy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import zlib
import logging

from nsis7z import analyze_installer_7z

## PLACEHOLDER: detect which type of compression was used for .exe file
## NSIS: supports zlib, bzip2 and lzma compression (default: zlib)

def find_nsis_magic(data):
    # Search for 0xDEADBEEF in little-endian: EF BE AD DE
    magic = b'\xEF\xBE\xAD\xDE'
    offset = data.find(magic)
    if offset == -1:
        raise ValueError("NSIS magic header (DEADBEEF) not found.")
    return offset

def try_find_zlib_stream(data, start_offset, search_window=1000):
    for offset in range(start_offset, start_offset + search_window):
        try:
            # Try decompressing from here
            result = zlib.decompress(data[offset:])
            print(f"Found valid zlib stream at offset: 0x{offset:X}")
            return result
        except zlib.error:
            continue
    raise RuntimeError("Could not find a valid zlib-compressed stream near NSIS header.")

def nsis_decompression(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            start_offset = find_nsis_magic(data)
            decompressed_data = try_find_zlib_stream(data, start_offset)
            print(f"Decompressed {len(decompressed_data)} bytes.")

    except Exception as e:
        print(f"Error reading file: {e}")

# Example usage:
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler("nsispy.log"),        # Log to a file
            logging.StreamHandler()                   # Also log to console
        ]
    )

    if len(sys.argv) != 2:
        print("Usage: python detect_nsis_compression.py <installer.exe>")
    else:
        metadata = analyze_installer_7z(sys.argv[1])