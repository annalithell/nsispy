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

import subprocess
import os
import re
import pprint

class NSIS7zAnalysisError(Exception):
    pass

def analyze_installer_7z(filepath):
    """
    Analyzes an NSIS-generated installer using 7-Zip.

    Parameters:
        filepath (str): Path to the .exe installer

    Returns:
        dict: A dictionary with keys like 'Path', 'Type', 'Method', etc.

    Raises:
        FileNotFoundError: If the file doesn't exist
        NSIS7zAnalysisError: If 7z fails or returns unexpected output
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File does not exist: {filepath}")
    
    ## Not great solution since it introduce dependability - the user have to install 7z
    seven_zip_path = r"C:\Program Files\7-Zip\7z.exe"  # modify to find global variable on user's machine 

    try:
        result = subprocess.run(
            [seven_zip_path, 'l', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
    except FileNotFoundError:
        raise NSIS7zAnalysisError("7z is not installed or not in PATH.")
    except subprocess.CalledProcessError as e:
        raise NSIS7zAnalysisError(f"7z failed: {e.stdout}")

    return _parse_7z_output(result.stdout)
    #return result.stdout


def _parse_7z_output(output):
    ## TODO Add additional parsing for file info
    """
    Parses the 7-Zip output and extracts metadata.

    Parameters:
        output (str): Raw text output from `7z l`

    Returns:
        dict: Parsed metadata
    """
    header_data = {}
    metadata = {}
    metadata_exists = False

    #print(output.splitlines())

    split = output.splitlines()
    # check if file contains metadata
    file_summary = str(split[-1]).strip().split(" ")
    # remove empty strings
    file_summary = list(filter(None, file_summary))

    #print("file_summary: " + str(file_summary))

    #print("file_summary: " + str(file_summary))
    if file_summary[2] == '0':
        print("No files found in the archive.")

    else:
        print("Files found in the archive.")
        metadata_exists = True
        total_files = int(file_summary[-2])
        #print("Total files: " + str(total_files))

    # Loop through each line and extract header- and/or metadata
    file_nr = 1
    for i, line in enumerate(split):
        header_match = re.match(r"^\s*(.+?)\s*=\s*(.+)$", line)

        if header_match:
            key, value = header_match.groups()
            header_data[key.strip()] = value.strip()
            continue
        
        metadata_match = re.match(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) +(\d+) +(\d+) +(.+)", line)

        if metadata_exists and metadata_match and file_nr <= total_files:
            #print("metadata exist: check for metadata")
            #print("metadata_match: " + str(metadata_match.groups()))
            metadata[file_nr] = {}
            metadata[file_nr]['Date'] = metadata_match.group(1)
            metadata[file_nr]['Time'] = metadata_match.group(2)
            metadata[file_nr]['Attr'] = metadata_match.group(3)
            metadata[file_nr]['Size'] = metadata_match.group(4)
            metadata[file_nr]['Compressed'] = metadata_match.group(5)
            metadata[file_nr]['Name'] = metadata_match.group(6)
            file_nr += 1

    print("header_data: ")
    pprint.pprint(header_data)
    print("metadata: ")
    pprint.pprint(metadata)

    return header_data
