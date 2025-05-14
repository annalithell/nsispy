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

    print(result.stdout)

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
    metadata = {}

    for line in output.splitlines():
        if " = " in line:
            key, value = line.split("=", 1)
            metadata[key.strip()] = value.strip()

    return metadata
