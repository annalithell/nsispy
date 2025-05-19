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
import logging
import shutil

logger = logging.getLogger(__name__)

class NSIS7zAnalysisError(Exception):
    pass

def list_contents_7z(filepath):
    """
    Lists contents of an NSIS-generated installer using 7-Zip.

    Parameters:
        filepath (str): Path to the .exe installer

    Returns:
        dict: A dictionary with keys like 'Path', 'Type', 'Method', etc.

    Raises:
        FileNotFoundError: If the file doesn't exist
        NSIS7zAnalysisError: If 7z fails or returns unexpected output
    """

    # Check if the file exists
    if not os.path.isfile(filepath):
        logger.error(f"File does not exist: {filepath}")
        raise FileNotFoundError(f"File does not exist: {filepath}")
    
    # Check if 7z is installed and in PATH
    path = shutil.which('7z') or shutil.which('7z.exe')
    
    if path is None:
        if os.path.exists(r"C:\Program Files\7-Zip\7z.exe"):
            path = r"C:\Program Files\7-Zip\7z.exe"
        else:
            logger.exception("7z not found in PATH and default location not accessible.")
            raise RuntimeError("7z executable not found. Please install 7-Zip or add it to PATH.")
        
    logging.debug(f"7z path is {path}")

    # Run the 7-Zip command-line utility to list the contents of the archive (filepath)
    try:
        result = subprocess.run(
            [path, 'l', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )

    except FileNotFoundError:
        logger.exception("7z is not installed or not in PATH.")
        raise NSIS7zAnalysisError("7z is not installed or not in PATH.")
    
    except subprocess.CalledProcessError as e:
        logger.error(f"7z failed: {e.stdout}")
        raise NSIS7zAnalysisError(f"7z failed: {e.stdout}")

    return _parse_7z_output(result.stdout)


def _parse_7z_output(output):
    """
    Parses the 7-Zip output and extracts both header- and metadata.

    Parameters:
        output (str): Raw text output from `7z l`

    Returns:
        dict: Parsed metadata
    """
    header = {}
    metadata = {}
    metadata_exists = False

    split = output.splitlines()

    # The last line contains a summary of files; split it and remove empty parts
    file_summary = list(filter(None, split[-1].strip().split(" ")))

    # Check if the output format is as expected (should have at least 3 parts)
    if len(file_summary) < 3:
        logger.warning("Unexpected 7z output format.")
        return {}
    
    # Check if the number of files in the archive is zero 
    # if this is the case, index 2 in summary is '0'
    try:
        total_files = int(file_summary[2])
        if total_files == 0:
            logger.info("No files found in the archive.")
        else: 
            # Files exist; set flag and extract the total number of files
            metadata_exists = True
            logger.info(f"Files found in the archive: {total_files}")

    except (ValueError, IndexError) as e:
        logger.warning(f"Unexpected 7z file summary format: {file_summary} - {e}")
        return {}

    file_nr = 1 # Counter to track the number of files processed

    # Iterate over each line of the output to extract headers and file metadata
    for line in split:

        # Attempt to match lines containing header key-value pairs (e.g. "Path = ...")
        header_match = re.match(r"^\s*(.+?)\s*=\s*(.+)$", line)
        if header_match:
            key, value = header_match.groups()
            header[key.strip()] = value.strip()
            continue # Skip to next line after processing header
        
        # Attempt to match lines containing file metadata info in a specific format:
        # Date Time Attr Size Compressed Name
        metadata_match = re.match(
            r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) +(\d+) +(\d+) +(.+)", line
        )

        # If metadata exists and the line matches file metadata format and we haven't exceeded the total files count:
        if metadata_exists and metadata_match and file_nr <= total_files:
            filename = metadata_match.group(6)
            # Store metadata info in the metadata dictionary, keyed by filename
            metadata[filename] = {
                'Date': metadata_match.group(1),
                'Time': metadata_match.group(2),
                'Attr': metadata_match.group(3),
                'Size': metadata_match.group(4),
                'Compressed': metadata_match.group(5)
            }
            file_nr += 1 # Increment the file counter

    logger.debug("Header data:\n%s", pprint.pformat(header))
    logger.debug("File metadata:\n%s", pprint.pformat(metadata))

    return {
        'header': header,
        'files': metadata
    }