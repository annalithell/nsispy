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
import pathlib

from .util import get_7z_path

logger = logging.getLogger(__name__)

def _parse_7z_output(output):
    """
    Parses the 7-Zip output and extracts both header- and metadata.

    Parameters:
        output (str): Raw text output from `list_contents_7z`

    Returns:
        dict: Parsed output containing:
            - 'header': Dictionary with header information (e.g., Path, Type, Method)
            - 'files': Dictionary with file metadata (e.g., Date, Time, Attr, Size, Compressed)
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

def list_contents_7z(filepath, logger):
    """
    Lists contents of an NSIS-generated installer using 7-Zip.

    Parameters:
        filepath (str): Path to the installer
        logger (logging.Logger): Logger instance for logging messages

    Returns:
        dict: Parsed output containing:
            - 'header': Dictionary with header information (e.g., Path, Type, Method)
            - 'files': Dictionary with file metadata (e.g., Date, Time, Attr, Size, Compressed)

    Raises:
        Exception: If the file does not exist or if an error occurs during processing

    """
    # Check if the file exists
    if not os.path.isfile(filepath):
        logger.error(f"File does not exist: {filepath}")
        raise FileNotFoundError(f"File does not exist: {filepath}")
    
    # Fetch path to 7zip executable
    path_7z = get_7z_path()

    # Run the 7-Zip command-line utility to list the contents of the archive (filepath)
    try:
        result = subprocess.run(
            [path_7z, 'l', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )

    except Exception as e:
        logger.error(f"An error occured: {e}")
        raise Exception("Failed to run subprocess '7z l':") from e

    return _parse_7z_output(result.stdout)


def extract_files_7z(filepath, output_dir):
    """
    Extracts the contents of an installer using 7-Zip.

    Parameters:
        filepath (str): Path to the .exe installer
        output_dir (str): Directory where the files will be extracted

    Returns:
        None

    Raises:
        Exception: If the 7z extraction subprocess fails
    """
    path_7z = get_7z_path()
    logger.debug("Using 7-Zip at: %s", path_7z)

    try:
        subprocess.run(
            [path_7z, 'x', filepath, f"-o{output_dir}", "-y"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )

    except Exception as e:
        logger.error(f"Failed to extract {filepath} to {output_dir}: {e}")
        raise Exception(f"Failed to extract {filepath} to {output_dir}: {e}") from e
    
    extracted_files = list(pathlib.Path(output_dir).rglob('*'))
    
    logger.info(f"Extracted {len(extracted_files)} files:")

    for f in extracted_files:
        logger.info(f" - {f}")

    return extracted_files