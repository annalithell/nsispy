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

logger = logging.getLogger(__name__)

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
        logger.error(f"File does not exist: {filepath}")
        raise FileNotFoundError(f"File does not exist: {filepath}")
    
    seven_zip_path = r"C:\Program Files\7-Zip\7z.exe"  # TODO: Improve portability

    try:
        result = subprocess.run(
            [seven_zip_path, 'l', filepath],
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
    file_summary = list(filter(None, split[-1].strip().split(" ")))

    if len(file_summary) < 3:
        logger.warning("Unexpected 7z output format.")
        return {}

    if file_summary[2] == '0':
        logger.info("No files found in the archive.")
    else:
        metadata_exists = True
        total_files = int(file_summary[-2])
        logger.info(f"Files found in the archive: {total_files}")

    file_nr = 1
    for i, line in enumerate(split):
        header_match = re.match(r"^\s*(.+?)\s*=\s*(.+)$", line)
        if header_match:
            key, value = header_match.groups()
            header[key.strip()] = value.strip()
            continue
        
        metadata_match = re.match(
            r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\S+) +(\d+) +(\d+) +(.+)", line
        )

        if metadata_exists and metadata_match and file_nr <= total_files:
            filename = metadata_match.group(6)
            metadata[filename] = {
                'Date': metadata_match.group(1),
                'Time': metadata_match.group(2),
                'Attr': metadata_match.group(3),
                'Size': metadata_match.group(4),
                'Compressed': metadata_match.group(5)
            }
            file_nr += 1

    logger.debug("Header data:\n%s", pprint.pformat(header))
    logger.debug("File metadata:\n%s", pprint.pformat(metadata))

    return {
        'header': header,
        'files': metadata
    }