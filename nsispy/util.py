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

import os
import shutil
import logging

logger = logging.getLogger(__name__)

def get_7z_path() -> str:
    """
    Get path of the 7z executable.
    If not found in PATH, check the default installation location.  
    Raise an error if not found.
    Returns:
        str: Path to the 7z executable.
    Raises:
        FileNotFoundError: If the file does not exist.
        RuntimeError: If 7z is not found in PATH or default location.
    """
    
    # Check if 7z is installed and in PATH
    path = shutil.which('7z') or shutil.which('7z.exe')
    
    if path is None:
        if os.path.exists(r"C:\Program Files\7-Zip\7z.exe"):
            path = r"C:\Program Files\7-Zip\7z.exe"
        else:
            logger.exception("7z not found in PATH and default location not accessible.")
            raise RuntimeError("7z executable not found. Please install 7-Zip or add it to PATH.")
        
    logging.debug(f"7z path is {path}")
    return path