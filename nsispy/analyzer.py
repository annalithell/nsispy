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
import pefile
import logging
import subprocess
from .util import sha256hash

logger = logging.getLogger(__name__)

def is_setup_exe(file_path):
    """
    Deny installers named "setup.exe". 
    Common name for installers exploiting bug in the Windows compatibility layer, 
    allowing injections of certain DLLs.
    Source: https://nsis.sourceforge.io/Best_practices
    """
    return os.path.basename(file_path).lower() == "setup.exe"


def analyze_pe_header(file_path):
    """
    Check if installer is NSIS or not. 
    """
    try:
        pe = pefile.PE(file_path, fast_load=False)
        last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        offset = last.PointerToRawData + last.SizeOfRawData
        with open(file_path, "rb") as f:
            f.seek(offset)
            compressed = f.read()
            #logger.info(compressed)
        # Check if valid NSIS installer TODO: add more magic numbers
        if b"NullsoftInst" in compressed:
            return True

    except Exception as e:
        logger.warning("Failed to process file: %s", e)

    return False

def is_signed(file_path):
    try:
        result = subprocess.run(
            ["powershell", "-Command", f"(Get-AuthenticodeSignature '{file_path}').Status"],
            capture_output=True, text=True
        )
        status = result.stdout.strip()
        logger.info("Signature status: %s", status)
        return status == "Valid"
    except Exception as e:
        logger.warning("Failed to check signature: %s", e)
        return False
    
def is_hash_known(filehash, vt_api_key):
    logger.info("Checking hash %s on VirusTotal...", filehash)
    ## TODO: Implement VirusTotal API check
    return False
    

def initial_analysis(file_path, check_virustotal, vt_api_key):
    """
    Wrapper function for initial analysis of the installer.
    This function checks if:
        1. The file is an NSIS installer
        2. The file is not named "setup.exe"
        3. If it is signed (Windows: use getAuthenticodeSignature)
        4. Optional: If hash is known on virustotal (requires API key from user)

    Parameters:
        file_path (str): Path to the installer file
        check_virustotal (bool): Flag to check hash on VirusTotal
        vt_api_key (str): API key for VirusTotal

    Returns:
        Dictionary: {
            "is_nsis": bool,
            "is_setup_exe": bool,
            "is_signed": bool,
            "hash_known": bool
        }
    """
    results = {}
    results["is_nsis"] = analyze_pe_header(file_path)
    results["is_setup_exe"] = is_setup_exe(file_path)
    results["is_signed"] = is_signed(file_path)
    if check_virustotal:
        results["is_hash_known"] = is_hash_known(sha256hash(file_path), vt_api_key)
    else:
        results["is_hash_known"] = False
    logger.info(results)
    return results



    
