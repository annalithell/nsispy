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

import logging
import pefile
import logging
import subprocess
import pprint
import requests
import tempfile
import pathlib

from .nsis7z import extract_files_7z, list_contents_7z
from .util import sha256hash

logger = logging.getLogger(__name__)

def _read_byte_sequence(compressed):
    """
    DEPRECATED:
    Read a byte sequence from the compressed NSIS payload and write it to a file. No longer used in the final analyzer.  
    """
    # Write the compressed NSIS payload to a file
    with open("nsis_payload.bin", "wb") as f:
        f.write(compressed)
        logger.info("NSIS payload written to nsis_payload.bin")
    
    with open("nsis_payload.bin", "rb") as f:
        # Check if the file starts with the NSIS magic number
        data = (f.read())
        logger.info(data)

def resolve_pe_imports(file_path, logger):
    """
    Resolve which DLLs and associated functions are imported by the Windows installer.

    Parameters:
        filepath (str): Path to the installer.
        logger (logging.Logger): Logger instance for logging messages.

    Returns:
        dict: A dictionary with the following structure:
            {
                "imports": dict
                    A dictionary mapping DLL names to dictionaries of
                    imported function names and their hint values.
                    Example: {"kernel32.dll": {"LoadLibraryA": 1234}}

                "ordinal_imports": dict
                    A dictionary mapping DLL names to lists of ordinals
                    imported by ordinal.
                    Example: {"user32.dll": [34]}

                "missing_IAT": list
                    A list of DLL names that were referenced but missing
                    from the import address table.
                    Example: ["missing.dll"]
            }

    References:
        Inspired by Vlad Topan's article:
        https://vtopan.wordpress.com/2019/04/12/patching-resolving-imports-in-a-pe-file-python-pefile/
    """
    results = {
        "imports": {},
        "ordinal_imports" : {},
        "missing_IAT" : [],
    }

    try:
        # read installer as bytearray
        data = bytearray(open(file_path, "rb").read())
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        
        # check if binary is 64 bit or 32 bit
        bits = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        #logger.info(f"Binary is {bits} bit")
       
        # create flag later used to check if file is imported by ordinal
        ordinal_flag = 2 ** (bits - 1)
        
        # entry corresponds to a DDL imported by the installer
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8")
            
            # fetch relative virtual address (RVA) of import lookup table (ILT)
            ilt_rva = entry.struct.OriginalFirstThunk
            
            # fetch RVA of the import address table (IAT)
            iat_rva = entry.struct.FirstThunk

            # fetch tables
            ilt = pe.get_import_table(ilt_rva)
            iat = pe.get_import_table(iat_rva)

            if iat is None:
                logger.warning("IAT is None for %s", dll_name)
                continue

            if ilt is None:
                logger.warning("ILT is None for %s", dll_name)
                results["missing_IAT"].append(dll_name)
                # broken ILT, use IAT as source as well as dest.
                ilt, ilt_rva = iat, iat_rva
                continue

            for idx in range(len(ilt)):
                hint_rva = ilt[idx].AddressOfData
                if hint_rva & ordinal_flag:
                    # import is done by ordinal
                    ordinal = hint_rva & 0xFFFF
                    if dll_name not in results["ordinal_imports"]:
                            results["ordinal_imports"][dll_name] = []
                    results["ordinal_imports"][dll_name].append(ordinal)
                    continue
                    #logger.info(f"Ordinal: {hex(ordinal)}")

                else:
                    try:
                        # hint_rva + 2 is the RVA of the IMAGE_IMPORT_BY_NAME structure
                        # get hint and the name of the function
                        hint = pe.get_word_from_data(pe.get_data(hint_rva, 2), 0)
                        func_name = pe.get_string_at_rva(hint_rva + 2, pefile.MAX_IMPORT_NAME_LENGTH)
                        if not pefile.is_valid_function_name(func_name):
                            logger.warning(f"[!] Invalid function name at {hex(hint_rva)}")
                            continue
                        func_name = func_name.decode('utf-8', errors='replace')

                        # store what functions are used from dll
                        if dll_name not in results["imports"]:
                            results["imports"][dll_name] = {}
                        results["imports"][dll_name][func_name] = hint

                    except Exception as e:
                        logger.warning(f"Failed to resolve function name at {hex(hint_rva)}: {e}")
                        continue
    
    except Exception as e:
        logger.warning("Failed to process file: %s", e)
        return None
    
    logger.info(pprint.pformat(results))
    return results


def is_nsis(file_path):
    """
    Check if Windows installer was created using NSIS (Nullsoft Scriptable Install System).

    Parameters:
        filepath (str): path to installer

    Returns:
        bool: True if installer is signed, otherwise False.
    """
    try:
        pe = pefile.PE(file_path, fast_load=False)
        last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        offset = last.PointerToRawData + last.SizeOfRawData

        # The NSIS data is appended after the last section of the PE file.
        with open(file_path, "rb") as f:
            f.seek(offset)
            compressed = f.read()

        if b"NullsoftInst" in compressed:
            logger.info("File is an NSIS installer.")

            # If you want to read the byte sequence of the installer, uncomment the line below.
            #  _read_byte_sequence(compressed)

            return True

    except Exception as e:
        logger.warning("Failed to process file: %s", e)
    return False


def is_signed(file_path):
    """
    Check if Windows installer is signed or not.

    Parameters:
        filepath (str): path to installer

    Returns:
        bool: True if installer is signed, otherwise False.
    """
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
    
    
def is_malicious_hash_virustotal(filehash, vt_api_key):
    """
    Check if the Windows installer is known to be malicious and/or suspicious on VirusTotal.
    This function requires a personal VirusTotal API key.

    Parameters:
        filehash (str): SHA256 hash of the installer
        vt_api_key (str): API key for VirusTotal

    Returns:
        bool: True if hash is known to be malicious and/or suspicious, False otherwise
    """
    logger.info("Checking hash %s on VirusTotal...", filehash)

    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {
    "accept": "application/json",
    "x-apikey": vt_api_key
    }

    try:
        response = requests.get(url, headers=headers)
        # Check if the request was successful
        response.raise_for_status()
    except requests.RequestException as e:
        logger.warning(f"Error checking hash on VirusTotal: {e}")
        return False
    
    if response.status_code == 404:
        logger.info("Hash not found on VirusTotal.")
        return False
    
    try:
        # Parse the JSON response
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        # check for reports of installer being malicious and / or suspicious
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            logger.warning("Hash is known to be malicious or suspicious on VirusTotal.")
            return True

        logger.info("Hash is not known to be malicious or suspicious on VirusTotal.")
        return False

    except (ValueError, KeyError) as e:
        logger.warning(f"Error parsing VirusTotal response: {e}")
        return False


def analyze_installer_metadata(file_path, check_virustotal, vt_api_key):
    """
    Wrapper function for initial analysis of the Windows installer.
    This function checks if: \n
        1. The installer was created using NSIS (Nullsoft Scriptable Install System)
        2. If it is signed
        3. Optional: If hash is known to be malicious and/or suspicious on VirusTotal (requires API key from user)

    Parameters:
        file_path (str): Path to the installer file
        check_virustotal (bool): Flag to check hash on VirusTotal
        vt_api_key (str): API key for VirusTotal

    Returns:
        dict: A dictionary with the following keys:
            - "is_nsis" (bool): Whether the installer is identified as NSIS.
            - "is_signed" (bool): Whether the installer is digitally signed.
            - "is_malicious_hash_virustotal" (bool): Whether the hash is flagged as malicious on VirusTotal.
    """
    results = {}
    results["is_nsis"] = is_nsis(file_path)
    results["is_signed"] = is_signed(file_path)
    if check_virustotal:
        results["is_malicious_hash_virustotal"] = is_malicious_hash_virustotal(sha256hash(file_path), vt_api_key)
    else:
        logger.info("Skipping VirusTotal check as per user request.")
        results["is_malicious_hash_virustotal"] = None
    return results


def analyze_installer(installer_path, check_vt, vt_api_key, logger):
    logger.info(f"Starting analysis for: {installer_path}")
    results = analyze_installer_metadata(installer_path, check_vt, vt_api_key)

    logger.info(f"Initial analysis completed. Results: {results}")

    list_contents_7z(installer_path, logger)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = extract_files_7z(installer_path, temp_dir)
            logger.info(f"Extraction completed. Files extracted to: {temp_dir}")

            for f in extracted_files:
                allowed_extensions = {'.exe', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.scr'}

                if pathlib.Path(f).suffix.lower() in allowed_extensions:
                    logger.info(f" Resolve .dll's in file - {f}")

                    ## resolve imports of extracted PE file
                    results = resolve_pe_imports(f, logger)
                    #logger.info(f"Resolved imports for {f}: {pprint.pprint(results)}")

                    # check if installer is using COM (Component Object Model) and uses ole32.dll
                    # this is a common library used for embedding files or additional script content.
                    # can be used to embedd .nsi script in the installer.
                    # uses_ole32 = False
                    # if 'ole32.dll' in results["imports"].keys():
                    #     uses_ole32 = True
                    #     logger.info(f"File {f} uses ole32.dll for COM operations? {uses_ole32}")
            
            logger.info("DLL analysis completed.")

    except Exception as e:
        logger.error(f"Failed to extract/analyze: {e}")