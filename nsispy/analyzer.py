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

from .nsis7z import extract_7z, list_contents_7z
from .util import sha256hash

logger = logging.getLogger(__name__)

# def resolve_pe_exports(file_path, logger):
# TODO: Maybe implement this later. 
#     return


def resolve_pe_imports(file_path, logger):
    """
    Resolve imports of a PE using PEFile. 
    This function's logic is inspired by the work of Vlad Topan.
    Reference: https://vtopan.wordpress.com/2019/04/12/patching-resolving-imports-in-a-pe-file-python-pefile/ 
    """
    results = {
        "imports": {},
        "ordinal_imports" : {},
        "missing_IAT" : [],
    }

    try:
        # read executable as bytearray
        data = bytearray(open(file_path, "rb").read())
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        
        # check if binary is 64 bit or 32 bit
        bits = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        #logger.info(f"Binary is {bits} bit")
       
        # create flag later used to check if file is imported by ordinal
        ordinal_flag = 2 ** (bits - 1)
        
        # entry corresponds to a DDL imported by the executable
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            ddl_name = entry.dll.decode("utf-8")
            
            # fetch relative virtual address (RVA) of import lookup table (ILT)
            ilt_rva = entry.struct.OriginalFirstThunk
            
            # fetch RVA of the import address table (IAT)
            iat_rva = entry.struct.FirstThunk

            # fetch tables
            ilt = pe.get_import_table(ilt_rva)
            iat = pe.get_import_table(iat_rva)

            # # check if installer is using COM (Component Object Model) and uses ole32.dll
            # # this is a common library used for embedding files or additional script content.
            # # can be used to embedd .nsi script in the installer.
            # uses_ole32 = False
            # if 'ole32.dll' in ddl_name.lower():
            #     uses_ole32 = True

            if iat is None:
                logger.warning("IAT is None for %s", ddl_name)
                continue

            if ilt is None:
                logger.warning("ILT is None for %s", ddl_name)
                results["missing_IAT"].append(ddl_name)
                # broken ILT, use IAT as source as well as dest.
                ilt, ilt_rva = iat, iat_rva
                continue

            for idx in range(len(ilt)):
                hint_rva = ilt[idx].AddressOfData
                if hint_rva & ordinal_flag:
                    # import is done by ordinal
                    ordinal = hint_rva & 0xFFFF
                    if ddl_name not in results["ordinal_imports"]:
                            results["ordinal_imports"][ddl_name] = []
                    results["ordinal_imports"][ddl_name].append(ordinal)
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
                        #logger.info(f"Imported Function: {func_name} (Hint: {hint})")
                        #results["imports"].append(f"{ddl_name}!{func_name}")
                        if ddl_name not in results["imports"]:
                            results["imports"][ddl_name] = {}

                        results["imports"][ddl_name][func_name] = hint

                        #logger.info(pprint.pprint(results["imports"]))
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
    Check if installer is NSIS or not. 
    """
    try:
        pe = pefile.PE(file_path, fast_load=False)
        last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        offset = last.PointerToRawData + last.SizeOfRawData
        # The NSIS data is appended after the last section of the PE file.
        with open(file_path, "rb") as f:
            f.seek(offset)
            compressed = f.read()
            #logger.info(f"Compressed data length: {len(compressed)}")
            #logger.info(compressed)
        if b"NullsoftInst" in compressed:
            logger.info("File is an NSIS installer.")

            # Write the compressed NSIS payload to a file
            with open("nsis_payload.bin", "wb") as f:
                f.write(compressed)
                logger.info("NSIS payload written to nsis_payload.bin")
            
            with open("nsis_payload.bin", "rb") as f:
                # Check if the file starts with the NSIS magic number
                data = (f.read())
                logger.info(data)
            return True

    except Exception as e:
        logger.warning("Failed to process file: %s", e)
    return False


def is_signed(file_path):
    """
    Check if file is signed or not. 
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
    
    
def is_hash_known(filehash, vt_api_key):
    """
    Check if the hash is known to be malicious and/or suspicious on VirusTotal.
    This function requires a personal VirusTotal API key.

    Parameters:
        filehash (str): SHA256 hash of the file
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

    response = requests.get(url, headers=headers, params={"apikey": vt_api_key})

    if response.status_code == 200:
        logger.info("Hash found on VirusTotal.")
        data = response.json().get("data", {})
        try:
            attributes = data.get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats")
            if last_analysis["malicious"] > 0 or last_analysis["suspicious"] > 0:
                logger.warning("Hash is known to be malicious or suspicious on VirusTotal.")
                return True
            else: 
                logger.info("Hash is not known to be malicious or suspicious on VirusTotal.")
                return False
        except KeyError as e:
            logger.warning("Error parsing VirusTotal response: %s", e)
            return False
    elif response.status_code == 404:
        logger.info("Hash not found on VirusTotal.")
        return False
    else:
        logger.warning("Error checking hash on VirusTotal: %s", response.status_code)
        return False
    

def initial_analysis(file_path, check_virustotal, vt_api_key):
    """
    Wrapper function for initial analysis of the installer.
    This function checks if:
        1. The file is an NSIS installer
        2. If it is signed (Windows: use getAuthenticodeSignature)
        3. Optional: If hash is known on virustotal (requires API key from user)

    Parameters:
        file_path (str): Path to the installer file
        check_virustotal (bool): Flag to check hash on VirusTotal
        vt_api_key (str): API key for VirusTotal

    Returns:
        Dictionary: {
            "is_nsis": bool,
            "is_signed": bool,
            "hash_known": bool
        }
    """
    results = {}
    results["is_nsis"] = is_nsis(file_path)
    results["is_signed"] = is_signed(file_path)
    if check_virustotal:
        results["is_hash_known"] = is_hash_known(sha256hash(file_path), vt_api_key)
    else:
        logger.info("Skipping VirusTotal check as per user request.")
        results["is_hash_known"] = False
    return results


def run_analysis(installer_path, check_vt, vt_api_key, logger):
    logger.info(f"Starting analysis for: {installer_path}")
    results = initial_analysis(installer_path, check_vt, vt_api_key)

    logger.info(f"Initial analysis completed. Results: {results}")

    list_contents_7z(installer_path, logger)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_files = extract_7z(installer_path, temp_dir)
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
                    uses_ole32 = False
                    if 'ole32.dll' in results["imports"].keys():
                        uses_ole32 = True
                        logger.info(f"File {f} uses ole32.dll for COM operations? {uses_ole32}")

                    # check if extracted PE file is signed or not
                    if is_signed(f):
                        logger.info(f"File {f} is signed.")
                    else:
                        logger.info(f"File {f} is not signed.")
            
            logger.info("DLL analysis completed.")

    except Exception as e:
        logger.error(f"Failed to extract/analyze: {e}")