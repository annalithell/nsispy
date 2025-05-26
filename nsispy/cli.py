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

# cli.py

import logging
import argparse
import pathlib
import tempfile
import sys

from .nsis7z import extract_7z
from .analyzer import initial_analysis, resolve_pe_imports, analyze_pe_header
from .util import setup_logging

def _prompt_for_virustotal_key(logger):
    proceed = input("In order to analyze the file using VirusTotal, we need your personal API key.\nDo you wish to proceed? (yes/no): ").strip().lower()
    if proceed not in ("yes", "y"):
        logger.info("User declined VirusTotal check.")
        return None
    api_key = input("Enter your VirusTotal API key: ").strip()
    if not api_key:
        logger.warning("No API key provided. Skipping VirusTotal check.")
        return None
    return api_key


def run_analysis(installer_path, check_vt, vt_api_key, logger):
    logger.info(f"Starting analysis for: {installer_path}")
    initial_analysis(installer_path, check_vt, vt_api_key)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            extract_7z(installer_path, temp_dir)
            logger.info(f"Extraction completed. Files extracted to: {temp_dir}")

            # List extracted files for info
            extracted_files = list(pathlib.Path(temp_dir).rglob("*"))

            logger.info(f"Extracted {len(extracted_files)} files:")
            for f in extracted_files:
                logger.info(f" - {f}")

            # TODO: integrate analyzer here in future
            #analyze_extracted_files(temp_dir)
            resolve_pe_imports(installer_path)
            logger.info("DLL analysis completed.")

    except Exception as e:
        logger.error(f"Failed to extract/analyze: {e}")


def main():
    logger = setup_logging()

    parser = argparse.ArgumentParser(description="NSIS Installer extractor and analyzer")
    parser.add_argument("--path", required=True, help="Path to the NSIS installer .exe file")
    parser.add_argument("-vt", "--check-vt", action="store_true", help="Provide flag to check file hash on VirusTotal")
    args = parser.parse_args()

    installer_path = args.path
    if not pathlib.Path(installer_path).is_file():
        logger.error(f"Invalid path provided: {installer_path}")
        sys.exit(1)

    vt_api_key = None
    if args.check_vt:
        vt_api_key = _prompt_for_virustotal_key(logger)

    run_analysis(installer_path, bool(vt_api_key), vt_api_key, logger)


if __name__ == "__main__":
    main()
