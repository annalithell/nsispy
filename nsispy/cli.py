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

from .nsis7z import extract_7z

def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler("nsispy.log"),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="NSIS Installer extractor and analyzer")
    parser.add_argument("installer", help="Path to the NSIS installer .exe file")
    args = parser.parse_args()

    installer_path = args.installer

    logger.info(f"Starting extraction for: {installer_path}")

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

    except Exception as e:
        logger.error(f"Failed to extract/analyze: {e}")


if __name__ == "__main__":
    main()
