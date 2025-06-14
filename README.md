# nsispy 

`nsispy` is a Python library and command-line tool (CLI) for inspecting and analyzing Windows Installers created with NSIS (Nullsoft Scriptable Install System). 

## Features
- Query the VirusTotal API to determine if an installer is flagged as malicious or suspicious.
- Extract embedded files from NSIS installers using 7-Zip.
- Verify the digital signature of installer files.
- Analyze extracted binaries to identify Windows API calls and imported DLLs.

## Installation

`nsispy` is currently available from source. To install and use it, clone the repository and set up a virtual environment:

```
# Clone the library source code
git clone https://github.com/annalithell/nsispy.git
cd nsispy

# Create and activate a virtual environment
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

# Install the library
pip install .
```

**Dependencies**
- **7-Zip** must be installed and accessible in your system's `PATH` to support extraction functionality. Download it from the official site: https://www.7-zip.org/ 
- This project was developed using Python 3.11.9. 

## Usage

This section explains how to use the CLI. To view available library functions, see [📚 nsispy Library Documentation](docs/library.md). 

**How to run the CLI**

Ensure you've followed the installation steps above. Activate your virtual environment and navigate to the `nsispy` directory. 

To analyze an NSIS installer from the command-line, run:
   
`nsispy --path /path/to/installer.exe --check-vt`

**CLI Options**
- `--path` [PATH]: Path to the `.exe` installer to be analyzed (*Required*).
- `--check-vt` or `-vt`: Optional flag to query the VirusTotal API for known threats.
- `--help` or `-h`: Display CLI usage instructions.

⚠️ To use `--check-vt` you must have a personal VirusTotal account and provide an API key when prompted by the CLI.

## License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](./LICENSE) file for details.
