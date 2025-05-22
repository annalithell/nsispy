# nsispy 

`nsispy` is a Python library and CLI tool for inspecting and analyzing NSIS (Nullsoft Scriptable Install System) `.exe` files.

## Features
- Extract `.exe` files using 7-Zip. 

TO BE CONTINUED 

## Installation

**Dependencies**
- To utilize the full functionality of the library, 7-Zip must be installed on you system. You can download it from the official website: https://www.7-zip.org/ 

TO BE CONTINUED

## Usage

This section describes how to run the CLI and what functions can be imported from the library. 

**How to run the CLI**

1. Clone the repo:
```
git clone https://github.com/annalithell/nsispy.git
cd nsispy 
``` 

1. Create a virtual environment:

`python -m venv venv`

3. Activate the virtual environment:

- On Windows:

`venv\bin\activate` 

4. Install the package:

`pip install .` 

5. Run the CLI:
   
`nsispy --path /path/to/installer.exe --check-vt`

**CLI Options**
- --path: Path to the `.exe` installer file to analyze (required).

- --check-vt: Optional flag to check the file hash on VirusTotal.
  
⚠️ To use `--check-vt` you must have a personal VirusTotal account and provide an API key when prompted.

**About the library**

TO BE CONTINUED

## Testing

TO BE CONTINUED

## License
This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](./LICENSE) file for details.
