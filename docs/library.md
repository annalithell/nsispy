# nsispy Library Documentation

This document provides a detailed reference for the primary library modules within the `nsispy` project.

***
## Module: `nsispy.analyzer`

This module is responsible for analyzing NSIS-based Windows installer executables (.exe). It inspects metadata, checks digital signatures, queries VirusTotal for known threats and analyze extracted PE files.

| Function | Description |
|----------|-------------|
| `analyze_installer (installer_path, check_vt, vt_api_key, logger)` | Performs a complete analysis of an installer, including metadata and PE import results. |
| `analyze_installer_metadata(file_path, check_virustotal, vt_api_key)` | Checks installer metadata including NSIS format, signature validity and VirusTotal status. |
| `is_nsis(file_path)` | Detects if the installer was created using NSIS. |
| `is_signed(file_path)` | Verifies whether the installer has a valid Authenticode signature. |
| `is_malicious_hash_virustotal(filehash, vt_api_key)` | Queries VirusTotal to check if a file hash is known to be malicious (*Requires Private API key*) |
| `resolve_pe_imports(file_path, logger)` | Parses a PE (Portable Executable) file to identify its imported DLLs and functions. |
| `_read_byte_sequence(compressed)` (*Deprecated*)| Previously used to dump raw NSIS byte payloads to a file. No longer active in the current analyzer. |

***

## Module: `nsispy.nsis7z`
This module handles 7-Zip-based operations for analyzing and extracting files from NSIS installer packages.

| Function | Description |
|----------|-------------|
| `list_contents_7z(filepath, logger)` | Lists contents of an NSIS-generated installer using 7-Zip. |
| `extract_files_7z(filepath, output_dir)` | Extracts the contents of an installer using 7-Zip. |
| `_parse_7z_output(output)` | Helper function used to parse the raw text output from 7-Zip. Extracts structured header and file metadata. 

***
## Module: `nsispy.util`
This utility module provides helper methods used in the `nsispy` library. 

| Function | Description |
|----------|-------------|
| `get_7z_path()` | Locates the 7-Zip executable on the system. |
| `sha256hash(file_path)` | Computes SHA-256 hash of a file. |
| `setup_logging()` | Configures logging with file and stream handlers.
