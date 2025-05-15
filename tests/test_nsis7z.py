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

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from nsispy.nsis7z import analyze_installer_7z, NSIS7zAnalysisError, _parse_7z_output

## TODO: Add more tests for different compression methods and edge cases

SAMPLE_OUTPUT = """
Path = test.exe
Type = NSIS
Method = LZMA2:24
Physical Size = 12345
Headers Size = 789
2019-01-01 12:34:56 ....A 1024 512 file1.txt
2019-01-01 12:35:00 ....A 2048 1024 file2.txt
-------------------
2 files, 3072 bytes
"""

ZERO_FILES_OUTPUT = """
Path = empty.exe
Type = NSIS
Method = LZMA2:24
Physical Size = 0
Headers Size = 0
-------------------
0 files, 0 bytes
"""

UNEXPECTED_OUTPUT = """
This is some unexpected output format
without proper file summary line
"""

@pytest.fixture(autouse=True)
def patch_isfile_true() -> None:
    """Patch os.path.isfile to always return True by default."""
    with patch("os.path.isfile", return_value=True):
        yield

@pytest.fixture(autouse=True)
def patch_shutil_which_7z() -> None:
    """Patch shutil.which to return a fake 7z path by default."""
    with patch("shutil.which", return_value="/usr/bin/7z"):
        yield

@pytest.fixture
def patch_subprocess_run() -> MagicMock:
    with patch("subprocess.run", autospec=True) as mock_run:
        yield mock_run

def test_file_not_found() -> None:
    with patch("os.path.isfile", return_value=False):
        with pytest.raises(FileNotFoundError, match="File does not exist:"):
            analyze_installer_7z("nonexistent.exe")

@patch("os.path.exists", return_value=False)
@patch("shutil.which", return_value=None)
@patch("os.path.isfile", return_value=True)
def test_7z_not_found_raises(mock_isfile, mock_which, mock_exists) -> None:
    with pytest.raises(RuntimeError, match="7z executable not found"):
        analyze_installer_7z("dummy.exe")

@patch("os.path.exists", return_value=True)
@patch("shutil.which", return_value=None)
@patch("os.path.isfile", return_value=True)
def test_7z_found_in_default_path(mock_isfile, mock_which, mock_exists, patch_subprocess_run: MagicMock) -> None:
    """Test fallback to default 7z path when not found in PATH."""
    mock_result = MagicMock()
    mock_result.stdout = SAMPLE_OUTPUT
    patch_subprocess_run.return_value = mock_result

    result = analyze_installer_7z("dummy.exe")
    assert result["header"]["Path"] == "test.exe"
    assert "file1.txt" in result["files"]

def test_analyze_success(patch_subprocess_run: MagicMock) -> None:
    mock_result = MagicMock()
    mock_result.stdout = SAMPLE_OUTPUT
    patch_subprocess_run.return_value = mock_result

    result = analyze_installer_7z("dummy.exe")

    assert isinstance(result, dict)
    assert "header" in result and "files" in result
    assert result["header"]["Path"] == "test.exe"
    assert "file1.txt" in result["files"]
    assert result["files"]["file1.txt"]["Size"] == "1024"

def test_subprocess_file_not_found(patch_subprocess_run: MagicMock) -> None:
    patch_subprocess_run.side_effect = FileNotFoundError
    with pytest.raises(NSIS7zAnalysisError, match="7z is not installed or not in PATH."):
        analyze_installer_7z("dummy.exe")

def test_subprocess_called_process_error(patch_subprocess_run: MagicMock) -> None:
    error = subprocess.CalledProcessError(1, ['7z', 'l', 'dummy.exe'], output="error output")
    patch_subprocess_run.side_effect = error
    with pytest.raises(NSIS7zAnalysisError, match="7z failed: error output"):
        analyze_installer_7z("dummy.exe")

def test_parse_7z_output_basic() -> None:
    parsed = _parse_7z_output(SAMPLE_OUTPUT)
    assert parsed["header"]["Path"] == "test.exe"
    assert "file1.txt" in parsed["files"]
    assert parsed["files"]["file2.txt"]["Compressed"] == "1024"

def test_parse_7z_output_zero_files() -> None:
    parsed = _parse_7z_output(ZERO_FILES_OUTPUT)
    assert parsed["header"]["Path"] == "empty.exe"
    assert parsed["files"] == {}

def test_parse_7z_output_unexpected_format() -> None:
    parsed = _parse_7z_output(UNEXPECTED_OUTPUT)
    assert parsed == {}
