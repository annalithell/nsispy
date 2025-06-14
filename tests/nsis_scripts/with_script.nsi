# Simulated malicious NSIS script (no harmful content)

!include "FileFunc.nsh"
!include "LogicLib.nsh"

Outfile "with_script.exe"
SilentInstall silent
RequestExecutionLevel admin

Section
    # Simulate writing an embedded EXE to a temp directory
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File /oname=payload.exe "hello_installer.exe"

    # Embed this script itself in the installer
    File /oname=benign_script.nsi "with_script.nsi"

    # Simulate registry persistence (harmless key)
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "BenignApp" "$PLUGINSDIR\payload.exe"

    # Simulate scheduled task or autorun (does nothing harmful)
    ExecShell "open" "$PLUGINSDIR\hello_installer.exe"

    # Simulate dropping decoy files
    SetOutPath "$INSTDIR\Docs"
    File "data.txt"

    # Simulate collecting system info (just writing it to file)
    nsExec::ExecToLog 'cmd /c echo %USERNAME% > $INSTDIR\user_info.txt'

    # Optional: create a fake uninstall entry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BenignApp" "DisplayName" "Benign App"
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Function .onInit
    MessageBox MB_OK "Benign NSIS installer running."
FunctionEnd

Function un.onUninstall
    Delete "$INSTDIR\payload.exe"
    Delete "$INSTDIR\user_info.txt"
    Delete "$INSTDIR\Docs\data.txt"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Run\BenignApp"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\BenignApp"
    RMDir /r "$INSTDIR"
FunctionEnd
