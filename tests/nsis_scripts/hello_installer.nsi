# hello_installer.nsi
# using zlib compression

Outfile "hello_installer.exe"
# Set install directory to where the installer is being run from
InstallDir "$EXEDIR"

Page directory
Page instfiles

Section "Install"

  # Create installation directory
  CreateDirectory "$INSTDIR"

  # Write a harmless text file
  FileOpen $0 "$INSTDIR\hello.txt" w
  FileWrite $0 "Hello World!\r\n"
  FileClose $0

SectionEnd
