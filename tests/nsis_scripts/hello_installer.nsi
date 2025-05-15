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

  # Extract the included file 'data.txt' to the install directory
  SetOutPath "$INSTDIR"
  File "data.txt"


SectionEnd
