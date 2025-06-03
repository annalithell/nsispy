**This file contains documentation about the project discoveries made so far.**

## The challenge
The main challenge is to retrieve all files associated with the NSIS-generated installer. In addition, retrieving the NSIS script would be helpful in order to retrieve what libraries are dynamically loaded by the installer during runtime.

## Using 7-zip
7-zip was capable of decompressing NSIS installers in past versions from 4.42. It was also capable of extracting the compiled scriptcode since version 9.34. However, this functionality was later removed in version 15.06 and have not been supported ever since ([source](https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer%3F)). Using the version from 2015 might be a straight road forward in order to retrieve the NSIS script, but the version contains well-documented vulnerabilities. I would therefore not recommend to follow this path, certainly not without utilizing a VM. 

## Path towards retrieving the NSIS script
According to my understanding, the author of a NSIS script can choose to not include any trace of the script in the final installer (see section ['About'](https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer%3F)). To investigate this hypothesis further, a way to move forward is to generate two nsis installers. These two installers should be generated using identical scripts except from the part where one explicitly states to included in the nsis script while the other one does not. They should use the same compression method. Finally, reverse-engineer the byte code of the two scripts to understand where the nsis-script is located in the installer. This can be achieved by first locating the nsis "magic number" reference in the byte code and from there reverse-engineer the byte sequence. 

## Path towards retrieving the DLLs 
So far, the library is capable of retrieving information about the DLLs by calling the function 'resolve_pe_imports', heavily inspired by the following [code](https://vtopan.wordpress.com/2019/04/12/patching-resolving-imports-in-a-pe-file-python-pefile/ ). The function parses information contained in the PE directory entry *IMAGE_DIRECTORY_ENTRY_IMPORT*. This entry contains information related to the Import Address Table (IAT) and contains information about DLLs and functions imported by the installer. So far, this information is pretty uninteresting, as most of the DLLs are valid and used frequenctly in any Windows application (malicious or not). Still it demonstrates some of the capabilities of the pefile Python library.
