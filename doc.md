**This file contains documentation about the project discoveries made so far.**

## The challenge
The main challenge is to retrieve all files associated with the NSIS-generated installer. In addition, retrieving the NSIS script would be helpful in order to retrieve what libraries are dynamically loaded by the installer during runtime, as these cannot be retrieved through static analysis. 

## Using 7zip
7zip was capable of retrieving the NSIS-script in past versions from 2015. In later version, this functionality have been abandoned. Using the version from 2015 might be a straight road forward in order to retrieve the NSIS script, but the version contains well-documented vulnerabilities. I would therefore not recommend to follow this path, certainly not without utilizing a VM. 

## How to retrieve the NSIS script
According to my understanding, the author of a NSIS script can choose to not include any trace of the script in the final installer. To investigate this hypothesis further, a way to move forward is to generate two nsis installer. These two installers should be generated using identical scripts except from the part where one explicitly is included in the installer while the other one is not. They should use the same compression method. Finally, reverse-engineer the byte code of the two scripts to understand where the nsis-script is located in the installer. This can be achieved by first locating the nsis "magic number" reference in the byte code and from there reverse-engineer the bytes. 
