# Description
These scripts are only meant to check of certain well known buffer overflow mitigation flags. you can use these scripts to quickly audit multiple elf files present in different directories.

The audit currently only includes checks for Buffer overflow prevention techniques such as RELRO, NoExecute (NX), Stack Canaries.


## ELF.py

usage:
> python3 ELF.py [path/to/ELFs]

Multiple path to elfs can be used as well.


This script filters all elf files and documents their path into a json file. it also documents all info on RELRO, canary and NX of every elf file avaliable
all results are stored in result.json




## sec.py

This script allows you to further filter result.json and print the path to elf files based on which filters are enabled.

run,

> sec.py -h 

for more info.