import sys
import json
import argparse, textwrap

#https://bitvijays.github.io/LFC-BinaryExploitation.html
#https://0xdefec8ed.github.io/analysing-elf-binaries.html


parser=argparse.ArgumentParser(description=''' pass args to filter out the result ''', 
    formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--norelro', action='store_true', help=textwrap.dedent('''\
    enable this to list all files with no relro\n
    RELRO stands for Relocation Read-Only. ELF binaries use a Global Offset Table (GOT) to resolve functions dynamically.
    more info on PLT/GOT: https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html \n
    When enabled, this security property makes the GOT within the binary read-only, which prevents some relocation attacks\n
    more info on norelro/partialrelro : https://ctf101.org/binary-exploitation/relocation-read-only/ 
    https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
    '''))

parser.add_argument('--partialrelro', action='store_true', help='enable this to list all files with partial relro')

parser.add_argument('--canary', action='store_true', help=textwrap.dedent('''\
    enable this to list all files with no canary\n
    canary is a random, known value by the kernel that are placed between a buffer and the return addresses information(stored in the stack 
    when a function makes a call to another functon)
    some overflow techniques can corrupt the stack with specially crafted values for the buffer. canary is used to mitigate such techniques.
    '''))

parser.add_argument('--nx', action='store_true', help=textwrap.dedent('''\
    enable this to list all files with no nx bit set\n
    NX stands for non executable stack. some buffer overflow techniques use stack to inject and execute malicious code.
    if this is set to disabled, the stack is exclusively set as non executable.\n

    '''))


args=parser.parse_args()
if len(sys.argv) == 1:
    print('to check usage, type: ', sys.argv[0], '-h')

with open('result.json') as json_file:
    data = json.load(json_file)

no_relro_files, partial_relro_files, canary_files, nx_files = [], [], [], []

for file_k, file_v in data.items():

    #file_v[0] #RELRO dict
    #file_v[1] #canary dict
    #file_v[2] #NX dict
    if file_v[0]['RELRO'] == 'no RELRO':
        no_relro_files.append(file_k)
    if file_v[0]['RELRO'] == 'partial RELRO':
        partial_relro_files.append(file_k)

    if file_v[1]['Canary'] == 'no canary found':
        canary_files.append(file_k)

    if file_v[2]['NX'] == 'NX not enabled':
        nx_files.append(file_k)


if args.norelro:
    if args.partialrelro:
        print('no data')
    elif args.canary:
        if args.nx:
            print(set(no_relro_files).intersection(canary_files).intersection(nx_files))
        else:
            print(set(no_relro_files).intersection(canary_files))
    elif args.nx:
        print(set(no_relro_files).intersection(nx_files))
    else:
        print(set(no_relro_files))
elif args.partialrelro:
    if args.canary:
        if args.nx:
            print(set(no_relro_files).intersection(canary_files).intersection(nx_files))
        else:
            print(set(no_relro_files).intersection(canary_files))
    elif args.nx:
        print(set(no_relro_files).intersection(nx_files))
    else:
        print(set(partial_relro_files))
elif args.canary:
    if args.nx:
        print(set(canary_files).intersection(nx_files))
    else:
        print(set(canary_files))
elif args.nx:
    print(set(nx_files))



    





