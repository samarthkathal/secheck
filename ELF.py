import os
import sys
import subprocess
import json


# reference 
# https://opensource.com/article/21/6/linux-checksec

elf_files = {}


#def checkReadELF():
#	reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])
#	installed_packages = [r.decode().split('==')[0] for r in reqs.split()]
#
#	if 'pyelftools' not in installed_packages:
#		#install pyelftools
#		subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyelftools'])


def process_file(filename):
	print('In file:', filename)
	with open(filename, 'rb') as f:
		elffile = ELFFile(f)

		for section in elffile.iter_sections():
			if section.name.startswith('.debug'):
				print('  ' + section.name)



def findELFs():
	a = []
	l = []
	for i in range(1, len(sys.argv)):

		for (dirpath, dirnames, files) in os.walk(sys.argv[i], followlinks=False):
			for f in files:
				file_path = os.path.join(dirpath, f)
				if os.path.isfile(file_path):
					l.append(file_path)
			

	for i in range(len(l)):
		with open(l[i], "rb") as f:
			byte = f.read(4)
			if byte == b'\x7fELF': #b'7F454C46'
				a.append(l[i])
			f.close()
	return a




def checkELF(a):
	d = {
	"arch" : False, #5th, if 1=32, 2=64
	"endian" : False, #6th, if 1=lsb, 2=msb
	"canary" : False, #https://www.elttam.com/blog/playing-with-canaries/	https://gcc.gnu.org/pub/gcc/summit/2003/Stackguard.pdf
	"PIE" : False, 
	"RELRO" : False, #https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
	}


def checkRELRO(a):

	#############
	#RELRO check
	#############

	proc1 = subprocess.Popen(['readelf', '-W', '-l', a], stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(['grep', 'GNU_RELRO'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc3 = subprocess.Popen(['grep', 'BIND_NOW'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


	proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
	out1, err1 = proc2.communicate()
	out2, err2 = proc3.communicate()

	r = "no RELRO"

	if out1 != b'':
		if out2 != b'':
			r = "full RELRO"
		else:
			r = "partial RELRO"

	return r

#	readelf -l ./ls | grep 'GNU_RELRO' # partial
#	readelf -l ./ls | grep 'GNU_RELRO' and readelf -l ./ls | grep 'BIND_NOW' #full
#	else, norelro
#


def checkCanary(a):
	#############
	#Canary check
	#############

	proc1 = subprocess.Popen(['readelf', '-W', '-s', a], stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(['grep', '__stack_chk_fail'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


	proc1.stdout.close() # Allow proc1 to receive a SIGPIPE if proc2 exits.
	out, err = proc2.communicate()
	if out != b'':
		r = "canary found"
	else:
		r = "no canary found"

	return r
#	readelf -s ./ls | grep '__stack_chk_fail' #canary, else no canary
#

def checkNX(a):
	#############
	#NX check
	#############
	proc1 = subprocess.Popen(['readelf', '-W', '-l', a], stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(['grep', 'GNU_STACK'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


	o, e = proc2.communicate()

	if o != b'':
		r = "NX enabled"
	else:
		r = "NX not enabled"

	return r
#	readelf -W -l ./ls | grep 'GNU_STACK' #NX, else no NX
#




elf_files = findELFs()

d = {}

for i in range(len(elf_files)):
	d[elf_files[i]] = [
						{'RELRO' : checkRELRO(elf_files[i]) },
						{'Canary' : checkCanary(elf_files[i]) },
						{'NX' : checkNX(elf_files[i]) },
						]



with open('result.json', 'w') as fp:
    json.dump(d, fp)