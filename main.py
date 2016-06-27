import pefile
import sys
import math
from tornado.template import Template

def main(args):
    print "PyCrypt by bilka00"
    print "License: GPL v3"
    file = args[0]
    print "File: "+file
    try:
		pe =  pefile.PE(file)
    except:
		print "[!] ERROR: Can not open file [%s]" % file
		sys.exit()
    #Print file info begin
    print "File Info: "
    print pe.FILE_HEADER
    print "[*] PE Section Information:"
    for section in pe.sections:
	    print "\t[+] Name: %s, Virtual Address: %s, Virtual Size: %s, Characteristics: %s" % (section.Name,
																		 hex(section.VirtualAddress),
																		 hex(section.Misc_VirtualSize),
																		 hex(section.Characteristics))
    #Print file info end
    #Add selection
    pe.add_last_section(size=1024)
    pe.sections[0].xor_data(code=1)
    pe.data_copy(pe.sections[0].PointerToRawData, pe.sections[-1].PointerToRawData, 512)

    try:
        pe.write(filename="result.exe")
    except:
        print "Error saving"
        sys.exit(1)
if __name__ == '__main__':
    main(sys.argv[1:])