import pefile
import sys
import os
import random
import math
from tornado.template import Template

def fasm_trash_gen():

    return
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
    print "[*] PE File Info: "
    print pe.FILE_HEADER
    print "[*] PE Section Information:"
    for section in pe.sections:
	    print "\t[+] Name: %s, Virtual Address: %s, Virtual Size: %s, Characteristics: %s" % (section.Name,
																		 hex(section.VirtualAddress),
																		 hex(section.Misc_VirtualSize),
																		 hex(section.Characteristics))
    print "[*] PE Import Information:"
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print entry.dll
        for imp in entry.imports:
            print '\t', hex(imp.address), imp.name
    #Print file info end

    #Add selection
    pe.add_last_section(size=1024)
    pe.sections[0].xor_data(code=1)
    pe.data_copy(pe.sections[0].PointerToRawData, pe.sections[-1].PointerToRawData, 512)


    imports = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            imports[imp.name] = imp.address

    asm = Template(open("pack.tpl.asm", "r").read()).generate(
        imports=imports,
        go=pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress+512,

    )

    with open("pack.asm", "w") as f:
        f.write(asm)
    os.system(r"C:\Users\admin\PycharmProjects\PythonCrypt\fasm\FASM.EXE pack.asm")
    asm = Template(open("copy.tpl.asm", "r").read()).generate(
        imports=imports,
        copy_from=pe.OPTIONAL_HEADER.ImageBase+pe.sections[-1].VirtualAddress,
        copy_to=pe.OPTIONAL_HEADER.ImageBase+pe.sections[0].VirtualAddress,
        copy_len=512,
        xor_len=pe.sections[0].Misc_VirtualSize,
        key_encode=1,
        original_eop=pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    )
    with open("copy.asm", "w") as f:
        f.write(asm)
    os.system(r"C:\Users\admin\PycharmProjects\PythonCrypt\fasm\FASM.EXE copy.asm")

    new_pack = open("pack.bin", "rb").read()
    new_copy = open("copy.bin", "rb").read()
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[0].VirtualAddress
    pe.data_replace(offset=pe.sections[0].PointerToRawData, new_data=new_pack)
    pe.data_replace(offset=pe.sections[-1].PointerToRawData+512, new_data=new_copy)
    pe.sections[0].Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]




    try:
        pe.write(filename="result.exe")
    except:
        print "Error saving"
        sys.exit(1)
if __name__ == '__main__':
    main(sys.argv[1:])