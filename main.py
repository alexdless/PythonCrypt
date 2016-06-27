import pefile
import pydasm
import sys

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
    print "File Info: "
    print pe.FILE_HEADER

if __name__ == '__main__':
    main(sys.argv[1:])