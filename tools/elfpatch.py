#
#   Patch ELF files so LD doesn't cry
#

import struct, sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} elf_files")
        sys.exit(1)

    for i in sys.argv[1:]:
        with open(i, 'r+b') as f:
            magic = struct.unpack('>I', f.read(4))[0]
            if magic != 0x7F454C46:
                print('Error: Not an ELF file')
                sys.exit(1)

            f.seek(36)
            f.write(struct.pack('>I', 0x20000001))
