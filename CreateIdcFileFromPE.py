import sys
import os.path
from SymnetStruct import *


def create_idc_file(file_path, symbol_table):
    with open('{0}.idc'.format(file_path[:-4]), 'w', 0) as f:
        f.write('#include <idc.idc>\nstatic main(void) {\n')
        for entry in symbol_table:
            if (entry.e_type & 0b00110000) >> 4 == int(DerivedType.DT_FCN) and entry.e_scnum > 0:
                name = entry.e.e_name.rstrip('\0')
                if not name.startswith('___'):
                    name = name.strip('_')
                address = str(hex(BASE_ADDRESS + entry.sec_vtrl_addrs + entry.e_value))
                f.write('\tMakeNameEx({0}, "{1}", SN_NOWARN);\n'.format(address, name))
                if name == 'main':
                    f.write('\tJump({0});\n'.format(address))
        f.write('}\n')
        f.close()


def main(argv):
    file_path = argv[0]
    symbol_table = []
    if not os.path.isfile(file_path):
        raise Exception('File Not Exist')

    with open(file_path, 'rb') as f:
        buf = f.read()
        if buf[:2] != 'MZ':
            raise Exception('Not A Valid x86 PE File')

        nt_header_location = struct.unpack_from("<I", buf[NT_HEADER_PTR_LOCATION:NT_HEADER_PTR_LOCATION + 4])[0]
        machine_type_location = nt_header_location + OFFSET_MACHINE_TYPE_LOCATION
        if struct.unpack_from("<H", buf[machine_type_location:machine_type_location+2])[0] != I386_MACHINE:
            raise Exception('Not A Valid x86 PE File')

        symbol_table_location = nt_header_location + OFFSET_PTR_SYMBOL_TABLE
        number_of_symbols_location = nt_header_location + OFFSET_NUM_OF_SYMBOL
        symbol_table_offset = struct.unpack_from("<I", buf[symbol_table_location:symbol_table_location+4])[0]
        number_of_symbols = struct.unpack_from("<I", buf[number_of_symbols_location:number_of_symbols_location+4])[0]

        if symbol_table_offset == 0 or number_of_symbols == 0:
            raise Exception('There is No Debug Data, You Will Need To Work Harder :-)')

        string_table_offset = symbol_table_offset + (number_of_symbols * SYMNET_STRUCT_SIZE)
        i = 0
        print '=' * 10 + 'Symbol Table' + '=' * 10
        while i < number_of_symbols:
            entry = Symnet(string_table_offset, buf, nt_header_location,symbol_table_offset + (i * SYMNET_STRUCT_SIZE))
            if entry.e_numaux > 0:
                i += entry.e_numaux
            print (entry)
            print '=' * 32
            symbol_table.append(entry)
            i += 1
        f.close()

    create_idc_file(file_path, symbol_table)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: CreateIdcFileFromPE.py pe_file_name'
    else:
        main(sys.argv[1:])
