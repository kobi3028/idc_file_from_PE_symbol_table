import struct
from enum import Enum

"""
documentation from: http://www.delorie.com/djgpp/doc/coff/symtab.html

typedef struct {
  union {
    char e_name[E_SYMNMLEN];
    struct {
      unsigned long e_zeroes;
      unsigned long e_offset;
    } e;
  } e;
  unsigned long e_value;
  short e_scnum;
  unsigned short e_type;
  unsigned char e_sclass;
  unsigned char e_numaux;
} SYMENT;
"""

# consts
BASE_ADDRESS = 0x400000
SECTION_HEADER_ENTRY_SIZE = 0x28
VIRTUAL_ADDRESS_OFFSET = 0x0c
SYMNET_STRUCT_SIZE = 0x12
I386_MACHINE = 0x14c

OFFSET_MACHINE_TYPE_LOCATION = 0x04
NT_HEADER_PTR_LOCATION = 0x3c
NT_HEADER_SIZE = 0xf8
OFFSET_PTR_SYMBOL_TABLE = 0x0c
OFFSET_NUM_OF_SYMBOL = 0x10


class BaseTypes(Enum):
    """
    on bits ---XXXXX
    """
    T_NULL = 0b0000  # No symbol
    T_VOID = 0b0001  # void function argument (not used)
    T_CHAR = 0b0010  # character
    T_SHORT = 0b0011  # short integer
    T_INT = 0b0100  # integer
    T_LONG = 0b0101  # long integer
    T_FLOAT = 0b0110  # floating point
    T_DOUBLE = 0b0111  # double precision float
    T_STRUCT = 0b1000  # structure
    T_UNION = 0b1001  # union
    T_ENUM = 0b1010  # enumeration
    T_MOE = 0b1011  # member of enumeration
    T_UCHAR = 0b1100  # unsigned character
    T_USHORT = 0b1101  # unsigned short
    T_UINT = 0b1110  # unsigned integer
    T_ULONG = 0b1111  # unsigned long
    T_LNGDBL = 0b10000  # long double(special case bit pattern)


class DerivedType(Enum):
    """
    on bits --XX----
    """
    DT_NON = 0b00  # No derived type
    DT_PTR = 0b01  # pointer to T
    DT_FCN = 0b10  # function returning T
    DT_ARY = 0b11  # array of T

    def __int__(self):
        return self._value_


class StorageClass(Enum):
    C_NULL = 0  # No entry
    C_AUTO = 1  # Automatic variable
    C_EXT = 2  # External(public) symbol - this covers globals and externs
    C_STAT = 3  # static(private) symbol
    C_REG = 4  # register variable
    C_EXTDEF = 5  # External definition
    C_LABEL = 6  # label
    C_ULABEL = 7  # undefined label
    C_MOS = 8  # member of structure
    C_ARG = 9  # function argument
    C_STRTAG = 10  # structure tag
    C_MOU = 11  # member of union
    C_UNTAG = 12  # union tag
    C_TPDEF = 13  # type definition
    C_USTATIC = 14  # undefined static
    C_ENTAG = 15  # enumaration tag
    C_MOE = 16  # member of enumeration
    C_REGPARM = 17  # register parameter
    C_FIELD = 18  # bit field
    C_AUTOARG = 19  # auto argument
    C_LASTENT = 20  # dummy entry(end of block)
    C_BLOCK = 100  # ".bb" or ".eb" - beginning or end of block
    C_FCN = 101  # ".bf" or ".ef" - beginning or end of function
    C_EOS = 102  # end of structure
    C_FILE = 103  # file name
    C_LINE = 104  # line number, reformatted as symbol
    C_ALIAS = 105  # duplicate tag
    C_HIDDEN = 106  # ext symbol in dmert public lib
    C_EFCN = 255  # physical end of function


class SectionType(Enum):
    N_UNDEF = 0  # An undefined(extern) symbol
    N_ABS = -1  # An absolute symbol(e_value is aconstant, not an address)
    N_DEBUG = -2  # A debugging symbol


def get_section(num):
    if -2 <= num <= 0:
        return SectionType(num).name
    else:
        return str(num)


class Name(object):
    FORMAT = "<L L"

    def __init__(self, string_table_offset, buf, offset=0):
        tmp = struct.unpack_from(Name.FORMAT, buf, offset)
        self.e_name = str(buf[offset:offset + 8])
        self.e_zeroes = tmp[0]
        self.e_offset = tmp[1]
        if self.e_zeroes == 0:
            self.e_name = ''
            i = 0
            while buf[string_table_offset + self.e_offset + i] != '\0':
                self.e_name += buf[string_table_offset + self.e_offset + i]
                i += 1


class Symnet(object):
    FORMAT = "<L h H B B"

    def __init__(self, string_table_offset, buf, nt_header_location, offset):
        tmp = struct.unpack_from(Symnet.FORMAT, buf, offset + 8)
        self.e = Name(string_table_offset, buf, offset)
        self.e_value = tmp[0]
        self.e_scnum = tmp[1]
        self.e_type = tmp[2]
        self.e_sclass = tmp[3]
        self.e_numaux = tmp[4]
        if self.e_scnum > 0:
            self.sec_vtrl_addrs = self.get_section_virtual_address(buf, nt_header_location)

    def get_value(self):
        if (self.e_type & 0b00110000) >> 4 == int(DerivedType.DT_FCN) and self.e_scnum > 0:
            return 'sub_' + str(hex(BASE_ADDRESS + self.sec_vtrl_addrs + self.e_value))[2:]
        else:
            return hex(self.e_value)

    def get_type(self):
        dt = DerivedType((self.e_type & 0b00110000) >> 4).name
        if self.e_type & 0b00011111 == 0b00010000:
            t = BaseTypes.T_LNGDBL
        else:
            t = BaseTypes(self.e_type & 0b00001111).name
        return '\n\tDerivedType:{0} BaseTypes:{1}\r'.format(dt, t)

    def get_section_virtual_address(self, buf, nt_header_location):
        loc = nt_header_location + NT_HEADER_SIZE + ((self.e_scnum - 1) * SECTION_HEADER_ENTRY_SIZE)\
              + VIRTUAL_ADDRESS_OFFSET
        return struct.unpack_from("<I", buf[loc:loc + 4])[0]

    def __str__(self):
        """

        :return: string object
        """
        return "Symbol name: {0}\nSymbol value: {1}\nSection Number: {2}\n" \
               "Symbol type: {3}\nStorage class: {4}\nNum of aux entries: {5}" \
            .format(self.e.e_name, self.get_value(),
                    get_section(self.e_scnum),
                    self.get_type(),
                    StorageClass(self.e_sclass).name,
                    self.e_numaux)
