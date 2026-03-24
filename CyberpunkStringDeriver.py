# Hunt for strings and verify using mangling and hashing
#@author Mozz
#@category Cyberpunk
#@keybinding 
#@menupath 
#@toolbar 

import re
import zlib
import hashlib

from collections import defaultdict

from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import StringDataType
from ghidra.program.model.symbol import SourceType,

from ghidra.app.util.demangler.microsoft import MicrosoftDemangler, MicrosoftMangledContext, MicrosoftDemanglerOptions

listing = currentProgram.getListing()
memBlocks = getMemoryBlocks()
errors = []
numSymbols = 0

class demangling:
    ms = MicrosoftDemangler()
    options = ms.createDefaultOptions()
    options.setApplySignature(False)
    options.setApplyCallingConvention(False)
    options.setDoDisassembly(True)
    
    @staticmethod
    def demangle(mangled):
        return demangling.ms.demangle(demangling.ms.createMangledContext(mangled, demangling.options, currentProgram, None))
    
    @staticmethod
    def demangleApplyAndLabel(address, mangled):
        global numSymbols
        demangled = demangling.demangle(mangled)
        try:
            demangled.applyTo(currentProgram, address, demangling.options, monitor)
            createLabel(address, mangled, False, SourceType.ANALYSIS)
            numSymbols += 1
            println("Derived `{}` at {}".format(demangled, address))
        except Exception as e:
            errors.append("Could not apply demangled label '{}' at {}: {}".format(str(demangled).strip(), address, e))

class hashing:
    @staticmethod
    def adler32(data_bytes):
        return int(zlib.adler32(data_bytes))

    @staticmethod
    def sha256(data_bytes):
        return hashlib.sha256(data_bytes).hexdigest()

    @staticmethod
    def fnv1a(data_bytes):
        h = 0xcbf29ce484222325
        for byte in data_bytes:
            h ^= byte
            h = (h * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
        if h >= (1 << 63):
            h -= (1 << 64)
        return h

    @staticmethod
    def jamcrc(data_bytes):
        return zlib.crc32(data_bytes) ^ 0xFFFFFFFF

class mangling:
    num_encoding = str.maketrans('0123456789abcdef', 'ABCDEFGHIJKLMNOP')
    str_deco_special_chars = (',', '/', '\\', ':', '.', ' ', '\n', '\t', "'", '-')
    str_deco_table = {ord(c): f'?{i}' for i, c in enumerate(str_deco_special_chars)}
    str_deco_lengths = [1] * 256
    for b in range(256):
        c = chr(b)
        if c.isalnum() or c in ('_', '$'):
            pass
        elif c in str_deco_special_chars:
            str_deco_lengths[b] = 2
        elif chr(b & 0x7F).isalpha():
            str_deco_table[b] = f'?{chr(b & 0x7F)}'
            str_deco_lengths[b] = 2
        else:
            str_deco_table[b] = f"?${chr(ord('A') + (b >> 4 & 0xF))}{chr(ord('A') + (b & 0xF))}"
            str_deco_lengths[b] = 4
    
    @staticmethod
    def mangleNumber(n):
        if n < 0:
            return '?'+mangling.mangleNumber(-n)
        if n == 0:
            return 'A@'
        if 1 <= n <= 10:
            return str(n - 1)
        return hex(n)[2:].translate(mangling.num_encoding)+'@'
    
    @staticmethod
    def mangleString(string):
        raw = string.encode('latin-1') + b'\x00'
        decorated = string.translate(mangling.str_deco_table)
        cutoff = sum(mangling.str_deco_lengths[b] for b in raw[:31])
        return f"??_C@_0{mangling.mangleNumber(len(raw))}{mangling.mangleNumber(hashing.jamcrc(raw))}{decorated[:cutoff]}@"

class resolving:
    seen_strings = set()
    
    @staticmethod
    def hashAddrMapByBlock(block_idx):
        if not hasattr(resolving, '_hashAddrMapByBlock'):
            hashAddrMapByBlock = []
            for block in memBlocks:
                hashAddrMap = defaultdict(list)
                for addr in listing.getCommentAddressIterator(AddressSet(block.getStart(), block.getEnd()), True):
                    if a32 := resolving.getAdler32HashAt(addr):
                        hashAddrMap[a32].append(addr)
                hashAddrMapByBlock.append(hashAddrMap)
            setattr(resolving, '_hashAddrMapByBlock', hashAddrMapByBlock)
        return resolving._hashAddrMapByBlock[block_idx]

    @staticmethod
    def getAdler32HashAt(addr):
        if (comment := getPlateComment(addr)) and (match := re.search(r'Adler32: (\b\d+\b)', comment)):
            return int(match.group(1))
    
    @staticmethod
    def getSHA256HashAt(addr):
        if (comment := getPlateComment(addr)) and (match := re.search(r'SHA256: ([a-f0-9]{64})', comment)):
            return match.group(1).strip()
    
    @staticmethod
    def findMangled(mangled, block_idx = 1):
        entries = resolving.hashAddrMapByBlock(block_idx)[hashing.adler32(mangled.encode('utf-8'))]
        if not entries:
            return None
        hash_sha256 = hashing.sha256(mangled.encode('utf-8'))
        for addr in entries:
            if hash_sha256 == resolving.getSHA256HashAt(addr):
                return addr
    
    @staticmethod
    def findMangledAndLabel(mangled, block_idx = 1):
        if addr := resolving.findMangled(mangled, block_idx):
            demangling.demangleApplyAndLabel(addr, mangled)
            return addr
    
    @staticmethod
    def resolveStrings():
        for found in findStrings(AddressSet(memBlocks[2].getStart(), memBlocks[3].getEnd()), 1, 2, True, False):
            addr = found.getAddress()
            length = found.getLength()
            string = str(found.getString(currentProgram.getMemory()))
            if string in resolving.seen_strings:
                continue
            if addr == resolving.findMangledAndLabel(mangling.mangleString(string), 2):
                clearListing(addr, addr.add(length))
                listing.createData(addr, StringDataType.dataType, length)
                resolving.seen_strings.add(string)
                yield string

start() # start transaction
shouldCommit = False
try:
    for string in resolving.resolveStrings():
        mangled_fnv1a = mangling.mangleNumber(hashing.fnv1a(string.encode('utf-8')))
        strip_mangled_fnv1a = mangling.mangleNumber(hashing.fnv1a(string[2:].encode('utf-8'))) # for RTTI field prefix stripping
        resolving.findMangledAndLabel(f"?s_registered@?$ConstNameBuilder@$0{mangled_fnv1a}@@2_NA", 3)
        resolving.findMangledAndLabel(f"?Build@?$ConstNameBuilder@$0{mangled_fnv1a}@@SA?AVCName@@QEBD@Z")
        resolving.findMangledAndLabel(f"?s_registered@?$ConstNameBuilder@$0{strip_mangled_fnv1a}@@2_NA", 3)
        resolving.findMangledAndLabel(f"?Build@?$ConstNameBuilder@$0{strip_mangled_fnv1a}@@SA?AVCName@@QEBD@Z")
    for error in errors:
        print(error)
    print(f"Found {numSymbols} symbols")
    shouldCommit = True
finally:
    end(shouldCommit) # end transaction
