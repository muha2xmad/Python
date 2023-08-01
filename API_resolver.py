# Import necessary modules from IDA Pro and external libraries
import idc
import idautils
import re
import requests
import pefile
from murmurhash2 import murmurhash2
import idaapi, ida_ua
# import struct
# Address of the decryption function in the binary
addr_api_resolver = 0x0042DD0C

# Initialize lists to store API hashes and DLL names
api_list = []
dll_list = []

# Path to the system32 directory where DLLs are located
DLLS_PATH = 'C:\\Windows\\System32\\'

# Constant seed value for hashing
SEED = 0x20

# Iterate through all code references (xrefs) to the 'addr_api_resolver'
for xref in idautils.XrefsTo(addr_api_resolver, 0):
    # Get the address of the API resolver function
    addr_api_resolver = xref.frm

    # Find the address of the instruction that pushes the API hash onto the stack
    addr_api_push_instr = idc.prev_head(addr_api_resolver)
    # print(hex(addr_api_push_instr))

    # # Find the address of the instruction that pushes the DLL name onto the stack
    addr_dll_push_instr = idc.prev_head(addr_api_push_instr)

    # # Check if the previous instruction is a 'push' instruction for API hash
    if idc.print_insn_mnem(addr_api_push_instr) == 'push':
        # Check if the operand of the 'push' instruction is an immediate value (API hash)
        if idc.get_operand_type(addr_api_push_instr, 0) == idc.o_imm:
            # Get the API hash as a hexadecimal value and add it to the API list
            api_hash = hex(idc.get_operand_value(addr_api_push_instr, 0))
            print(api_hash)
            api_list.append(api_hash)

    # Check if the previous instruction is a 'push' instruction for DLL name
    if idc.print_insn_mnem(addr_dll_push_instr) == 'push':
        # Check if the operand of the 'push' instruction is an immediate value (DLL name address)
        if idc.get_operand_type(addr_dll_push_instr, 0) == idc.o_imm:
            # Get the DLL name from memory and convert it to a string
            dll_name = idc.get_operand_value(addr_dll_push_instr, 0)
            dll_name = idc.get_bytes(dll_name, 50)
            dll_name = dll_name.split(b'\x00\x00')[0].replace(b'\x00', b'').decode()
            # pryint(dll_name)

            # Add the DLL name to the DLL list
            dll_list.append(dll_name)
    #     else:
    #         # If the DLL name is not directly pushed, use 'winhttp.dll' as a fallback
    #         dll_name = 'winhttp.dll'
    
    # # Resolve the APIs for the current API hash and DLL name pair
    dll_path = DLLS_PATH + dll_name
    pe = pefile.PE(dll_path)
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        expName = export.name
        if expName is None:
            # Handle the case when the export symbol has no name
            continue
        # Compute the MurmurHash2 hash for the export name using the constant seed
        hashValue = murmurhash2(expName, SEED)
        # Check if the computed hash matches the API hash
        if hex(hashValue) == api_hash:
            # If there is a match, associate the resolved API name as a comment to the 'addr_api_resolver'
            resolved_api = expName.decode()
            # set a comment in the assembly code
            idc.set_cmt(addr_api_resolver, resolved_api, 0) 
            # set a comment in the decompiled code
            cfunc = idaapi.decompile(addr_api_resolver)
            tl = idaapi.treeloc_t()
            tl.ea = addr_api_resolver
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, resolved_api)
            cfunc.save_user_cmts() 
            # Print the address of the resolved API
            print(hex(addr_api_resolver))
            break





# ref: https://0xtoxin.github.io/malware%20analysis/Lumma-Breakdown/