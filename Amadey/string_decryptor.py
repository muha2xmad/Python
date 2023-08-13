
# Import necessary modules from IDA Pro
import idc
import idautils
import idaapi, ida_ua
import base64
import re
from itertools import zip_longest


# Function to set a Hex-Rays comment at a given address
def set_hexrays_comment(address, text):
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 
    ea = idaapi.get_screen_ea()

# Function to change variable names and set comments
def change_str_ptr_name(addr_constructor_function, istr):
            try:
                addr_mov_instr = idc.prev_head(addr_constructor_function)
                var_1 = idc.get_operand_value(addr_mov_instr, 1)
                # The name will be in the format "str_<deobfuscated_string>"
                idc.set_name(var_1, "var_" + istr, SN_NOWARN)

                # change variable name
                addr_push_instr = idc.prev_head(addr_mov_instr)
                var_2 = idc.get_operand_value(addr_push_instr, 0)
                idc.set_name(var_2, "ptr_" + istr, SN_NOWARN)
                # print(hex(addr_push_instr))
                
            except Exception as e:
                print(e)
            return

# Function to set comments at a given address
def set_comment(address, text):
    try:
        idc.set_cmt(address, text, 0)
        set_hexrays_comment(address, text)
        change_str_ptr_name(address,text)
    except Exception as e:
        print(e)
        return

# Function to decrypt obfuscated strings
def decrypt(str_data, str_key, str_alphabet):
    str_hash = ''
    for i in range(len(str_data)):
        str_hash += str_key[i % len(str_key)]

    out = ''

    for i in range(len(str_data)):
        if str_data[i] not in str_alphabet:
            out += str_data[i]
            continue
        alphabet_count = str_alphabet.find(str_data[i])
        hash_count = str_alphabet.find(str_hash[i])
        index_calc = (alphabet_count + len(str_alphabet) - hash_count) % len(str_alphabet)
        out += str_alphabet[index_calc]

    return base64.b64decode(out)




obfuscated_str = ''
# This is not the decryption function, it's the function that will help us to get the strings - a string constructor.
constructor_func = 0x00416360
b64_str_list=[]
alphabet_str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '
comm_addr = []


# Iterate over cross-references to the decryption function
for xref in idautils.XrefsTo(constructor_func, 0):
    # Get the address of the decryption function caller
    addr_constructor_function = xref.frm
    # comment_addr = addr_decryption_function

    # Get the previous instruction before the decryption function call
    addr_mov_instr = idc.prev_head(addr_constructor_function)

    # Check if the previous instruction is a 'push' instruction
    if idc.print_insn_mnem(addr_mov_instr) == 'mov' and idc.get_operand_type(addr_mov_instr, 0) == idc.o_reg and idc.get_operand_type(addr_mov_instr, 1) == idc.o_imm:
        # print(hex(addr_push_instr))
        addr_push_instr = idc.prev_head(addr_mov_instr)

        if idc.print_insn_mnem(addr_push_instr) == 'push' and idc.get_operand_type(addr_push_instr, 0) == idc.o_imm :
            # Read 100 bytes of data from the specified address 'data'
            data = idc.get_bytes(idc.get_operand_value(addr_push_instr, 0), 50)

            obfuscated_str= data
            # Extract clean strings
            try:
                index_of_null = obfuscated_str.index(b'\x00')
                clean = obfuscated_str[:index_of_null]
                clean = clean.decode()
            except:
                 continue

        if re.match(r'[a-zA-Z =0-9]{4,}', clean):
            b64_str_list.append(clean)
            comm_addr.append(addr_constructor_function)
           

# Extract the key and string list
# the Key is first item in the list
key = b64_str_list[0]

# The first four items are not base64 strings, so we exclude them
b64_str_list = b64_str_list[4:-1]

# Get the addresses of these base64 strings
comm_addr_b64 = comm_addr[4:-1]

# Decrypt and set comments
for s,addr in zip(b64_str_list,comm_addr_b64):
    try:
        decrypted_str = decrypt(s, key, alphabet_str)
        decrypted_str = decrypted_str.decode()
        # print(decrypted_str)

        set_comment(addr,decrypted_str)
    except:
        continue



# ref: [OALABS](https://research.openanalysis.net/cpp/stl/amadey/loader/config/2022/11/13/amadey.html)