
# Import necessary modules from IDA Pro
import idc
import idautils
import idaapi, ida_ua
import base64
from Crypto.Cipher import ARC4


# def replace_string(ea, new_str):
#     ea_start = ea
#     for s in new_str:
#         idaapi.patch_byte(ea, s)  # Replace each byte in the old string with a byte from the new string
#         ea += 1
#     idc.create_strlit(ea_start, idc.BADADDR)  # Create a string literal in the database

def set_hexrays_comment(address, text):
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 
    ea = idaapi.get_screen_ea()

def change_str_ptr_name(addr_decryption_function, str):
            addr_push_instr = idc.prev_head(addr_decryption_function)
            var_1 = idc.get_operand_value(addr_push_instr, 0)
            # The name will be in the format "str_<deobfuscated_string>"
            idc.set_name(var_1, "ptr_" + str, SN_NOWARN)
            # change variable name
            addr_var_str = addr_decryption_function+8
            var_2 = idc.get_operand_value(addr_var_str, 0)
            idc.set_name(var_2, "var_" + str, SN_NOWARN)

            return

def set_comment(address, text):
    try:
        idc.set_cmt(address, text, 0)
        set_hexrays_comment(address+8, text)
        change_str_ptr_name(address,str)
    except Exception as e:
        print(e)
        return
    
def decryption_func(obfuscated_str, key):
        decoded_data = base64.b64decode(obfuscated_str)
        cipher = ARC4.new(key)
        decrypted_data = cipher.decrypt(decoded_data)
        # Convert the decrypted bytes to a string
        return decrypted_data.decode()

# Address of the decryption function in the binary
decrypt_func = 

rec4_key = b''

for xref in idautils.XrefsTo(decrypt_func, 0):
    # Get the address of the decryption function caller
    addr_decryption_function = xref.frm
    comment_addr = addr_decryption_function

    # Get the previous instruction before the decryption function call
    addr_push_instr = idc.prev_head(addr_decryption_function)
    # print(hex(addr_decryption_function))

    # Check if the previous instruction is a 'push' instruction
    if idc.print_insn_mnem(addr_push_instr) == 'push' and idc.get_operand_type(addr_push_instr, 0) == idc.o_imm:

        # Read 100 bytes of data from the specified address 'data'
        data = idc.get_bytes(idc.get_operand_value(addr_push_instr, 0), 100)

        # Split the data at the null bytes (0x00) and take the first part (before the null bytes)
        # Then remove any remaining null bytes and decode the bytes to get the string
        obfuscated_str = data.split(b'\x00\x00')[0].replace(b'\x00', b'').decode()
        # print(hex(addr_push_instr))
        # print(obfuscated_str)
        str = decryption_func (obfuscated_str,rec4_key)
        # print(str)
        set_comment (comment_addr, str)
