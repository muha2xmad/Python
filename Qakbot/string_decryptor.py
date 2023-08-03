
# 89c23c74007fa94ce211d4c7df481788214f0a8732237fd58e120b9f528a883b
# 4ad081aa013b7dbe936738d9c5445528bd7f4e6b1c2ac39545871b715e7ed49f

import idc
import idautils


import binascii

decrypt_func = 0x0010009D5D


for xref in idautils.XrefsTo(decrypt_func, 0):
    # Get the address of the decryption function caller
    addr_decryption_function = xref.frm
    # print(hex(addr_decryption_function))

    # Get the previous instruction before the decryption function call
    addr_mov1_instr = idc.prev_head(addr_decryption_function)
    addr_mov2_inst_ = idc.prev_head(addr_mov1_instr)
    noneed_inst = idc.prev_head(addr_mov2_inst_)
    addr_size = idc.prev_head(noneed_inst)
    

    if idc.print_insn_mnem(addr_size) == 'mov':
                
        if idc.get_operand_type(addr_size, 1) == idc.o_imm:
            size=idc.get_operand_value(addr_size, 1)
            # print('addr size 1: ',hex(addr_size))
            # print('size func 1: ',hex(size))
            

    if idc.print_insn_mnem(addr_mov1_instr) == 'mov':
                
        if idc.get_operand_type(addr_mov1_instr, 1) == idc.o_imm:
            blob1 = idc.get_bytes(idc.get_operand_value(addr_mov1_instr, 1), size)
            blob1 = blob1.split(b'\x00\x00')[0]
            # print('addr blob_1: ',hex(addr_mov1_instr))
            # print(blob1)

            

    if idc.print_insn_mnem(addr_mov2_inst_) == 'push':
        if idc.get_operand_type(addr_mov2_inst_, 0) == idc.o_imm:            
            blob2 = idc.get_bytes(idc.get_operand_value(addr_mov2_inst_, 0), size)

            blob2= blob2.split(b'\x00\x00')[0]
            # print('addr blob_2: ',hex(addr_mov2_inst_))         
            # print('blob_2: ',blob2)

    collected_words = []
    current_word = ""
    decoded = b''
    clean_list = []
    for i in range(0, size):
        decoded = bytes([blob1[i] ^ blob2[i % len(blob2)]])
        decoded = decoded.decode()
        clean_list.append(decoded)
        for char in clean_list:
            if char == '\x00':
                if current_word:
                    collected_words.append(current_word)
                    current_word = ""
            else:
                current_word += char
        # print(collected_words)
    if current_word:  # Add the last word if it's not empty
        collected_words.append(current_word)
    
    for word in collected_words:
        print(word)

    # break


# ref: MAS 2


