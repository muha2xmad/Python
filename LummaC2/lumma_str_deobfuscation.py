# Import necessary modules from IDA Pro
import idc
import idautils


# Address of the decryption function in the binary
decrypt_func = 0x001000865C

# A list to store the decrypted and deobfuscated strings
clean_str = []

# The deobfuscator string used for removing obfuscation
deobfuscator_str = '576xed'

# Iterate through all code references (xrefs) to the 'decrypt_func'
for xref in idautils.XrefsTo(decrypt_func, 0):
    # Get the address of the decryption function caller
    addr_decryption_function = xref.frm

    # Get the previous instruction before the decryption function call
    addr_push_instr = idc.prev_head(addr_decryption_function)

    # Check if the previous instruction is a 'push' instruction
    if idc.print_insn_mnem(addr_push_instr) == 'push':

        # Check if the 'push' instruction has an immediate operand
        if idc.get_operand_type(addr_push_instr, 0) == idc.o_imm:

            # Get the data that is being pushed (string data) based on the immediate operand
            # data = idc.get_operand_value(addr_push_instr, 0)

            # Read 100 bytes of data from the specified address 'data'
            data = idc.get_bytes(idc.get_operand_value(addr_push_instr, 0), 100)

            # Split the data at the null bytes (0x00) and take the first part (before the null bytes)
            # Then remove any remaining null bytes and decode the bytes to get the string
            obfuscated_str = data.split(b'\x00\x00')[0].replace(b'\x00', b'').decode()

            # Remove the deobfuscator string from the obtained string
            obfuscated_str = obfuscated_str.replace(deobfuscator_str, "")

            # Add the deobfuscated string to the 'clean_str' list
            clean_str.append(obfuscated_str)

            # Iterate through the list of clean strings
            for itm in clean_str:

                # Check if the current instruction in the decryption function is a 'call' instruction
                if idc.print_insn_mnem(addr_decryption_function) == "call":

                    # Set a comment at the address of the decryption function caller
                    # The comment will be the deobfuscated string 'itm'
                    idc.set_cmt(addr_decryption_function, itm, 1)

                # Check if the previous instruction is still a 'push' instruction
                if (idc.print_insn_mnem(addr_push_instr) == "push"):

                    # Get the value of the operand being pushed (string address)
                    var = idc.get_operand_value(addr_push_instr, 0)

                    # Set a name for the string at the specified address
                    # The name will be in the format "str_<deobfuscated_string>"
                    idc.set_name(var, "str_" + itm, SN_NOWARN)




# ref: https://0xtoxin.github.io/malware%20analysis/Lumma-Breakdown/