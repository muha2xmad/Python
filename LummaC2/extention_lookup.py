# Import necessary modules from IDA Pro
import idc
import idautils
import re
import requests

# Address of the decryption function in the binary
decrypt_func = 0x45DF86

# A list to store the decrypted and deobfuscated strings
clean_str = []

# The deobfuscator string used for removing obfuscation
deobfuscator_str = '576xed'

# Regular expression pattern to match IDs
id_pattern = '^[a-z]{32}'

# Regular expression pattern to match Chrome Web Store URLs
url_pattern = re.compile(r'https://chrome\.google\.com/webstore/detail/([^/]+)/([a-z]{32})')

# Keep track of seen IDs and names using lists
seen_ids = []
seen_names = []

# Iterate through all code references (xrefs) to the 'decrypt_func'
for xref in idautils.XrefsTo(decrypt_func, 0):
    addr_decryption_function = xref.frm
    addr_push_instr = idc.prev_head(addr_decryption_function)
    
    # Check if the previous instruction is a 'push' instruction
    if idc.print_insn_mnem(addr_push_instr) == 'push':
        
        # Check if the 'push' instruction has an immediate operand
        if idc.get_operand_type(addr_push_instr, 0) == idc.o_imm:
            data = idc.get_operand_value(addr_push_instr, 0)
            data = idc.get_bytes(data, 100)
            
            # Split the data at the null bytes (0x00) and take the first part (before the null bytes)
            # Then remove any remaining null bytes and decode the bytes to get the string
            obfuscated_str = data.split(b'\x00\x00')[0].replace(b'\x00', b'').decode()
            
            # Remove the deobfuscator string from the obtained string
            obfuscated_str = obfuscated_str.replace(deobfuscator_str, "")
            
            # Add the deobfuscated string to the 'clean_str' list
            clean_str.append(obfuscated_str)
            
            # Iterate through the list of clean strings
            for itm in clean_str:
                if re.findall(id_pattern, itm):
                    id_itm = itm
                    url = f'https://chrome.google.com/webstore/detail/{itm}'
                    response_txt = requests.get(url).text
                    matches = url_pattern.findall(response_txt)
                    
                    # Iterate through the matches found in the response text
                    for ext_name, ext_id in matches:
                        if ext_id not in seen_ids:
                            seen_ids.append(ext_id)
                            seen_names.append(ext_name)
                            print("[+] Extension Name:", ext_name.title().replace('-', ' '), "| Extension ID:", ext_id)





ref: https://0xtoxin.github.io/malware%20analysis/Lumma-Breakdown/