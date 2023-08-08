import idaapi, idc, idautils
import struct
# import  inspect
# from io import BytesIO

# Define a function to perform XOR decryption on data using a given key
def xor_decrypt(data, key):
    out = []
    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])  # Perform XOR operation
    return bytes(out)

# Define a function to decrypt data at a given effective address (ea)
def decrypt(ea):
    key = idc.get_bytes(ea, 4)  # Get the decryption key (4 bytes)
    # print(hex(ea))
    # print(key.hex())
    xor_len = idc.get_bytes(ea + 4, 4)  # Get the XORed length value (4 bytes)
    # print(xor_len.hex())
    str_len = struct.unpack('<I', key)[0] ^ struct.unpack('<I', xor_len)[0]
    # print(hex(str_len))
    
    # Add a sanity check for length to avoid processing overly long strings
    if str_len > 1000:
        return
    
    data = idc.get_bytes(ea + 8, str_len)  # Get the encrypted data using the calculated length
    print(data.hex())  # Print the hex representation of the encrypted data
    ptxt_data = xor_decrypt(data, key)  # Decrypt the data using the key
    print(ptxt_data)  # Print the decrypted data
    
    if is_ascii(ptxt_data):  # Check if the decrypted data is ASCII
        replace_string(ea, ptxt_data + b'\x00')  # Replace the encrypted string with the decrypted one

# Define a function to check if a given string is composed of ASCII characters
def is_ascii(s):
    return all(c < 128 for c in s)

# Define a function to replace a string in the IDB (IDA Pro database)
def replace_string(ea, new_str):
    ea_start = ea
    for s in new_str:
        idaapi.patch_byte(ea, s)  # Replace each byte in the old string with a byte from the new string
        ea += 1
    idc.create_strlit(ea_start, idc.BADADDR)  # Create a string literal in the database

# Define the start and end effective addresses for processing
ea = 0x10001000
ea_end = 0x1000193C

# Iterate through the specified address range
while ea < ea_end:
    xrefs = [addr.frm for addr in idautils.XrefsTo(ea)]  # Get cross-references to the current address
    if len(xrefs) != 0:  # If there are cross-references to this address
        decrypt(ea)  # Decrypt the data at this address
    ea += 4  # Move to the next address (assuming the data is aligned)
    # break  # (Optional) Break the loop early for testing



# ref: OALABS