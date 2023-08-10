import struct
import pefile

# Define a function to convert data to hexadecimal format
def tohex(data):
    import binascii
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))  # Convert string to hex
    else:
        return binascii.hexlify(data)  # Convert bytes to hex

# Define a function to perform XOR decryption on data using a given key
def xor_decrypt(data, key):
    out = []
    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])  # Perform XOR operation
    return bytes(out)

# Define a function to check if a given string is composed of ASCII characters
def is_ascii(s):
    return all(c < 128 for c in s)

# Path to the Emotet DLL file to be analyzed
EMOTET_FILE = r""

# Read the binary data from the Emotet DLL file
data = open(EMOTET_FILE, 'rb').read()

# Load the PE file using the pefile library
pe = pefile.PE(data=data)

data_data = None
# Loop through each section in the PE file
for s in pe.sections:
    if b'.data' in s.Name:  # Check if the section's name contains the bytes '.data'
        data_data = s.get_data()  # Retrieve the raw data from the section and assign it to data_data

print(data_data[:100])  # Print the first 100 bytes of the data_data

key = data_data[:4]  # Extract the first 4 bytes of data_data and assign them to the key
data_len = struct.unpack('<I', data_data[:4])[0] ^ struct.unpack('<I', data_data[4:8])[0]  # Calculate data length

enc_data = data_data[8:8 + data_len]  # Extract encrypted data
ptxt_data = xor_decrypt(enc_data, key)  # Decrypt the data using the key

print(tohex(ptxt_data))  # Print the hexadecimal representation of the decrypted data
print(ptxt_data)  # Print the decrypted data

print("\n== C2 List== ")
# Loop through decrypted data in chunks of 8 bytes
for i in range(0, len(ptxt_data), 8):
    # Unpack IP address and port number and print them in a specific format
    print("%d.%d.%d.%d:%d" % (ptxt_data[i + 0], ptxt_data[i + 1], ptxt_data[i + 2],
                               ptxt_data[i + 3], struct.unpack('>H', ptxt_data[i + 4:i + 6])[0]))

# ref: OALABS