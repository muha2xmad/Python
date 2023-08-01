
# 7031d644284a0e58afcdf412bf6f2fdaaf82a67b1b738d834692942b44823907
# ab2a474c3fd276095d7db5d78df356a572b1eee397ef1977facd8df214db3db0



import binascii
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
import pefile


def extract_data(filename):
    pe=pefile.PE(filename)
    for section in pe.sections:
        if ".data" in section.Name.decode('utf-8').rstrip('x00'):
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)

def data_decryptor(rc4key,encrypted_config):
    rc4_cipher = ARC4.new(rc4key)
    decrypt_config= rc4_cipher.decrypt(encrypted_config)
    return decrypt_config


config_list = []

filename = r''
data = extract_data(filename)

key= data[16:24]
hashed_key=SHA.new(key).hexdigest()
true_key=hashed_key[:10]

enc_data =binascii.hexlify(data[24:255])

config = data_decryptor(binascii.unhexlify(true_key), binascii.unhexlify(enc_data))
# print(config.split(b'\x00'))
for clean in config.split(b'\x00'):
    if clean != b'':
        # config = s
        config_list.append(clean.decode())

id=config_list[0]
print("ID: ",id)
# C2=config_list[1:]
# print("C2: ", C2)
# print
c2_string = config_list[1]  # Get the first element of the list (C2 server addresses)
c2_list = c2_string.split('|')  # Split the C2 server addresses using '|'
for c2 in c2_list:
    if c2 != '':
        print("C2: ", c2)


# ref: MAS 1 article