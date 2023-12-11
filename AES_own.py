from Crypto.Cipher import AES
from Crypto import Random


# AES密钥生成，加解密

# 生成随机16位的的密钥串
def aes_key_gen():
    import random
    import string
    aes_key: str = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    # print('生成的AES密钥为：'+aes_key)
    aes_keys = bytes(aes_key, encoding='utf-8')
    with open('./A_file/aes_key', 'wb') as f:  # 保存AES密钥
        f.write(aes_keys)
        f.close()
    return aes_key


# AES进行文件加解密
# AES加密
def aes_encrypt(aes_file, key, iv):  # aes_file 文件，key16-bytes对称密钥
    cipher = AES.new(key, AES.MODE_OFB, iv)  # 生成了加密时需要的实际密码，这里采用OFB模式
    x = len(aes_file) % 16
    # print("要加密文件的长度是：%d" % len(aes_file))
    # print("需要填充的数据长度：%d" % ((16 - x) % 16))
    # aes_files = bytes(aes_file, encoding='utf-8')
    aes_files = aes_file.decode('utf-8-sig', errors='replace')
    print(type(aes_files))
    if x != 0:
        aes_file_pad = aes_files + '0' * (16 - x)
    else:
        aes_file_pad = aes_files
    msg = cipher.encrypt(aes_file_pad.encode('utf-8'))
    return msg, (16 - x) % 16.


# AES解密
def aes_decrypt(aes_file, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)  # 生成了解密时需要的实际密码，这里采用了OFB模式
    msg = cipher.decrypt(aes_file)
    return msg
