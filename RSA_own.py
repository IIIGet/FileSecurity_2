from Crypto.PublicKey import RSA
import rsa
from Crypto import Random

# RSA密钥生成，加解密，签名验签

key_site = 2048  # 密钥长度

def A_generate_key_pair():
    # 生成密钥对
    (public_key, private_key) = rsa.newkeys(key_site)
    # randoms = Random(0, 100)
    # 保存私钥
    with open('./A_file/A_private_key', 'wb') as f:
        f.write(private_key.save_pkcs1())
        f.close()

    # 保存公钥
    with open('./A_file/A_public_key', 'wb') as f:
        f.write(public_key.save_pkcs1())
        f.close()

def B_generate_key_pair():
    # 生成密钥对
    (public_key, private_key) = rsa.newkeys(key_site)
    # randoms = Random(0, 100)
    # 保存私钥
    with open('./B_file/B_private_key', 'wb') as f:
        f.write(private_key.save_pkcs1())
        f.close()

    # 保存公钥
    with open('./B_file/B_public_key', 'wb') as f:
        f.write(public_key.save_pkcs1())
        f.close()


# 利用RSA进行数字签名
# RSA私钥加密
def rsa_private_encrypt(msg, file_rsa_private_key_name):
    with open(file_rsa_private_key_name, 'rb+') as file:
        private_key_data = file.read()
    rsa_private_key = rsa.PrivateKey.load_pkcs1(private_key_data)  # 在PEM文件中加载PKCS#1格式的RSA密钥
    print('密钥类型')
    print(rsa_private_key)
    # msg_encrypted = rsa_private_key.private_encrypt(msg, RSA.pkcs1_padding)
    # print(type(msg))
    msg_encrypted = rsa.encrypt(msg.encode('utf-8'), rsa_private_key)
    file.close()
    return msg_encrypted


# # RSA公钥解密
#
# def rsa_public_decrypt(msg, file_rsa_public_name):
#     with open(file_rsa_public_name, 'rb+') as file:
#         public_key_data = file.read()
#     rsa_public_key = rsa.PublicKey.load_pkcs1(public_key_data)  # 在PEM文件中加载PKCS#1格式的RSA密钥
#     msg_decrypted = rsa.decrypt(msg, rsa_public_key)
#
#     file.close()
#     return msg_decrypted


# RSA进行AES密钥加解密
# 进行RSA公钥加密
def rsa_public_encrypt(msg, file_rsa_public_name):
    with open(file_rsa_public_name, 'rb+') as file:
        public_key_data = file.read()
    rsa_public_key = rsa.PublicKey.load_pkcs1(public_key_data)
    msg_encrypted = rsa.encrypt(msg, rsa_public_key)
    file.close()
    return msg_encrypted


# 对应解密部分 RSA私钥解密
def rsa_private_decrypt(msg, file_rsa_private_key_name):
    with open(file_rsa_private_key_name, 'rb+') as file:
        private_key_data = file.read()
    rsa_private_key = rsa.PrivateKey.load_pkcs1(private_key_data)
    msg_decrypted = rsa.decrypt(msg, rsa_private_key)
    file.close()
    return msg_decrypted


# 签名
def rsa_sign(sign_info, private_key):
    # 消息签名：sign(sign_info,private_key,hash-method) sign_info:签名的信息，byte类型 private_key:RSA私钥类型 hash-method:指代的hash算法
    return rsa.sign(sign_info, private_key, 'SHA-256')


# 验签
def rsa_verify(info, sign_info, public_key):
    # 消息签名：verify(info,sign_info,public_key) info:要验证签名的信息，byte类型  signature：要验证的签名 字符串形式 public_key:RSA公钥类型
    if rsa.verify(info, sign_info, public_key):
        print('验证成功')
    else:
        print("验证失败，请重新查看")
