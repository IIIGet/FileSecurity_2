import rsa

import AES_own
import MD5
import RSA_own
import File_operation
from Crypto.Cipher import AES
from Crypto import Random

files = './B_file/'

if __name__ == '__main__':
    # 解密流程
    file_aes_key_encrypted_name = files + 'AES_key_encrypted'
    iv_encrypted_name = files + 'file_iv_encrypted'
    file_rsa_private_key_name = files+'B_private_key'
    file_aes_key_encrypted = open(file_aes_key_encrypted_name, 'rb')
    aes_key_encrypted = file_aes_key_encrypted.read()
    file_iv_encrypted = open(iv_encrypted_name, 'rb')
    iv_encrypted = file_iv_encrypted.read()

    print("开始解密AES秘钥......")
    aes_key = RSA_own.rsa_private_decrypt(aes_key_encrypted, file_rsa_private_key_name)
    print("AES秘钥解密完成！")
    print("开始解密AES初始化向量......")
    iv = RSA_own.rsa_private_decrypt(iv_encrypted, file_rsa_private_key_name)
    print("AES初始化向量解密完成！\n")
    file_encrypted_name = files + 'file_encrypted_msg'
    file_encrypted = open(file_encrypted_name, 'rb')
    file_encrypted_msg = file_encrypted.read()

    file_fill_number_name = files + 'fill_number'
    file_fill_number = open(file_fill_number_name, 'rb')
    fill_number = file_fill_number.read()
    print("开始对加密文件进行AES解密")
    file_msg = AES_own.aes_decrypt(file_encrypted_msg, aes_key, iv)
    file_msg = file_msg[0:len(file_msg) - int(float(fill_number))]  # 去掉AES加密时填充的位

    print("加密文件AES解密完成！\n")
    file_fill_number.close()
    file_decrypted = open('./B_file/file_decrypted', 'wb')
    file_decrypted.write(file_msg)
    md5_file_msg = MD5.md5_encrypt(file_msg)
    file_decrypted.close()
    file_encrypted.close()
    file_aes_key_encrypted.close()
    file_iv_encrypted.close()

    print("已接收签名文件！")
    file_signature_encrypted_name = files + 'file_signature_encrypted'
    file_signature_encrypted = open(file_signature_encrypted_name, 'rb')
    signature_encrypted = file_signature_encrypted.read()
    file_signature_encrypted.close()
    print("文件AES解密")


    sender_public_key_name = './B_file/A_public_key'
    public_key = File_operation.read_file(sender_public_key_name)
    public_keys = rsa.PublicKey.load_pkcs1(public_key)
    print("进行签名认证")

    RSA_own.rsa_verify(md5_file_msg.encode('utf-8'), signature_encrypted, public_keys)
    print("签名文件RSA解密完成，得到原文件MD5值！\n")

    print("解密程序运行完毕，请提取解密文件！")
    print('解密完成')