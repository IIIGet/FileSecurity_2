import rsa

import AES_own
import MD5
import RSA_own
import File_operation
from Crypto.Cipher import AES
from Crypto import Random

if __name__ == '__main__':
    # 文件加密，签名
    plaintext_file = input('请输入要加密的文件名：')
    # 读取要加密的文件
    file_encrypt = File_operation.read_file(plaintext_file)  # 读取原文文件
    # 生成AES密钥字符串
    AES_own.aes_key_gen()  # 产生AES密钥
    aes_key = File_operation.read_file('./A_file/aes_key')  # 将AES密钥进行保存
    # 生成一个随机的AES向量
    iv = Random.new().read(AES.block_size)  # 使用OFB模式加密，要产生一个iv向量并保存
    print("开始对原文件进行AES加密......")
    # 调用加密函数，生成填充位字符
    file_encrypt_msg, fill_number = AES_own.aes_encrypt(file_encrypt, aes_key, iv)  # 使用AES密钥和iv向量
    file_encrypted = open('./A_file/file_encrypted_msg', 'wb')  # 生成存储加密后文件
    file_encrypted.write(file_encrypt_msg)  # 写入文件中
    file_encrypted.close()
    print("原文件AES加密完成！")
    file_fill_number = open('./A_file/fill_number', 'wb')  # 生成存储填充位数文件
    file_fill_number.write(str(fill_number).encode('utf-8'))  # 写入文件中
    file_fill_number.close()
    #
    print("开始对原文件进行MD5摘要......")
    md5_msg = MD5.md5_encrypt(file_encrypt)  # 生成MD5摘要

    print("MD5摘要完成！")

    print("生成你的RSA私钥文件中......\n")
    RSA_own.A_generate_key_pair()  # 生成公私钥，这里是A的
    private_key = File_operation.read_file('./A_file/A_private_key')
    private_keys = rsa.PrivateKey.load_pkcs1(private_key)  # 保存到文件中
    print("开始对MD5摘要签名")

    signature_msg = RSA_own.rsa_sign(md5_msg, private_keys)  # 用自己私钥加密生成数字签名

    file_signature_encrypted = open('./A_file/file_signature_encrypted', 'wb+')  # 写入文件中
    file_signature_encrypted.write(signature_msg)  # 写入文件中
    file_signature_encrypted.close()
    print("MD5摘要签名完成！")

    print("接收接收者RSA公钥文件中......\n")
    print("开始对AES秘钥进行RSA加密")
    aes_key_encrypted = RSA_own.rsa_public_encrypt(aes_key, './A_file/B_public_key')  # 对AES密钥进行加密
    file_aes_key_encrypted = open('./A_file/AES_key_encrypted', 'wb')
    file_aes_key_encrypted.write(aes_key_encrypted)
    file_aes_key_encrypted.close()
    print("AES秘钥RSA加密完成！")
    print("开始对iv进行RSA加密")
    iv_encrypted = RSA_own.rsa_public_encrypt(iv, './A_file/B_public_key')  # 由于是OFB模式，所以iv需要加密保存到文件中
    file_iv_encrypted = open('./A_file/file_iv_encrypted', 'wb')
    file_iv_encrypted.write(iv_encrypted)
    file_iv_encrypted.close()
    print("对iv的RSA加密完成！")

    print("加密过程结束！\n")
    print("发送给接收者的文件：")
    print("1.已加密文件：file_encrypted")
    print("2.加密后的AES秘钥文件：AES_key_encrypted")
    print("3.AES加密后的初始化向量文件：file_iv_encrypted")
    print("4.加密后的签名文件：file_signature_encrypted")
    print("5.填充位数文件：fill_number")
