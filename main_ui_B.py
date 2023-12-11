import os
import sys

import socket
import zipfile
import os
import rsa
from PyQt5 import QtWidgets
from Recieve import Ui_Form
import sys
from PyQt5.QtWidgets import QFileDialog
import AES_own
import MD5
import RSA_own
import File_operation
from Crypto.Cipher import AES
from Crypto import Random
import struct

HOST ='127.0.0.1'

PORT = 9999
files = './B_file/'

def receive_and_extract_zipfile(conn, save_path):
    with open('received_files.zip', 'wb') as f:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            f.write(data)

    with zipfile.ZipFile('received_files.zip', 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith('/'):  # 如果是文件夹，跳过
                continue
            zip_ref.extract(file, save_path)

    os.remove('received_files.zip')  # 删除zip文件


class Mywindow(QtWidgets.QWidget, Ui_Form):
    def  __init__ (self):
        super(Mywindow, self).__init__()
        self.setupUi(self)
        self.pushButton_Recievefile_public_key.clicked.connect(self.Recieve_public)#接收A的公钥按钮
        self.pushButton_Send_public_key.clicked.connect(self.Send_public_B)#发送B的公钥按钮
        self.pushButton_Recieve_file.clicked.connect(self.Recieve_file)#接收文件的按钮
        self.pushButton_decrypted_AES_key.clicked.connect(self.Decrypted_AES_key)#解密密钥的按钮
        self.pushButton_decrypted_ciphertext.clicked.connect(self.Decrypted_ciphertext)#解密密文的按钮
        self.pushButton_verify_sign.clicked.connect(self.Verify_sign)#验证数字签名的按钮
        self.textEdit.setText("接收端B日志消息：")
    def Recieve_public(self):
        save_path = R"D:\存放qt的文件\试验目录\实验专用\文件传输系统\加密解密拆分\B_file\A_public_key"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST, PORT))
            sock.listen()
            print(f"正在监听{HOST}:{PORT}")
            conn, addr = sock.accept()
            print(f'{addr}已连接')
            f = open(save_path, 'wb')
            while True:
                data = conn.recv(1024)
                f.write(data)
                if not data:
                    self.textEdit.append(save_path+"接收完毕")
                    f.close()
                    break

    def Send_public_B(self):
        RSA_own.B_generate_key_pair()  # 生成公私钥，这里是B的
        file_path = R"D:\存放qt的文件\试验目录\实验专用\文件传输系统\加密解密拆分\B_file\B_public_key"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", 8888))
            f = open(file_path, 'rb')
            while True:
                data = f.read(1024)
                if not data:
                    self.textEdit.append(file_path+"传输完毕")
                    break
                sock.send(data)
    def Recieve_file(self):#接收文件
        save_path = 'D:/存放qt的文件\试验目录/实验专用/文件传输系统/加密解密拆分/B_file'  # 指定保存路径

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            receive_and_extract_zipfile(s, save_path)

    def Decrypted_AES_key(self):#解密AES密钥的按钮功能
        file_aes_key_encrypted_name = files + 'AES_key_encrypted'
        file_aes_key_encrypted = open(file_aes_key_encrypted_name, 'rb')
        file_rsa_private_key_name = './B_file/B_private_key'#RSA私钥的路径
        aes_key_encrypted = file_aes_key_encrypted.read()#AES加密密钥
        self.textEdit.append("开始解密AES秘钥......")
        aes_key = RSA_own.rsa_private_decrypt(aes_key_encrypted, file_rsa_private_key_name)
        file_name = open('./B_file/aes_key','wb')
        file_name.write(aes_key)
        file_name.close()
        self.textEdit.append("AES秘钥解密完成！")

    def Decrypted_ciphertext(self):#解密密文的按钮功能
        iv_encrypted_name = files + 'file_iv_encrypted'
        file_iv_encrypted = open(iv_encrypted_name, 'rb')
        file_rsa_private_key_name = './B_file/B_private_key'
        iv_encrypted = file_iv_encrypted.read()#得到iv向量的内容
        aes_key = File_operation.read_file('./B_file/aes_key')

        self.textEdit.append("开始解密AES初始化向量......")
        iv = RSA_own.rsa_private_decrypt(iv_encrypted, file_rsa_private_key_name)
        self.textEdit.append("AES初始化向量解密完成！\n")
        file_encrypted_name = files + 'file_encrypted_msg'
        file_encrypted = open(file_encrypted_name, 'rb')
        file_encrypted_msg = file_encrypted.read()

        file_fill_number_name = files + 'fill_number'
        file_fill_number = open(file_fill_number_name, 'rb')
        fill_number = file_fill_number.read()
        self.textEdit.append("开始对加密文件进行AES解密")
        file_msg = AES_own.aes_decrypt(file_encrypted_msg, aes_key, iv)
        file_msg = file_msg[0:len(file_msg) - int(float(fill_number))]  # 去掉AES加密时填充的位
        filename = open('./B_file/mingwen','wb')
        filename.write(file_msg)
        self.textEdit.append("加密文件AES解密完成！\n")
    def Verify_sign(self):
        # 解密流程
        file_msg = File_operation.read_file('./B_file/mingwen')
        md5_file_msg = MD5.md5_encrypt(file_msg)
        self.textEdit.append("已接收签名文件！")
        file_signature_encrypted_name = files + 'file_signature_encrypted'
        file_signature_encrypted = open(file_signature_encrypted_name, 'rb')
        signature_encrypted = file_signature_encrypted.read()
        file_signature_encrypted.close()
        self.textEdit.append("文件AES解密")

        sender_public_key_name = './B_file/A_public_key'
        public_key = File_operation.read_file(sender_public_key_name)
        public_keys = rsa.PublicKey.load_pkcs1(public_key)
        self.textEdit.append("进行签名认证")

        RSA_own.rsa_verify(md5_file_msg.encode('utf-8'), signature_encrypted, public_keys)#验证数字签名的函数
        self.textEdit.append("签名文件RSA解密完成，得到原文件MD5值！\n")

        self.textEdit.append("解密程序运行完毕，请提取解密文件！")
        self.textEdit.append('解密完成')


if __name__=="__main__":
    app=QtWidgets.QApplication(sys.argv)
    ui = Mywindow()
    ui.show()
    sys.exit(app.exec_())