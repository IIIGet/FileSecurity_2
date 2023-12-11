import struct
import time
import zipfile
from idlelib import testing
from turtle import pd

#这是文件的发送端
import socket


from PyQt5 import QtWidgets
from Sending import Ui_Form
import sys
from PyQt5.QtWidgets import QFileDialog
import rsa

import AES_own
import MD5
import RSA_own
import File_operation
from Crypto.Cipher import AES
from Crypto import Random


import os

from 试验目录.实验专用.文件传输系统.加密解密拆分 import RSA_own, MD5

HOST ='127.0.0.1'
PORT = 9999

def create_zipfile(files_to_compress, zip_name):
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for file in files_to_compress:
            zipf.write(file, os.path.basename(file))  # 添加文件但是不包含路径

def send_zipfile(conn, zip_name):
    with open(zip_name, 'rb') as f:
        file_data = f.read(1024)
        while file_data:
            conn.sendall(file_data)
            file_data = f.read(1024)


class mywindow(QtWidgets.QWidget, Ui_Form):
    def  __init__ (self):
        super(mywindow, self).__init__()
        self.setupUi(self)
        self.pushButton_input_file.clicked.connect(self.read_file)#添加文件
        self.pushButton_send_file.clicked.connect(self.Send_File)#发送文件的按钮
        self.RecieveButton.clicked.connect(self.Recieve_public_B)#接收B公钥的按钮

        self.pushButton_Sending.clicked.connect(self.Send_Digital)#发送数字信封的按钮

        self.pushButton_AES_encrypted.clicked.connect(self.AES_encrypted)#AES加密按钮
        self.pushButton_MD5.clicked.connect(self.MD5_encypted)#MD5按钮
        self.pushButton_general_sign.clicked.connect(self.general_sign)#生成签名按钮
        self.pushButton_encrypted_AES_key.clicked.connect(self.encrypted_AES_key)#加密密钥按钮

        self.textEdit.setText("发送端A的日志消息：")
    def read_file(self):#添加按钮的功能
        # 选取文件
        filename, filetype = QFileDialog.getOpenFileName(self, "选取文件", "D:\存放qt的文件\试验目录\实验专用\文件传输系统\加密解密拆分", "All Files(*);;Text Files(*.csv)")
        #self.textEdit.append(filename, filetype)
        self.lineEdit.setText(filename)


    def Send_File(self):
        #选取文件发送给client端
        RSA_own.A_generate_key_pair()  # 生成公私钥，这里是A的
        file_path = R"D:\存放qt的文件\试验目录\实验专用\文件传输系统\加密解密拆分\A_file\A_public_key"
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect((HOST,PORT))
            f = open(file_path,'rb')
            while True:
                data = f.read(1024)
                if not data:
                    self.textEdit.append(file_path+"传输完毕")
                    break
                sock.send(data)
    def Recieve_public_B(self):
        save_path = R"D:\存放qt的文件\试验目录\实验专用\文件传输系统\加密解密拆分\A_file\B_public_key"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 8888))
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

    def AES_encrypted(self):
        filename = self.lineEdit.text()  # 获取文本内容
        self.textEdit.append("准备进行加密操作\n")
        # 文件加密，签名
        plaintext_file = filename
        # 读取要加密的文件
        file_encrypt = File_operation.read_file(plaintext_file)  # 读取原文文件
        # 生成AES密钥字符串
        AES_own.aes_key_gen()  # 产生AES密钥
        aes_key = File_operation.read_file('./A_file/aes_key')  # 将AES密钥进行保存
        # 生成一个随机的AES向量
        iv = Random.new().read(AES.block_size)  # 使用OFB模式加密，要产生一个iv向量并保存
        # iv_file = open('./A_file/iv', 'wb')
        # iv_file.write(iv)
        # iv_file.close()
        File_operation.write_file(iv,'./A_file/iv') # iv向量保存
        self.textEdit.append("开始对原文件进行AES加密......")
        # 调用加密函数，生成填充位字符
        file_encrypt_msg, fill_number = AES_own.aes_encrypt(file_encrypt, aes_key, iv)  # 使用AES密钥和iv向量
        file_encrypted = open('./A_file/file_encrypted_msg', 'wb')  # 生成存储加密后文件
        file_encrypted.write(file_encrypt_msg)  # 写入文件中
        file_encrypted.close()
        self.textEdit.append("原文件AES加密完成！")
        file_fill_number = open('./A_file/fill_number', 'wb')  # 生成存储填充位数文件
        file_fill_number.write(str(fill_number).encode('utf-8'))  # 写入文件中
        file_fill_number.close()

    def MD5_encypted(self):
        filename1 = self.lineEdit.text()  # 获取文本内容
        self.textEdit.append("准备进行加密操作\n")
        # 文件加密，签名
        plaintext_file = 'AES.txt'
        # 读取要加密的文件
        file_encrypt = File_operation.read_file(plaintext_file)  # 读取原文文件

        self.textEdit.append("开始对原文件进行MD5摘要......")
        md5_msg = MD5.md5_encrypt(file_encrypt)  # 生成MD5摘要
        type(md5_msg)
        md5_file = open('./A_file/MD5_msg', 'w')  # 生成存储加密后文件
        md5_file.write(md5_msg)  # 写入文件中
        md5_file.close()
        self.textEdit.append("MD5摘要完成！")

    def general_sign(self):
        private_key = File_operation.read_file('./A_file/A_private_key')
        private_keys = rsa.PrivateKey.load_pkcs1(private_key)  # 保存到文件中
        self.textEdit.append("开始对MD5摘要签名")
        md5_msg = File_operation.read_file('./A_file/MD5_msg')#读取MD5_msg文件

        print(md5_msg)

        signature_msg = RSA_own.rsa_sign(md5_msg, private_keys)  # 用自己私钥加密生成数字签名
        file_signature_encrypted = open('./A_file/file_signature_encrypted', 'wb+')  # 写入文件中
        file_signature_encrypted.write(signature_msg)  # 写入文件中
        file_signature_encrypted.close()
        self.textEdit.append("MD5摘要签名完成！")

    def encrypted_AES_key(self):
        self.textEdit.append("开始对AES秘钥进行RSA加密")
        aes_key = File_operation.read_file('./A_file/aes_key')  # 读取aes_key文件
        aes_key_encrypted = RSA_own.rsa_public_encrypt(aes_key, './A_file/B_public_key')  # 对AES密钥进行加密
        file_aes_key_encrypted = open('./A_file/AES_key_encrypted', 'wb')
        file_aes_key_encrypted.write(aes_key_encrypted)
        file_aes_key_encrypted.close()
        self.textEdit.append("AES秘钥RSA加密完成！")
        self.textEdit.append("开始对iv进行RSA加密")
        iv = File_operation.read_file('./A_file/iv')
        iv_encrypted = RSA_own.rsa_public_encrypt(iv, './A_file/B_public_key')  # 由于是OFB模式，所以iv需要加密保存到文件中
        file_iv_encrypted = open('./A_file/file_iv_encrypted', 'wb')
        file_iv_encrypted.write(iv_encrypted)
        file_iv_encrypted.close()
        self.textEdit.append("对iv的RSA加密完成！")

        self.textEdit.append("加密过程结束！\n")
        self.textEdit.append("发送给接收者的文件：")
        self.textEdit.append("1.已加密文件：file_encrypted")
        self.textEdit.append("2.加密后的AES秘钥文件：AES_key_encrypted")
        self.textEdit.append("3.AES加密后的初始化向量文件：file_iv_encrypted")
        self.textEdit.append("4.加密后的签名文件：file_signature_encrypted")
        self.textEdit.append("5.填充位数文件：fill_number")
        self.textEdit.append("加密完成！")

    def Send_Digital(self):
        files_to_compress = [R'D:/存放qt的文件/试验目录/实验专用/文件传输系统/加密解密拆分/A_file/AES_key_encrypted',
                     R'D:/存放qt的文件/试验目录/实验专用/文件传输系统/加密解密拆分/A_file/file_encrypted_msg',
                     R'D:/存放qt的文件/试验目录/实验专用/文件传输系统/加密解密拆分/A_file/file_iv_encrypted',
                     R'D:/存放qt的文件/试验目录/实验专用/文件传输系统/加密解密拆分/A_file/file_signature_encrypted',
                     R'D:/存放qt的文件/试验目录/实验专用/文件传输系统/加密解密拆分/A_file/fill_number']

        #files_to_compress = ['./A_file/file1.txt', './A_file/file2.txt']

        create_zipfile(files_to_compress, 'compressed_files.zip')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()

            conn, addr = s.accept()
            print('Connected by', addr)

            send_zipfile(conn, 'compressed_files.zip')

if __name__=="__main__":
    app=QtWidgets.QApplication(sys.argv)
    ui = mywindow()
    ui.show()
    sys.exit(app.exec_())
