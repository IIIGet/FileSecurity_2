# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Sending.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(732, 598)
        self.label_File_List = QtWidgets.QLabel(Form)
        self.label_File_List.setGeometry(QtCore.QRect(30, 150, 121, 16))
        self.label_File_List.setObjectName("label_File_List")
        self.line_5 = QtWidgets.QFrame(Form)
        self.line_5.setGeometry(QtCore.QRect(110, 420, 501, 20))
        self.line_5.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_5.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_5.setObjectName("line_5")
        self.textEdit = QtWidgets.QTextEdit(Form)
        self.textEdit.setGeometry(QtCore.QRect(90, 180, 541, 221))
        self.textEdit.setObjectName("textEdit")
        self.line = QtWidgets.QFrame(Form)
        self.line.setGeometry(QtCore.QRect(110, 490, 501, 20))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.layoutWidget = QtWidgets.QWidget(Form)
        self.layoutWidget.setGeometry(QtCore.QRect(110, 450, 495, 30))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.pushButton_AES_encrypted = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_AES_encrypted.setObjectName("pushButton_AES_encrypted")
        self.horizontalLayout_2.addWidget(self.pushButton_AES_encrypted)
        self.pushButton_MD5 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_MD5.setObjectName("pushButton_MD5")
        self.horizontalLayout_2.addWidget(self.pushButton_MD5)
        self.pushButton_general_sign = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_general_sign.setObjectName("pushButton_general_sign")
        self.horizontalLayout_2.addWidget(self.pushButton_general_sign)
        self.pushButton_encrypted_AES_key = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_encrypted_AES_key.setObjectName("pushButton_encrypted_AES_key")
        self.horizontalLayout_2.addWidget(self.pushButton_encrypted_AES_key)
        self.pushButton_Sending = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_Sending.setObjectName("pushButton_Sending")
        self.horizontalLayout_2.addWidget(self.pushButton_Sending)
        self.widget = QtWidgets.QWidget(Form)
        self.widget.setGeometry(QtCore.QRect(110, 90, 473, 30))
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.pushButton_send_file = QtWidgets.QPushButton(self.widget)
        self.pushButton_send_file.setObjectName("pushButton_send_file")
        self.horizontalLayout.addWidget(self.pushButton_send_file)
        self.RecieveButton = QtWidgets.QPushButton(self.widget)
        self.RecieveButton.setObjectName("RecieveButton")
        self.horizontalLayout.addWidget(self.RecieveButton)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.pushButton_input_file = QtWidgets.QPushButton(self.widget)
        self.pushButton_input_file.setObjectName("pushButton_input_file")
        self.horizontalLayout.addWidget(self.pushButton_input_file)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Alice"))
        self.label_File_List.setText(_translate("Form", "消息提示框："))
        self.pushButton_AES_encrypted.setText(_translate("Form", "AES加密"))
        self.pushButton_MD5.setText(_translate("Form", "MD5摘要"))
        self.pushButton_general_sign.setText(_translate("Form", "生成签名"))
        self.pushButton_encrypted_AES_key.setText(_translate("Form", "加密密钥"))
        self.pushButton_Sending.setText(_translate("Form", "发送文件"))
        self.pushButton_send_file.setText(_translate("Form", "发送公钥"))
        self.RecieveButton.setText(_translate("Form", "接收公钥"))
        self.pushButton_input_file.setText(_translate("Form", "添加"))
