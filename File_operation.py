# 文件操作
def read_file(self,str_filename):
    try:
        f = open(str_filename, 'rb+')
        s = f.read()
        f.close
        # print(str_filename + '文件读取成功！')
        self.textEdit.append(str_filename + "文件读取成功")
        # print('文件内容为：')
        # print(s)
        return s
    except IOError:
        # print(str_filename + '文件读取错误！')
        self.textEdit.append(str_filename + "文件读取错误")


# 将信息写入文件中
def write_file(self,str_name, str_filename):
    try:
        f = open(str_filename, 'w', encoding='utf-8')
        f.write(str_name)
        f.close
        # print(str_filename + '文件写入成功！')
        self.textEdit.append(str_filename+"文件保存成功")
    except IOError:
        # print(str_filename + '文件写入错误！')
        self.textEdit.append(str_filename+"文件保存错误")