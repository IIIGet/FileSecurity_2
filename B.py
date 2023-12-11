import socket
import zipfile
import os

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

def main():
    host = '127.0.0.1'
    port = 12345
    save_path = 'D:/存放qt的文件\试验目录/实验专用/文件传输系统/加密解密拆分/B_file'  # 指定保存路径

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        receive_and_extract_zipfile(s, save_path)

if __name__ == "__main__":
    main()