import socket
import zipfile
import os


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


def main():
    host = '127.0.0.1'
    port = 12345
    save_path = '/path/to/save'  # 指定保存路径
    files_to_compress = ['./A_file/file1.txt', './A_file/file2.txt']

    create_zipfile(files_to_compress, 'compressed_files.zip')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        conn, addr = s.accept()
        print('Connected by', addr)

        send_zipfile(conn, 'compressed_files.zip')


if __name__ == "__main__":
    main()
