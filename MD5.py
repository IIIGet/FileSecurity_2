from Crypto.Hash import MD5


# MD5生成信息摘要，通过Crypto库里的md5算法
def md5_encrypt(md5_file):
    # pycrypto包未更新，只能使用pycryptodome包，里面的Crypto库是小写形式
    msg = MD5.new()  # 定义一个MD5加密对象  计算MD5值
    msg.update(md5_file)
    return msg.hexdigest()
