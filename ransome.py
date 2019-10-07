from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
import os, glob

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)


def main():
    password = raw_input('Password: ')
    _encFiles = glob.glob("files\\*.encrypted")
    _txtFiles = glob.glob("files\\*.txt")
    _jpgFiles = glob.glob("files\\*.jpg")
    _allFiles = _txtFiles + _jpgFiles

    if _allFiles != []:
        for in_filename in _allFiles:
            with open(in_filename, 'rb') as in_file:
                out_filename = in_filename+".encrypted"
                out_file = open(out_filename, 'wb')
                encrypt(in_file, out_file, password)
                in_file.close()
                os.remove(in_filename)

    elif _allFiles == [] and _encFiles != []:
        for in_filename in _encFiles:
            with open(in_filename, 'rb') as in_file:
                out_filename = in_filename.replace(".encrypted", "")
                out_file = open(out_filename, "wb")
                decrypt(in_file, out_file, password)
                in_file.close()
                os.remove(in_filename)
    else:
        print ("There is no files to Encrypt/Decrypt")



main()
