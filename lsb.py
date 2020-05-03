import matplotlib.image as mpimg
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import numpy as np

import argparse

parser = argparse.ArgumentParser(description="Hide or retrieve a message from an image")
parser.add_argument('-i','--input',type=str,default=None,help='The file to be read or changed')
parser.add_argument('-o','--output',type=str,default=None,help='The file to write. If present, a message must be provided. If not present, I will try to read a message from -i')
parser.add_argument('-m','--message',type=str,default="",help='The message to hide')
parser.add_argument('-p','--password',type=str,default="",help='The password to use')

def main():
    args = parser.parse_args()
    if args.input is None:
        return 0
    if args.output is None:
        # Read from image
        print(decode_from_image(args.input,args.password))
        return 0
    else:
        encode_in_image(args.input,args.output,args.message.encode(),args.password)
        return 0

def get_bits(message):
    '''Generator for all bits in message. Message must be bytes-like'''
    for byte in message:
        for i in range(8):
            yield ((byte & (0x01 << i))>>i)

def get_lsbs(message):
    for byte in message:
        yield(byte & 1)
def rebuild_from_bits(bitseq):
    res = []
    k=0
    cur = 0
    for b in bitseq:
        cur |= b<<k
        k+=1
        if k == 8:
            k=0
            res.append(cur)
            cur=0
    return res

def imread (path):
    '''Returns byte sequence of image'''
    image = np.uint8 (mpimg.imread (path)*255)
    return image.tobytes (),image.shape

def imsave (path,im,shape):
    buf = np.reshape (np.frombuffer (im,np.uint8),shape)
    mpimg.imsave (path, buf)


def get_length (buff):
    '''Returns the maximum length of the message that can be encoded in buff'''
    return len (buff)//8


def encode_message_in_buffer (message,imbuff):
    if type(imbuff) is bytes:
        imbuffx = [i for i in imbuff]
        imbuff = imbuffx
    i=0
    for b in get_bits (message):
        if b == 1:
            imbuff [i] |=1
        else:
            imbuff[i] &=~1
        i+=1
    return bytes(imbuff)

def decode_message_from_buffer (imbuff):
    i=0
    message = rebuild_from_bits(get_lsbs(imbuff))
    return bytes(message)

def encrypt(message,key):
    iv = Random.new().read(AES.block_size)
    ciph = AES.new(key,AES.MODE_CFB,iv)
    cryptogram = ciph.encrypt(message)
    strlength = "{:016}".format(len(cryptogram)).encode()

    ciph = AES.new(key,AES.MODE_CFB,iv)
    length = ciph.encrypt(strlength)
    #print("len: {}".format(length))

    return iv + length + cryptogram

def decrypt(cryptogram,key):
    iv = cryptogram[:AES.block_size]
    ciph = AES.new(key,AES.MODE_CFB,iv)
    received_len = cryptogram[AES.block_size:AES.block_size+16]
    #print("Received_len: {}".format(received_len))
    try:
        length = int (ciph.decrypt(received_len))
    except ValueError:
        print("No se ha encontrado ningún mensaje oculto")
        exit(-1)
    ciph = AES.new(key,AES.MODE_CFB,iv)
    return ciph.decrypt(cryptogram[AES.block_size+16:AES.block_size+16+length])




def gen_key_from_passwd(passwd):
    if type(passwd) is str:
        passwd = passwd.encode()
    h = SHA256.new()
    h.update(passwd)
    return h.digest()

def test_encryption(message,passwd):
    key = gen_key_from_passwd(passwd)
    print("Message: \"{}\"".format(message))
    cryptogram = encrypt(message,key)
    print("Cryptogram: \"{}\"".format(cryptogram))
    print("Decrypted: \"{}\"".format(decrypt(cryptogram,key)))


def encode_in_image(path_in, path_out,message,passwd):
    key = gen_key_from_passwd(passwd)
    buff = encrypt(message,key)
    imin,shape = imread(path_in)
    imout = encode_message_in_buffer(buff,imin)
    imsave(path_out,imout,shape)

def decode_from_image(path,passwd):
    key = gen_key_from_passwd(passwd)
    im,_ = imread(path)
    cryptogram = decode_message_from_buffer(im)
    return decrypt(cryptogram,key).decode()


if __name__ == "__main__":
    main()
