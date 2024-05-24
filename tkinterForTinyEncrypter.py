# https://gist.github.com/vigneshreddyputluri/a86209c8c2b3cd94af49386bc2a66d2e

# importing required modules

import base64
import ctypes
import itertools
import math
import time

from tkinter import *

# defining the functions work for our project

# encrypting function
def encrypt(plaintext, key):
    
    start_time = time.perf_counter()
    if not plaintext:
        return ''

    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])

    bytearray_ = b''.join(_vec2str(_encipher(chunk, k))
                         for chunk in _chunks(v, 2))
    result = base64.b64encode(bytearray_).decode()
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return [result, elapsed_time]

# decrypting function
def decrypt(ciphertext, key):
    
    start_time = time.perf_counter()
    if not ciphertext:
        return ''

    k = _str2vec(key.encode()[:16])
    v = _str2vec(base64.b64decode(ciphertext.encode()))
    result = b''.join(_vec2str(_decipher(chunk, k))
                    for chunk in _chunks(v, 2)).decode()
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return [result, elapsed_time]

# additional functions used to encrypt and decrypt

def _encipher(v, k):
    
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum_ = ctypes.c_uint32(0)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        sum_.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum_.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum_.value ^ (y.value >> 5) + k[3]

    return [y.value, z.value]

def _decipher(v, k):
    
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum_ = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        z.value -= (y.value << 4) + k[2] ^ y.value + sum_.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sum_.value ^ (z.value >> 5) + k[1]
        sum_.value -= delta

    return [y.value, z.value]

def _chunks(iterable, n):
    
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

def _str2vec(value, l=4):
    
    n = len(value)

    # Split the string into chunks
    num_chunks = math.ceil(n / l)
    chunks = [value[l * i:l * (i + 1)]
              for i in range(num_chunks)]

    return [sum([character << 8 * j
                 for j, character in enumerate(chunk)])
            for chunk in chunks]

def _vec2str(vector, l=4):
    
    return bytes((element >> 8 * i) & 0xff
                 for element in vector
                 for i in range(l)).replace(b'\x00', b'')



# tkinter code, for developing the window

Main = Tk()
Main.geometry("800x100")
buttonFrame = Frame(Main)
buttonFrame.pack(fill=BOTH, expand=True)
 
# functions for buttons (when clicked)

def onEncrypt():
    global l, b, output, cipher
    m = "Confirm to encrypt?\n" + '"' + msg.get() + '"'
    l = Label(buttonFrame, text=m, width=100)
    cipher = encrypt(msg.get(), key.get())  # Moved this line here
    output = Label(buttonFrame, text= "Encrypted. The cipher generated is \"" + cipher[0] + "\"\nIn an Elapsed time of " + str(cipher[1]) + " seconds", width=100)

    b = Button(buttonFrame, text="Confirm", command=onConfirm, width=100)
    msg.pack_forget()
    key.pack_forget()
    encryptor.pack_forget()
    decryptor.pack_forget()
    l.pack()
    b.pack()

     
def onDecrypt():
    m = "Confirm to decrypt?\n" +'"'+ msg.get() +'"'
    global l, b, output, resultMsg
    l = Label(buttonFrame, text=m, width=100)
    resultMsg = decrypt(msg.get(), key.get())
    output = Label(buttonFrame, text= "Decrypted. The message generated is \"" + resultMsg[0] + "\"\nIn an Elapsed time of " + str(resultMsg[1]) + " seconds", width=100)

    b = Button(buttonFrame, text = "Confirm", command=onConfirm, width=100)
    msg.pack_forget()
    key.pack_forget()
    encryptor.pack_forget()
    decryptor.pack_forget()
    l.pack()
    b.pack()

def onConfirm():
    l.pack_forget()
    b.pack_forget()
    output.pack(fill=X, expand=True, side=TOP)
    restarter.pack()


def restart():
    output.pack_forget()
    restarter.pack_forget()
    msg.pack()
    key.pack()
    encryptor.pack()
    decryptor.pack()


# defining the buttons and their working

msg = Entry(buttonFrame, width=50)
key = Entry(buttonFrame, width=50)
encryptor = Button(buttonFrame, text= "Encrypt", command= onEncrypt, width=30)
decryptor = Button(buttonFrame, text= "Decrypt", command= onDecrypt, width=30)

restarter = Button(buttonFrame, text="Start Again", command=restart, width=100)

# aligning the buttons

msg.pack()
key.pack()
encryptor.pack()
decryptor.pack()

Main.mainloop()