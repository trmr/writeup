#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket
import commands
import array
import binascii
import hashlib
import os
import time

HOST = '127.0.0.1'
PORT = 8888

def list_xor(l1,l2):
    return map(lambda x: x[0]^x[1], zip(l1,l2))

def sock(remoteip, remoteport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteip, remoteport))
    return s, s.makefile('rw', bufsize=0)

def read_until(f, delim='\n'):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

#def findproof(prefix):
#    r = commands.getoutput("./a.out '%s'" % prefix)
#    print r
#    return r.decode("hex")

def findproof(prefix):
    brute_len = 5
    for i in xrange (1 << brute_len*8):
        list_i = []
        while i > 0:
            list_i.append(i & 0xff)
            i = i >> 8
        seed = prefix + "".join(map(chr,list_i))
        if hashlib.sha1(seed).hexdigest().endswith("ffff"):
            return seed

def rot3(x):
    return ((x<<3)|(x>>5))&0xff

def gBox(a,b,mode):
    return rot3((a+b+mode)%256)

def fBox(plain):
    t0 = (plain[2] ^ plain[3])
    y1 = gBox(plain[0] ^ plain[1], t0, 1)
    y0 = gBox(plain[0], y1, 0)
    y2 = gBox(t0, y1, 0)
    y3 = gBox(plain[3], y2, 1)

    return [y3, y2, y1, y0]

def encrypt(plain,subkeys):
    pleft = plain[0:4]
    pright = plain[4:]

    left = list_xor(pleft, subkeys[4])
    right = list_xor(pright, subkeys[5])

    R2L = list_xor(left, right)
    R2R = list_xor(left, fBox(list_xor(R2L, subkeys[0])))

    R3L = R2R;
    R3R = list_xor(R2L, fBox(list_xor(R2R, subkeys[1])))

    R4L = R3R;
    R4R = list_xor(R3L, fBox(list_xor(R3R, subkeys[2])))

    cipherLeft = list_xor(R4L, fBox(list_xor(R4R, subkeys[3])))
    cipherRight = list_xor(cipherLeft, R4R)

    return cipherLeft+cipherRight

def get_ciphertext(plaintext):
    s,f = sock(HOST, PORT)
    read_until(f,"21 bytes, starting with ")
    prefix = f.read(16)
    chall = findproof(prefix)
    f.write(chall)
    f.read(20)
    f.read(50)
    f.write(plaintext)
    C = f.read(16)
    return C

def get_plaintext(diff_list):
    plain_a = array.array("B",os.urandom(8))
    plain_b = list_xor(plain_a,diff_list)

    toSend_a = "".join(map(chr,plain_a))
    toSend_b = "".join(map(chr,plain_b))
    return (toSend_a,toSend_b)

def check_subkey3(k_list, diff_list):
    check_num = 5
    for x in xrange(check_num):
        (toSend_a, toSend_b) = get_plaintext(diff_list)
        Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
        Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
        diff_CL = list_xor(Ca,Cb)[0:4]
        CL_and_CR_a = list_xor(Ca[0:4],Ca[4:8])
        CL_and_CR_b = list_xor(Cb[0:4],Cb[4:8])

        d = 0x04000000
        d_list = []
        for x in xrange(4):
            d_list.append(int(d&0xff))
            d = d >> 8

        A = fBox(list_xor(CL_and_CR_a, k_list))
        B = fBox(list_xor(CL_and_CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
            return False
    return True

def search_subkey3(Ca, Cb, diff_list):
    diff_CL = list_xor(Ca,Cb)[0:4]
    CL_and_CR_a = list_xor(Ca[0:4],Ca[4:8])
    CL_and_CR_b = list_xor(Cb[0:4],Cb[4:8])

    d = 0x04000000
    d_list = []
    for x in xrange(4):
        d_list.append(int(d&0xff))
        d = d >> 8

    for subkey in xrange(1<<4*8):

    #    k_list = array.array("B","abcd")
        k_list = []
        for x in xrange(4):
            k_list.append(int(subkey&0xff))
            subkey = subkey >> 8
#        k_list[1] = 98
#        k_list[2] = 99
#        k_list[3] = 100

        A = fBox(list_xor(CL_and_CR_a, k_list))
        B = fBox(list_xor(CL_and_CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] == 0 and diff[1] == 0 and diff[2] == 0 and diff[3] == 0:
            if check_subkey3(k_list, diff_list) == True:
                return k_list

def recover_4th_round(cipher, subkey3):
    cl = list_xor(cipher[0:4],cipher[4:8])
    cr = list_xor(cipher[0:4],fBox(list_xor(cl,subkey3)))
    return cl+cr

def recover_round(cipher, subkey):
    cl = cipher[4:8]
    cr = list_xor(cipher[0:4],fBox(list_xor(cl,subkey)))
    return cl+cr

def check_subkey2(k_list, diff_list, subkey3):
    check_num = 5
    for x in xrange(check_num):
        (toSend_a, toSend_b) = get_plaintext(diff_list)
        Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
        Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
        Ca = recover_4th_round(Ca, subkey3)
        Cb = recover_4th_round(Cb, subkey3)
        diff_CL = list_xor(Ca,Cb)[0:4]
        CR_a = Ca[4:8]
        CR_b = Cb[4:8]

        d = 0x04000000
        d_list = []
        for x in xrange(4):
            d_list.append(int(d&0xff))
            d = d >> 8

        A = fBox(list_xor(CR_a, k_list))
        B = fBox(list_xor(CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
            return False
    return True

def search_subkey2(Ca, Cb, diff_list, subkey3):
    diff_CL = list_xor(Ca,Cb)[0:4]
    CR_a = Ca[4:8]
    CR_b = Cb[4:8]

    d = 0x04000000
    d_list = []
    for x in xrange(4):
        d_list.append(int(d&0xff))
        d = d >> 8

    for subkey in xrange(1<<4*8):

    #    k_list = array.array("B","abcd")
        k_list = []
        for x in xrange(4):
            k_list.append(int(subkey&0xff))
            subkey = subkey >> 8
#        k_list[1] = 98
#        k_list[2] = 99
#        k_list[3] = 100

        A = fBox(list_xor(CR_a, k_list))
        B = fBox(list_xor(CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] == 0 and diff[1] == 0 and diff[2] == 0 and diff[3] == 0:
            if check_subkey2(k_list, diff_list, subkey3) == True:
                return k_list

def check_subkey1(k_list, diff_list, subkey3, subkey2):
    check_num = 5
    for x in xrange(check_num):
        (toSend_a, toSend_b) = get_plaintext(diff_list)
        Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
        Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
        Ca = recover_4th_round(Ca, subkey3)
        Cb = recover_4th_round(Cb, subkey3)
        Ca = recover_round(Ca, subkey2)
        Cb = recover_round(Cb, subkey2)
        diff_CL = list_xor(Ca,Cb)[0:4]
        CR_a = Ca[4:8]
        CR_b = Cb[4:8]

        d = 0x04000000
        d_list = []
        for x in xrange(4):
            d_list.append(int(d&0xff))
            d = d >> 8

        A = fBox(list_xor(CR_a, k_list))
        B = fBox(list_xor(CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
            return False
    return True

def search_subkey1(Ca, Cb, diff_list, subkey3, subkey2):
    diff_CL = list_xor(Ca,Cb)[0:4]
    CR_a = Ca[4:8]
    CR_b = Cb[4:8]

    d = 0x04000000
    d_list = []
    for x in xrange(4):
        d_list.append(int(d&0xff))
        d = d >> 8

    for subkey in xrange(1<<4*8):

    #    k_list = array.array("B","abcd")
        k_list = []
        for x in xrange(4):
            k_list.append(int(subkey&0xff))
            subkey = subkey >> 8
#        k_list[1] = 98
#        k_list[2] = 99
#        k_list[3] = 100

        A = fBox(list_xor(CR_a, k_list))
        B = fBox(list_xor(CR_b, k_list))
        Y = list_xor(list_xor(A,B),d_list)
        diff = list_xor(diff_CL,Y)
        if diff[0] == 0 and diff[1] == 0 and diff[2] == 0 and diff[3] == 0:
            if check_subkey1(k_list, diff_list, subkey3, subkey2) == True:
                return k_list

def check_subkey0(subkeys):
    check_num = 5
    for x in xrange(check_num):
        plaintext = os.urandom(8)
        ciphertext = get_ciphertext(plaintext)
        toEnc = array.array("B",plaintext)
        C = binascii.hexlify("".join(map(chr,encrypt(toEnc,subkeys))))

        if ciphertext != C:
            return False
    return True

def search_subkey0(C, subkey3, subkey2, subkey1):
    CL = C[0:4]
    CR = C[4:8]

    for subkey0 in xrange(1<<4*8):

        k_list = []
        for x in xrange(4):
            k_list.append(int(subkey0&0xff))
            subkey0 = subkey0 >> 8
#        k_list[1] = 98
#        k_list[2] = 99
#        k_list[3] = 100

        A = fBox(list_xor(CR, k_list))
        subkey4 = list_xor(CL, A)
        subkey5 = list_xor(CR, subkey4)
        subkeys = (k_list, subkey1, subkey2, subkey3, subkey4, subkey5)
        if check_subkey0(subkeys) == True:
            return subkeys


print "recovering subkey3..."
starttime = time.clock()
diff_list = [0x80,0x80,0x00,0x00,0x80,0x80,0x00,0x00]
(toSend_a, toSend_b) = get_plaintext(diff_list)
Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
subkey3 = search_subkey3(Ca, Cb, diff_list)
endtime = time.clock()
print "subkey3 is %s"%subkey3
print "time:%s"%str(endtime-starttime)

print "recovering subkey2..."
starttime = time.clock()
diff_list = [0x00,0x00,0x00,0x00,0x80,0x80,0x00,0x00]
(toSend_a, toSend_b) = get_plaintext(diff_list)
Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
Ca = recover_4th_round(Ca, subkey3)
Cb = recover_4th_round(Cb, subkey3)
subkey2 = search_subkey2(Ca, Cb, diff_list, subkey3)
endtime = time.clock()
print "subkey2 is %s"%subkey2
print "time:%s"%str(endtime-starttime)

print "recovering subkey1..."
starttime = time.clock()
diff_list = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04]
(toSend_a, toSend_b) = get_plaintext(diff_list)
Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
Ca = recover_4th_round(Ca, subkey3)
Cb = recover_4th_round(Cb, subkey3)
Ca = recover_round(Ca, subkey2)
Cb = recover_round(Cb, subkey2)
subkey1 = search_subkey1(Ca, Cb, diff_list, subkey3, subkey2)
endtime = time.clock()
print "subkey1 is %s"%subkey1
print "time:%s"%str(endtime-starttime)

print "recovering all subkeys..."
starttime = time.clock()
plaintext = [0,0,0,0,0,0,0,0]
toSend = "".join(map(chr,plaintext))
C = array.array("B",binascii.unhexlify((get_ciphertext(toSend))))
C = recover_4th_round(C, subkey3)
C = recover_round(C, subkey2)
C = recover_round(C, subkey1)
#CL = K4+K5, CR = K4 + f(K4+K5+K0)
print search_subkey0(C, subkey3, subkey2, subkey1)
endtime = time.clock()
print "time:%s"%str(endtime-starttime)

