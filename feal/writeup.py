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
NUM_CHECK = 5

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

def convert_list(input):
    return [int(((input & (0xff << 8*i)) >> 8*i)) for i in xrange(4)]

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

def decrypt(plain,subkeys):
    cipherLeft = plain[0:4]
    cipherRight = plain[4:]

    def list_xor(l1,l2):
        return map(lambda x: x[0]^x[1], zip(l1,l2))
    R4R = list_xor(cipherLeft,cipherRight)
    R4L = list_xor(cipherLeft, fBox(list_xor(R4R, subkeys[3])))


    R3R = R4L
    R3L = list_xor(R4R , fBox(list_xor(R3R, subkeys[2])))

    R2R = R3L
    R2L = list_xor(R3R, fBox(list_xor(R2R, subkeys[1])))

    left = list_xor(R2R, fBox(list_xor(R2L, subkeys[0])))
    right = list_xor(left, R2L)

    pleft = list_xor(left, subkeys[4])
    pright = list_xor(right, subkeys[5])

    return pleft+pright

def get_ciphertext(plaintext):
    s,f = sock(HOST, PORT)
    read_until(f,"21 bytes, starting with ")
    prefix = f.read(16)
    chall = findproof(prefix)
    f.write(chall)
    f.read(20)
    read_until(f,"Please decrypt: ")
    key_cipher = f.read(33)
    f.write(plaintext)
    C = f.read(16)
    return C

def get_keycipher(plaintext):
    s,f = sock(HOST, PORT)
    read_until(f,"21 bytes, starting with ")
    prefix = f.read(16)
    chall = findproof(prefix)
    f.write(chall)
    f.read(20)
    read_until(f,"Please decrypt: ")
    key_cipher = f.read(32)
    return key_cipher

def get_plaintext(diff_list):
    plain_a = array.array("B",os.urandom(8))
    plain_b = list_xor(plain_a,diff_list)

    toSend_a = "".join(map(chr,plain_a))
    toSend_b = "".join(map(chr,plain_b))
    return (toSend_a,toSend_b)

def recover_4th_round(cipher, subkey3):
    cl = list_xor(cipher[0:4],cipher[4:8])
    cr = list_xor(cipher[0:4],fBox(list_xor(cl,subkey3)))
    return cl+cr

def recover_round(cipher, subkey):
    cl = cipher[4:8]
    cr = list_xor(cipher[0:4],fBox(list_xor(cl,subkey)))
    return cl+cr

def search_subkey3(ca_list, cb_list):
    diff_cl_list = [list_xor(ca_list[x],cb_list[x])[0:4] for x in xrange(5)]
    clcr_a_list = [list_xor(ca_list[x][0:4],ca_list[x][4:8]) for x in xrange(5)]
    clcr_b_list = [list_xor(cb_list[x][0:4],cb_list[x][4:8]) for x in xrange(5)]

    d = 0x04000000
    d_list = convert_list(d)

    for subkey in xrange(1<<4*8):

        count = 0
        k_list = convert_list(subkey)
        #k_list[0] = 97
        #k_list[1] = 98
        k_list[2] = 98
        k_list[3] = 57

        for x in xrange(NUM_CHECK):

            A = fBox(list_xor(clcr_a_list[x], k_list))
            B = fBox(list_xor(clcr_b_list[x], k_list))
            Y = list_xor(list_xor(A,B),d_list)
            diff = list_xor(diff_cl_list[x],Y)
            if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
                break
            count += 1

        if count == NUM_CHECK:
            return k_list

def search_subkey2(ca_list, cb_list):
    diff_cl_list = [list_xor(ca_list[x],cb_list[x])[0:4] for x in xrange(5)]
    clcr_a_list = [ca_list[x][4:8] for x in xrange(5)]
    clcr_b_list = [cb_list[x][4:8] for x in xrange(5)]

    d = 0x04000000
    d_list = convert_list(d)

    for subkey in xrange(1<<4*8):

        count = 0
        k_list = convert_list(subkey)
        #k_list[0] = 97
        #k_list[1] = 98
        k_list[2] = 54
        k_list[3] = 97

        for x in xrange(NUM_CHECK):

            A = fBox(list_xor(clcr_a_list[x], k_list))
            B = fBox(list_xor(clcr_b_list[x], k_list))
            Y = list_xor(list_xor(A,B),d_list)
            diff = list_xor(diff_cl_list[x],Y)
            if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
                break
            count += 1

        if count == NUM_CHECK:
            return k_list

def search_subkey1(ca_list, cb_list):
    diff_cl_list = [list_xor(ca_list[x],cb_list[x])[0:4] for x in xrange(5)]
    clcr_a_list = [ca_list[x][4:8] for x in xrange(5)]
    clcr_b_list = [cb_list[x][4:8] for x in xrange(5)]

    d = 0x04000000
    d_list = convert_list(d)

    for subkey in xrange(1<<4*8):

        count = 0
        k_list = convert_list(subkey)
        #k_list[0] = 97
        #k_list[1] = 98
        k_list[2] = 51
        k_list[3] = 56

        for x in xrange(NUM_CHECK):

            A = fBox(list_xor(clcr_a_list[x], k_list))
            B = fBox(list_xor(clcr_b_list[x], k_list))
            Y = list_xor(list_xor(A,B),d_list)
            diff = list_xor(diff_cl_list[x],Y)
            if diff[0] != 0 or diff[1] != 0 or diff[2] != 0 or diff[3] != 0:
                break
            count += 1

        if count == NUM_CHECK:
            return k_list

def search_subkey0(p_list, c_list, ca_list, subkey3, subkey2, subkey1):
    cl = [x[0:4] for x in ca_list]
    cr = [x[4:8] for x in ca_list]

    for subkey0 in xrange(1<<4*8):

        count = 0

        k_list = convert_list(subkey0)
        #k_list[0] = 97
        #k_list[1] = 98
        k_list[2] = 55
        k_list[3] = 98

        for x in xrange(4):
            A = fBox(list_xor(cr[x], k_list))
            subkey4 = list_xor(list_xor(cl[x], A),p_list[x][0:4])
            subkey5 = list_xor(list_xor(list_xor(cr[x], subkey4),p_list[x][0:4]),p_list[x][4:8])
            subkeys = (k_list, subkey1, subkey2, subkey3, subkey4, subkey5)

            cand_c = binascii.hexlify("".join(map(chr,encrypt(p_list[x+1],subkeys))))
            c = "".join(binascii.hexlify(c_list[x+1]))

            if cand_c != c:
                break
            count += 1

        if count == 4:
            return subkeys


print "recovering subkey3..."
starttime = time.clock()
diff_list = [0x80,0x80,0x00,0x00,0x80,0x80,0x00,0x00]
ca_list = []
cb_list = []
for x in xrange(NUM_CHECK):
    (toSend_a, toSend_b) = get_plaintext(diff_list)
    Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
    Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
    ca_list.append(Ca)
    cb_list.append(Cb)
subkey3 = search_subkey3(ca_list, cb_list)
endtime = time.clock()
print "subkey3 is %s"%subkey3
print "time:%s"%str(endtime-starttime)

print "recovering subkey2..."
starttime = time.clock()
diff_list = [0x00,0x00,0x00,0x00,0x80,0x80,0x00,0x00]
ca_list = []
cb_list = []
for x in xrange(NUM_CHECK):
    (toSend_a, toSend_b) = get_plaintext(diff_list)
    Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
    Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
    Ca = recover_4th_round(Ca, subkey3)
    Cb = recover_4th_round(Cb, subkey3)
    ca_list.append(Ca)
    cb_list.append(Cb)
subkey2 = search_subkey2(ca_list, cb_list)
endtime = time.clock()
print "subkey2 is %s"%subkey2
print "time:%s"%str(endtime-starttime)

print "recovering subkey1..."
starttime = time.clock()
diff_list = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04]
ca_list = []
cb_list = []
for x in xrange(NUM_CHECK):
    (toSend_a, toSend_b) = get_plaintext(diff_list)
    Ca = array.array("B",binascii.unhexlify(get_ciphertext(toSend_a)))
    Cb = array.array("B",binascii.unhexlify(get_ciphertext(toSend_b)))
    Ca = recover_4th_round(Ca, subkey3)
    Cb = recover_4th_round(Cb, subkey3)
    Ca = recover_round(Ca, subkey2)
    Cb = recover_round(Cb, subkey2)
    ca_list.append(Ca)
    cb_list.append(Cb)
subkey1 = search_subkey1(ca_list, cb_list)
endtime = time.clock()
print "subkey1 is %s"%subkey1
print "time:%s"%str(endtime-starttime)

print "recovering all subkeys..."
starttime = time.clock()
diff_list = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
p_list = []
c_list = []
ca_list = []
for x in xrange(NUM_CHECK):
    (toSend, toSend_b) = get_plaintext(diff_list)
    C = array.array("B",binascii.unhexlify((get_ciphertext(toSend))))
    Ca = recover_4th_round(C, subkey3)
    Ca = recover_round(Ca, subkey2)
    Ca = recover_round(Ca, subkey1)
    p_list.append(array.array("B",toSend))
    c_list.append(C)
    ca_list.append(Ca)
subkeys = search_subkey0(p_list, c_list, ca_list, subkey3, subkey2, subkey1)
endtime = time.clock()
print "time:%s"%str(endtime-starttime)

cipher = binascii.unhexlify(get_keycipher(toSend))
kp1 = "".join(map(chr,decrypt(array.array("B",cipher[0:8]),subkeys)))
kp2 = "".join(map(chr,decrypt(array.array("B",cipher[8:16]),subkeys)))
print "OK, all subkeys recovered"
print "plaintext is "
print kp1+kp2


