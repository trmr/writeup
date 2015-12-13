#!/usr/bin/env python
#-*- coding:utf-8 -*-

import array
import os
import struct
import copy
import commands
import socket
import subme

EQUAL = "."
DIFFER = "D"

HOST = '127.0.0.1'
#HOST = 'katagaitai.orz.hm'
PORT = 9999

def s2b(s):
    """
    String to binary.
    """
    ret = []
    for c in s:
        ret.append(bin(ord(c))[2:].zfill(8))
    return "".join(ret)


def b2s(b):
    """
    Binary to string.
    """
    ret = []
    for pos in range(0, len(b), 8):
        ret.append(chr(int(b[pos:pos + 8], 2)))
    return "".join(ret)


def sock(remoteip, remoteport):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteip, remoteport))
    return s, s.makefile('rw', bufsize=0)

def read_until(f, delim='\n'):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

def findproof(prefix):
    r = commands.getoutput("./a.out '%s'"%prefix)
    return r.decode("hex")

def get_ciphertext(msg):
    s,f = sock(HOST, PORT)
    read_until(f,"21 bytes, starting with ")
    prefix = f.read(16)
    chall = findproof(prefix)
    f.write(chall)
    length = struct.pack("H",len(msg))
    f.write(length)
    f.write(msg)
    read_until(f,"HERE IS YOUR STRING ")
    c = f.read()
    return eval(c)


def get_list_ci(li_msg,pos):
    list_ci = []
    msg = []
    li_msg_copy = copy.copy(li_msg)
    for x in xrange(256):
        li_msg_copy[pos] = x
        msg.extend("".join(map(chr,li_msg_copy)))
    ci = get_ciphertext("".join(msg))
    for x in range(256):
        list_ci.append(ci[x*8:x*8+8])
    return list_ci

def get_list_ci_by_c21(li_c21,pos,k1):
    list_ci = []
    msg = []
    li_c13=copy.copy(li_c21)
    for x in xrange(256):
        li_c13[pos] = x
        li_c12 = map(ord,subme.unPermute("".join(map(chr,li_c13))))
        li_c11 = subme.unSubStr(li_c12)
        li_m = []
        for i in xrange(len(k1)):
            li_m.append(li_c11[i]^k1[i])
        msg.extend("".join(map(chr,li_m)))            
    ci = get_ciphertext("".join(msg))
    for x in range(256):
        list_ci.append(ci[x*8:x*8+8])
    return list_ci


def inv_bit_order(i):
    """
    数字で扱うとbitを右からカウントする対応
    """
    a, b = divmod(i, 8)
    return a * 8 + (7 - b)

def get_diff_c12():
    """
    最下位1ビットが違うc12ペアでの出力差分リスト
    """
    out_bits_list = []
    for sbox2 in xrange(8): # c12 that has difference at LSB
        out_bits = []
        for bits in xrange(8):
            x = subme.lper[sbox2*8+bits]
            out_bits.append(inv_bit_order(x))
        out_bits_list.append(out_bits)
    return out_bits_list

def get_diff_c22():
    """
    最下位1ビットが違うc22ペアでの出力差分リスト
    """
    out_bits_list = []
    for sbox2 in xrange(8): # c22 that has difference at LSB
        x = subme.lper[sbox2*8]
        out_bits_list.append(inv_bit_order(x))
    return out_bits_list

def make_diff(c1, c2):
    return map(lambda (a, b): DIFFER if a != b else EQUAL, zip(c1, c2))

def check_diff(out_bits, diff):
    carry = True
    for i in xrange(len(diff)-1, -1, -1):
        if i in out_bits:
            carry = True
            continue

        if diff[i] == EQUAL:
            carry = False
            continue
        elif diff[i] == DIFFER:
            if not carry:
                return False
            else:
                # continue line
                continue
        else:
            print "WTF!!"
            quit()
    return True

def check_diff2(out_bit, diff):
    carry = True
    for i in xrange(len(diff)-1, -1, -1):
        if i == out_bit:
            carry = True
            continue

        if diff[i] == EQUAL:
            carry = False
            continue
        elif diff[i] == DIFFER:
            if not carry:
                return False
            else:
                # continue line
                continue
        else:
            print "WTF!!"
            quit()
    return True

def check_key_byte(pos,k):
    round = 5 #チェック回数
    flag = 0
    for i in xrange(round):
        out_bits_list = get_diff_c12()
        c12a=os.urandom(8)
        li_c12a=array.array("B",c12a)
        li_c12b=copy.copy(li_c12a)
        li_c12b[pos] = li_c12b[pos]^1
        li_ma = subme.unSubStr(li_c12a)
        li_mb = subme.unSubStr(li_c12b)
        list_ci = get_list_ci(li_ma,pos)

        li_ma[pos] = li_ma[pos]^k
        li_mb[pos] = li_mb[pos]^k
        ca = list_ci[li_ma[pos]]
        cb = list_ci[li_mb[pos]]
        bin_ca = s2b(ca[::-1])
        bin_cb = s2b(cb[::-1])
    
        diff = make_diff(bin_ca, bin_cb)

        sbox2 = inv_bit_order(subme.lper[inv_bit_order(pos*8+7)])/8
        if check_diff(out_bits_list[sbox2], diff) == True:
            flag = flag + 1

        li_ma[pos] = li_ma[pos]^k
        li_mb[pos] = li_mb[pos]^k
        li_c12b[pos] = li_c12b[pos]^2

    if flag == round:
        return True
    return False

def check_key_byte2(pos,k1,k2):
    round = 5 #チェック回数
    flag = 0
    out_bits_list = get_diff_c22()
    c22a=os.urandom(8)
    li_c22a=array.array("B",c22a)
    li_c22b=copy.copy(li_c22a)

    for i in xrange(round):
        li_c22b[pos] = li_c22b[pos]^1
        li_c21a = subme.unSubStr(li_c22a)
        li_c21b = subme.unSubStr(li_c22b)
        li_c21a[pos] = li_c21a[pos]^k2
        li_c21b[pos] = li_c21b[pos]^k2
        list_ci = get_list_ci_by_c21(li_c21a,pos,k1)

        ca = list_ci[li_c21a[pos]]
        cb = list_ci[li_c21b[pos]]
        bin_ca = s2b(ca[::-1])
        bin_cb = s2b(cb[::-1])
        diff = make_diff(bin_ca, bin_cb)

        sbox2 = pos
        if check_diff2(out_bits_list[sbox2], diff) == True:
            flag = flag + 1
    li_c22b[pos] = li_c22b[pos]^1

    if flag == round:
        return True
    return False

def recover_k1():
    k1 = []
    out_bits_list = get_diff_c12()
    c12a=os.urandom(8)
    li_c12a=array.array("B",c12a)
    li_c12b=copy.copy(li_c12a)

    for pos in xrange(8):
        li_c12b[pos] = li_c12b[pos]^1
        li_ma = subme.unSubStr(li_c12a)
        li_mb = subme.unSubStr(li_c12b)
        list_ci = get_list_ci(li_ma,pos)

        for k in xrange(256):
            li_ma[pos] = li_ma[pos]^k
            li_mb[pos] = li_mb[pos]^k
            ca = list_ci[li_ma[pos]]
            cb = list_ci[li_mb[pos]]
            bin_ca = s2b(ca[::-1])
            bin_cb = s2b(cb[::-1])
    
            diff = make_diff(bin_ca, bin_cb)

            sbox2 = inv_bit_order(subme.lper[inv_bit_order(pos*8+7)])/8
            if check_diff(out_bits_list[sbox2], diff) == True:
                if check_key_byte(pos,k) == True:
                    print "k[%d]=%d" % (pos,k)
                    k1.append(k)
                    break

            li_ma[pos] = li_ma[pos]^k
            li_mb[pos] = li_mb[pos]^k
        li_c12b[pos] = li_c12b[pos]^1
    return k1

def recover_k2(k1):
    k2 = []
    out_bits_list = get_diff_c22()
    c22a=os.urandom(8)
    li_c22a=array.array("B",c22a)
    li_c22b=copy.copy(li_c22a)

    for pos in xrange(8):
        li_c22b[pos] = li_c22b[pos]^1
        li_c21a = subme.unSubStr(li_c22a)
        li_c21b = subme.unSubStr(li_c22b)
        list_ci = get_list_ci_by_c21(li_c21a,pos,k1)

        for k in xrange(256):
            li_c21a[pos] = li_c21a[pos]^k
            li_c21b[pos] = li_c21b[pos]^k
            ca = list_ci[li_c21a[pos]]
            cb = list_ci[li_c21b[pos]]
            bin_ca = s2b(ca[::-1])
            bin_cb = s2b(cb[::-1])
    
            diff = make_diff(bin_ca, bin_cb)

            sbox2 = pos
            if check_diff2(out_bits_list[sbox2], diff) == True:
                if check_key_byte2(pos,k1,k) == True:
                    print "k[%d]=%d" % (pos+8,k)
                    k2.append(k)
                    break

            li_c21a[pos] = li_c21a[pos]^k
            li_c21b[pos] = li_c21b[pos]^k

        li_c22b[pos] = li_c22b[pos]^1
    return k2

def recover_k3(k1,k2):
    ma = "aaaaaaaa"
    ca = get_ciphertext(ma)

    toEnc= array.array("B",ma)
    for el in xrange(len(k1)):
        toEnc[el]=toEnc[el]^k1[el]

    toEnc=subme.subStr(toEnc)
    toEnc=map(ord,subme.permute("".join(map(chr,toEnc))))

    for el in xrange(len(k2)):
        toEnc[el]=toEnc[el]^k2[el]
    toEnc=subme.subStr(toEnc)
    toEnc=map(ord,subme.permute("".join(map(chr,toEnc))))

    ints=0
    toEnc.reverse()
    for el in xrange(len(toEnc)):
        ints+=((toEnc[el])<<(8*el))
    ints=ints%18446744073709551615

    ca=struct.unpack("Q",ca)
    k3 = ca[0] -ints
    k3 = k3%18446744073709551615
    k3_list = []
    while k3>0:
        k3_list.append(int(k3&0xff))
        k3=k3>>8
    k3_list.reverse()
    return k3_list

k1 = recover_k1()
k2 = recover_k2(k1)
k3 = recover_k3(k1,k2)
key = k1+k2+k3
print `"".join(map(chr,key))`
