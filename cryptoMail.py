#!/usr/bin/env python3

# (c) 2020 HvA yasin.tas@hva.nl
# Leerlingnummer 500816623
__version__ = '1.1 2021-01-19'

import os, sys
import getopt
import textwrap 
import base64
import json
import random
import traceback

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.backends import default_backend

import pprint

class HvaCryptoMsg:
    """ Class om messages te encrypten/decrypten en ondertekenen/verifiveren
    """
    # The prelude and postlude of an Cryto-Message
    _mark = '--- HvA Crypto Message ---\n'
    def __init__(self, mode: list=[]) -> None:
        """ Initilalise the used variables """
        self.version = '1.0'    # Version number
        self.names   = {}       # names of sender and receiver ('snd', 'rcv')
        self.mode    = mode     # Specifies the used algoritms
        self.sesIv   = None     # (optional) supplied Iv
        self.encKey  = None     # (optional) protected session key (contains session key)
        self.sesKey  = None     # (optional) session key                 # Never exported directly
        self.cPrvKey = None     # (optional) private key Encrypt/Decrypt # Never exported directly
        self.sPrvKey = None     # (optional) private key Sign/verify     # Never exported directly
        self.cPubKey = None     # (optional) public key  Encrypt/Decrypty
        self.sPubKey = None     # (optional) public key  Sign/verify
        self.code    = None     # (optional) the encrypted message
        self.mesg    = None     # (optional) the messages
        self.signed  = None     # (optional) the signature of the message
        self.hashed  = None     # (optional) the hash of the message


    def addMode(self, mode: str) -> None:
        """ Add the use mode to the mode-list
            Only one type crypted and Only one type of signed """
        if mode not in [ 'crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256', 'signed:rsa-pss-mgf1-sha256' ]:
            # crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256
            #   Message padded with pkcs7
            #   Message Encrypted with AES-128 met CBC
            #   Key protected with RSA with OAEP, MGF1 and SHA256
            # signed:rsa-pss-mgf1-sha256
            #   Message Signed with with RSA with PSS, MGF1 and SHA256
            # Andere modes hoeven niet geimplementeerd te worden.
            Exception('Unexptected mode:{}'.format(mode))
        self.mode.append(mode)


    def hasMode(self, mode: str) -> bool:
        """ Check whether a mode is supported this HvaCryptoMessage """
        for _mode in self.mode:
            if _mode.startswith(mode): return True
        return False


    def getName(self, typ: str) -> str:
        """ get the ame of the key,
            so we know which key to be loaded """
        assert typ in [ 'snd', 'rcv' ], f'Unknow typ={typ}'

        return self.names.get(typ, '')


    def setName(self, name: str, typ: str) -> None:
        """ set the name of the key
            so the receiving party knows which key to load """
        assert typ in [ 'snd', 'rcv' ], f'Unknow typ={typ}'
        self.names[typ] = name


    def setPubKey(self, key: object) -> None:
        """ add the key to the HvACryptoMessage
            the receiving party can use this pubic key """
        self.sPubKey = key


    def loadPrvKey(self, name: str='', fname: str='') -> object:
        """ Load a Private key for user `name` from file `fname` """
        print(f"DEBUG:FHS name={name}, fname={fname}")
        if not fname: fname = name +'.prv'

        if gDbg: print('DEBUG:loadPrvKey', fname)
        # Load the prv-key from file `fname` and return it
# Student work {{
        with open(fname, "rb") as key_file:
            prvKey = serialization.load_pem_private_key(key_file.read(), password=None)
# Student work }}
        return prvKey


    def loadPubKey(self, name: str='', fname: str='') -> object:
        """ Load a public key for user `name` from file `fname` """
        if not fname: fname = name +'.pub'
        
        if gDbg: print('DEBUG:setPubKey', fname)
        # Load the pub-key from file `fname` and return it
# Student work {{
        with open(fname, "rb") as key_file:
            pubKey = serialization.load_pem_public_key(key_file.read())
# Student work }}
        return pubKey


    def genSesKey(self, n: int=32) -> None:
        """ Generate a (secure) session key for symmetric encryption. """
        # set self.sesKey with an usable key
# Student work {{
        self.sesKey  = os.urandom(n)
# Student work }}
        return


    def genSesIv(self, n: int=16) -> None:
        """ Generate a (secure) intial-vector key for symmetric encryption. """
        # set self.sesIv with an usable intial vector
# Student work {{
        self.sesIv = os.urandom(n)
# Student work }}
        return


    def encryptSesKey(self, key: object) -> None:
        """ Encrypt the session-key """
        # Implememt encryption using RSA with OAEP, MGF1 and SHA256
        assert 'crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256' in self.mode, \
                f'Unknown mode={self.mode}'
        # set self.encKey with the encrypted session key
# Student work {{
        self.encKey = key.encrypt(self.sesKey, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
# Student work }}
        return


    def decryptSesKey(self, key: object) -> None:
        """ Decrypt the session-key """
        # Implememt decryption using RSA with OAEP, MGF1 and SHA256
        # set self.sesKey extracted from the encrypted session key
# Student work {{
        self.sesKey = key.decrypt(self.encKey, asympadding.OAEP(mgf=asympadding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
# Student work }}
        return


    def encrypt(self, plainBytes: bytes) -> None:
        """ Encrypt the message """
        # set.code with encrypted plain-text (bytes)
# Student work {{
        padding = sympadding.PKCS7(128).padder()
        paddingk = padding.update(plainBytes) + padding.finalize()
       
        encryptie = ciphers.Cipher(algorithms.AES(self.sesKey),modes.CBC(self.sesIv),backend=default_backend())
        encryptor = encryptie.encryptor()
        self.code = encryptor.update(paddingk) + encryptor.finalize()
        
# Student work }}
        return


    def decrypt(self) -> bytes:
        """ Decrypt the message """
        assert 'crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256' in self.mode, \
                f'Unknown mode={self.mode}'

        # decrypt self.code into plain-text (bytes)
# Student work {{
        decryption = ciphers.Cipher(algorithms.AES(self.sesKey),modes.CBC(self.sesIv),backend=default_backend())
        decryptor = decryption.decryptor()
        decoded = decryptor.update(self.code) + decryptor.finalize()
        unpadding = sympadding.PKCS7(128).unpadder()
        plainBytes = unpadding.update(decoded) + unpadding.finalize()
# Student work }}
        return plainBytes


    def sign(self, plainBytes: bytes, key: object) -> None:
        """ Sign the message """
        # Implememt decryption using RSA with PSS, MGF1 and SHA256
        assert 'signed:rsa:pss-mgf1:sha256' in self.mode, \
                f'Unknown mode={self.mode}'
# Student work {{
        self.signed = key.sign(plainBytes, asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()),salt_length=asympadding.PSS.MAX_LENGTH),hashes.SHA256())
# Student work }}
        return

    def verify(self, plainBytes: bytes, key: object) -> bytes:
        """ Verify the message Return
            None is signature is incorrect, return plainBytes if correct """
        # Implememt decryption using RSA with PSS, MGF1 and SHA256
        assert 'signed:rsa:pss-mgf1:sha256' in self.mode, \
                f'Unknown mode={self.mode}'
# Student work {{
        plainBytes = key.verify(self.sign, plainBytes, asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()),salt_length=asympadding.PSS.MAX_LENGTH),hashes.SHA256())
# Student work }}
        return plainBytes


    def getMesg(self) -> str:
        """ Import internal state from a garded 'Hva Crypto Message' """
        jdct = {}
        if self.version: jdct['version'] = self.version
        if self.mode:    jdct['mode'] = list(self.mode)
        if self.names:   jdct['names'] = self.names
        if self.sesIv:   jdct['sesIv'] = self.sesIv.hex()
        if self.encKey:  jdct['encKey'] = self.encKey.hex()
        if self.sPubKey: jdct['sPubKey'] = str(
                                    self.sPubKey.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo),
                                    encoding='ascii')
        if self.mesg:    jdct['mesg'] = self.mesg.hex()
        if self.code:    jdct['code'] = self.code.hex()
        if self.signed:  jdct['sign'] = self.signed.hex()
        if self.hashed:  jdct['hash'] = self.hashed.hex()

        if gVbs: pprint.pprint(jdct)
        payload = base64.b64encode(bytes(json.dumps(jdct), encoding='utf-8'))
        s = self._mark + \
               '\n'.join(textwrap.wrap(str(payload, encoding='ascii'))) + '\n' + \
               self._mark
        return s


    def setMesg(self, msg: str) -> None:
        """ Export internal state to a garded 'Hva Crypto Message' """
        if not (msg.startswith(self._mark) and msg.endswith(self._mark)):
            raise Exception('Invalid HvA Cryto Mesg')

        payload = msg[len(self._mark):-len(self._mark)]
        jdct = json.loads(base64.b64decode(payload))
        if gVbs: pprint.pprint(jdct)

        self.version = jdct.get('version')
        self.mode    = set(jdct.get('mode'))
        self.names   = jdct.get('names', {})
        self.sesIv   = bytes.fromhex(jdct.get('sesIv', ''))
        self.encKey  = bytes.fromhex(jdct.get('encKey', ''))
        sPubKey       = bytes(jdct.get('sPubKey', ''), encoding='ascii')
        self.sPubKey  = serialization.load_pem_public_key(sPubKey) if sPubKey else None
        self.mesg    = bytes.fromhex(jdct.get('mesg', ''))
        self.code    = bytes.fromhex(jdct.get('code', ''))
        self.signed  = bytes.fromhex(jdct.get('sign', ''))
        self.hashed  = bytes.fromhex(jdct.get('hash', ''))
        return

# end of class HvaCryptoMsg

def encode(mesg: bytes, fname: str, cKeyName: str, sKeyName: str) -> None:
    """ Encode (encrypt and/or sign) based on the given keys """
    cm = HvaCryptoMsg()
    if cKeyName:
        # Choose one of the next lines to add a mode, this line can be removed
        # cm.addMode('signed:rsa:pss-mgf1:sha256')
        cm.addMode('crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256')
        # The modes are set in the message-structure
        # Decode will use those mode to see how to decrypt / verify
# Student work {{
        key = cm.loadPubKey(sKeyName)
        pubKey = cm.setPubKey(key)
        iv = cm.genSesIv()
        sesKey = cm.genSesKey()
        encSesKey = cm.encryptSesKey(key) 
        name = cm.setName(cKeyName,'rcv')
        code = cm.encrypt(mesg)

        # hashed = hashes.Hash(hashes.SHA256())
        # hashed.update(mesg)
        # hashed = hashed.finalize() 
# Student work }}
    if sKeyName:
        # Choose one of the next lines to add a mode, this line can be removed
        cm.addMode('signed:rsa:pss-mgf1:sha256')
        # cm.addMode('crypted:aes-cbc:pkcs7:rsa-oaep-mgf1-sha256')
# Student work {{
        prv = cm.loadPrvKey(sKeyName)
        name = cm.setName(sKeyName,'snd')
        sign = cm.sign(mesg,prv)
# Student work }}
    cmesg = cm.getMesg()
    fp = open(fname, 'w') # if fname else sys.stdout
    fp.write(cmesg)
    return


def decode(fname: str, cKeyName: str='', sKeyName: str='') -> bytes:
    """ Encode (encrypt and/or sign) based on the content of cmesg keys """
    plainBytes = b''
    cryptName = ''
    signName = ''
    cm = HvaCryptoMsg()
    fp = open(fname, 'r') # if fname else sys.stdin
    cmesg = fp.read()
    cm.setMesg(cmesg)
    if cm.hasMode('crypted'):
        if gVbs: print('Verbose: crypted')
# Student work {{
        cryptName = cm.getName('rcv')
        cKeyName = cm.loadPrvKey(cryptName)
        cm.decryptSesKey(cKeyName)
        plainBytes = cm.decrypt()
        cryptName = cm.getName('snd')      
# Student work }}
    if cm.hasMode('signed'):
        if gVbs: print('Verbose: signed')
# Student work {{
    signName = cm.getName('rcv')
# Student work }}
    # Return text, cryptName and signName
    return plainBytes, cryptName, signName



gVbs = False
gDbg = False
gSil = False
if __name__ == '__main__':
    mesg = ''
    fname = iFname = oFname = ''
    cKeyName = ''
    sKeyName = ''
    fname = 'mesg1.mbx'
    opts, args = getopt.getopt(sys.argv[1:], 'hVDSf:m:c:s:i:o:', [ 'encode', 'decode' ])
    for opt, arg in opts:
        if opt == '-h':
            print(f'Usage: {sys.argv[0]} -[HVDS] [ -f <msgFname> ] [-c <cryptKeyFile>] [-s <signKeyFile>]')
            print(f'\t\t[-i <infile> | -m <mesg>] [-o <outfile>] encode|decode')
        if opt == '-V': gVbs = True
        if opt == '-D': gDbg = True
        if opt == '-S': gSil = True
        if opt == '-m': mesg = arg
        if opt == '-f': fname = arg
        if opt == '-c': cKeyName = arg
        if opt == '-s': sKeyName = arg
        if opt == '-i': iFname = arg
        if opt == '-o': oFname = arg

    if fname == '':
        print('Error: no <fname>.mbx')
        sys.exit(2)

    if iFname:
        mesg = open(iFname, 'r', encoding='utf-8').read()

    if 'encode' in args and (cKeyName == '' and sKeyName == ''):
        print('Error: -e <id> or -s <id> expected.')
        sys.exit(2)

    res = True
    if 'encode' in args:
        try:
            mesgBytes = bytes(mesg, encoding='UTF-8')
            encode(mesgBytes, fname, cKeyName, sKeyName)

        except Exception as e:
            res = False
            if not gSil:
                print('Exception e={}'.format(e))
                traceback.print_exc(limit=None, file=None, chain=True)

    if 'decode' in args:
        try:
            decodedBytes, cryptName, signName  = decode(fname, cKeyName, sKeyName)
            if decodedBytes is None:
                res = False
                print('Decoding failed.')

            if decodedBytes:
                decoded = str(decodedBytes, encoding='UTF-8')
                if oFname:
                    open(oFname, 'w', encoding='utf-8').write(decoded)
                else:
                    print('Decoded:      ', decoded)
                    if signName:  print('Signed by:    ', signName)
                    if cryptName: print('Encrypted for:', cryptName)

        except Exception as e:
            if not gSil:
                print('Exception e={}'.format(e))
                traceback.print_exc(limit=None, file=None, chain=True)

    sys.exit(0 if res else 1)
