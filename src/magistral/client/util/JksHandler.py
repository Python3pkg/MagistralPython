'''
Created on 16 Sep 2016
@author: rizarse
'''

import jks, textwrap, base64
from os.path import expanduser
import os.path
import atexit
import shutil

from os import makedirs

class JksHandler(object):

    def __init__(self, params):
        pass
    
    @staticmethod
    def writePkAndCerts(ks, token):
        
        uid = None
        
        home = expanduser("~")
        
        def deleteCerts(self, path):
            shutil.rmtree(path)
        
        atexit.register(deleteCerts, home + '/magistral/' + token)
        
        for alias, pk in list(ks.private_keys.items()): 
            
            uid = alias
            
            if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
                
                if os.path.exists(home + '/magistral/' + token) == False:
                    makedirs(home + '/magistral/' + token)
                
                key = home + '/magistral/' + token + '/key.pem'
                
                if os.path.exists(key): os.remove(key) 
                                
                with open(key, 'wb') as f:
                    f.seek(0)
                    f.write(bytearray(b"-----BEGIN RSA PRIVATE KEY-----\r\n"))
                    f.write(bytes("\r\n".join(textwrap.wrap(base64.b64encode(pk.pkey).decode('ascii'), 64)), 'utf-8'))
                    f.write(bytearray(b"\r\n-----END RSA PRIVATE KEY-----"))                    
                    f.close()   
             
            counter = 0;
            
            cert = home + '/magistral/' + token + '/certificate.pem'
            if os.path.exists(cert): os.remove(cert)
            
            with open(cert, 'wb') as f:
                f.seek(0)
                   
                for c in pk.cert_chain:               
                    f.write(bytearray(b"-----BEGIN CERTIFICATE-----\r\n"))
                    f.write(bytes("\r\n".join(textwrap.wrap(base64.b64encode(c[1]).decode('ascii'), 64)), 'utf-8'))
                    f.write(bytearray(b"\r\n-----END CERTIFICATE-----\r\n"))   
                    counter = counter + 1
                    if (counter == 2): break                 
                
                f.close()
            
            ca = home + '/magistral/' + token + '/ca.pem'
            if os.path.exists(ca): os.remove(ca)
            
            with open(ca, 'wb') as f:         
                for alias, c in list(ks.certs.items()):    
                    f.write(bytearray(b"-----BEGIN CERTIFICATE-----\r\n"))
                    f.write(bytes("\r\n".join(textwrap.wrap(base64.b64encode(c.cert).decode('ascii'), 64)), 'utf-8'))
                    f.write(bytearray(b"\r\n-----END CERTIFICATE-----\r\n"))                    
                    
                f.close()
            
        return uid
                 
    
    @staticmethod
    def printJks(ks):
        
        def print_pem(der_bytes, _type_):
            print(("-----BEGIN %s-----" % _type_))
            print(("\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))))
            print(("-----END %s-----" % _type_))

        for _, pk in list(ks.private_keys.items()):
            print(("Private key: %s" % pk.alias))
            if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
                print_pem(pk.pkey, "RSA PRIVATE KEY")
            else:
                print_pem(pk.pkey_pkcs8, "PRIVATE KEY")
        
            for c in pk.cert_chain:
                print_pem(c[1], "CERTIFICATE")
            print()
        
        for _, c in list(ks.certs.items()):
            print(("Certificate: %s" % c.alias))
            print_pem(c.cert, "CERTIFICATE")
            print()
        
        for _, sk in list(ks.secret_keys.items()):
            print(("Secret key: %s" % sk.alias))
            print(("  Algorithm: %s" % sk.algorithm))
            print(("  Key size: %d bits" % sk.key_size))
            print(("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key))))
            print()    
