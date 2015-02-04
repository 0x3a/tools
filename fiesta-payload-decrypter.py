#!/usr/bin/python

"""
    Created by Yonathan Klijnsma
    - http://blog.0x3a.com/
    - http://twitter.com/ydklijnsma

    Code comes from an article I've written about the Fiesta exploit kit.
    This Python script is able to decrypt the payloads retrieved from the
    Fiesta exploit kit after successful exploitation of some kind.
    Shellcode based and non shellcode based payloads are supported.

    This script was tested against payloads dropped in January 2015.
    If it stops working please file a bug report at the Github repo!

    Github repository URL: https://github.com/0x3a/tools/
"""

import sys

def ShellcodeDecrypt(data):
    return NonShellcodeDecrypt(data[16:])[25:-1]

def NonShellcodeDecrypt(data):
    key_offset = 256
    ldata = list(data[key_offset:])
    lkey = list(data[:key_offset])

    c_index_s1 = 0
    c_index_s2 = 0
    decrypted_data = ''

    for i in xrange(0, len(ldata)):
        c_index_s1 = c_index_s1 + 1 & 0xFF;
        c_index_s2 = c_index_s2 + ord(lkey[c_index_s1]) & 0xFF;
        j = lkey[c_index_s1];
        lkey[c_index_s1] = lkey[c_index_s2];
        lkey[c_index_s2] = j;
        k = ord(lkey[c_index_s1]) + ord(lkey[c_index_s2]) & 0xFF;
        decrypted_data += chr(ord(ldata[i]) ^ ord(lkey[k]));

    return decrypted_data

def DecryptFiestaPyload(inputfile, outputfile):
    fdata = open(inputfile, "rb").read()
    print '[+] Encrypted file size %d' % len(fdata)

    decrypted_fdata = NonShellcodeDecrypt(fdata)

    if decrypted_fdata[:2] != 'MZ':
        decrypted_fdata = ShellcodeDecrypt(fdata)

        if decrypted_fdata[:2] != 'MZ':
            print '[!] Unable to decrypt data!'
            return
        else:
            print '[+] Payload was used by a shellcode based exploit, decrypted successfully!'
    else:
        print '[+] Payload was used for a non-shellcode based exploit, decrypted successfully!'

    print '[+] Decrypted file size %d' % len(decrypted_fdata)

    open(outputfile, "wb").write(decrypted_fdata)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print '%s <input filename> <output filename>' % sys.argv[0]
    else:
        sys.exit(DecryptFiestaPyload(sys.argv[1], sys.argv[2]))