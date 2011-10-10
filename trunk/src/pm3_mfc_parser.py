#!/usr/bin/python

# Original source: proxmark3.org community forum

import sys
import os
import string
import commands

def line_tag(line):
    if string.find(line, 'TAG') > 0:
        return True
    
    return False

def line_rdr(line):
    if string.find(line, 'TAG') < 1:
        return True
    
    return False

def line_bytes(line):
    bytes = line[20:len(line)-1]
    bytes = bytes.replace('crc', '')
    bytes = bytes.replace('!', '')
    bytes = bytes.replace(' ', '')
    
    return len(bytes)/2

try:
    file= open(sys.argv[1])
except:
    print
    print '\tusage:', sys.argv[0], '<proxmark3_snoop.log>'
    print
    sys.exit(True)

lines = file.readlines()
uid = ''
find_multi_sector = False

for i in range(len(lines)):
    if string.find(lines[i],':     93  20') > 0 and line_tag(lines[i + 1]) and line_bytes(lines[i + 1]) == 5:
        find_multi_sector = False
        key = ''        
        
        uid = lines[i + 1][20:34]
        uid = uid.replace(' ', '')
        print 'Found TAG UID:', uid
        
    if uid and (string.find(lines[i],':     60') > 0 or string.find(lines[i],':     61') > 0) and line_tag(lines[i + 1]) and line_bytes(lines[i + 1]) == 4 and line_rdr(lines[i + 2]) and line_bytes(lines[i + 2]) == 8 and line_tag(lines[i + 3]) and line_bytes(lines[i + 3]) == 4:
        tag_challenge = lines[i+1][20:34]
        tag_challenge = tag_challenge.replace(' ', '')
        tag_challenge = tag_challenge.replace('!', '')
        print 'Nt:', tag_challenge

        reader_challenge_response = lines[i+2][20:50]
        reader_challenge_response = reader_challenge_response.replace(' ', '')
        reader_challenge_response = reader_challenge_response.replace('!', '')
        print 'Nt\':', reader_challenge_response

        tag_response = lines[i+3][20:34]
        tag_response = tag_response.replace(' ', '')
        tag_response = tag_response.replace('!', '')
        print 'Nr:', tag_response

        find_multi_sector = True
    
    # Usually, a multi-sector authentication if a sequence of R->T 4 bytes (encrypted 60 xx p1 p2 or 61 xx p1 p2) and T->R 4 bytes
    if find_multi_sector and line_rdr(lines[i]) and line_bytes(lines[i]) == 4 and string.find(lines[i],':     60') < 1 and string.find(lines[i],':     61') < 1 and line_tag(lines[i + 1]) and line_bytes(lines[i + 1]) == 4:
        encr_multi_sect_auth = lines[i][20:34]
        encr_multi_sect_auth = encr_multi_sect_auth.replace(' ', '')
        encr_multi_sect_auth = encr_multi_sect_auth.replace('!', '')
        #print 'Multi-sector AUTH (candidates):', encr_multi_sect_auth
        
        encr_multi_sect_Nt = lines[i + 1][20:34]
        encr_multi_sect_Nt = encr_multi_sect_Nt.replace(' ', '')
        encr_multi_sect_Nt = encr_multi_sect_Nt.replace('!', '')
        #print 'Multi-sector encrypted Nt (candidates):', encr_multi_sect_Nt
        
        mfcuk_P_params = './mfcuk -P ' + '0x' + uid + ':' + '0x' + tag_challenge + ':' + '0x' + reader_challenge_response[0:8] + ':' + '0x' + reader_challenge_response[8:16] + ':' + '0x' + tag_response + ':' + '0x' + encr_multi_sect_auth

        print 'Executing ', mfcuk_P_params
        #os.execv('./mfcuk',string.split(mfcuk_P_params))
