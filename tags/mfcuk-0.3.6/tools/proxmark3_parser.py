#!/usr/bin/python

# Original source: proxmark3.org community forum

import sys
import os
import string

try:
	file= open(sys.argv[1])
except:
	print 
	print '\tusage: mifarecrack.py <proxmark3 logfile>'
	print
	sys.exit(True)

lines= file.readlines()
uid= ''

gotone= False
for i in range(len(lines)):
	if not uid and string.find(lines[i],':     93  20') > 0:
		uid= lines[i + 1][20:34]
		print
		print 'Found TAG UID:', uid
	if string.find(lines[i],':     60') > 0 or string.find(lines[i],':     61') > 0:
		gotone= True
		tag_challenge= lines[i+1]
		reader_challenge_response= lines[i+2]
		tag_response= lines[i+3]
		break
if not gotone:
	print 'No crypto exchange found!'
	sys.exit(True)	

crackstring= './mifarecrack '+ uid

# now process challenge/response
crackstring += ' ' + tag_challenge[20:34]
crackstring += ' ' + reader_challenge_response[20:50]
crackstring += ' ' + tag_response[20:34]
print 'Executing ', crackstring
os.execv('./mifarecrack',string.split(crackstring))
