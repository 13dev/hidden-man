#!/usr/bin/python
import sys, os, ipgetter, requests, subprocess, socket
from os.path import expanduser
from time import sleep
import random, argparse, threading, commands
from subprocess import Popen, PIPE

class Color():
	RESET = "\033[0m"
	BOLD = "\033[1m"
	UNDERLINE = "\033[4m"
	REVERSE = "\033[7m"
	BLACK = "\033[30m"
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	MAGENTA = "\033[35m"
	CYAN = "\033[36m"
	WHITE = "\033[37m"
	ON_BLACK = "\033[40m"
	ON_RED = "\033[41m"
	ON_GREEN = "\033[42m"
	ON_YELLOW = "\033[43m"
	ON_BLUE = "\033[44m"
	ON_MAGENTA = "\033[45m"
	ON_CYAN = "\033[46m"
	ON_WHITE = "\033[47m"

	def out(self, message, *args):
		style = ""
		for s in args:
			style += s
		return style+message+self.RESET

if not os.geteuid() == 0:
    print "You must be root to run this script.\n"
    sys.exit(1)

c = Color()
logFile = "hiddenman.log"
version = "v1.3"

def get_resolvers():
	resolvers = []
	try:
		with open( '/etc/resolv.conf', 'r' ) as resolvconf:
			for line in resolvconf.readlines():
				line = line.split( '#', 1 )[ 0 ];
				line = line.rstrip();
				if 'nameserver' in line:
					resolvers.append( line.split()[ 1 ] )
		return resolvers
	except IOError as error:
		return error.strerror

def ipInfo():
	sleep(2)
	IP 	= ipgetter.myip()
	url = 'http://freegeoip.net/json/' + IP
	r 	= requests.get(url)
	js 	= r.json()
	resolvers = get_resolvers()

	if(js):
		print c.out('%s[+] %sGetting information...'%(c.YELLOW, c.RESET))
		sleep(8)
		print ""
		if(js['ip']):			print c.out('%s[*] %sIP Adress: 		%s'%(c.GREEN, c.RESET, js['ip']))
		if(js['country_code']):	print c.out('%s[*] %sCountry Code: 	%s'%(c.GREEN, c.RESET, js['country_code']))
		if(js['country_name']):	print c.out('%s[*] %sCountry Name: 	%s'%(c.GREEN, c.RESET, js['country_name']))
		if(js['region_code']):	print c.out('%s[*] %sRegion Code: 	%s'%(c.GREEN, c.RESET, js['region_code']))
		if(js['region_name']):	print c.out('%s[*] %sRegion Name: 	%s'%(c.GREEN, c.RESET, js['region_name']))
		if(js['city']):			print c.out('%s[*] %sCity Name: 		%s'%(c.GREEN, c.RESET, js['city']))
		if(js['zip_code']):		print c.out('%s[*] %sZip code: 		%s'%(c.GREEN, c.RESET, js['zip_code']))
		if(js['time_zone']):	print c.out('%s[*] %sTime Zone: 		%s'%(c.GREEN, c.RESET, js['time_zone']))
		if(js['latitude']):		print c.out('%s[*] %sLatitude: 		%s'%(c.BLUE, c.RESET, str(js['latitude'])))
		if(js['longitude']):	print c.out('%s[*] %sLongitude: 		%s'%(c.BLUE, c.RESET, str(js['longitude'])))

	if(resolvers):
		print ""
		print c.out('%s[*] %sGetting resolvers...'%(c.YELLOW, c.RESET))
		sleep(2)
		for key, resolv in enumerate(resolvers):
			print c.out('%s	[%s]%s %s' %(c.BLUE, str(key + 1), c.RESET, resolv))

			#192.168.1.1
			if(resolv == '192.168.1.1'):
				print c.out('%s[%s]	%sWARNING: You have default dns-nameserver!' %(c.RED, str(key + 1), c.ON_YELLOW))
				print c.out('%s[%s]	%sAdd: dns-nameserver 8.8.8.8, 8.8.4.4 to /etc/network/interfaces' %(c.RED, str(key + 1), c.ON_YELLOW))

def is_connected():
	print c.out('%s[*]%s Checking your Internet connection...' %(c.YELLOW, c.RESET))
	sleep(2)
	try:
		host = socket.gethostbyname("www.google.com")
		
		s = socket.create_connection((host, 80), timeout=10)
		print c.out('%s[+]%s Connection established successfully!' %(c.GREEN, c.RESET))
		return True
	except:
		pass
	print c.out('%s[-]%s Please check your Internet connection!' %(c.RED, c.RESET + c.ON_YELLOW))
	return False

def stopAll():
	os.system("killall openvpn 2> /dev/null")
	os.system("ps -uax | grep log- | awk '{print $2}' | xargs kill -9 2> /dev/null")
	os.system("ps -aux | grep openvpn | awk '{print $2}' | xargs kill -9 2> /dev/null")
	os.system("ifconfig $(ifconfig | egrep -io 'tun\w') down 2> /dev/null")
	
	#restart interface
	sleep(1)
	eth = Popen("route | grep '^default' | grep -o '[^ ]*$'", shell=True, stdout=PIPE).communicate()[0].strip()
	os.system("ifconfig " + eth + " down")
	os.system("ifconfig " + eth + " up")

def checkProccess():
	(_, outputPidof) = commands.getstatusoutput("pidof -x openvpn")
	if(outputPidof.strip()):
		print c.out("%s[-]%s The process 'openvpn' is already running!, try: %s--forcestop" %(c.RED, c.RESET, c.RED))
		sys.exit()

def downloadVPN(url, file):
	sleep(1)
	if(not os.path.isfile(expanduser("~") + "/openvpn/" + file)):
		print c.out("%s[+] %sDownloading required files." %(c.GREEN , c.RESET + c.ON_CYAN))
		sleep(1.5)
		os.system("wget --output-document='temp.zip' " + url)

		#if temp.zip exists then move it.
		os.system("[ -f temp.zip ] && mv temp.zip ~/openvpn/")

		# extract only selected file 'vpnbook-de-tcp443.ovpn'
		sleep(1)
		print c.out("%s[+] %sUnzip downloaded file." %(c.GREEN, c.RESET + c.ON_CYAN))
		sleep(1)
		os.system("[ -e ~/openvpn/temp.zip ] && unzip -o ~/openvpn/temp.zip '" + file + "' -d ~/openvpn/")

		#remove downloaded file
		sleep(1.5)
		print c.out("%s[+] %sRemoving files." %(c.GREEN, c.RESET + c.ON_CYAN))
		os.system("[ -e ~/openvpn/temp.zip ] && rm ~/openvpn/temp.zip")
	else:
		print c.out("%s[+] %sFile has already been downloaded, no download required." %(c.GREEN , c.RESET + c.ON_CYAN))

def processVPNChoice(choice):

	if(choice == 'de'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-DE1.zip"
		zipFile 		= "vpnbook-de233-tcp443.ovpn"
		nameChoice		= "Germany"

	elif(choice == 'eu2'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-Euro2.zip"
		zipFile 		= "vpnbook-euro2-tcp443.ovpn"
		nameChoice		= "Europe"

	elif(choice == 'eu1'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-Euro1.zip"
		zipFile 		= "vpnbook-euro1-tcp443.ovpn"
		nameChoice		= "Europe"

	elif(choice == 'ca'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-CA1.zip"
		zipFile 		= "vpnbook-ca1-tcp443.ovpn"
		nameChoice		= "Canada"

	elif(choice == 'us2'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-US2.zip"
		zipFile 		= "vpnbook-us2-tcp443.ovpn"
		nameChoice		= "United-states"

	elif(choice == 'us1'):
		downloadFile 	= "https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-US1.zip"
		zipFile 		= "vpnbook-us1-tcp443.ovpn"
		nameChoice		= "United-states"

	else:
		print c.out("%s[-] %sNot valid answer." %(c.RED, c.RESET))
		return

	#downloading files...
	downloadVPN(downloadFile, zipFile)

	#start vpn
	sleep(2)
	print c.out("%s[+] %sConnecting to %s server." %(c.GREEN, c.RESET + c.ON_CYAN, nameChoice))

	#add configure the ovpn file...
	#os.system("sed -i '/auth-user-pass/d' ~/openvpn/" + zipFile)
	#os.system("sed -i '10iauth-user-pass authfile' ~/openvpn/" + zipFile)

	#clean log file
	os.system("cat /dev/null > ~/openvpn/" + logFile)

	#start
	#os.system("nohup openvpn --cd ~/openvpn --config " + zipFile + " --auth-user-pass ./authfile > ~/openvpn/" + logFile + " 2>&1 &")
	#print c.out("%s[*]%s Always check log file in: ~/openvpn/%s." %(c.YELLOW, c.RESET, logFile))
	sleep(3)
	fileToSaveLog = open(expanduser("~") + '/openvpn/' + logFile, "w")

	vpn = subprocess.Popen(["openvpn --cd %s --config %s --auth-user-pass %s &" %('~/openvpn', zipFile,'./authfile')], shell=True, stdout=PIPE, stderr=fileToSaveLog)
	sleep(8)
	vpn.wait()

	(_, outputCommand) = commands.getstatusoutput('pidof -x openvpn')

	if(not outputCommand):
		print c.out("%s[-] %sError connecting VPN check ~/openvpn/%s." %(c.RED, c.RESET, logFile))
	else:
		print c.out("%s[+] %sConnected to %s VPN." %(c.GREEN, c.RESET + c.ON_GREEN, nameChoice))

	if(vpn):
		ipInfo()
	else:
		sys.exit()

def getRandomMac():
	'''Returns a random MAC''' 
	# first byte must be even
	chars = '0123456789ABCDEF'
	MAC = random.choice(chars) + random.choice(chars[::2]) + ':'
	for i in xrange(5):
		MAC += ''.join(random.choice(chars)  for n in xrange(2)) + ':'
	return MAC[:-1].strip()

def hideMacAddress():
	# wich interface to change mac
	eth = Popen("route | grep '^default' | grep -o '[^ ]*$'",shell=True, stdout=PIPE).communicate()[0].strip()
	
	mac = getRandomMac()
	cmd = []
	cmd.append( "ifconfig %s down" % eth )
	cmd.append( "ifconfig %s hw ether %s " % ( eth, mac) )
	cmd.append( "ifconfig %s up" % eth )
	print c.out(c.RESET + "Please wait...\n")
	for command in cmd:
		print c.out("%s[+]%s Executing %s." %(c.GREEN, c.RESET, command))
		os.system(command)
		sleep(3)
	print c.out("%s[+] %sMAC-Address Changed successfully(%s)." %(c.GREEN, c.RESET + c.ON_GREEN, mac))

def defaultMacAddress():

	# wich interface to change mac
	eth = Popen("route | grep '^default' | grep -o '[^ ]*$'",shell=True, stdout=PIPE).communicate()[0].strip()
	# get the perm mac
	mac = Popen("ethtool -P " + eth + " | grep -Po '[^ ]+$'",shell=True, stdout=PIPE).communicate()[0].strip()
	cmd = []
	cmd.append( "ifconfig %s down" % eth )
	cmd.append( "ifconfig %s hw ether %s " % ( eth, mac) )
	cmd.append( "ifconfig %s up" % eth )
	print c.out(c.RESET + "Please wait...\n")
	for command in cmd:
		print c.out("%s[+]%s Executing %s." %(c.GREEN, c.RESET, command))
		os.system(command)
		sleep(3)
	print c.out("%s[+] %sMAC-Address Changed to original(%s)." %(c.GREEN, c.RESET + c.ON_GREEN, mac))

def hideIP():

	if(not os.path.exists(expanduser("~") + "/openvpn")):
		print c.out("%s[+]%s Creating working directory..." %(c.GREEN, c.RESET))
		os.system("mkdir ~/openvpn")
		os.system("chmod 777 ~/openvpn")

	os.system("clear")
	print c.out("%s[+]%s Connecting to: www.vpnbook.com/freevpn..." %(c.GREEN, c.RESET))
	os.system("wget -q -O ~/vpnbook.tmp www.vpnbook.com/freevpn")
	username = Popen("cat ~/vpnbook.tmp | grep -m 1 -i '<li>Username:' | replace '<li>Username: <strong>' '' | replace '</strong></li>' '' | tr  -d '\t' | tr -d ' '",shell=True, stdout=PIPE).communicate()[0].strip()
	password = Popen("cat ~/vpnbook.tmp | grep -m 1 -i '<li>Password:' | replace '<li>Password: <strong>' '' | replace '</strong></li>' '' | tr  -d '\t'",shell=True, stdout=PIPE).communicate()[0].strip()
	
	os.system("cat /dev/null > ~/openvpn/authfile")
	os.system("chmod 600 ~/openvpn/authfile")
	os.system("echo '" + username + "\n" + password+ "' > ~/openvpn/authfile")
	os.system("rm ~/vpnbook.tmp")
	print("\n")
	print c.out(c.RED + c.BOLD + "Choose your VPN connection destination:")
	print(c.GREEN + c.BOLD)
	print("-> DE")
	print("-> EU2")
	print("-> EU1")
	print("-> CA")
	print("-> US2")
	print("-> US1")
	print("\n")

	try:
		destination = raw_input(c.BLUE + c.BOLD +'Choice > ' + c.RESET).lower().strip()
		processVPNChoice(destination)
	except KeyboardInterrupt:
		sys.exit(c.RED + c.BOLD + "\nChoice cancelled...")

parser = argparse.ArgumentParser(description='Hide your entity, Hidden-Man.')
parser.add_argument('--hidemac', help = 'Hide you MAC-Address.',required=False, action='store_true',default=False)
parser.add_argument('--restoremac', help = 'Set to default MAC-Address.',required=False, action='store_true',default=False)
parser.add_argument('--hideip', help = 'Hide you IP-Address using VPN.',required=False, action='store_true',default=False)
parser.add_argument('--restoreip', help = 'Stop VPN.',required=False, action='store_true',default=False)
parser.add_argument('--forcestop', help = 'Force to stop all process.',required=False, action='store_true',default=False)
parser.add_argument('--checkinternet', help = 'Check if you are connected to the internet.',required=False, action='store_true',default=False)
parser.add_argument('--getinfo', help = 'Get information about your connection.',required=False, action='store_true',default=False)

args = parser.parse_args()

logo = u"""
     _  _ ___ ___  ___  ___ _  _     __  __   _   _  _ \N{COPYRIGHT SIGN}
    | || |_ _|   \|   \| __| \| |___|  \/  | /_\ | \| |
    | __ || || |) | |) | _|| .` |___| |\/| |/ _ \| .` |
    |_||_|___|___/|___/|___|_|\_|   |_|  |_/_/ \_\_|\_| """ + version + """
    
"""
for char in logo:
	sleep(.004)
	sys.stdout.write(c.RED)
	sys.stdout.write(char)
	sys.stdout.flush()

print c.out("    %s> DEVELOPED BY 13DEV (qwerty124563@gmail.com)" %( c.GREEN))
sys.stdout.write(c.RESET)
sleep(.5)

if(args.forcestop):
	stopAll()
	print c.out("%s[-]%s All process were closed." %(c.GREEN, c.RESET))
	sys.exit()

if(args.restoreip):
	stopAll()
	print c.out("%s[-]%s VPN was closed." %(c.GREEN, c.RESET))

if(args.checkinternet):
	is_connected()
	sys.exit()

if(args.hidemac):
	hideMacAddress()
	sys.exit()

if(args.restoremac):	
	defaultMacAddress()
	sys.exit()

if(args.hideip):
	if(not is_connected()):
		sys.exit()

	checkProccess()
	hideIP()

if(args.getinfo):
	if(not is_connected()):
		sys.exit()
	ipInfo()







