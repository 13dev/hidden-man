#!/usr/bin/python
import sys, os
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
count = 0
logFile = "hiddenman.log"
version = "v1.0"

def checkOpenVPN():
	global count
	#t = threading.Timer(5.0, checkOpenVPN)
	#t.start()
	(_, outputTun) = commands.getstatusoutput("ifconfig | grep tun | awk '{print $1}'")
	(_, outputPidof) = commands.getstatusoutput("pidof -x openvpn")

	if(not outputTun):
		count += 1

	#print outputTun
	#print count

	if(count == 6):
		print c.out("%s[-]%s Error connecting VPN check ~/openvpn/%s." %(c.RED, c.RESET, logFile))
		#t.cancel()
		stopAll()
		sys.exit()

def stopAll():
	os.system("ps -uax | grep log- | awk '{print $2}' | xargs kill -9 2> /dev/null")
	os.system("ps -aux | grep openvpn | awk '{print $2}' | xargs kill -9 2> /dev/null")
	os.system("ifconfig $(ifconfig | egrep -io 'tun\w') down 2> /dev/null")

def checkProccess():
	(_, outputPidof) = commands.getstatusoutput("pidof -x openvpn")
	if(outputPidof.strip()):
		print c.out("%s[-]%s The process 'openvpn' is already running!, try: %s--forcestop" %(c.RED, c.RESET, c.RED))
		sys.exit()

def downloadVPN(url, file):
	sleep(1)
	if(not os.path.isfile(expanduser("~") + "/openvpn/" + file)):
		print c.out("%s[+]%s Downloading required files." %(c.GREEN , c.RESET + c.ON_CYAN))
		sleep(1.5)
		os.system("wget --output-document='temp.zip' " + url)
		os.system("[ -f temp.zip ] && mv temp.zip ~/openvpn/")

		# extract only selected file 'vpnbook-de-tcp443.ovpn'
		sleep(1)
		print c.out("%s[+]%s Unzip downloaded file." %(c.GREEN, c.RESET + c.ON_CYAN))
		sleep(1)
		os.system("[ -e ~/openvpn/temp.zip ] && unzip -o ~/openvpn/temp.zip '" + file + "' -d ~/openvpn/")

		#remove downloaded file
		sleep(1.5)
		print c.out("%s[+]%s Removing files." %(c.GREEN, c.RESET + c.ON_CYAN))
		os.system("[ -e ~/openvpn/temp.zip ] && rm ~/openvpn/temp.zip")
	else:
		print c.out("%s[+]%s File has already been downloaded, no download required." %(c.GREEN , c.RESET + c.ON_CYAN))

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
		print c.out("%s[-]%s Not valid answer." %(c.RED, c.RESET))
		return

	#downloading files...
	downloadVPN(downloadFile, zipFile)


	#check if process if alredy running
	(_, outputPidof) = commands.getstatusoutput("pidof -x openvpn")
	if(outputPidof.strip()):
		print c.out("%s[-]%s Error connecting VPN check ~/openvpn/%s." %(c.RED, c.RESET, logFile))
		stopAll()
		sys.exit()

	#start vpn
	sleep(2)
	print c.out("%s[+]%s Connecting to %s server." %(c.GREEN, c.RESET + c.ON_CYAN, nameChoice))
	sleep(1)

	#add configure the ovpn file...
	#os.system("sed -i '/auth-user-pass/d' ~/openvpn/" + zipFile)
	#os.system("sed -i '10iauth-user-pass authfile' ~/openvpn/" + zipFile)

	#clean log file
	os.system("cat /dev/null > ~/openvpn/" + logFile)

	#start
	os.system("nohup openvpn --cd ~/openvpn --config " + zipFile + " --auth-user-pass ./authfile > ~/openvpn/" + logFile + " 2>&1 &")
	print c.out("%s[*]%s Always check log file in: ~/openvpn/%s." %(c.YELLOW, c.RESET, logFile))

	checkOpenVPN()

def getRandomMac():
	'''Returns a random MAC''' 
	# first byte must be even
	chars = '0123456789ABCDEF'
	MAC = random.choice(chars) + random.choice(chars[::2]) + ':'
	for i in xrange(5):
		MAC += ''.join(random.choice(chars)  for n in xrange(2)) + ':'
	return MAC[:-1].strip()

def hideMacAddress(hide):
	if (not hide): 
		return
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

def defaultMacAddress(hide):
	if (not hide): 
		return
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

def hideIP(hide):
	if (not hide): return

	if(not os.path.exists("~/openvpn")):
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
		destination = raw_input(c.BLUE + c.BOLD +'Choice >' + c.RESET).lower().strip()
		processVPNChoice(destination)
	except KeyboardInterrupt:
		sys.exit(c.RED + c.BOLD + "\nChoice cancelled...")

parser = argparse.ArgumentParser(description='Hide your entity, Hidden-Man.')
parser.add_argument('--hidemac', help = 'Hide you MAC-Address.',required=False, action='store_true',default=False)
parser.add_argument('--restoremac', help = 'Set to default MAC-Address..',required=False, action='store_true',default=False)
parser.add_argument('--hideip', help = 'Hide you IP.',required=False, action='store_true',default=False)
parser.add_argument('--forcestop', help = 'Force to stop all process.',required=False, action='store_true',default=False)

args = parser.parse_args()

logo = u"""
     _  _ ___ ___  ___  ___ _  _     __  __   _   _  _ \N{COPYRIGHT SIGN}
    | || |_ _|   \|   \| __| \| |___|  \/  | /_\ | \| |
    | __ || || |) | |) | _|| .` |___| |\/| |/ _ \| .` |
    |_||_|___|___/|___/|___|_|\_|   |_|  |_/_/ \_\_|\_|""" + version + """
    
    Developed by 13dev @o_psy__ - qwerty124563@gmail.com

"""

for char in logo:
    sleep(.004)
    sys.stdout.write(c.RED)
    sys.stdout.write(char)
    sys.stdout.flush()

sys.stdout.write(c.RESET)
sleep(.5)

if(args.forcestop):
	stopAll()
	print c.out("%s[-]%s All process were closed." %(c.GREEN, c.RESET))

checkProccess()

hideMacAddress(args.hidemac)
hideIP(args.hideip)
defaultMacAddress(args.restoremac)




