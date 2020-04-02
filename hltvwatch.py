#!/usr/bin/python

"""
HLTVWatch (v2.0)
HLTGV monitoring and restarter script

This script is released under the GPL (http://www.gnu.org/licenses/gpl.html)

Contact: http://github.com/smkerz
"""

import random
import sys
#import zipfile
import tarfile
import time

import configparser
import os.path, re, socket
from socket import gethostname

#from os import geteuid, devnull
import subprocess
from sys import argv, exit, version_info
from time import strftime, sleep


# --- User preferences ---

# Delay (in sec) for status checks
check_interval = 10

# File logging
# To change log file location, enter the full path of desired location
# in log_filename eg /var/www/hldswatch.log
log_to_file	= 1
log_filename   = "hltvwatch.log"

# --- End of user preferences ---


# Query constants
HEADER		   			= b"\xFF\xFF\xFF\xFF"
A2A_PING				= b"\x69\x00"

A2A_RESPONSE			= b"\xFF\xFF\xFF\xFF"
A2A_RESPONSE_PING		= b"\x6A\x00"

QUERY_TIMEOUT	= 3
QUERY_RETRY	  = 3
QUERY_RETRY_WAIT = 5

QUERY_DELAY_HLTV = 10


class HLTVWatch(object):

	def __init__(self, conf):
		if os.path.isfile(conf):
			self.c = configparser.ConfigParser()
			self.c.read_file(open(conf))
		else:
			exit("Error: Config file given does not exist!")
			
		# Hold all server settings
		self.serverconfig = {}
		self.trackingarray = {}	

		# Remember script's working dir
		self.cwdir = os.getcwd()

		# validate and cache all server settings
		self.validate_config()

		
		
	"""Message logging"""
	def printlog(self, msg):
		cur_time = strftime("%m-%d %H:%M:%S")
		log_msg = "%s -> %s" % (cur_time, msg)

		print(log_msg)

		if log_to_file and log_filename:
			with open(log_filename, 'a') as f:
				f.write(log_msg + '\n')
				f.close()


				
	"""Parse and validate options in config file"""
	def validate_config(self):
		for sec in self.c.sections():
		
			if not re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+$", sec):
				exit('Error: "[%s]" is invalid section name. All section names must be in [<ip>:<port>] form' % sec)
			else:
				# game_screen
				game_screen = self.c.get(sec, "game_screen")
				if not game_screen:
					exit("Error: [%s] 'game_screen' is required and cannot be left out when autorestart is enabled" % sec)
				elif not re.match("^[A-Za-z0-9_]+$", game_screen):
					exit("Error: [%s] 'game_screen' must contain only alphanumeric and underscore character" % sec)
					
				# start_dir
				start_dir = self.c.get(sec, "start_dir")
				if not start_dir:
					exit("Error: [%s] 'start_dir' is required and cannot be left out when autorestart is enabled" % sec)
				elif not os.path.isdir(start_dir):
					exit("Error: [%s] 'start_dir' path doesn't exist" % sec)
	
				# hltv_screen
				hltv_screen = self.c.get(sec, "hltv_screen")
				if not hltv_screen:
					exit("Error: [%s] 'hltv_screen' is required and cannot be left out when autorestart is enabled" % sec)
				elif not re.match("^[A-Za-z0-9_]+$", hltv_screen):
					exit("Error: [%s] 'hltv_screen' must contain only alphanumeric and underscore character" % sec)
					
				# hltv_port
				hltv_port = self.c.get(sec, "hltv_port")
				if not hltv_port:
					exit("Error: [%s] 'hltv_port' is required and cannot be left out when autorestart is enabled" % sec)
				elif not re.match("^[0-9]*$", hltv_port):
					exit("Error: [%s] 'hltv_port' must be a number" % sec)
										
				# method
				method = self.c.get(sec, "method")
				if not method:
					exit("Error: [%s] 'method' type is left out" % sec)
				elif not re.match("^(?:players|matchcase)$", method):
					exit("Error: [%s] 'method' is unknown and not supported" % sec)
				elif method == "players":
					
					# sup_player
					sup_player = self.c.get(sec, "sup_player")
					if not sup_player:
						exit("Error: [%s] 'sup_player' if players methos is selected, sup_player is required" % sec)
					elif not re.match("^[0-9]*$", sup_player):
						exit("Error: [%s] 'sup_player' must be a number" % sec)
					
					# inf_player
					inf_player = self.c.get(sec, "inf_player")
					if not inf_player:
						exit("Error: [%s] 'inf_player' if players methos is selected, inf_player is required" % sec)
					elif not re.match("^[0-9]*$", inf_player):
						exit("Error: [%s] 'inf_player' must be a number" % sec)

				# ftp_path
				ftp_path = self.c.get(sec, "ftp_path")
				if not ftp_path:
					exit("Error: [%s] 'ftp_path' is required and cannot be left out when autorestart is enabled" % sec)
				elif not os.path.isdir(ftp_path):
					exit("Error: [%s] 'ftp_path' path doesn't exist" % sec)

			# Cache all server specific configs
			self.serverconfig[sec] = {'game_screen' : game_screen,
									'start_dir' : start_dir,
									'hltv_screen' : hltv_screen,
									'hltv_port' : hltv_port,
									'method' : method,
									'sup_player' : sup_player,
									'inf_player' : inf_player,
									'ftp_path' : ftp_path}
									

			self.trackingarray[sec] = {'hltv_state' : 0,
								'hltv_retry' : 0,
								'hltv_timer' : 0,
								'dem_file' : ""}
		
		
		
	"""Server status check"""
	def is_up(self, ip, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.settimeout(float(QUERY_TIMEOUT))

		packet = HEADER + A2A_PING
		response = A2A_RESPONSE + A2A_RESPONSE_PING

		retry, status = 0, 0
		reply = None
		while retry < QUERY_RETRY:
				
			try:		
				# Send ping to server
				s.sendto(packet, (ip, int(port))) 
				reply = s.recv(4096)
				
				if len(reply) > 4:
					if reply == response:
						status = 1
						break
				
			except socket.error:
				pass			

			retry += 1
			sleep(2)

		s.close()
		return status == 1

	

	"""Launch HLTV"""
	def launch_hltv(self, start_dir, hltv_screen, hltv_port, game_screen, hltv_tmp_file, ip, port):
		#I'm connecting to the server
		self.printlog("launch HLTV ...")
		
		# CD into server dir
		try:
			os.chdir(start_dir)
		except OSError:
			self.printlog("* Unable to cd into server dir '%s'" % start_dir)
			return 0
			
		with open(os.devnull, "w") as blackhole:
			# In case server process is unresponsive or hung and doesn't quit itself after crashed
			cmd_screen = "-p 0 -S " + hltv_screen + " -X "
			cmd = "quit"
			#subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)
			subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)
						
			# Start the HLTV
			cmd_screen = "-dmS " + hltv_screen
			cmd = " ./hltv.lib -port " + hltv_port
			subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)

		sleep(3)
			
		os.chdir(self.cwdir)

		#I've to know what is the password of the server
		self.call_to_screen(hltv_tmp_file, game_screen, "sv_password")
		password = self.catch_to_screen(hltv_tmp_file, game_screen, "\"sv_password\" is \"(.+)\"")
		
		if password is not None:
			with open(os.devnull, "w") as blackhole:
				# Now I've IP and password, I can connect to the server
				cmd_screen = "-p 0 -S " + hltv_screen + " -X "
				cmd = "eval 'stuff \"serverpassword \"'" + password + "'""\015'"
				subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)
	
		with open(os.devnull, "w") as blackhole:
			cmd_screen = "-p 0 -S " + hltv_screen + " -X "
			cmd = "eval 'stuff \"connect \"" + ip + ":" + port + "\015'"	
			subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)
		
		sleep(3)

		# # Connecting ...
		# # cmd = "eval 'stuff \"say Hi ! I''m auto-HLTV.\"\015'"
		# subprocess.call("screen " + cmd_screen + cmd, shell=True)
		
		with open(os.devnull, "w") as blackhole:
			# Recording
			cmd = "eval 'stuff \"record hltv\"\015'"
			subprocess.call("screen " + cmd_screen + cmd, stdout=blackhole, stderr=blackhole, shell=True)
	
		#Delay is supported by another infinite loop which can wait when hltv is ready
		return 1
	
	def stop_hltv(self, start_dir, hltv_screen, hltv_tmp_file, ftp_path, dem_file):
		#Say hltv is done to the server and to the console
		self.printlog("stop HLTV ...")
	
		cmd_screen = "-p 0 -S " + hltv_screen + " -X "
		# cmd = "eval 'stuff \"say Recording is done.\"\015'"
		# subprocess.call("screen " + cmd_screen + cmd, shell=True)
		# sleep(1)
		# cmd = "eval 'stuff \"say Please take note of the date and current time to backup HLTV.\"\015'"
		# subprocess.call("screen " + cmd_screen + cmd, shell=True)
		# sleep(1)
		
		with open(os.devnull, "w") as blackhole:
			#Terminate recording
			cmd = "eval 'stuff \"stoprecording\"\015'"
			subprocess.call("screen " + cmd_screen + cmd, shell=True)
			sleep(1)
			# cmd = "eval 'stuff \"say auto-HLTV script ended.\"\015'"
			# subprocess.call("screen " + cmd_screen + cmd, shell=True)
		
			#Terminate hltv
			cmd = "eval 'stuff \"stop\"\015'"
			subprocess.call("screen " + cmd_screen + cmd, shell=True)
		
			#Terminate screen session
			cmd = "quit"
			subprocess.call("screen " + cmd_screen + cmd, shell=True)
			
		# Delete tmp_file
		os.remove(hltv_tmp_file)
			
		return 0
			
			
	def say_hltv(self, hltv_screen, say):
		with open(os.devnull, "w") as blackhole:
			#Terminate recording
			cmd_screen = "-p 0 -S " + hltv_screen + " -X "
			cmd = "eval 'stuff \"say " + say + "\"\015'"
			subprocess.call("screen " + cmd_screen + cmd, shell=True)
	
	
#	def install_hltv(self, start_dir,):
#		# Install hltv.lib
#		if path.exists("hltv.lib"):
#			copyfile("hltv.lib", start_dir + "hltv.lib")
#
#		# Install hltv.cfg
#		if path.exists("hltv.cfg"):
#			copyfile("hltv.cfg", start_dir + "hltv.cfg")
#			

			

	
	# Call status command to server
	def call_to_screen(self, hltv_tmp_file, game_screen, command):
		cmd_screen = "-p 0 -S " + game_screen + " -X "
		cmd = ""
		
		if command != None:
			with open(os.devnull, "w") as blackhole:
				cmd = "eval 'stuff \"" + command + "\"\015'"
				subprocess.call("screen " + cmd_screen + cmd, shell=True)

	
	# Extract the output
	def catch_to_screen(self, hltv_tmp_file, game_screen, pattern):

		cmd_screen = "-p 0 -S " + game_screen + " -X "
		last_line = ""
		
		cmd = "hardcopy " + hltv_tmp_file
		subprocess.call("screen " + cmd_screen + cmd, shell=True)
		
		if os.path.exists(hltv_tmp_file):
			with open(hltv_tmp_file, "r", encoding="utf8", errors='ignore') as f1:
				last_line = f1.readlines()[-10:]
				last_line = "".join(last_line)
				subprocess.call("screen " + cmd_screen + "eval 'stuff \015\015\015'", shell=True)
		
		# Check res line
		p = re.compile(pattern)
		check_line = p.search(last_line)
		
		if check_line is None:
			return None
		else:
			# Return the players
			return check_line.group(1)
			
			
	def backup_hltv_to_ftp(self, start_dir, dem_file, ftp_path):
		# CD into server dir
		try:
			os.chdir(start_dir)
		except OSError:
			self.printlog("* Unable to cd into server dir '%s'" % start_dir)
			return 0
		
		if dem_file is not None:
			source_filename = start_dir + "cstrike/" + dem_file
			output_filename = ftp_path + dem_file + ".tar.gz"

			with tarfile.open(output_filename, "w:gz") as tar:
				tar.add(source_filename, arcname=os.path.basename(source_filename))
				os.chmod(output_filename, 755)
				
				if os.path.exists(output_filename):
					os.remove(source_filename)
					
					
	"""Monitor HLTVs"""
	def watch(self):
	# Here we go
		self.printlog("HLTVWatch started")
		self.printlog("Monitoring %i HLTV(s)" % len(self.serverconfig))

		try:
			# Loop forever
			while True:

				for addr in self.serverconfig:
					ip, port = addr.split(':')
					
					method = self.serverconfig[addr]['method'] 
					game_screen = self.serverconfig[addr]['game_screen']
					hltv_screen = self.serverconfig[addr]['hltv_screen']
					start_dir = self.serverconfig[addr]['start_dir']
					hltv_port = self.serverconfig[addr]['hltv_port']
					sup_player = self.serverconfig[addr]['sup_player']
					inf_player = self.serverconfig[addr]['inf_player']
					ftp_path = self.serverconfig[addr]['ftp_path']
					
					hltv_state = self.trackingarray[addr]['hltv_state']
					hltv_retry = self.trackingarray[addr]['hltv_retry']
					hltv_timer = self.trackingarray[addr]['hltv_timer']
					dem_file = self.trackingarray[addr]['dem_file']
					
					hltv_tmp_file = self.cwdir + "/." + hltv_screen + ".tmp"
					
					self.printlog("****************************")
					self.printlog("HLTV - " + hltv_screen)
					self.printlog("****************************")
					
					print("hlds_state: " + str(hltv_state))
					
					# Depending on the method
					if method == "players":
						# Get the players
						self.call_to_screen(hltv_tmp_file, game_screen, "status")
						current_player = self.catch_to_screen(hltv_tmp_file, game_screen, "(.*) users")
						
						if(current_player != None):
							current_player = int(current_player)
							self.printlog("Current players: " + str(current_player))

					# Waiting players or flags state
					if hltv_state == 0:
		
						if (current_player != None and 
							current_player >= int(sup_player)):
							
							self.printlog("Current players is ge than sup_player")
							hltv_state = int(self.launch_hltv(start_dir, hltv_screen, hltv_port, game_screen, hltv_tmp_file, ip, port))
							self.printlog("HLTV waiting...")
							
					# Waiting recording state
					if hltv_state == 1:
						self.printlog("ping " + str(hltv_retry) + "?")
					
						dem_file = self.catch_to_screen(hltv_tmp_file, hltv_screen, "Start recording to (.+).")
						print("dem_file: ", dem_file)
						
						# HLDS server down or timeout
						if(not self.is_up(ip, port) or 
							hltv_retry >= QUERY_DELAY_HLTV):
							
							self.printlog("Record time out...")
							hltv_state = self.stop_hltv(start_dir, hltv_screen, hltv_tmp_file, ftp_path, dem_file)
							hltv_retry = 0
							sleep(60)
							
						# Record lauch detection
						if dem_file != None:
							self.printlog("Record started to " + dem_file)
							self.say_hltv(hltv_screen, "Record started, download here: http://2manygames.fr/hltv/demos/" + dem_file + ".zip")
							self.say_hltv(hltv_screen, "HLTV ip: " + ip + ":" + hltv_port)
							hltv_retry = 0
							hltv_state = 2	
							self.printlog("HLTV recording!")
							hltv_timer = time.time()
						
						hltv_retry += 1
						self.printlog("pong!")
	
					# Recording state
					if hltv_state == 2:
						time_hltv_recording = time.time() - hltv_timer
						print("time: " + str(time_hltv_recording))
					
						# If, HLDS server down or timeout
						# Or, Less than inf_player
						# Or, Global timer is ge than 1h
						if (not self.is_up(ip, port) or 
							(current_player != None and current_player-1 <= int(inf_player)) or
							time_hltv_recording >= 3600):
							
							self.printlog("Recording done")
							hltv_state = self.stop_hltv(start_dir, hltv_screen, hltv_tmp_file, ftp_path, dem_file)
							self.backup_hltv_to_ftp(start_dir, dem_file, ftp_path)
							self.printlog("HLTV stopped.")
							time_hltv_recording = 0
						
						# String detected: "Completed demo (.+)."
						completed_dem = self.catch_to_screen(hltv_tmp_file, hltv_screen, "Completed demo (.+).")
						
						if (completed_dem != None and completed_dem == dem_file):
#						and dem_file != completed_dem):
						#new_dem_file = self.call_to_screen(hltv_tmp_file, hltv_screen, None, "Start recording to (.+).")
						
						# Changelevel
						#if (new_dem_file != completed_dem):
						
							# Backup HLTV of the previous map and change hltv_state to 1
							self.printlog("Level has changed!")
							self.backup_hltv_to_ftp(start_dir, dem_file, ftp_path)
							hltv_state = 1
							time_hltv_recording = 0
							dem_file = None
								
							# Stop HLTV
							#else:
							#	hltv_state = self.stop_hltv(start_dir, hltv_screen, hltv_tmp_file, ftp_path, dem_file)
							#	self.backup_hltv_to_ftp(start_dir, dem_file, ftp_path)
								#	self.printlog("HLTV stopped.")
								
					self.trackingarray[addr]['hltv_state'] = hltv_state
					self.trackingarray[addr]['hltv_retry'] = hltv_retry
					self.trackingarray[addr]['hltv_timer'] = hltv_timer
					self.trackingarray[addr]['dem_file'] = dem_file
						
					self.printlog(" ")

					sleep(check_interval)

		except KeyboardInterrupt:
			self.printlog("HLTVWatch terminated")
	
	
if __name__ == '__main__':
	# Idiot check..never run hlds/srcds as root!
	if os.geteuid() == 0:
		exit('Error: I have a bad feeling about this')

	# We need at least python 3 to run this script
	if int(sys.version[0]) < 3:
		exit('Error: Your python version is too old! This script requires at least python 2.6.x or newer')

	# Must give a config file
	if len(argv) != 2:
		exit("Usage: ./hltvwatch.py <configfile>")
	else:
		hltv = HLTVWatch(argv[1])
		hltv.watch()




# # vim: tabstop=4:softtabstop=4:shiftwidth=4:expandtab
