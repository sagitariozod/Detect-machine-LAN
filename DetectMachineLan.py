#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

""" Detect machine LAN """

import sys
import nmap
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp
import re
import os
import smtplib
import time,datetime
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
gi.require_version('Notify', '0.7')
from gi.repository import Gtk
from gi.repository import AppIndicator3
from gi.repository import Notify
from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser
import signal

__author__	= "GoldraK"
__credits__	= "GoldraK"
__version__	= "0.1.1"
__maintainer__	= "Sagitariozod"
__email__	= "delfinb@gmail.com"
__status__	= "Development"
__adaptedby__	= "Sagitariozod"

APPINDICATOR_ID = "appindicator"

class DetectMachineLan():

	def __init__(self):
		self.version = "0.1.1"
		self.whitelist_file = ""
		self.log_file = ""
		self.log = False
		self.verbose = False

	def DetectMachineLan(self):
		(opts, args) = self.__handleArguments()
		if opts.macsearch and opts.ip:
			self.__detectMachinesNetwork(opts)
		if opts.macadd:
			macs = opts.macadd.split(",")
			for x in macs:
				self.__writeWhitelist(x)
		if opts.macremove:
			macs = opts.macremove.split(",")
			for x in macs:
				self.__removeWhitelist(x)
		if opts.ip and opts.xnotify:
			signal.signal(signal.SIGINT, signal.SIG_DFL)
			self.mainGtk(opts)
		if opts.ip and opts.macsearch == False:
			self.__detectMachinesWhitelist(opts)

	def mainGtk(self,opts):
		indicator = AppIndicator3.Indicator.new(
												APPINDICATOR_ID,
												os.path.dirname(os.path.abspath(__file__))+"/Detect_Network-GTK.png",
												AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
		indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
		indicator.set_menu(self.menu_control(opts))
		Notify.init(APPINDICATOR_ID)

		Gtk.main()
		sys.exit(0)

	def menu_control(self,opts):
		"""Return a Gtk+ menu."""
		menu = Gtk.Menu()
		whitelist = self.__read_file()
		msg = ''
		alert_mac = ''
		check_mac = []
		if self.log:
			self.__writeLog(msg)
		if opts.scapy:
			machines = self.__scanNetworkScapy(opts.ip)
		else:
			machines = self.__scanNetworkNmap(opts.ip)
	
		for ip,mac in machines:
			try:
				msg = ''
				if mac in whitelist and mac in check_mac:
					msg = 'Mac find: '+mac+'\tIp: '+ip+'\tWARNING Mac duplicate'
					alert_mac = alert_mac+'Mac find: '+mac+'\tIp: '+ip+'\tWARNING Mac duplicate\n'
					item_menu = Gtk.MenuItem(msg)
					item_menu.connect('activate', self.menu_action)
					menu.append(item_menu)
				elif mac in whitelist and mac not in check_mac:
					msg = 'Mac find: '+mac+'\tIp: '+ip
				elif mac not in whitelist and mac in check_mac:
					msg = 'New mac detected: '+mac+'\tIp: '+ip+'\tWARNING Mac duplicate'
					alert_mac = alert_mac+'New mac detected: '+mac+'\tIp: '+ip+'\tWARNING Mac duplicate\n'
					item_menu = Gtk.MenuItem(msg)
					item_menu.connect('activate', self.menu_action)
					menu.append(item_menu)
				else:
					msg = 'New mac detected: '+mac+'\tIp: '+ip
					alert_mac = alert_mac+'New mac detected: '+mac+'\tIp: '+ip+'\n'
					item_menu = Gtk.MenuItem(msg)
					item_menu.connect('activate', self.menu_action)
					menu.append(item_menu)
				check_mac.append(mac)
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg)
			except: 
				if self.verbose:
					self.__consoleMessage(msg)						
				if self.log:
					self.__writeLog(msg)
				self.__gtkinfo("Errors occurred in run.")

		item_menu = Gtk.SeparatorMenuItem()
		menu.append(item_menu)
	
		item_quit = Gtk.MenuItem("Quit")
		item_quit.connect('activate', self.quit)
		menu.append(item_quit)

		menu.show_all()
		
		if opts.emailto:
			self.__sendEmail(alert_mac,opts)
		if opts.gtk:
			self.__gtkinfo(alert_mac)

		Notify.init("DetectMachineLan")
		Notify.Notification.new('Ip and Mac found:', alert_mac,	None).show()
	
		return menu

	def menu_action(self,source):
		Notify.Notification.new(source.get_label(), source.get_label(),	None).show()

	def quit(self,source):
		Notify.uninit()
		Gtk.main_quit()

	def __scanNetworkNmap(self,ip):
		nm = nmap.PortScanner()
		machines_nmap=nm.scan(hosts=ip, arguments='-sP')
		machines = []
		for k,v in machines_nmap['scan'].items():
			if str(v['status']['state']) == 'up':
				try:
					machines.append([str(v['addresses']['ipv4']),str(v['addresses']['mac'])])
				except:
					machines.append([str(v['addresses']['ipv4']),'00:00:00:00:00:00']) #Mac not detected
		return sorted(machines,key=lambda machines:machines[1])

	def __scanNetworkScapy(self,ip):
		"""Arping function takes IP Address or Network, returns nested ip/mac list"""
		machines = []
		try:
			ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
			for snd, rcv in ans:
				result = ((rcv.sprintf(r"%ARP.psrc% %Ether.src%")).upper().split())
				machines.append(result)
		except:
			pass
		return sorted(machines,key=lambda machines:machines[1])

	def __detectMachinesNetwork(self,opts):
		check_mac = []
		if opts.scapy:
			machines = self.__scanNetworkScapy(opts.ip)
		else:
			machines = self.__scanNetworkNmap(opts.ip)
		for ip,mac in machines:
			print("")
			try:
				if mac in check_mac:
					print(ip+" --> "+mac+ "\tWARNING Mac duplicate")
				else:
					print(ip+" --> "+mac)
				check_mac.append(mac)
			except:
				pass
		print("")

	def __detectMachinesWhitelist(self,opts):
		whitelist = self.__read_file()
		msg = ""
		alert_mac = ""
		check_mac = []
		if self.log:
			self.__writeLog(msg)
		if opts.scapy:
			machines = self.__scanNetworkScapy(opts.ip)
		else:
			machines = self.__scanNetworkNmap(opts.ip)
		for ip,mac in machines:
			try:
				if mac in whitelist:
					if mac in check_mac:
						msg = 'Mac find: '+mac+'  Ip: '+ip+'\tWARNING Mac duplicate'
						alert_mac = alert_mac+'Mac find: '+mac+'  Ip: '+ip+'\tWARNING Mac duplicate\n'
					else:
						msg = 'Mac find: '+mac+' Ip: '+ip
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg)
				else:
					if mac in check_mac:
						msg = 'New mac detected: '+mac+'  Ip: '+ip+'\tWARNING Mac duplicate'
						alert_mac = alert_mac+'New mac detected '+mac+'  Ip: '+ip+'\tWARNING Mac duplicate\n'
					else:
						msg = 'New mac detected: '+mac+'  Ip: '+ip
						alert_mac = alert_mac+'New mac detected: '+mac+'  Ip: '+ip+'\n'
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg)
				check_mac.append(mac)
			except: 
				if self.verbose:
					self.__consoleMessage(msg)						
				if self.log:
					self.__writeLog(msg)
		if opts.emailto:
			self.__sendEmail(alert_mac,opts)
		if opts.gtk:
			self.__gtkinfo(alert_mac)

	def __handleArguments(self,argv=None):
		"""
		This function parses the command line parameters and arguments
		"""
		parser = OptionParser()
		if not argv:
			argv = sys.argv

		mac = OptionGroup(parser, "Mac", "At least one of these "
			"options has to be provided to define the machines")

		mac.add_option('--ms','--macsearch', action='store_true', default=False, dest='macsearch', help='Search machine Network')
		mac.add_option('--ma','--macadd', action='store', dest='macadd', help='Add mac to whitelist')
		mac.add_option('--mr','--macremove', action='store', dest='macremove', help='Remove mac from whitelist')


		email = OptionGroup(parser, "Email", "You need user, password, server and destination "
			"options has to be provided to define the server send mail")

		email.add_option('-u','--user', action='store', dest='user', help='User mail server')
		email.add_option('--pwd','--password', action='store', dest='password', help='Password mail server')
		email.add_option('-s','--server', action='store', dest='server', help='Mail server')
		email.add_option('-p','--port', action='store', default='25', dest='port', help='Port mail server')
		email.add_option('--et','--emailto', action='store', dest='emailto', help='Destination E-mail')

		parser.add_option('-r','--range', action='store', dest='ip', help='Secure network range ')
		parser.add_option('--wl','--whitelist', action='store', default=os.path.dirname(os.path.abspath(__file__))+'/whitelist.txt' , dest='whitelist_file', help='File have Mac whitelist ')
		parser.add_option('-l','--log', action='store_true', default=False, dest='log', help='Log acctions script')
		parser.add_option('-v','--verbose', action='store_true', default=False, dest='verbose', help='Verbose actions script')
		parser.add_option('-g','--gui', action='store_true', default=False, dest='gtk', help='GTK Windows with info')
		parser.add_option('--ns','--scapy', action='store_true', default=False, dest='scapy', help='Scan network whith Scapy')
		parser.add_option('-x','--xnotify', action='store_true', default=False, dest='xnotify', help='GTK Notify info with icon')

		parser.add_option_group(mac)
		parser.add_option_group(email)

		(opts, args) = parser.parse_args()

		self.log = opts.log
		self.log_file = os.path.dirname(os.path.abspath(__file__))+'/log.txt'
		self.verbose = opts.verbose
		self.whitelist_file = opts.whitelist_file

		if opts.user or opts.password or opts.server or opts.emailto:
			if not all([opts.user, opts.password,opts.server,opts.emailto]):
				errMsg = "missing some email option (-u, --pwd, -s, --et), use -h for help"				
				parser.error(errMsg)
				self.__writeLog(errMsg)
				sys.exit(-1)
		if opts.macsearch and not opts.ip:
			errMsg = "missing some range scan option (-r), use -h for help"
			parser.error(errMsg)
			self.__writeLog(errMsg)
			sys.exit(-1)
		return opts, args


	def __sendEmail(self,alert_mac,opts):
		"""
		This function send mail with the report
		"""
		header  = 'From: %s\n' % opts.user
		header += 'To: %s\n' % opts.emailto
		if alert_mac:
			header += 'Subject: New machines connected\n\n'
			message = header + 'List macs: \n'+str(alert_mac)
		else:
			header += 'Subject: No intruders - All machines are known \n\n'
			message = header + 'No intruders'

		server = smtplib.SMTP(opts.server+":"+opts.port)
		server.starttls()
		server.login(opts.user,opts.password)
		if self.verbose or self.log:
			debugemail = server.set_debuglevel(1)
			if self.verbose:
				self.__consoleMessage('debugemail')
		problems = server.sendmail(opts.user, opts.emailto, message)
		if self.verbose:
			print(problems)
		server.quit()

	def __gtkinfo(self,alert_mac):
		parent = Gtk.Window()
		if alert_mac:
			md = Gtk.Dialog('List macs:', parent, 
				Gtk.DialogFlags.DESTROY_WITH_PARENT | Gtk.DialogFlags.MODAL,
				(Gtk.STOCK_CLOSE, Gtk.ButtonsType.CLOSE))
			label = Gtk.Label(str(alert_mac))
		else:
			md = Gtk.Dialog('No intruders:', parent, 
				Gtk.DialogFlags.DESTROY_WITH_PARENT | Gtk.DialogFlags.MODAL,
				(Gtk.STOCK_OK, Gtk.ButtonsType.OK))
			label = Gtk.Label("\nAll machines are known.\n")

		md.set_default_size(500, 0)
		box = md.get_content_area()
		box.add(label)
		md.show_all()
		md.run()
		md.destroy()
		parent = None

	def __consoleMessage(self,message):
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		print('['+st+'] '+str(message))

	def __writeLog(self,log):
		"""
		This function write log
		"""
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		if os.path.isfile(self.log_file):
			try:
				file_read = open(self.log_file, 'a')
				if log:
					file_read.write('['+st+'] '+log+"\n")
				else:
					file_read.write(log+"\n")
				file_read.close()
			except IOError:
				msg = 'ERROR: Cannot open'+ self.log_file
				if self.verbose:
					self.__consoleMessage(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The Log file ", self.log_file, " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			sys.exit(-1)


	def __writeWhitelist(self,mac):
		"""
		This function add newmac to whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'a')
					file_read.write(mac+"\n")
					file_read.close()
					msg = "Mac: "+ mac + " add correctly"
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
				except IOError:
					print()
					msg = 'ERROR: Cannot open'+ self.whitelist_file
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Mac "+ mac +" not valid!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 

	def __removeWhitelist(self,mac):
		"""
		This function remove newmac from whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'r')
					lines = file_read.readlines()
					file_read.close()
					file_read = open(self.whitelist_file, 'w')
					for line in lines:
						if line.strip() != mac:
							file_read.write(line)
					file_read.close()
					msg = "Mac "+mac+" remove correctly"
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
				except IOError:
					msg = 'ERROR: Cannot open '+ self.whitelist_file
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Mac "+ mac + " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 

	def __read_file(self):
		"""
		This function read the whitelist
		"""
		whitelist = []
		if os.path.isfile(self.whitelist_file):
			try:
				file_read = open(self.whitelist_file, 'r')
				for line in file_read:
					if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", line.strip().lower()):
							whitelist.append(line.strip())
				return whitelist
			except IOError:
				msg = 'ERROR: Cannot open '+ self.whitelist_file
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 
			sys.exit(-1)



if __name__ == "__main__":
	p = DetectMachineLan()
	p.DetectMachineLan()
