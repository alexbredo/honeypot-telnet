#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.


import time, uuid
from twisted.internet import protocol, reactor
from twisted.protocols.basic import LineReceiver
from twisted.conch.telnet import TelnetProtocol

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager

'''
TODO:
 - Read User + Passwords from file
 - Emulate OS (new class -- use together with ssh-module)
   - Filesystem (read files, write files, Executables) - Pseudo-Function. Data changes in-memory only.
   - Network (ping, nslookup, traceroute, ...)
'''

class TelnetConfig(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.0'
		self.__appname = 'honeypot_telnet'
		self.port = 23
		self.hostname = 'dc1.example.com'
		self.enabled_handlers = {
			'elasticsearch': True, 
			'screen': True,
			'file': True
		}
		self.elasticsearch = {
			'host': '127.0.0.1', 
			'port': 9200, 
			'index': 'honeypot'
		}
		self.filename = 'honeypot_output.txt'
		
config = TelnetConfig()
handler = HandlerManager(config)

class SimpleTelnetSession(LineReceiver, TelnetProtocol):
	def __init__(self):
		self.session = str(uuid.uuid1())

	def connectionMade(self):
		self.__logInfo('connected', '', True)
		self.transport.write('Username: ')
		self.state = 'USERNAME'

	def connectionLost(self, reason):
		self.__logInfo('disconnected', '', True)

	def lineReceived(self, line):
		getattr(self, 'telnet_' + self.state)(line)

	def telnet_USERNAME(self, line):
		self.username = line
		self.transport.write('Password: ')
		self.state = 'PASSWORD'

	def telnet_PASSWORD(self, line):
		self.password = line
		if (self.username.strip().lower() in ['administrator','default','admin'] and self.password.strip().lower() in ['admin', 'test', 'administrator', '', '123456']):
			self.__logInfo('login', 'Credentials: ' + self.username + ':' + self.password, True)
			self.__clearTelnetScreen()
			self.transport.write('Microsoft(R) Windows NT(TM)\r\n')
			self.transport.write('(c) Copyright 1985-1993 Microsoft Corp.\r\n\r\n')
			self.transport.write('C:\users\default>')
			self.state = 'CLI'
		else:
			self.__logInfo('login', 'Credentials: ' + self.username + ':' + self.password, False)
			self.__clearTelnetScreen()
			self.transport.write('Sorry, something went wrong. Please try again.\r\n\r\n')
			self.transport.write('Username: ')
			self.state = 'USERNAME'

	def telnet_CLI(self, line):
		command = line.strip().lower()
		self.__logInfo('shell', command, False)

		if command.startswith('help'):
			 self.transport.write('Available commands are: \r\n')
			 self.transport.write(' help cls cd dir hostname type exit\r\n')
		elif command.startswith('cls'):
			 self.__clearTelnetScreen()
		elif command.startswith('dir'):
			 self.transport.write(' Datenträger in Laufwerk C: ist System\r\n')
			 self.transport.write(' Volumeseriennummer: A2F7-732F\r\n\r\n')
			 self.transport.write(' Verzeichnis von c:\users\default\r\n\r\n')
			 self.transport.write('13.04.1997  11:41	<DIR>		  .\r\n')
			 self.transport.write('21.01.2000  11:41	<DIR>		  ..\r\n')
			 self.transport.write('26.07.2003  11:41	<DIR>		  pass.txt\r\n')
		elif command.startswith('hostname'):
			 self.transport.write('%s\r\n' % config.hostname)
		elif command.startswith('type'):
			 if 'pass.txt' in command:
				 self.transport.write('Administrator:admin\r\n')
				 self.transport.write('default:\r\n')
			 else:
				 self.transport.write('File not found.\r\n')
		elif command.startswith('exit'):
			 self.transport.write('Goodbye.\r\n')
			 self.transport.loseConnection()
		elif command.startswith('cd'):
			 self.transport.write('Device not ready: I/O Error.\r\n')
		else:
			 if ('.exe' in command or '.com' in command):
				 self.transport.write('command.com: Not a valid Win32 application\r\n')
			 else:
				 self.transport.write('command.com: Command not found.\r\n')
		self.transport.write('\r\nC:\users\default>')

	def __clearTelnetScreen(self):
		self.transport.write(chr(27) + '[2J')

	def __logInfo(self, type, command, successful):
		try: # Hack: On Connection-Close socket unavailable. remember old ip.
			self.myownhost = self.transport.getHost()
		except AttributeError:
			pass # nothing

		data = {
			'module': 'TELNET', 
			'@timestamp': int(time.time() * 1000), # in milliseconds
			'sourceIPv4Address': str(self.transport.getPeer().host), 
			'sourceTransportPort': self.transport.getPeer().port,
			'type': type,
			'command': command, 
			'success': successful, 
			'session': self.session
		}
		if self.myownhost:
			data['destinationIPv4Address'] = str(self.myownhost.host)
			data['destinationTransportPort'] = self.myownhost.port

		handler.handle(data)

class TelnetFactory(protocol.Factory):
	def buildProtocol(self, addr):
		return SimpleTelnetSession()

if __name__ == '__main__':
	try:
		reactor.listenTCP(
			config.port, 
			TelnetFactory()
		)
		log.info('Server listening on Port %s.' % config.port)
		reactor.run()
	except Exception, e:
		log.error(str(e));
		exit(-1)
	log.info('Server shutdown.')