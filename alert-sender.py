#!/usr/bin/env python
# Author : Wiesław Herr (herself@makhleb.net)
# Check the included LICENSE file for licensing information
#
# Exports OSSEC alerts from the text log to a Sentry backend
##############

import time, re, os, logging, raven, sys, datetime

##############
#XXX: this should be set by command line arguments or files. maybe soon
NAME = "alerts.log"
OSSEC_CLIENT_URL = "http://XX@YY/Z"
INTERNAL_CLIENT_URL = "http://XX@YY/Z"

ossec_client = raven.Client(OSSEC_CLIENT_URL)
internal_client = raven.Client(INTERNAL_CLIENT_URL)
##############

f = open(NAME)
f.seek(os.stat(NAME)[6])

#inode numbers are used for detecting log file rotations
inode = os.stat(NAME).st_ino 
last_inode = inode

#patterns for parsing the log files
extractor = re.compile("\*\* Alert (?P<timestamp>\S+?):.*? - (?P<tags>.+?)\n\
\d{4} \S{3} \d{2} \d{2}:\d{2}:\d{2} (?P<server_name>\(\S+\) |)(?P<source>.+?)\n\
Rule: (?P<rule_num>\d+) \(level (?P<rule_severity>\d+?)\) -> '(?P<rule_name>.+?)'\n\
(?P<content>.*)", flags=re.S|re.M)

user_pattern = "User: (?P<user>\S+?)\n"
user_extrator = re.compile(user_pattern, flags=re.M)

ip_pattern = "Src IP: (?P<ip>\S+?)\n"
ip_extrator = re.compile(ip_pattern, flags=re.M)

#main read loop
while True:
	time.sleep(10)
	inode = os.stat(NAME).st_ino 
	#check if file was truncated
	if inode != last_inode:
		f.close()
		time.sleep(120)
		f = open(NAME)
		#XXX: debug
		print "ROTATED!!!!!"
	
	#XXX: debug
	print "Date: {}".format(datetime.datetime.now().strftime("%a %b %y %H:%M:%S"))
	print "inode: {}, last_inode: {}".format(inode, last_inode)
	
	last_inode = inode

	where = f.tell()
	lines = f.readlines()
	#if we didn't read any lines, we should rewind to the last good location
	if not lines:
		f.seek(where)
	else:
		try:
			content = "".join(lines)
			alerts = content.split("\n\n")
			#parse each alert - they are separated by double newlines
			for alert in alerts:
				#sometimes a blank line gets caught
				if not alert:
					continue

				#strip leading newlines, if any
				alert = alert.lstrip("\n")
				#XXX: debug
				print alert
				m_extractor = extractor.match(alert)

				content_group = m_extractor.group("content")

				#XXX: calculating the alert level. this should be parametrized
				level = "info"
				if int(m_extractor.group("rule_severity")) >= 10:
					level = "fatal"
				elif int(m_extractor.group("rule_severity")) >= 8:
					level = "error"
				elif int(m_extractor.group("rule_severity")) >= 5:
					level = "warning"

				#extract server name, if missing set the alert to local
				if m_extractor.group("server_name"):
					server = m_extractor.group("server_name").lstrip("(").rstrip(") ")
				else:
					server = "local"

				#build the message contents from the regexps	
				data={
					"logger": m_extractor.group("rule_num"),
					"server_name": server,
					"level": level,
				}
				extra={
					'source': m_extractor.group("source"),
					'tags': m_extractor.group("tags").rstrip(","),
				}

				#messages can be truncated, a workaround is to split them to parts on newlines
				if len(content_group) < 390:
					extra["full_message"] = content_group
				else:
					for (i, msg) in enumerate(content_group.split("\n")):
						extra["full_message_part_{:03}".format(i)] = msg

				#build the header
				message="{} - {}".format(server, m_extractor.group("rule_name"))

				#get the username, if any
				u_extractor = user_extrator.search(content_group)
				if u_extractor != None:
					extra["user"] = u_extractor.group('user')
					content_group = re.sub(user_pattern, "", content_group)

				#get the source ip, if any
				i_extractor = ip_extrator.search(content_group)
				if i_extractor != None:
					extra["src_ip"] = i_extractor.group('ip')
					content_group = re.sub(ip_pattern, "", content_group)

				#XXX: debug
				print ">>>>>>>"
				print "data: {}".format(data)
				print "extra: {}".format(extra)
				print "-------"

				#send the message to Sentry
				ossec_client.capture("Message", message=message, data=data, extra=extra)
		except Exception:
			#log all exceptions to sentry, for good measure
			internal_client.captureException(extra={"alert": content,})
