#!/usr/bin/python

# Copyright (c) 2013, 2016 "Rob van Eijk", "Floor Terra", "Vincent Toubiana"
#
# Permission to use, copy, modify, and/or distribute this software for any 
# purpose with or without fee is hereby granted, provided that the above 
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH 
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY 
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, 
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR 
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
# PERFORMANCE OF THIS SOFTWARE.


import sqlite3
import json
import sys
import time
import datetime
import os
from urlparse import urlparse
from py2neo import Node, Relationship, Graph, authenticate
from py2neo.ogm import GraphObject




import sys
from urlparse import urlparse, parse_qs
from math import log, sqrt




hostcache = dict()
cookiecache = dict()
setscache = set()
usescache = set()
referscache = set()



def filter_header( key, value):
	if key in ["Referer","Host","Connection","Accept-Language","Accept-Encoding","Accept","User-Agent","Content-Length","Content-Type","Origin","X-Requested-With","If-Modified-Since","Cache-Control","Pragma"]:
		return False
	if value.startswith("http"):
		return False
	return True

def parse_headers(raw_headers):
	my_header = {}
	headers = json.loads(raw_headers)
	for x in headers:
		 if filter_header(x[0],x[1]): 
			my_header[x[0]] = x[1]
	#print my_header
	return my_header
	
def entropy(s):
    return -len(s)*sum([log(float(s.count(c))/len(s),2)*float(s.count(c))/len(s) for c in set(s)])

def get_host_str(urlstring):
    """Retrieve the host from a url string"""
    try:
        netloc = urlparse(urlstring).netloc
    except:
        print urlstring
        return ""
    if not netloc:
        return ""
    if len(netloc.split(".")) > 2:
        if netloc.split(".")[-2] == "co":  # Hack for co.uk domains
            return ".".join(netloc.split(".")[-3:])
        return ".".join(netloc.split(".")[-2:])
    return netloc

# Lookup host in the database.
# Create a node for the given hostname if it doesn't exist.
# Return the node for the given hostname
def get_or_create_host(name, origin_=0):
    global g
    global hostcache
    if hostcache.has_key(name):
        return hostcache[name]
    host = Node("Host",  name= name, origin = origin_)
    g.merge(host,"Host","name")
    hostcache[name] = g.find_one("Host", "name",name)
    return hostcache[name]

# Lookup cookie in the database.
# Create a node for the given cookie if it doesn't exist.
# Return the node for the given cookie
def get_or_create_cookie( name, value, inurl = 0 , inetag = 0):
    global g
    global cookiecache
    if cookiecache.has_key(value):
        return cookiecache[value]
    cookie = Node("Cookie", value= value, entropy=entropy(value), name = name , inurl = inurl, inetag = inetag)
    g.merge(cookie, "Cookie", "value")
    cookiecache[value] = g.find_one("Cookie", "value", value)
    return cookiecache[value]
    
# At the start of mitmproxy connect to the Neo4j database
def start():
    global g, port
    ## LOGIN/PASSWORD TO REPLACE ##

    g = Graph(host= "localhost", http_port = port, user= "neo4j", password= XXX)

   
# Called when a http response is received. 


def create_cookie_relations(cookie, host, top_host) :
	global g
	host_cookie = Relationship(host, "Uses", cookie)
	g.create(host_cookie)
	is_read_on = Relationship(cookie, "IsReadOn", top_host)
	g.create(is_read_on)
	if host != top_host:
		tophost_trackers = Relationship(host, "TracksOn", top_host)
		g.create(tophost_trackers)

def process_request( host, url, referrer, head, top_url, top_host ):
    global g
    # Get the hostname from the corresponding request
    if len(host.split(".")) > 2:
        if host.split(".")[-2] == "co": # Hack for co.uk domains
            host = ".".join(host.split(".")[-3:])
        else:
            host = ".".join(host.split(".")[-2:])
    host = get_or_create_host(host)
    top_host = get_or_create_host(top_host)
    # Store parameters in the url as session cookies
    
    headers = parse_headers(head)
    #print headers
    for key, val in headers.items():
        if key in ["Cookie","Etag"]:
			continue
        #print key + ":" + val
        if entropy(val) > 20:
			cookie = get_or_create_cookie(name = key,value=val, inurl = 1)
			if not (host, cookie) in usescache:
				create_cookie_relations(cookie, host, top_host)
				usescache.add((host, cookie))
    # Get the referer from the request
    if referrer:
        referrer = get_or_create_host(referrer)
    if "Cookie" in headers:
		for subcookie in headers["Cookie"].split("; "):
			key_c, value_c = subcookie.split("=")[0:2]
			if not value_c: continue
			if entropy(value_c) > 20:
				cookie = get_or_create_cookie(name = key_c,value=value_c)
				create_cookie_relations(cookie, host, top_host)
    # Store the ETag as a cookie
    if "ETag" in headers:
		for etag in headers["ETag"]:
			cookie = get_or_create_cookie(name="etag",value=etag, inetag = 1)
			if not cookie["inetag"]:
				cookie["inetag"]=1
				g.push(cookie)
			host_cookie = Relationship(host, "uses", cookie)
			g.create(host_cookie)
			if referrer:
					if not (cookie, referrer) in referscache:
						cookie_refer = Relationship(cookie, "refers", referrer)
						g.create(cookie_refer)
						referscache.add((cookie, referrer))
        

def get_host( url ):
	o = urlparse(url)
	return o.hostname

def run_query(db_path,arraysize=100000, start_index = 0):
	connection = sqlite3.connect(db_path)
	cursor = connection.cursor()
	sql_command = "SELECT crawl_id, url, referrer, headers, top_url, time_stamp FROM http_requests"
	cursor.execute(sql_command)
	i= 0
	while True:
			if i>= start_index:
				results = cursor.fetchmany(arraysize)
				if not results:
					break
				for row in results:
					url = row[1]
					referrer = row[2]
					headers = row[3]
					top_url = row[4]
					host = get_host(url)
					top_host = get_host(top_url)
					try:
						process_request( host, url, referrer, headers, top_url, top_host )
					except :
						print "Could not parse requst:" + host
			i = i+ arraysize
			print "The script has processed " + str(i) + " lines"
			
	connection.close()


def print_help_message():
    """ prints out the help message in the case that too few arguments are mentioned """
    print "\nMust call simple crawl script with at least one arguments: \n" \
          "The absolute directory path of the new crawl DB\n"


def main(argv):
    """ main helper function, reads command-line arguments and launches crawl """
    # filters out bad arguments
    global port
    port = 7474 
    start_index = 0
    if len(argv) < 1 :
        print_help_message()
        return
    for i in xrange(2, len(argv), 2):
        if argv[i] == "-port":
            port = int(argv[i+1])
        if argv[i] == "-start":
            start_index = int(argv[i+1])
    db_path = argv[1]  
    start()  
    run_query(db_path, 20000,start_index)




if __name__ == "__main__":
    main(sys.argv)
