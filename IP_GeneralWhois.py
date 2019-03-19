#!/usr/bin/python


#Scripts by @AZobec
#Objectives : give a bulk ip file to get informations such as AS description, abuse emails, geoloc to export it in maps for magic


from optparse import OptionParser
import optparse
import sys
import socket
import progressbar

from ipwhois import IPWhois
from pprint import pprint
from geoip import geolite2
from geoip import open_database


#Requires pip install progressbar2
#Requires pip install python-geoip
#Requires pip install python-geoip-geolite2

#This product includes GeoLite2 data created by MaxMind, available from
#<a href="https://www.maxmind.com">https://www.maxmind.com</a>.

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def parse_bulk(input_file, output_file,count,GeoLiteDB):

	bar = progressbar.ProgressBar(max_value=count)
	counter = 0
	fileread = open(input_file,"r")
	filewrite = open(output_file,"w")

	filewrite.write("IP,asn_description,country,lat,lon\n")
	
	for line in fileread:
		ip = line[:-1]
		if is_valid_ipv4_address(ip) == True:
			obj = IPWhois(ip)
			try:
				results = obj.lookup_whois(inc_nir=True)
				#pprint(results)
			except Exception as error:
				print ("Exception:  "+str(error))
			
			try:
				#match = geolite2.lookup(ip)
				
				with open_database(GeoLiteDB) as db:
					match = db.lookup(ip)
	
				lat = str(match.location[0])
				lon = str(match.location[1])
				country = "\""+str(match.country)+"\""
				asn_description = "\""+str(results["asn_description"].replace("\n",""))+"\""	
			
				lookup = asn_description+","+country+","+lat+","+lon
				infos = ip+","+lookup+"\n"

				#print(infos)
				counter=counter+1
				bar.update(counter)
				filewrite.write(infos)
				#print("\""+str(results["nets"][0]["description"]).replace("\n","")+"\"")
			except Exception as error:
				print("Exception:  "+str(error) +"IP buggued :"+ip)
			#filew.write(line[:-1]+","+"\""+str(results["nets"][0]["description"]).replace("\n","")+"\""+"\n")

	filewrite.close()
	fileread.close()

if __name__ == "__main__":

	usage = "Usage: %prog [options] arg1 arg2"
	arguments = dict()

	arguments["input_file"] = ""
	arguments["output_file"] = ""
	arguments["GeoDB"] = ""
	parser = optparse.OptionParser()
	parser = OptionParser(usage = usage)
	
	parser.add_option("-i", "--input", dest = 'input_file', help = "Input file of bulk IP", metavar = "FILE", default = False)
	parser.add_option("-o", "--output", dest = 'output_file', help = "Output csv file", metavar = "FILE", default = False)
	parser.add_option("-g", "--geodblite", dest = 'GeoDB', help = "GeoLite2 DB file location", metavar = "PATH", default = False)

	if len(sys.argv)==1:
		parser.print_help()
		exit()
	

	options,args = parser.parse_args()

	if options.input_file != False:
		arguments["input_file"] = options.input_file
		tempFileLen = open(arguments["input_file"])
		count = len(tempFileLen.readlines(  ))
		tempFileLen.close()
	if options.output_file != False:
		arguments["output_file"] = options.output_file
	if options.GeoDB != False:
		arguments["GeoDB"] = options.GeoDB

	if options.output_file!=False and options.input_file!=False:
		parse_bulk(arguments["input_file"],arguments["output_file"],count,arguments["GeoDB"])	
