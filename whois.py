import os
from socket import gethostbyname, gaierror
import optparse

def lets_roll(input_filename):
	with open(input_filename,'r') as input: 
		if os.path.exists(input_filename+'.csv'):
			os.remove(input_filename+'.csv')

		with open(input_filename+'.csv','a') as output:
			output.write('Target,Organization,IP,CIDR,NetRange\n')
			for line in input.readlines():
				target = (line.split(','))[0].strip('"')
				organization = whois_domain(target)
				(NetRange,CIDR,ip) = whois_ip(target)
				output.write(target+','+organization+','+ip+','+CIDR+','+NetRange+'\n')
		output.close()
	input.close()
		
def whois_domain(target):
	print "#1#Fetching whois for "+target
	try:
		whois_domain = (os.popen('whois '+target+' | grep "Registrant Organization"').read()).replace(" ","").split('\n')
		organization = whois_domain[0].split(':')[1]

	except IndexError:organization='null'
	return organization

def whois_ip(target):
	ip = resolve(target)
	if ip!='null':
		whoisIP = (os.popen('whois '+str(ip)+' | grep "CIDR\|NetRange"').read()).replace(" ","").split('\n')
		NetRange = whoisIP[0].split(':')[1]
		CIDR = whoisIP[1].split(':')[1]
	else:
		print "#3#Couldn't resolve IP for "+target
		CIDR=NetRange='null'
		
	return NetRange,CIDR,ip
			
def resolve(target):
	try:
		print "#2#Resolving IP "+target
		ipv4 = gethostbyname(target)
	except gaierror:
		ipv4='null'
	return ipv4
	
def main():
	parser = optparse.OptionParser('%prog ' + '-i <input_filename>')
	parser.add_option('-i' ,dest ='input_filename', type='string', help = 'Specify input filepath')
	
	(options, args) = parser.parse_args()
	input_filename = options.input_filename
	
	checkfilepath(input_filename)
	lets_roll(input_filename)

def checkfilepath(input_filename):
	if not os.path.isfile(input_filename):
		print '[+]' + input_filename + ' :Does not exist'
		exit(0)

	if not os.access(input_filename,os.R_OK):
		print '[+] '+ input_filename + ' Access Denied'
		exit(0)
	return
	
main()
