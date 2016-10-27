import os
import socket 
import optparse
from netaddr import *
import math

global output
output_filepath= os.getcwd()
global NetRange
NetRange = 'null'
global CIDR
CIDR = 'null'
global NetName
global Organization
global Customer
Customer='null'

def lets_roll(input_filename):
	target_list=[]
	with open(input_filename,'r') as input: 
		if os.path.isfile(input_filename):
			with open(output_filepath+'/output.csv','a') as output:
				output.write('Target,Organization,Customer,IP,CIDR,NetRange,NetName,Address,City,State,PostalCode,Country,Source\n')
				for line in input.readlines():
					target_list.append((line.split(','))[0].strip('"').strip())
				print "Fetching data for "+str(len(target_list)) 
				for target in target_list:
					(NetRange,CIDR,NetName,Organization,Customer,Address,City,State,PostalCode,Country),ip,source= whois_ip(target)
					output.write(target+','+'"'+Organization+'"'+','+'"'+Customer+'"'+','+ip+','+CIDR+','+NetRange+', '+NetName+', '+'"'+Address+'"'+', '+City+', '+State+', '+PostalCode+', '+Country+','+source+'\n')	

					percentage = (float(target_list.index(target))/len(target_list))*100
					print '[+]'+ str(percentage)+"% completed"+'\n'
		else:		
			print '[+]' + input_filename + ' :Does not exist'
			exit(0)
	

def whois_ip(target): 
	Range = []
	source ='null'
	ip = resolve(target)
#	print ip
	if ip!='null':
		whoisIP = (os.popen('whois -h whois.arin.net '+str(ip)+' | grep "OrgId\|NetRange:\|CIDR:\|NetName:\|Organization:\|inetnum:\|route:\|netname:\|descr:\|Customer\|# end\|Address:\|City:\|StateProv:\|PostalCode:\|Country\|country:"').read()).replace(" ","").split('\n')
#Below function handles three cases returned by whois. 
		if whoisIP:				#True if whois returns something.
			if "OrgId:RIPE" in whoisIP: #Case1. When whois returns query from ARIN which points to RIPE
				source='RIPE'
#				if (source=='RIPE'):
#					print 'RIPE'
				result = RIPE(whoisIP)
				return result,ip,source
			elif ("OrgId:RIPE" not in whoisIP) and (whoisIP.count('#end') ==2): #Case2.When whois returns query from ARIN having multiple datasets.
				source = 'ARIN(Returns two data sets)'
				index = whoisIP.index('#end')
				list1 = Assign(whoisIP[:index])
				list2 = Assign(whoisIP[index+1:])
				(len1,len2)=iprange(list1,list2)
				if compare(len1,len2):
					result = ARIN(list1)
				
				else:
					result = ARIN(list2)
				return result,ip,source

			elif ("OrgId:RIPE" not in whoisIP) and (whoisIP.count('#end') ==0): #Case3. When whois returns single ARIN or data from other server.
				source = "ARIN or See Organiztion column to cofirm"
				result=ARIN(whoisIP)
				return result,ip,source
			else: 								#Case4: If nothing matches above
				CIDR=NR=NN=Org=Cust=Add=City=SP=PC=Country='null'
				return (NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country),ip,source
		else:									#When whois return nothing
			CIDR=NR=NN=Org=Cust=Add=City=SP=PC=Country='null'
			return (NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country),ip,source		
	else:
		print "[+] Couldn't resolve IP for "+target+'[+]'+'\n'
		CIDR=NR=NN=Org=Cust=Add=City=SP=PC=Country='null'
		return (NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country),ip,source

#Below three function is performed when whois return twp sets of data

def Assign(bucket):
	list = []
	for data in bucket:
		list.append(data)

	return list

#This checks the NetRange from two data sets of whois and return the length
def iprange(list1,list2):
	for data in list1:
		if ("NetRange" or "netrange") in data:
			Range1 = data.split(':')[1]
			l_range1=Range1.split('-')
			IP1=list(iter_iprange(l_range1[0],l_range1[1]))
			IP_Length1= len(IP1)

	for data in list2:
		if ("NetRange" or "netrange") in data:
			Range2 = data.split(':')[1]
			l_range2 = Range2.split('-')
			IP2=list(iter_iprange(l_range2[0],l_range2[1]))
			IP_Length2=len(IP2)

	return IP_Length1,IP_Length2

#This compares two lengh of NetRange and the boolen which is utlizied in determining which data out of two should be written to csv
def compare(len1,len2):
	if (len1<len2):
		return True
	elif (len1>len2):
		return False
		
#This function extract the data from RIPE source is ARIN points to RIPE and return a list to be written to the file	
def RIPE(bucket):
#	print bucket
	NR=CIDR=NN=Org=Cust=Add=City=SP=PC=Country='null'
	count=0
	for data in bucket:
		if ("inetnum" in data):
			NR = data.split(':')[1]
	
		elif ("route" in data):
			CIDR = data.split(':')[1]
				
		elif ("netname" in data):
			NN = data.split(':')[1]

		elif (count==0) and ("descr" in data):
			Org = data.split(':')[1]
			count+=1

#		elif "Customer" in data:
#			Cust = data.split(':')[1]

		elif (count>0) and("descr" in data):
			if (count==1):
				Add1 = data.split(':')[1]
				count+=1
			elif (count >1) and (count<3):
				Add2=data.split(':')[1]
				Add=Add1+'-'+Add2
				count+=1
			elif (count==3):
				Add3=data.split(':')[1]
				Add=Add1+'-'+Add2+'-'+Add3

		elif ("country" in data):
			Country = data.split(':')[1]

#	print NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country
	return NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country	

#This function extract the data from ARIN source and return a list to be written to the file
def ARIN(bucket):
	NR=CIDR=NN=Org=Cust=Add=City=SP=PC=Country='null'
#	print bucket
	count =0
	for data in bucket:
		if ("NetRange" in data):
			NR = data.split(':')[1]
	
		elif ("CIDR" in data):
			CIDR = data.split(':')[1]
				
		elif ("NetName" in data):
			NN = data.split(':')[1]

		elif ("Organization" in data):
			Org = data.split(':')[1]

		elif "Customer" in data:
			Cust = data.split(':')[1]

		elif ("Address" in data):
			if (count==0):
				Add1 = data.split(':')[1]
				count+=1
				Add=Add1
			elif (count >0 and count<2):
				Add2=data.split(':')[1]
				Add=Add1+'-'+Add2
				count+=1
			elif (count==2):
				Add3=data.split(':')[1]
				Add=Add1+'-'+Add2+'-'+Add3
			
		elif "City" in data:
			City = data.split(':')[1]
		elif "StateProv" in data:
			SP = data.split(':')[1]
		elif "PostalCode" in data:
			PC = data.split(':')[1]
		elif ("Country" in data) or ("country" in data):
			Country = data.split(':')[1]
		elif "#end" in data:
			break
#	print NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country
	return NR,CIDR,NN,Org,Cust,Add,City,SP,PC,Country
			
def resolve(target):
	socket.setdefaulttimeout(3)
	try:			
		print "[+] Resolving IP for "+target+'[+]'
		ipv4 = socket.gethostbyname(target)
	except socket.gaierror as error:
		print error
		ipv4='null'
	return ipv4
	
def main():
	parser = optparse.OptionParser('%prog ' + '-i <input_filename>')
	parser.add_option('-i' ,dest ='input_filename', type='string', help = 'Specify input filepath')
	
	(options, args) = parser.parse_args()
	input_filename = options.input_filename
	
	checkfilepath(input_filename)
	outputfile(output_filepath+'/output.csv')
	lets_roll(input_filename)

def checkfilepath(input_filename):
	if not os.path.isfile(input_filename):
		print '[+]' + input_filename + ' :Does not exist'
		exit(0)
	return

def outputfile(outfile):
	if os.path.exists(outfile):
		os.remove(outfile)
	return
main()
