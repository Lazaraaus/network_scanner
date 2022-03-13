import subprocess
import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import sys
from datetime import datetime, date
import time

def main(filename):
	d = datetime.now()
	unixtime = time.mktime(d.timetuple())
	# Create results dict
	results = {}
	results['scan_time'] = unixtime
	# create contents arr
	contents = []
	# Get list of websties
	if filename == 'popular':
		with open('popular_websites.txt', 'r') as file:
			for line in file:
				contents.append(line.replace('\n', ''))
			file.close()
	elif filename == 'random':
		with open('random_websites.txt', 'r') as file:
			for line in file:
				contents.append(line.replace('\n', ''))
			file.close()
	elif filename == 'test':
		with open('test_websites.txt', 'r') as file:
			for line in file:
				contents.append(line.replace('\n', ''))
			file.close()

	
	# Create resolver class
	resolver = dns.resolver.Resolver(configure=False)
	# Set nameserver as public DNS nameserver
	resolver.nameservers = ['8.8.8.8']
	# Loop through sites
	for site in contents:
		results[site] = {}
		try:
			# Try to resolve for IPV4
			answer_ipv4 = resolver.resolve(site, 'A')
		except:
			# Set value in dict to None
			results[site]['ipv4'] = None
		else:
			for record in answer_ipv4:
				#record_tuple = (site, record.address)
				results[site]['ipv4'] = record.address
		try:
			# Try to resolve for IPV6
			answer_ipv6 = resolver.resolve(site, 'AAAA')
		except:
			# Except
			results[site]['ipv6'] = None
		else:
			for record in answer_ipv6:
				#record_tuple = (site, record.address)#._as_ipv6_address())
				results[site]['ipv6'] = record.address
		#print(answer_ipv4)
		#print(dir(answer_ipv4))
		#print(answer_ipv6)
		#print(dir(answer_ipv6))
		#for record in answer_ipv4:
			#print(record)
		#for record in answer_ipv6:
			#print(record)
	
	print(results)	


	# code inspired by source: https://github.com/rthalley/dnspython/blob/master/examples/query_specific.py
	#query_n = dns.name.from_text(contents[0])
	#query = dns.message.make_query(query_n, dns.rdatatype.A)
	#print(query)
	#resp = dns.query.udp(query, '8.8.8.8')
	#print(resp)
	#dns_result_ipv6 = dns.resolver.query_ipv6(site, 'AAAA')
	# Do DNS Lookups
	# dns_results = []
	# # Loop through websites
	# for site in contents:
	# 	# Get Query Name
	# 	query_name = dns.name.from_text(site)
	# 	# Make Queries for ipv4, ipv6
	# 	query_ipv4 = dns.message.make_query(query_name, dns.rdatatype.A)
	# 	query_ipv6 = dns.message.make_query(query_name, dns.rdatatype.AAAA) 
	# 	# Get Responses for Queries
	# 	resp_ipv4 = dns.query.udp(query_ipv4, '8.8.8.8')
	# 	resp_ipv6 = dns.query.udp(query_ipv6, '8.8.8.8')
	# 	# Put results in a tuple
	# 	resp_tuple = (site, resp_ipv4.answer, resp_ipv6.answer)
	# 	# Append to dns results
	# 	dns_results.append(resp_tuple)
	
	# print(dns_results)
	# print(dns_results[0][1][0].to_rdataset())	
	#print(dns_results[0][1][0].full_match)
	#print(dir(dns_results[0][1][0]))
	
if __name__ == "__main__":
	filename = sys.argv[1]
	main(filename)