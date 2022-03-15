import subprocess
import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.reversename
import sys
from datetime import datetime, date
import time
import pprint
import requests 
import json
import os
import pandas as pd
import maxminddb
import numpy as np
import simplejson
import socket
SERVER_INFO_KEYS = ['Server', 'server', 'Via', 'via']
SITE_LIST = []
TELNET_PORTS = ['80', '443', '22']
NAME_SERVERS = ["208.67.222.222",
		"1.1.1.1",
		"8.8.8.8",
		"8.26.56.26",
		"9.9.9.9",
		"64.6.65.6",
		"91.239.100.100",
		"185.228.168.168",
		"77.88.8.7",
		"156.154.70.1",
		"198.101.242.72",
		"176.103.130.130"]
#
#  https://github.com/drwetter/testssl.sh
#
def extract_from_df(df):
	info = []
	# Iterate through rows
	for index, row in df.iterrows():
		# Check if id is a security protocol
		if row['id'] == 'SSLv2':
			# See if offered
			offer = row['finding']#.to_string()
			# If so
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				# Append to info list
				info.append('SSLv2')

		if row['id'] == 'SSLv3':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				info.append('SSLv3')

		if row['id'] == 'TLS1':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				info.append('TLSv1.0')
			
		if row['id'] == 'TLS1_1':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				info.append('TLSv1.1')

		if row['id'] == 'TLS1_2':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				info.append('TLSv1.2')

		if row['id'] == 'TLS1_3':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered' or offer == 'offered with final':
				info.append('TLSv1.3')

	return info
	# ssl3_row = df.loc[df['id'] == 'SSLv3']	
	# ssl3_offered = ssl3_row['finding'].to_string()
	# tls1_row = df.loc[df['id'] == 'TLS1']
	# tls1_offered = tls1_row['finding'].to_string()
	# tls1_1_row = df.loc[df['id'] == 'TLS1_1']
	# tls1_1_offered = tls1_1_row['finding'].to_string()
	# tls1_2_row = df.loc[df['id'] == 'TLS1_2']
	# tls1_2_offered = tls1_2_row['finding'].to_string()
	# tls1_3_row = df.loc[df['id'] == 'TLS1_3']
	# tls1_3_offered = tls1_3_row['finding'].to_string()

def main(filename):
	global SITE_LIST	
	# Create results dict
	results = {}
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

	# Non Test String
	else:
		with open(filename, 'r') as file:
			for line in file:
				contents.append(line.replace('\n', ''))
	SITE_LIST = contents
	
	# Create resolver class
	resolver = dns.resolver.Resolver(configure=True)	
	resolver.timeout = 2.0
	resolver.lifetime = 5.0
	resolver.nameservers = NAME_SERVERS
	loop = 0
	# Loop through sites
	for site in contents:		
		# Create sub dict to hold info for this site
		results[site] = {}
		# Scan Time
		d = datetime.now()
		unixtime = time.mktime(d.timetuple())
		results[site]['scan_time'] = unixtime
		# IPV4, IPV6 Address
		# Set nameserver as public DNS nameserver
		#for nameserver in NAME_SERVERS:
		#resolver.nameservers = [nameserver]
		try:
			# Try to resolve for IPV4
			answer_ipv4 = resolver.resolve(site, 'A')
		except:
			# Set value in dict to None
			results[site]['ipv4_addresses'] = []
		else:
			ipv4s = []
			for record in answer_ipv4:
				#record_tuple = (site, record.address)
				ipv4s.append(record.address)
			results[site]['ipv4_addresses'] = ipv4s
		try:
			# Try to resolve for IPV6
			answer_ipv6 = resolver.resolve(site, 'AAAA')
		except:
			# Except
			results[site]['ipv6_addresses'] = []
		else:
			ipv6s = []
			for record in answer_ipv6:
				#record_tuple = (site, record.address)#._as_ipv6_address())
				ipv6s.append(record.address)
			results[site]['ipv6_addresses'] = ipv6s

		# Sever Header
		# Build site name
		site_name = 'http://' + site + ':80'
		site_name_https = 'https://' + site 
		# Build Headers
		headers = {'Upgrade-Insecure-Requests': '1'}
		# Get headers using head method of requests class
		resp = requests.head(site_name)#, headers=headers)
		results[site]['status_code'] = resp.status_code
		# Get Headers for Server Info
		headers = resp.headers
		# Print URL
		# Check if location in headers --> indicates a redirect
		try: 
			location = headers['location']

		# KeyError aka No redirect	
		except KeyError:
			# If not, redirect is false
			location = ''
			# Check HTTPS req
			try:
				http_resp = requests.head(site_name_https, timeout=(5, 5))
			# SSL Cert Error
			except requests.exceptions.SSLError as e:
				print(e)
				results[site]['hsts'] = 'false'
			# Timeout Error
			except requests.exceptions.Timeout as e:
				print(e)
				results[site]['hsts'] = 'false'
			# HTTP Success
			else:
				print(http_resp.url)
				# Check for hsts header
				if 'Strict-Transport-Security' in http_resp.headers.keys():
					results[site]['hsts'] = 'true'
				else:
					results[site]['hsts'] = 'false'

		# Use location for HTTPS req
		else:
			try:
				location_resp = requests.head(location, headers=headers, timeout=(5, 5))#, allow_redirects=False)
			except requests.exceptions.SSLError as e:
				print(e)
				results[site]['hsts'] = 'false'
			except requests.exceptions.Timeout as e:
				print(e)
				results[site]['hsts'] = 'false'
			else:
				# Check for hsts header	
				if 'Strict-Transport-Security' in location_resp.headers.keys():
					results[site]['hsts'] = 'true'
				else:
					results[site]['hsts'] = 'false'

		# Set Location for http_redirect proof	
		results[site]['location'] = location
		
		# Check if we got 200
		if results[site]['status_code'] >= 200 and results[site]['status_code'] < 300:
			results[site]['insecure_http'] = 'true'
			results[site]['redirect_to_https'] = 'false'
		# Check if we redirected
		elif results[site]['status_code'] >= 300 and results[site]['status_code'] < 400:
			results[site]['insecure_http'] = 'true'
			results[site]['redirect_to_https'] = 'true'
	
		# Will need to conver 'NaN' to JSON null later
		server = np.nan
		for key_name in SERVER_INFO_KEYS:
			try:
				server = headers[key_name] 
			except KeyError:
				pass
		# Add Server Header to results
		results[site]['http_server'] = server

		# Check which security protocols/certs the server offers
		shell_call_str = 'testssl.sh/testssl.sh --protocols --connect-timeout 5 --openssl-timeout 5 --parallel --fast --csvfile ' + 'testssl_data/' + site + '.csv ' + site
		save_name = 'testssl_data/' + site + '.csv'
		try:
			os.system(shell_call_str)
		except:
			print("Error: Skipping testing for security protocols")
		else:
			certs = []
			#subprocess.run(['sh', 'testssl.sh/testssl.sh', '--protocols', '--jsonfile', save_name]) # Doesn't Work For Some Reason
			# Load JSON Output from shell script
			certificate_protocol_data = pd.read_csv(save_name)
			info = extract_from_df(certificate_protocol_data)
			results[site]['tls_versions'] = info

		# ROOT CERTIFICATE AUTHORITY
		host_name = site.split('.')[0]
		out_file = 'ca_info/ca_info_' + host_name + '.txt'
		shell_openssl_str = 'echo | openssl s_client -connect ' + site + ':443 >' + out_file
		try:
			exit_status = os.WEXITSTATUS(os.system(shell_openssl_str))
			print(f"Exit Status for Root CA: {exit_status}")
		except:
			print("ERROR: Skipping Root Certificate Authority")
		else:
			content = []
			line_count = 0
			with open(out_file, 'r') as file:
				for line in file:
					if line != '---\n':
						content.append(line)
					elif line == '---\n' and line_count > 1:
						break
					line_count += 1
				file.close()
			root_line = content[-1]
			root_line_split = root_line.split(',')
			for info_line in root_line_split:
				if 'O = ' in info_line:
					info = " ".join(info_line.split(" ")[3:])
					# Handle Weirdness with Baltimore Cybertrust Root CA
					if info == 'Baltimore':
						info = 'Baltimore Cybertrust Root'
					if 'i:0 =' in info:
						info = info[5:]
					results[site]['root_ca'] = info
					break
		
		# Reverse DNS Name Lookup
		reverse_names = []
		for ipv4 in results[site]['ipv4_addresses']:
			try:
				name, alias, addresslist = socket.gethostbyaddr(ipv4)
			except socket.herror as e:
				print("Error with reverse DNS lookup")
				print(e)
			else:
				reverse_names.append(name)
		results[site]['rdns_names'] = reverse_names

		# RTT using Telnet and Subprocess
		rtt_times = []
		min_time = 1000000
		max_time = -100000
		for ipv4 in results[site]['ipv4_addresses']:
			for telnet_port in TELNET_PORTS:
				telnet_shell_str = "time echo -e '\x1dclose\x0d' | telnet " +  ipv4 + " 80"
				init_time = time.time()
				result = subprocess.run(telnet_shell_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				if result.returncode == 0:
					#os.system(telnet_shell_str)
					end_time = time.time() - init_time
					if end_time < min_time:
						min_time = end_time
					if end_time > max_time:
						max_time = end_time

					# Port Satisfies telnet call, break
					break	
			
		# Add to results dict
		results[site]['rtt_range'] = [int(round(min_time * 1000)), int(round(max_time * 1000))]

		# Geolocations
		geo_locations = []
		# Open DB
		with maxminddb.open_database("geo_data/GeoLite2-City.mmdb") as reader:
			# Loop through IPs
			for ipv4 in results[site]['ipv4_addresses']:
				# Try to get info for IP
				try:
					geo_location = reader.get(ipv4)

				# Handle Error, append empty list to results
				except ValueError:
					print('Value Error - no entry for this IP in the DB\n')

				# Otherwise, try to get (city, state/province, country)
				else:
					try:
						city = geo_location['city']['names']['en']
						country = geo_location['country']['names']['en']
						state_or_province = geo_location['subdivisions'][0]['names']['en']

					# If any error, append empty list
					except KeyError:
						print("One of City, Country, or State/Province is unavailable from the DB\n")
						print("Skipping....\n")

					# Success, append info to geo_locations list as tuple
					else:
						location_str = city + ', ' + state_or_province + ', ' + country 
						geo_locations.append(location_str)

			# Set geo_locations list in dict
			results[site]['geo_locations'] = geo_locations
			# Close DB 
			reader.close()

	# Return results dict
	return results

def print_info(results):
	for site in SITE_LIST:
			# Print Results entries
			print(f"Site: {site}")
			print(f"Site Info: ")
			pprint.pprint(results[site])
			print("\n\n")
		
if __name__ == "__main__":

	filename = sys.argv[1]
	outfile = sys.argv[2]
	# Get Info Dict
	info_dict = main(filename)
	# Dump Info Dict to JSON
	json_obj = simplejson.dumps(info_dict, ignore_nan=True, indent=4)
	with open(outfile, "w") as file:
		file.write(json_obj)
	print_info(info_dict)