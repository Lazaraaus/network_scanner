import subprocess
import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import sys
from datetime import datetime, date
import time
import pprint
import requests 
import json
import os
import pandas as pd
SERVER_INFO_KEYS = ['Server', 'server', 'Via', 'via']
SITE_LIST = []
def extract_from_df(df):
	info = []
	# Iterate through rows
	for index, row in df.iterrows():
		# Check if id is a security protocol
		if row['id'] == 'SSLv2':
			# See if offered
			offer = row['finding']#.to_string()
			print(offer)
			# If so
			if offer == 'offered (deprecated)' or offer == 'offered':
				# Append to info list
				info.append('SSLv2')

		if row['id'] == 'SSLv3':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered':
				info.append('SSLv3')

		if row['id'] == 'TLS1':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered':
				info.append('TLSv1.0')
			
		if row['id'] == 'TLS1_1':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered':
				info.append('TLSv1.1')

		if row['id'] == 'TLS1_2':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered':
				info.append('TLSv1.2')

		if row['id'] == 'TLS1_3':
			offer = row['finding']
			if offer == 'offered (deprecated)' or offer == 'offered':
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
	SITE_LIST = contents
	
	# Create resolver class
	resolver = dns.resolver.Resolver(configure=False)
	# Set nameserver as public DNS nameserver
	resolver.nameservers = ['8.8.8.8']
	loop = 0
	# Loop through sites
	for site in contents:
		# IPV4, IPV6 Address
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
		print(f"url: {resp.url}")
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
			print(f"Location {location}")
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
		server = 'NaN'
		for key_name in SERVER_INFO_KEYS:
			try:
				server = headers[key_name] 
			except KeyError:
				pass
		# Add Server Header to results
		results[site]['Server'] = server

		# Check which security protocols/certs the server offers
		shell_call_str = 'testssl.sh/testssl.sh --protocols --csvfile ' + 'testssl_data/' + site + '.csv ' + site
		save_name = 'testssl_data/' + site + '.csv'
		os.system(shell_call_str)
		certs = []
		#subprocess.run(['sh', 'testssl.sh/testssl.sh', '--protocols', '--jsonfile', save_name]) # Doesn't Work For Some Reason
		# Load JSON Output from shell script
		certificate_protocol_data = pd.read_csv(save_name)
		info = extract_from_df(certificate_protocol_data)
		results[site]['tls_versions'] = info


for site in SITE_LIST:
		# Print Results entries
		print(f"Site: {site}")
		print(f"Site Info: ")
		pprint.pprint(results[site])
		print("\n\n")
	
	
if __name__ == "__main__":
	filename = sys.argv[1]
	# # Sever Header
	# # Build site name
	# site_name = 'http://uchicago.edu'
	# # Build Headers
	# headers = {'Upgrade-Insecure-Requests': '1'}
	# # Get headers using head method of requests class
	# resp = requests.get(site_name, headers=headers)
	# print(resp.headers)
	# print(resp.status_code)
	# print(resp.url)
	#temp = input("INput something to continue....")

	main(filename)