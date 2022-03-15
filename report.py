import texttable
import sys
import json
from collections import Counter
from itertools import chain

TLS_SSL = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'SSLv2', 'SSLv3']
# FIXES (YJ) - only need to opn the json file once. Need to close file and return resources to system after opening. 
# You get the filename of the json file as 'input' you don't need add '.txt' or '.json' onto the end. 
# Syntax Errors. 
# Poor understanding of how the open function works

def main(input, output):
    #part 1
    #initialize table
    table = texttable.Texttable()
    table.set_cols_align(["r", "r", "r",
                            "r", "r", "r",
                            "r", "r", "r",
                            "r", "r", "r", "r"])
    table.set_cols_width([12, 10, 20, 15, 11, 13, 11, 5, 15, 15, 15, 5, 20])
    #add first header row
    # table.add_rows([["Website", "scan_time", "ipv4_addresses", 
    #                 "ipv6_addresses", "http_server", "insecure_http", 
    #                 "redirect_to_https", "hsts", "tls_versions", 
    #                 "root_ca", "rdns_names", "rtt_range", "geo_locations"],
    #                 ])
    #create rows array for rest of information
    info_rows = [["Website", "scan_time", "ipv4_addresses", 
                    "ipv6_addresses", "http_server", "insecure_http", 
                    "redirect_to_https", "hsts", "tls_versions", 
                    "root_ca", "rdns_names", "rtt_range", "geo_locations"]]
    #read output file (UNSURE) # I don't think you need to re-read this as we didn't close the original - Yjaden
    with open(input, 'r') as open_file:
        data_file = json.load(open_file)
        keys = list(data_file.keys())
    open_file.close 
    
    #loop through output file and append info to rows, then add that to table
    for website, data in data_file.items():
        info_rows.append([website, data["scan_time"], data["ipv4_addresses"], data["ipv6_addresses"],
                        data["http_server"], data["insecure_http"], data["redirect_to_https"], data["hsts"], 
                        data["tls_versions"], data["root_ca"], data["rdns_names"], data["rtt_range"], data["geo_locations"]])
    table.add_rows(info_rows)
    
    #part 2
    #initialize table
    table2 = texttable.Texttable()
    table2.set_cols_align(["r", "r", "r"])
    table2.set_cols_width([10, 10, 10])
    #get rtt
    rtt = []
    
    for key, info in data_file.items():
        rtt.append({
            "website": key,
            "range": info["rtt_range"],
            "minimum": info["rtt_range"][0],
        })
    
    #sort dictionary
    rtt = sorted(rtt, key=lambda item: item["minimum"])
    
    #add header row
    info_rows = [["Website", "RTT Minimum", "RTT Maximum"]]
    for website in rtt:
        info_rows.append([website["website"], website["minimum"], website["range"][1]])

    table2.add_rows(info_rows)


    # Part 3
    table3 = texttable.Texttable()
    table3.set_cols_align(["r", "r"])
    table3.set_cols_width([10, 5])
    info_rows = [["ROOT CA", "Count"]]
    cert_auths = []
    # Loop through keys
    for host in keys:
        # Add root ca to list
        cert_auths.append(data_file[host]['root_ca'])
    # Get non-duplicate list of cert_auths
    single_cert_auths = set(cert_auths)
    # Count apperances of each CA
    ca_counts = Counter(cert_auths) 
    # Loop through cert_auths
    for cert_auth in single_cert_auths:
        # Build new row
        row = [cert_auth, ca_counts[cert_auth]]
        # Append to info rows
        info_rows.append(row)

    sorted_data = sorted(info_rows[1:], key = lambda row: row[1])
    #info_rows.append(sorted_data[::-1])
    sorted_data = sorted_data[::-1]
    sorted_data.insert(0, info_rows[0])
    table3.add_rows(sorted_data)


    # Part 4
    table4 = texttable.Texttable()
    table4.set_cols_align(["r", "r"])
    table4.set_cols_width([15, 5])
    info_rows = [["SERVER", "Count"]]
    servers = []
    # Loop through keys
    for host in keys:
        # Add root ca to list
        servers.append(data_file[host]['http_server'])
    # Get non-duplicate list of cert_auths
    single_servers = set(servers)
    # Count apperances of each CA
    server_counts = Counter(servers) 
    # Loop through cert_auths
    for server in single_servers:
        # Build new row
        row = [server, server_counts[server]]
        # Append to info rows
        info_rows.append(row)
    
    sorted_data = sorted(info_rows[1:], key = lambda x: x[1])
    sorted_data = sorted_data[::-1]
    sorted_data.insert(0, info_rows[0])
    table4.add_rows(sorted_data)

 # Part 5
    table5 = texttable.Texttable()
    table5.set_cols_align(["r", "r"])
    table5.set_cols_width([10, 10])
    info_rows = [["Protocl", "Percentage of Domains Supporting"]]
    security_info = {}
    tls_ssl_info = []
    plain_http_info = []
    https_redirect_info = []
    hsts_info = []
    ipv6_info = []
    # Loop through keys and gather relevant info
    for host in keys:
        # TLS/SSL
        no_dups_info = set(data_file[host]['tls_versions'])
        tls_ssl_info.append(list(no_dups_info))
        # Plain HTTP
        #no_dups_info = set(data_file[host]['insecure_http'])
        plain_http_info.append(data_file[host]['insecure_http'])
        # HTTPS Redirect
        https_redirect_info.append(data_file[host]['redirect_to_https'])
        # HSTS
        hsts_info.append(data_file[host]['hsts'])
        # ipv6
        ipv6_info.append(data_file[host]['ipv6_addresses'])
    
    # Count tls/ssl certs using Counter and chain
    tls_ssl_counts = Counter(chain(*[x for x in tls_ssl_info]))
    tls_ssl_keys = list(tls_ssl_counts.keys())
    # Check for missing TLS/SSL protocol
    if any(TLS_SSL) not in tls_ssl_keys:
        # Set keys to master TLS/SSL protocl list
        tls_ssl_keys = TLS_SSL

    # Loop through tls/ssl protocols
    for sec_key in tls_ssl_keys:
        # Try to calc percentage supported
        try:
            percent_supp = (tls_ssl_counts[sec_key] / len(keys)) * 100
            # Append info to info_rows
            info_rows.append([sec_key, percent_supp])

        # Handle KeyError from missing protocol
        except KeyError:
            info_rows.append([sec_key, 0])

    plain_http_counts_pct = (Counter(plain_http_info)['true'] / len(keys)) * 100
    info_rows.append(['plain_http', plain_http_counts_pct])

    https_redirect_counts_pct = (Counter(https_redirect_info)['true'] / len(keys)) * 100
    info_rows.append(['https_redirect', https_redirect_counts_pct])

    hsts_counts_pct = (Counter(hsts_info)['true'] / len(keys)) * 100
    info_rows.append(['hsts', hsts_counts_pct])

    num_ipv6 = 0
    for ipv6 in ipv6_info:
        num_ipv6 += len(ipv6)
    num_ipv6_pct = (num_ipv6 / len(keys)) * 100
    info_rows.append(['ipv6', num_ipv6_pct])
    
    table5.add_rows(info_rows)


    # Write tables to file
    with open(output, "w") as outfile:
        outfile.write(table.draw())
        outfile.write("\n\n\n")
        outfile.write(table2.draw())
        outfile.write("\n\n\n")
        outfile.write(table3.draw())
        outfile.write("\n\n\n")
        outfile.write(table4.draw())
        outfile.write("\n\n\n")
        outfile.write(table5.draw())
        outfile.close()
    return table, table2
    

if __name__ == "__main__":
    input = sys.argv[1]
    outfile = sys.argv[2]
    print(input)
    print(outfile)
    info = main(input, outfile)
#     with open(outfile, 'w') as outfile:
#         outfile.write(table1.draw())
#         outfile.write(table2.draw())
   