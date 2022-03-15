import texttable
import sys
import json

def make_report(output):
    #initialize table
    table = texttable.Texttable()
    table.set_cols_align(["r", "r", "r",
                            "r", "r", "r",
                            "r", "r", "r",
                            "r", "r", "r", "r"])
    #add first header row
    table.add_rows([["Website", "scan_time", "ipv4_addresses", 
                    "ipv6_addresses", "http_server", "insecure_http", 
                    "redirect_to_https", "hsts", "tls_versions", 
                    "root_ca", "rdns_names", "rtt_range", "geo_locations"],
                    ])
    #create rows array for rest of information
    rows = []
    #read output file (UNSURE)
    with open('output') as json_file:
        data = json.load(json_file)
    #loop through output file and append info to rows
    for website, info in data.items():
        pass
    #add rows to table
 
    
    """
    with open('output') as json_file:
        data = json.load(json_file)
        print(data)

    table = texttable.Texttable()
    table.set_cols_align(["r", "r", "r"])
    #table.set_cols_valign(["t", "m", "b"])
    table.add_rows([["Name", "Age", "Nickname"],
                    ["Mr\nXavier\nHuon", 32, "Xav'"],
                    ["Mr\nBaptiste\nClement", 1, "Baby"],
                    ["Mme\nLouise\nBourgeau", 28, "Lou\n\nLoue"]])
    #for website, info in output.items():

    print(table.draw())
    print()

    table = texttable.Texttable()
    table.set_deco(texttable.HEADER)
    table.set_cols_dtype(['t',  # text
                            'f',  # float (decimal)
                            'e',  # float (exponent)
                            'i',  # integer
                            'a']) # automatic
    table.set_cols_align(["l", "r", "r", "r", "l"])
    table.add_rows([["text",    "float", "exp", "int", "auto"],
                    ["abcd",    "67",    654,   89,    128.001],
                    ["efghijk", 67.5434, .654,  89.6,  12800000000000000000000.00023],
                    ["lmn",     5e-78,   5e-78, 89.4,  .000000000000128],
                    ["opqrstu", .023,    5e+78, 92.,   12800000000000000000000]])
    print(table.draw())
    """