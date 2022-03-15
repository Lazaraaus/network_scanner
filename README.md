# Network Scanner
#### Written by: Yjaden Wood - ycw942

## How to Run This Project
In order to run the project, you need to download and navigate to the project directory. From there, optionally activate a virtual environment and then install the necessary libraries by running `pip install -r requirements.txt` or `pip3 install -r requirements.txt`. If you are using a moore machine use moore_requirements.txt. 

After the repo is cloned run `dltestssl.sh` in your terminal to download the testssl repo. Alternatively you can navigate to the repo can clone it yourself. 

The project has two folders which will populate based on information retrieved for a hosts ssl/tls certs (from testssl) and their root certificate authority in testssl_data/ and ca_info/ respectively. 

## Project Parameters
To run the project in the project directory, run the `python3 scan.py [website_list.txt] [output_file]` command. Below are more details about each of the parameters.
- `website_list.txt`: A textfile containing a list of newline separated host names to scan and gather details. We have give three test files which can be used with their respective keyword:
	- `random`: Uses the file random_websites.txt
	- `test`: Uses the file test_websites.txt
	- `popular`: Uses the file popular_websites.txt. Warning can take some time to complete. 
- `output_file`: Lists the path to an output file to which the jsonified data will be written.
- `url`: The URL of the input recipe from www.allrecipes.com.



## Attirbutions
The very awesome testssl.sh project found here: https://github.com/drwetter/testssl.sh was an instrumental part in this project! 