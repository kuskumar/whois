# whois
Python code to fetch whois data for list of host and IP. This tool runs on Linux/Kali box.

# Description

The code has been developed for purpose of iterating through a file containing list of hostname for which whois data needs to be extracted.Code takes a file in csv/text format then iterate through each hostname and extract the relevant data from ARIN adn RIPE database and store the data in output.csv format.The code can be modified as per user needs.

# Arguments

Code takes two arguments which is full input file path.

# Help
python whois.py --help

# Usages
python whois.py -i inputfilename

# Prerequiste
You need to install netaddr package. Fire command "pip install netaddr"
