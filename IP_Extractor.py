#******************************************************************************************************************************************
#python program to extract unique ips from a file.  The idea is to open a file from a path, 
#read it, extract ips using regex, remove duplicate with set then create a list of unique ips, and return the list. 
#******************************************************************************************************************************************

import pathlib
import re

def read_content_extract_ip(file_path):
...     x = pathlib.Path(r"file_path")
...     with x.open("rt") as fh:
...         read_file = fh.read()
...         extract_ip = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", read_file)
...         ips_set = set(extract_ip)
...         ips_list = list(ips_set)
            string_list = str(ips_list)
...     return ips_list

read_content_extract_ip

