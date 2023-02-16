IP_RANGE_ANALYSER
------------
This tool is designed to identify IP ranges within a set of IP addresses. If a certain percentage of IP addresses, 
as defined by the 'threshold' parameter, are found within the same range, the tool can convert all of the IP addresses to that range. 
This can help reduce the size of a blacklist by consolidating similar IP addresses into ranges. Using pypy3 can improve performance by up to 5 times compared to standard CPython




Usage
------------
To launch run : ```python ip_range_analyser/run_interactive.py --file <ip.txt> --output <out.txt> --stats```

