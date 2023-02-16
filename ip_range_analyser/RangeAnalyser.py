
import collections
import getpass
import ipaddress
import json
import re
import sys
import requests
from geolite2 import geolite2
from tqdm import tqdm


class RangeAnalyser:
    ''' IP RANGE ANALYSER '''

    def __init__(self, stats=False, threshold=0.7):
        self.source_ip = None
        self.blacklist_ip = None
        self.whitelist_ip = None
        self.threshold = 0.7
        self.stats = stats



    def write_blacklist(self, filename=None):
        """
        Write blacklisted IP in file (one per line)

        :param filename: filename of output 
        :type filename: str
        """
        if(filename != None):

            with open(filename, 'w') as f:
                print('\n'.join(self.blacklist_ip), file=f)
        else:
            print('\n'.join(self.blacklist_ip), file=sys.stdin)

    def write_whitelist(self, filename=None):
        """
        Write whitelisted IP in file (one per line)

        :param filename: filename of output 
        :type filename: str
        """
        if(filename != None):

            with open(filename, 'w') as f:
                print('\n'.join(self.whitelist), file=f)
        else:
            print('\n'.join(self.whitelist), file=sys.stdin)

    def collect_ip_from_file(self, filename):
        """
        Read all IP from file (one per line)

        :param filename: filename of output 
        :type filename: str
        """

        with open(filename, 'r') as f:
            self.source_ip = self.__uniq(f.read().splitlines())

    def __apply_mask(self, ip_bin, mask):
        """
        Apply filter on ip depending of the mask( keep first n bits)

        :param ip: list of ip in binary format
        :type ip: list

        :param mask: bit that must be keep(first n bit), value between 1 and 31
        :type mask: int


        """
        return [ip_bin[i][:mask] for i in range(len(ip_bin))]

    def __uniq(self, ip):
        """
        Make list uniq
        :type ip: list
        :return : uniq ip list
        """
        return list(set(ip))

    def __convert_to_binary(self, ip):
        """
        convert ipv4 format ip in binary

        :param ip: ipv4 (ex: 128.12.254.96)

        :return: ip in binary format(ex: 10000000000011001111111001100000)
        """
        return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

    def __convert_to_ipv4(self, ip):
        """
        convert ip binary format to ipv4 format

        :param ip: binary ip (ex:10000000000011001111111001100000 )

        :return: ip in ipv4 format(ex: 128.12.254.96)

        """
        while(len(ip) != 32):
            ip += '0'

        ip = f"{ip[:8]}.{ip[8:]}"
        ip = f"{ip[:17]}.{ip[17:]}"
        ip = f"{ip[:26]}.{ip[26:]}"
        return '.'.join([str(int(x, 2)) for x in ip.split('.')])

    def __find_ip_range(self, ip_bin, mask):
        """
        Group all IP in the range found

        :param ip_bin: list of ip in binary format
        :mask: integer between 1 and 31

        :return: list of ip with a len=mask  and their percentage

        """

        interesting_ip_range = []
        ip_bin_masked = self.__apply_mask(ip_bin, mask)
        occurrences = collections.Counter(ip_bin_masked)

        for j, occ in enumerate(occurrences.most_common(len(occurrences))):
            # if mask is fill at more than (self.threshold*100)% of its capacity then we found a IP range
            if occ[1] < self.threshold*(2**(32-mask)):
                break
            #Append percentage
            percentage = (occ[1]/(2**(32-mask)))*100
            interesting_ip_range.append((occ[0], percentage, mask,))

        return interesting_ip_range

    def __delete_sub_network(self, ip_mask_parent, ip_mask_children, mask_parent_value):
        """
        Merge ip_mask_parent and ip_mask_childre

        :param ip_mask_parent: list of ip with len=mask_parent_value
        :param ip_mask_children: list of ip with len=mask_parent_value+1

        :return: ip_mask_parent + (ip_mask_children - ip_mask_children include in ip_mask_parent)
        """

        ip_mask_merged = ip_mask_parent[:]

        # Append IP only if its not include in ip_mask_parents
        for occ in ip_mask_children:
            if(occ[0][:mask_parent_value] not in [x[0] for x in ip_mask_parent]):
                ip_mask_merged.append(occ)

        return ip_mask_merged

    def analyse(self, range_min=18, range_max=30):
        """
        Process analyse of IP, find ranges, filter and sort IP, compute stats and find country

        :param range_min: max size of the range
        :param range_max: min size of the range

        """

        # Convert IP to binary data
        ip_bin = []
        ip_bin.extend(self.__convert_to_binary(self.source_ip[x])
                      for x in range(len(self.source_ip)) if(len(self.__convert_to_binary(self.source_ip[x])) == 32))

        # Run throught range_max to range_min and find the number of IP includes in, then delete IP ranges child includes in bigger IP ranges
        with tqdm(total=range_max-range_min,desc='Finding IP range') as pbar:

            j = range_max
            ip_range = self.__find_ip_range(ip_bin, j)

            while(j > range_min):
                ip_range_above = self.__find_ip_range(ip_bin, j-1)
                ip_range = self.__delete_sub_network(ip_range_above, ip_range, j-1)
                pbar.update(1)
                j -= 1


        # Sort IP in two lists, ip that actually are find in  IP ranges and the others
        ip_in_range = []
        ip_out_range = []

        with tqdm(total=len(ip_bin),desc='Filtering results') as pbar:
            for bin in ip_bin:
                is_in = False
                for network, percentage, mask, in ip_range:
                    if(bin[:mask] == network):
                        ip_in_range.append(self.__convert_to_ipv4(bin))
                        is_in = True
                        break
                if(not is_in):
                    ip_out_range.append(self.__convert_to_ipv4(bin))
                pbar.update(1)

        ip_range = [
            (f"{self.__convert_to_ipv4(bin)}/{str(mask)}", percentage)
            for (bin, percentage, mask) in ip_range
        ]


        # Compute Stats
        if self.stats:
            self._analyse(ip_in_range, ip_out_range, ip_range)
        self.blacklist_ip = [x for (x,y) in ip_range] + ip_out_range

    def _analyse(self, ip_in_range, ip_out_range, ip_range):
        locations_country = []
        locations_subdivisions = []

        # Geolocalate IP
        with tqdm(total=len(self.source_ip),desc='Processing stats') as pbar:
            for ip in self.source_ip:
                reader = geolite2.reader()
                # google ip
                match = reader.get(ip)
                if(match is not None):
                        # print(match)
                    if('country' in match):   
                        locations_country.append(match['country']['names']['fr'])

                    elif( 'continent' in match):
                        locations_country.append(match['continent']['code'])

                    if 'subdivisions' in match and 'country' in match:
                        locations_subdivisions.append(match['country']['names']['fr'] + " " + match['subdivisions'][0]['names']['en'])
                pbar.update(1)

        total = len(ip_in_range)+len(ip_out_range)
        print(f"Number IP in a range :{len(ip_in_range)}")
        print(f"Number IP out of range:{len(ip_out_range)}")
        print("Percentage : %d %%"%((len(ip_in_range)/(total))*100))
        print(f"Sample : {str(ip_range[:min(len(ip_range), 5)])}")
        print(f"Line saved :{str(len(ip_in_range) - len(ip_range))}")

        occurrences = self._find_most_common(
            locations_country,
            total,
            "Country/Continent(if country did'nt found) top results \n%s\n",
        )
        occurrences = self._find_most_common(
            locations_subdivisions, total, "Subdivisions top results \n%s\n"
        )

    # TODO Rename this here and in `analyse`
    def _find_most_common(self, arg0, total, arg2):
        result = collections.Counter(arg0)
        result = result.most_common(min(len(result), 20))
        result = [(x,round((y/total*100),1)) for (x,y) in result]
        print(arg2 % result)

        return result
