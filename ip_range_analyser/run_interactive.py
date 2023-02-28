import sys
import getpass
from RangeAnalyser import RangeAnalyser
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='')
    
    parser.add_argument("--stats", action="store_true",
                        help="Compute stats")
    
    parser.add_argument('--threshold', dest='threshold', default=0.7, type=int, required=False,
                        help='Threshold ip range (must be between 0.5 and 1)')


    parser.add_argument('--range', dest='range', default=None, type=int, required=False,
                        help='range',nargs=2, metavar=('min','max'))

    parser.add_argument("--file", dest='file',
                        required=True, default=False, type=str, help="Input file ip source")
    
    parser.add_argument("--output", dest='output',
                        required=False, default=False, type=str, help="Output File destination (blacklist)")


    args = parser.parse_args()
    rangeAnalyser = RangeAnalyser(args.stats)

    rangeAnalyser.collect_ip_from_file(args.file)
    rangeAnalyser.analyse()
    if(args.output):
        rangeAnalyser.write_blacklist(args.output)
        

