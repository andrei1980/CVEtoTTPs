# Find MITRE tecniques by CVE
# Ex: python cve2ttps.py -c CVE-2021-20021
# Ex: python cve2ttps.py -f cvelist.txt
# EX: python cve2ttps.py -f cvelist.txt | python3 -mjson.tool
import csv
from argparse import ArgumentParser
import json
import sys
import zipfile
import urllib.request
from urllib.error import HTTPError, URLError
import os.path
from pathlib import Path

def process_cve(_cveid, _cwe_ttps_map, _cve_dic, verbose, is_update):

    year_of_cve = _cveid.split("-")[1]
    filename = "nvdcve-1.1-" + year_of_cve + ".json"
    result = []
    if year_of_cve not in _cve_dic:
        if verbose: print("Load cve details for: %s year" % year_of_cve)
        if is_update or not os.path.isfile("./nvd/%s.zip" % filename):
            if verbose: print("Download: https://nvd.nist.gov/feeds/json/cve/1.1/%s.zip ..." % filename)
            try:
                urllib.request.urlretrieve("https://nvd.nist.gov/feeds/json/cve/1.1/%s.zip" % filename, "./nvd/%s.zip" % filename)
            except HTTPError as eh:
                if verbose: print("Http error while downloading from URL https://nvd.nist.gov/feeds/json/cve/1.1/%s.zip :\n%s" % (filename, eh))
                return result
        try:
            with zipfile.ZipFile("./nvd/%s.zip" % filename) as zf, zf.open(filename, mode='r') as cf:
                _cve_dic[year_of_cve] = json.load(cf)
        except FileNotFoundError:
            if verbose: print("No CVE details for year: %s" % year_of_cve)
            return result

    for item in _cve_dic[year_of_cve]['CVE_Items']:
        cve_id = item['cve']['CVE_data_meta']['ID']
        if cve_id == _cveid and item['cve']['problemtype']['problemtype_data'] and item['cve']['problemtype']['problemtype_data'][0]['description']:
            for cwedesc in item['cve']['problemtype']['problemtype_data'][0]['description']:
                cwedesc = cwedesc['value']
                if cwedesc == "NVD-CWE-Other" or cwedesc == "NVD-CWE-noinfo":
                    if verbose:
                        print("CWE ID is NVD-CWE-Other or NVD-CWE-noinfo. Skipp it.")
                    return
                cwe_id = cwedesc.split("-")[1]
                if verbose:
                    print('CWE ID:', cwe_id)
                if cwe_id in _cwe_ttps_map.keys():
                    result = result + _cwe_ttps_map[cwe_id]
    return result


if __name__ == "__main__":
    Path("./nvd").mkdir(parents=True, exist_ok=True)
    cwe_ttps_map = {}
    cve_dic = {}
    cve2ttps = {}
    parser = ArgumentParser(description='CVE to Mitre TTPS mapping')
    parser.add_argument("-i", "--input",
                        help="file name with CVE list", metavar="CVELISTFILE")
    parser.add_argument("-c", "--cve",
                        help="CVE in format CVE-XXXX-YYYY", metavar="CVE")
    parser.add_argument("-o", "--output",
                        help="output file name. If not use, than print to stdout.", metavar="OUTPUT")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="enable verbose output", default=False)
    parser.add_argument("-u", "--update", dest="update", action="store_true",
                        help="update cve and capex files", default=False)
    args = parser.parse_args()

    if args.update or not os.path.isfile("658.csv.zip"):
        if args.verbose: print("Download: https://capec.mitre.org/data/csv/658.csv.zip ...")
        try:
            urllib.request.urlretrieve("https://capec.mitre.org/data/csv/658.csv.zip","658.csv.zip")
        except HTTPError as eh:
            if args.verbose: print("Http error while downloading from URL  https://capec.mitre.org/data/csv/658.csv.zip. Exist.")
            sys.exit(0)

    unpacked_capex = []
    try:
        with zipfile.ZipFile('658.csv.zip') as z, z.open('658.csv', mode='r') as csv_file:
            for line in csv_file.readlines():
                unpacked_capex.append(str(line))
    except FileNotFoundError:
        if args.verbose: print("File 658.csv.zip not found. Exit.")
        sys.exit(0)

    csv_reader = csv.DictReader(unpacked_capex)
    for row in csv_reader:
        for cwe in str(row["Related Weaknesses"]).split("::"):
            if cwe:
                for ttps in str(row["Taxonomy Mappings"]).split("::"):
                    if "NAME:ATTACK:ENTRY" in ttps:
                        # print("%s -> %s" % (cwe, ttps))
                        if cwe not in cwe_ttps_map:
                            cwe_ttps_map[cwe] = []
                        cwe_ttps_map[cwe].append(ttps)

    if args.cve:
        cveid = str(args.cve).upper()
        if args.verbose:
            print("Process CVE: %s" % cveid)
        cve2ttps[cveid] = process_cve(cveid, cwe_ttps_map, cve_dic, args.verbose, args.update)
    elif args.input:
        if args.verbose:
            print("Process file: %s" % args.input)
        with open(args.input, 'r') as cvefile:
            for line in cvefile:
                cveid = line.rstrip().upper()
                if cveid:
                    if args.verbose:
                        print("Process CVE: %s" % cveid)
                    if res := process_cve(cveid, cwe_ttps_map, cve_dic, args.verbose, args.update):
                        cve2ttps[cveid] = res
    else:
        parser.print_help(sys.stderr)
        sys.exit(0)

    if args.output:
        print("Save result to: %s" % args.output)
        with open(args.output, 'w') as f:
            json.dump(cve2ttps, f)
    else:
        print(json.dumps(cve2ttps))
