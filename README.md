# CVEtoTTPs
Mapping CVE to MITRE TTPs by using cross references between some vuln classifications and threat classifications, such as CVE - CWE - CAPEX - MITRE ATT&amp;CK
```
usage: cve2ttps.py [-h] [-i CVELISTFILE] [-c CVE] [-o OUTPUT] [-v] [-u]
options:
  -h, --help            show this help message and exit
  -i CVELISTFILE, --input CVELISTFILE
                        file name with CVE list
  -c CVE, --cve CVE     CVE in format CVE-XXXX-YYYY
  -o OUTPUT, --output OUTPUT
                        output file name. If not use, than print to stdout.
  -v, --verbose         enable verbose output
  -u, --update          update cve and capex files
```

Known issues: TODO
