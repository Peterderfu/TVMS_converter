# import xml.etree.ElementTree as etree
from lxml import etree
import os
import csv
import argparse
from _io import StringIO
TVMS_FIELDS = ['弱點發現時間','弱點所在網路位址','弱點所在網路埠號','檔案名稱/URL','弱點所在之網路協定','弱點名稱','弱點嚴重性或合規檢測結果','弱點類別','弱點CVE ID清單','評估工具原廠之弱點編號','弱點說明','弱點意見','弱點修補建議','弱點證據描述','類型(弱點或合規)']
STID_ID = ['WN16-SO-000030','WN16-SO-000160','WN16-AC-000040','WN16-00-000110']
XPATH = {'time':'/html/body/div[1]/h4',
         'compliance_failed':'//*[@id="report"]/div[3]/ul/li[1]/ul/*/a',
         'compliance_passed':'//*[@id="report"]/div[3]/ul/li[3]/ul/*/a'}
def get_host_data(root):
    """Traverses the html tree and build lists of scan information
    and returns a list of lists.
    """
    
    host_data = []
    hosts = root.findall('host')
def parse_html(filename):
    """Given an HTML filename, reads and parses the HTML file"""
    parser = etree.HTMLParser()
    try:
#         tree = etree.parse(filename,parser)
        html = open(filename,encoding='utf-8')
        html_str = html.read()
        tree = etree.parse(StringIO(html_str),parser)
    except Exception as error:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(error))
        exit()
    root = tree.getroot()
    
    # read time record from HTML 
    record = root.xpath(XPATH['time'])
    if record:
        report_time = record[0].text
    else:
        print("[-] Unable to read time record from input HTML file {}.".format(filename))
    
    # read compliance failed list
    record = root.xpath(XPATH['compliance_failed'])
    if record:
        compliance_failed = []
        for r in record:
            try:
                match = STID_ID.index(r.text.split(" ",maxsplit=1)[0])
                compliance_failed.append({"STID":STID_ID[match],"HTMLID":r.attrib['href'].strip("#")})
            except ValueError as error: #
                continue #can't find desired STID in current compliance failed item, skipp it

    # read compliance passed list
    record = root.xpath(XPATH['compliance_passed'])
    if record:
        compliance_passed = []
        for r in record:
            try:
                match = STID_ID.index(r.text.split(" ",maxsplit=1)[0])
                compliance_passed.append({"STID":STID_ID[match],"HTMLID":r.attrib['href'].strip("#")})
            except ValueError as error: #
                continue #can't find desired STID in current compliance passed item, skipp it

    
    for d in compliance_failed:
        s = "//*[@id=\"" + d["HTMLID"] + "-container\"]/div[//text()=\"Hosts\"]/following-sibling::h2"
        record = root.xpath(s)
        if record:
            for r in record:
                print("{}:{}".format(d["STID"],r.text))
    pass
        
def main():
    """Main function of the script."""
    filename = "".join(args.filename)
    if not os.path.exists(filename):
        parser.print_help()
        print("\n[-] The file {} cannot be found or you do not have "
                "permission to open the file.".format(filename))
    with open(filename,encoding='utf-8') as fh:
        contents = fh.read()
        if not contents.lower().startswith('<html'):
            print("[-] Error! This input {} is not HTML format".format(filename))
            exit()
    data = parse_html(filename)
#     if args.csv:
#         parse_to_csv(data)
      
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--filename",
                        nargs='*',
                        help="Specify a file containing Nessus report of "
                             "scan in HTML format.")
    parser.add_argument("-csv", "--csv",
                        nargs='?', const='output.csv',
                        help="Specify the name of a csv file to write to")
    
    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("\n[-] Please specify an input file to parse. "
              "Use -f <nessus_scan.html> to specify the file\n")
        exit()
    if not args.csv:
        parser.print_help()
        print("\n[-] Please specify an output. "
              "Use -csv <output.csv> to specify the file\n")
        exit()
    
    csv_name = args.csv
    main()
