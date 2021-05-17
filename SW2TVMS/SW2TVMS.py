# -*- coding: utf-8 -*-
import os,sys,argparse,openpyxl,re,json
from pygments.lexers.csound import newline
from prompt_toolkit.utils import is_windows
AV_BASE_VER = '14.0.8378'
FAILED = "不符合"
CHECK_TYPE = "合規"
TOOL_NAME = "軟體版本檢測"
UNUPDATED = "未更新"
MERGED_HEADER = {   'A':'Hostname',\
                    'B':'IP',\
                    'C':'OS version',\
                    'D':'Office',\
                    'E':'Adobe Reader',\
                    'F':'Adobe Reader latest',\
                    'G':'Adobe Reader status',\
                    'H':'Flash Player',\
                    'I':'Flash Player latest',\
                    'J':'Flash Player status',\
                    'K':'Java',\
                    'L':'Java latest',\
                    'M':'Java status',\
                    'N':'Antivirus'}

TVMS_HEADERS = {"A":"弱點發現時間",\
                "B":"弱點所在網路位址",\
                "C":"弱點所在網路埠號",\
                "D":"檔案名稱/URL",\
                "E":"弱點所在之網路協定",\
                "F":"弱點名稱",\
                "G":"弱點嚴重性或合規檢測結果",\
                "H":"弱點類別",\
                "I":"弱點CVE ID清單",\
                "J":"評估工具原廠之弱點編號",\
                "K":"弱點說明",\
                "L":"弱點意見",\
                "M":"弱點修補建議",\
                "N":"弱點證據描述",\
                "O":"類型(弱點或合規)"}
def is_office_phaseout(s):
    pattern = 'office\s+(95|97|2003|2007|2010)'
    return re.search(pattern,s,re.I)
def is_windows_phaseout(s):
    pattern = 'Windows\s+(7|Vista|XP|ME|2000|98|NT|95)'
    m = re.search(pattern, s, re.I)
    if m:
        return True
    else:
        pattern = 'Windows server\s+(2008|2003|2000|NT)'
        return re.search(pattern, s, re.I)
def is_antivirus_phaseout(s):
    pattern = "(?<=_).+"
    m = re.search(pattern, s)
    if m:
        return m.group(0) < AV_BASE_VER
#     AV_BASE_VER
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--read", help = "來源Excel檔案路徑")
    parser.add_argument("-o", "--output", help = "輸出TVMS檔案路徑")
    args = parser.parse_args()
    INPUT_DIR = args.read
    OUTPUT_FILE = args.output
    paths = os.listdir(INPUT_DIR)
    source_paths = {"GCBOS":"".join([os.path.join(INPUT_DIR,p) for p in paths if p.startswith("01")]),
                    "GCBSW":"".join([os.path.join(INPUT_DIR,p) for p in paths if p.startswith("02")]),
                    "MBSA":"".join([os.path.join(INPUT_DIR,p) for p in paths if p.startswith("03")])}
#----------------------------------------------------------------------------------------------------------    
    try:
        gcbos_file = openpyxl.load_workbook(source_paths['GCBOS'],read_only=False,data_only=True)
    except :
        print(f'Unable to open {source_paths["GCBOS"]}--', sys.exc_info()[0])
        raise
    ws = gcbos_file.active
    GCBOS = {}
    for row in ws.iter_rows(min_row=2): # ignore the first row
        IPs = row[0].value.split(",")
        host_name = row[1].value
        os_version = row[4].value
        for ip in IPs:
            GCBOS[ip.strip()] = {MERGED_HEADER['A']:host_name,MERGED_HEADER['C']:os_version}
    gcbos_file.close()
#----------------------------------------------------------------------------------------------------------
    MBSA = {}
    for filename in os.listdir(source_paths["MBSA"]):
        if 'adobe' in filename:
            try:
                mbsa_file = open(os.path.join(source_paths["MBSA"],filename),encoding='big5',newline='')
                lines = mbsa_file.read().splitlines()
            except :
                print(f'Unable to open {filename}--', sys.exc_info()[0])
            tmpdict = {}
            for r in range(1,len(lines)):
                [IPs,version,latest,status] = [lines[r].split(',')[i] for i in [2,3,4,5]]
                IPs = IPs.strip(";").split(";")
                for ip in IPs:
                    tmpdict[ip.strip()] = {MERGED_HEADER['E']:version,MERGED_HEADER['F']:latest,MERGED_HEADER['G']:status}
            mbsa_file.close()
            MBSA['adobe'] = tmpdict
        elif 'flashplayer' in filename:
            try:
                mbsa_file = open(os.path.join(source_paths["MBSA"],filename),encoding='big5',newline='')
                lines = mbsa_file.read().splitlines()
            except :
                print(f'Unable to open {filename}--', sys.exc_info()[0])
            tmpdict = {}
            for r in range(1,len(lines)):
                [IPs,version,latest,status] = [lines[r].split(',')[i] for i in [2,3,4,5]]
                IPs = IPs.strip(";").split(";")
                for ip in IPs:
                    tmpdict[ip.strip()] = {MERGED_HEADER['H']:version,MERGED_HEADER['I']:latest,MERGED_HEADER['J']:status}
            mbsa_file.close()
            MBSA['flashplayer'] = tmpdict
        elif 'java' in filename:
            try:
                mbsa_file = open(os.path.join(source_paths["MBSA"],filename),encoding='big5',newline='')
                lines = mbsa_file.read().splitlines()
            except :
                print(f'Unable to open {filename}--', sys.exc_info()[0])
            tmpdict = {}
            for r in range(1,len(lines)):
                [IPs,version,latest,status] = [lines[r].split(',')[i] for i in [2,3,4,5]]
                IPs = IPs.strip(";").split(";")
                for ip in IPs:
                    tmpdict[ip.strip()] = {MERGED_HEADER['K']:version,MERGED_HEADER['L']:latest,MERGED_HEADER['M']:status}
            mbsa_file.close()
            MBSA['java'] = tmpdict
            
#----------------------------------------------------------------------------------------------------------    
    GCBSW = {}
    for filename in os.listdir(source_paths["GCBSW"]):
        m = re.search('(?<=_)\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(?=_)',filename)
        if m: # filename pattern "_[IPv4]_" found 
            ip = m.group(0)
            try:
                gcbsw_file = openpyxl.load_workbook(os.path.join(source_paths["GCBSW"],filename),read_only=False,data_only=True)
                ws = gcbsw_file.active
                office = []
                Antivirus = ""
                for row in ws.iter_rows(min_row=2):
                    if row[1].value and ("OfficeScan" in row[1].value or "Apex One Security Agent" in row[1].value):
                        Antivirus = row[1].value + "_" + row[2].value
                    elif row[0].value and row[1].value and ("Microsoft" in row[0].value) and ("Office" in row[1].value):
                        office.append(row[1].value + "_" + row[2].value)
                    GCBSW[ip] =  {MERGED_HEADER['D']:";".join(office),MERGED_HEADER['N']:Antivirus}
                gcbsw_file.close()
            except:
                print(f'Unable to open {filename}--', sys.exc_info()[0])
                raise
#----------------------------------------------------------------------------------------------------------
#     with open('GCBOS','w') as f:
#         json.dump(GCBOS,f)
#     with open('GCBSW','w') as f:
#         json.dump(GCBSW,f)
#     with open('MBSA','w') as f:
#         json.dump(MBSA,f)
#     exit
#     with open('GCBOS','r') as f:
#         GCBOS = json.load(f)
#     with open('GCBSW','r') as f:
#         GCBSW = json.load(f)
#     with open('MBSA','r') as f:
#         MBSA = json.load(f)
    
    merged_data = {}
    headers = [x for x in MERGED_HEADER.values() if not x=="IP"]
    for d in GCBOS.items():
        ip = d[0]
        row = dict(zip(headers,[""]*len(headers)))
        row[MERGED_HEADER['A']] = d[1][MERGED_HEADER['A']]
        row[MERGED_HEADER['C']] = d[1][MERGED_HEADER['C']]
        
        if ip in GCBSW:
            row[MERGED_HEADER['D']] = GCBSW[ip][MERGED_HEADER['D']]
            row[MERGED_HEADER['N']] = GCBSW[ip][MERGED_HEADER['N']]
            
        if ip in MBSA['adobe']:
            row[MERGED_HEADER['E']] = MBSA['adobe'][ip][MERGED_HEADER['E']]
            row[MERGED_HEADER['F']] = MBSA['adobe'][ip][MERGED_HEADER['F']]
            row[MERGED_HEADER['G']] = MBSA['adobe'][ip][MERGED_HEADER['G']]
        if ip in MBSA['flashplayer']:
            row[MERGED_HEADER['H']] = MBSA['flashplayer'][ip][MERGED_HEADER['H']]
            row[MERGED_HEADER['I']] = MBSA['flashplayer'][ip][MERGED_HEADER['I']]
            row[MERGED_HEADER['J']] = MBSA['flashplayer'][ip][MERGED_HEADER['J']]
        if ip in MBSA['java']:
            row[MERGED_HEADER['K']] = MBSA['java'][ip][MERGED_HEADER['K']]
            row[MERGED_HEADER['L']] = MBSA['java'][ip][MERGED_HEADER['L']]
            row[MERGED_HEADER['M']] = MBSA['java'][ip][MERGED_HEADER['M']]
        merged_data[ip] = row
    
    merged_file = os.path.join(os.path.dirname(OUTPUT_FILE),"merged_"+os.path.basename(OUTPUT_FILE))
    with open(merged_file,'w') as f:
        f.write(",".join(list(MERGED_HEADER.values())) + '\n')
        for ip,v in merged_data.items():
            line = list(v.values())
            line.insert(1, ip)
            f.write(",".join(line) + '\n')
    
#     tvms_all_file = os.path.join(os.path.dirname(OUTPUT_FILE),"tvms_all_"+os.path.basename(OUTPUT_FILE))
    tvms_failed_file = OUTPUT_FILE
#     with open(tvms_all_file,'w') as f_all:
    with open(tvms_failed_file,'w') as f_failed:
        headers = list(TVMS_HEADERS.values())
#         f_all.write(",".join(headers) + '\n')
        f_failed.write(",".join(headers) + '\n')
        for ip,v in merged_data.items():
            result_list = dict(zip(TVMS_HEADERS.keys(),['']*len(TVMS_HEADERS.keys())))
            
            if is_office_phaseout(v['Office']):
                result_list['F'] = 'Office軟體版本過舊'
                result_list['K'] = v['Office']
                result_list['G'] = FAILED
            if is_windows_phaseout(v['OS version']):
                result_list['F'] = 'Windows作業系統版本過舊'
                result_list['K'] = v['OS version'] 
                result_list['G'] = FAILED
            if is_antivirus_phaseout(v['Antivirus']):
                result_list['F'] = '防毒軟體未更新'
                result_list['K'] = v['Antivirus'] 
                result_list['G'] = FAILED
            if UNUPDATED in v['Adobe Reader status']:
                result_list['F'] = 'Adobe Reader未更新'
                result_list['K'] = v['Adobe Reader status']
                result_list['G'] = FAILED
            if UNUPDATED in v['Flash Player status']:
                result_list['F'] = 'Flash Player未更新'
                result_list['K'] = v['Flash Player status']
                result_list['G'] = FAILED
            if UNUPDATED in v['Java status']:
                result_list['F'] = 'Java未更新'
                result_list['K'] = v['Java status']
                result_list['G'] = FAILED
            if result_list['G'] == FAILED:
                result_list['B'] = ip
                result_list['J'] = "軟體版本檢測" 
                result_list['O'] = CHECK_TYPE
                result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                f_failed.write(",".join(list(result_list.values()))+"\n")
    
         
if __name__ == '__main__':
    try:
        main()
    except:
        print(f'Failed--', sys.exc_info()[0])