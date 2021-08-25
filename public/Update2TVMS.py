# -*- coding: utf-8 -*-
import openpyxl,sys,argparse,re,os,csv,glob
from os.path import join
MERGED_HEADER = {'A':'Hostname',\
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
VUL_NAME = {"D":"作業系統更新",\
            "E":"第三方軟體",\
            "F":"第三方軟體", \
            "G":"第三方軟體", \
            "H":"第三方軟體",\
            "I":"防毒",\
            "J":"防毒",\
            "K":"防毒",\
            "L":"第三方軟體",\
            "M":"作業系統更新"}
UNUPDATED = "未更新"
UPDATED = "已更新至最新"
KBNOTFOUND = "kbid is not found"
MALWARENOTFOUND = "未發現惡意程式"
FAILED = "不符合"
PASSED = "符合"
TOOL_NAME = "神網資產管理系統健診說明"
CHECK_TYPE = "合規"
GCB_AUDIT = 'GCB合規檢測'
MBSA = {"ADOBE":"adobe_big5.csv",\
        "FLASHPLAYER":"flashplayer_big5.csv",\
        "JAVA":"java_big5.csv",\
        "ANTIVIRUS":"antivirus_big5.csv"}
R0=R1=R2=R3=R4=R5=R6=None
AV_BASE_VER = ''
RECORD_PREFIX = ''
count = 0
def is_office_phaseout(s):
    pattern = 'office.+(95|97|2003|2007|2010)'
    return re.search(pattern,s,re.I)

def is_windows_phaseout(s):
    pattern = 'Windows.+(7|Vista|XP|ME|2000|98|NT|95|2008|2003)'
    return re.search(pattern, s)

def getRecSeq(count):
    global RECORD_PREFIX
#     return "{}{:0>10d}".format(RECORD_PREFIX,count)
    return ""
def csv2exel(csvfile):
    wb = openpyxl.Workbook()
    ws = wb.active

    with open(csvfile,newline='') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            ws.append(row)
    return wb
def init_input(input_dir):
    global R0,R1,R2,R3,R4,R5,R6
     #檢驗資料夾結構     
    if not os.path.isdir(input_dir): 
        sys.exit(f"資料夾:{input_dir} 不存在")
    subdirs = sorted(os.listdir(input_dir))
    if len(subdirs) == 0:
        sys.exit(f"{input_dir}內無資料夾")
    if not (subdirs[0].startswith("01_") and \
            subdirs[1].startswith("02_") and \
            subdirs[2].startswith("03_") and \
            subdirs[3].startswith("04_")):
        sys.exit(f"{input_dir} 內資料夾名稱不符-請用 以下名稱\n\
                    01_伺服器更新報表\n\
                    02_軟體版本更新報表\n\
                    03_作業系統版本報表\n\
                    04_MBSA版本報表")
    subdirs = [os.path.normpath(join(input_dir,d)) for d in subdirs]
    
    #開啟伺服器更新報表
    R0 = os.listdir(subdirs[0])
    try:
        if (len(R0) == 0):
            sys.exit(f"\"{subdirs[0]}\" 資料夾內沒有更新報表檔案")
        if not (len(R0) == 1):
            sys.exit(f"\"{subdirs[0]}\" 資料夾內應僅有1個更新報表檔案")
    except SystemExit as e:
        print(str(e))
        exit
    R0 = os.path.normpath(join(subdirs[0],R0[0]))
    [_,ext]=os.path.splitext(R0)
    if ext=='.csv':
        R0 = csv2exel(R0)
    else:
        try:
            R0 = openpyxl.load_workbook(R0,read_only=False,data_only=True)
        except :
            print(f'無法開啟伺服器更新報表檔案 {R0}--', sys.exc_info()[0])
            exit
        
    #開啟MBSA版本報表
    temp = os.listdir(subdirs[1])
    try:
        if (len(temp) == 0):
            sys.exit(f"\"{subdirs[1]}\" 資料夾內沒有MBSA版本報表檔案")
        for t in list(MBSA.values()):
            if not (t in temp):
                sys.exit(f"\"{subdirs[1]}\" 資料夾內沒有MBSA版本報表檔案: {t}")
    except SystemExit as e:
        print(str(e))
        exit
    try:
        R1 = os.path.normpath(join(subdirs[1],MBSA['ADOBE']))
        [_,ext]=os.path.splitext(R1)
        if ext=='.csv':
            R1 = csv2exel(R1)
        else:            
            R1 = open(R1,encoding='big5',newline='')
        R2=os.path.normpath(join(subdirs[1],MBSA['FLASHPLAYER']))
        [_,ext]=os.path.splitext(R2)
        if ext=='.csv':
            R2 = csv2exel(R2)
        else:    
            R2 = open(R2,encoding='big5',newline='')
        R3 = os.path.normpath(join(subdirs[1],MBSA['JAVA']))
        [_,ext]=os.path.splitext(R3)
        if ext=='.csv':
            R3 = csv2exel(R3)
        else:    
            R3 = open(R3,encoding='big5',newline='')
        R4 = os.path.normpath(join(subdirs[1],MBSA['ANTIVIRUS']))
        [_,ext]=os.path.splitext(R4)
        if ext=='.csv':
            R4 = csv2exel(R4)
        else:    
            R4 = open(R4,encoding='big5',newline='')
    except :
        print(f'無法開啟MBSA版本報表檔案 --', sys.exc_info()[0])
        exit
    
    #開啟軟體版本更新報表
    R5 = os.listdir(subdirs[2])
    try:
        if (len(R5) == 0):
            sys.exit(f"\"{subdirs[5]}\" 資料夾內沒有軟體版本報表檔案")
    except SystemExit as e:
        print(str(e))
        exit
    R5 = [os.path.normpath(join(subdirs[2],f)) for f in R5]
    
    #開啟作業系統版本報表
#     R6 = os.listdir(subdirs[3])
    R6 = glob.glob(subdirs[3]+"/*.xl*")
    try:
        if (len(R6) == 0):
            sys.exit(f"\"{subdirs[3]}\" 資料夾內沒有作業系統版本檔案")
#         if not (len(R6) == 1):
#             sys.exit(f"\"{subdirs[3]}\" 資料夾內應僅有1個作業系統版本檔案")
    except SystemExit as e:
        print(str(e))
        exit    
    R6 = os.path.normpath(join(subdirs[3],R6[0]))
    try:
        R6 = openpyxl.load_workbook(R6,read_only=False,data_only=True)
    except :
        print(f'無法開啟作業系統版本報表檔案 {R6}--', sys.exc_info()[0])
        exit
def process_R0(R0):
    global count
    output = []
    ws = R0.active
    for cols in ws['D:E']: #依序讀取D,E欄的儲存格
        for cell in cols:
            if cell.row == 1:
                continue # skip the first row
            else:
                if (UNUPDATED in cell.value) or (KBNOTFOUND in cell.value): #儲存格中有  【未更新】 或 【kbid is not found】
                    result_list = dict(zip(TVMS_HEADERS.keys(),['']*len(TVMS_HEADERS.keys())))
                    IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                    result_list['H'] = VUL_NAME[cell.column_letter]
                    result_list['G'] = FAILED                    
                    m = re.search("(?<=:).+(?=;)", cell.value)
                    if m: # UNUPDATED
                        s = ";".join(["KB"+i.strip() for i in m.group(0).split(";")])
                        result_list['N'] = "目前版本：未更新" + s
                        result_list['M'] = "更新至" + s + "或以上版本"
                    
                    m = re.search(KBNOTFOUND, cell.value)
                    if m: # KBNOTFOUND
                        result_list['N'] = m.group(0)
                        result_list['M'] = "Windows update安全性更新至最新"
                    
                    result_list['K'] = "作業系統安全性更新編號"
                    result_list['O'] = CHECK_TYPE
                    result_list['F'] = GCB_AUDIT
                    for ip in IP:
                        result_list['J'] = getRecSeq(count+1)
                        result_list['B'] = ip
                        result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                        output.append(",".join(list(result_list.values())))
                        count = count + 1
                else:
                    result_list = dict(zip(TVMS_HEADERS.keys(),['']*len(TVMS_HEADERS.keys())))
                    IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                    result_list['H'] = VUL_NAME[cell.column_letter]
                    result_list['G'] = PASSED
                    result_list['N'] = "已更新至最新版本"
                    result_list['M'] = "已更新至最新版本，無修補建議"
#                     m = re.search("(?<=:).+(?=;)", cell.value)
#                     if m: # UNUPDATED
#                         s = ";".join(["KB"+i.strip() for i in m.group(0).split(";")])
#                         result_list['N'] = "目前版本：未更新" + s
#                         result_list['M'] = "更新至" + s + "或以上版本"
#                     
#                     m = re.search(KBNOTFOUND, cell.value)
#                     if m: # KBNOTFOUND
#                         result_list['N'] = m.group(0)
#                         result_list['M'] = "Windows update安全性更新至最新"
                    
                    result_list['K'] = "作業系統安全性更新編號"
                    result_list['O'] = CHECK_TYPE
                    result_list['F'] = GCB_AUDIT
                    for ip in IP:
                        result_list['J'] = getRecSeq(count+1)
                        result_list['B'] = ip
                        result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                        output.append(",".join(list(result_list.values())))
                        count = count + 1
    return output


def process_R1(R1):
    global count
    output = []
    ws = R1.active
    for cell in ws['F']:
        if cell.row == 1:
            continue  # skip the first row
        else:
            if UNUPDATED in cell.value:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['F']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本：Adobe Reader " + ws[f'E{cell.row}'].value
                result_list['M'] = "更新至{}或以上版本".format(ws[f'D{cell.row}'].value)
                result_list['K'] = "Adobe Reader未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['F']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "Adobe Reader未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def process_R2(R2):
    global count
    output = []
    ws = R2.active
    for cell in ws['F']:
        if cell.row == 1:
            continue  # skip the first row
        else:
            if UNUPDATED in cell.value:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['G']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本：Flash Player " + ws[f'E{cell.row}'].value
                result_list['M'] = "建議移除軟體"
                result_list['K'] = "Flash Player未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['G']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "Flash Player未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def process_R3(R3):
    global count
    output = []
    ws = R3.active
    for cell in ws['F']:
        if cell.row == 1:
            continue  # skip the first row
        else:
            if UNUPDATED in cell.value:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['H']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本：Java " + ws[f'E{cell.row}'].value
                result_list['M'] = "更新至{}或以上版本".format(ws[f'D{cell.row}'].value)
                result_list['K'] = "Java未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['H']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "Java未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def process_R4(R4):
    global count
    output = []
    ws = R4.active
    for cell in ws['F']: #check "防毒軟體病毒碼未更新"
        if cell.row == 1:
            continue  # skip the first row
        else:
            if UNUPDATED in cell.value:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['K']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本： " + ws[f'E{cell.row}'].value
                result_list['M'] = "更新至{}或以上版本".format(ws[f'D{cell.row}'].value)
                result_list['K'] = "防毒軟體病毒碼更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['K']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "防毒軟體病毒碼更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    
    for cell in ws['F']: # check "防毒軟體未安裝"
        if cell.row == 1:
            continue  # skip the first row
        else:
            if cell.value == "":
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['J']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本：未發現防毒軟體"
                result_list['M'] = f'安裝本府趨勢防毒軟體{AV_BASE_VER}版本'
                result_list['K'] = "防毒軟體未安裝"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'C{cell.row}'].value.strip(";").split(";")
                result_list['H'] = VUL_NAME['J']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "防毒軟體未安裝"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def process_R5(R5):
    global count
    output = []
    for f in R5:
        m = re.search('(?<=_)\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}.*(?=_)', f)
        if m:  # filename pattern "_[IPv4]_" found 
            IP = m.group(0).split(',')
        else:
            sys.exit('No IP pattern found in {f}')
            raise

        try:
            r = openpyxl.load_workbook(f,read_only=False,data_only=True)
        except :
            print(f'無法開啟軟體版本更新報表檔案 --', sys.exc_info()[0])
            exit
        ws = r.active
#         av_ver = [] # antivirus software versions
        av_ver = {}
        office_ver = [] #Office versions
        for cell in ws['B']: #check "防毒軟體未更新" & "Office軟體版本過舊"
            if cell.row == 1:
                continue  # skip the first row
            else:
#                 if ("Trend Micro Apex One Security Agent" in cell.value) or ("OfficeScan" in cell.value):
#                     av_ver.append(ws[f'C{cell.row}'].value)
                if ("Trend Micro Apex One Security Agent" in cell.value):
                    av_ver.update({'Apex':ws[f'C{cell.row}'].value})
                if ("OfficeScan" in cell.value):
                    av_ver.update({'Officescan':ws[f'C{cell.row}'].value})
                if ("office" in cell.value) and not ("OfficeScan" in cell.value):
                    office_ver.append(cell.value)
                    
        if len(av_ver) > 0:
#             if AV_BASE_VER > sorted(av_ver)[-1]: # av version smaller than required
            if AV_BASE_VER > sorted(av_ver.items())[0][-1]: # get Apex'ver insted of Officescan's ver and compare version smaller than required
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                result_list['H'] = VUL_NAME['I']
                result_list['G'] = FAILED
#                 result_list['N'] = "目前版本： " + sorted(av_ver)[-1]
                result_list['N'] = "目前版本： " + sorted(av_ver.items())[0][-1]
                result_list['M'] = f'安裝本府趨勢防毒軟體{AV_BASE_VER}版本'
                result_list['K'] = "防毒軟體未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                result_list['H'] = VUL_NAME['I']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "防毒軟體未更新"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
        
        for v in office_ver:
            if is_office_phaseout(v):
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                result_list['H'] = VUL_NAME['L']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本： " + v
                result_list['M'] = "更新至Microsoft Office 2013或以上"
                result_list['K'] = "Office應用程式安全性更編號"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                result_list['H'] = VUL_NAME['L']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "Office應用程式安全性更編號"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def process_R6(R6):
    global count
    output = []
    ws = R6.active
    for cell in ws['E']: #check "Windows作業系統版本過舊"
        if cell.row == 1:
            continue  # skip the first row
        else:
            if is_windows_phaseout(cell.value):
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'A{cell.row}'].value.split(",")
                result_list['H'] = VUL_NAME['M']
                result_list['G'] = FAILED
                result_list['N'] = "目前版本： " + ws[f'E{cell.row}'].value
                result_list['M'] = "更新至Microsoft Windows Server 2012或以上"
                result_list['K'] = "作業系統安全性更新編號"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
            else:
                result_list = dict(zip(TVMS_HEADERS.keys(), [''] * len(TVMS_HEADERS.keys())))
                IP = ws[f'A{cell.row}'].value.split(",")
                result_list['H'] = VUL_NAME['M']
                result_list['G'] = PASSED
                result_list['N'] = "已更新至最新版本"
                result_list['M'] = "已更新至最新版本，無修補建議"
                result_list['K'] = "作業系統安全性更新編號"
                result_list['O'] = CHECK_TYPE
                result_list['F'] = GCB_AUDIT
                for ip in IP:
                    result_list['J'] = getRecSeq(count+1)
                    result_list['B'] = ip
                    result_list = dict(sorted(result_list.items(), key=lambda item: item[0]))
                    output.append(",".join(list(result_list.values())))
                    count = count + 1
    return output
def getMBSA(file_mbsa):
    MBSA = {}
    for f in file_mbsa.keys():
        ws = file_mbsa[f][0].active
        tmpdict = {}
        for row in ws.iter_rows(min_row=2):
            [IPs,latest,version,status] = [row[2].value,row[3].value,row[4].value,row[5].value]
            IPs = IPs.strip(";").split(";")
            for ip in IPs:
                tmpdict[ip] = {file_mbsa[f][1][0]:version,file_mbsa[f][1][1]:latest,file_mbsa[f][1][2]:status}
        MBSA[f] = tmpdict
    return MBSA
def getGCBSW(file_gcbsw):
    GCBSW = {}
    for filename in file_gcbsw:
        m = re.search('(?<=_)\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}.*(?=_)',filename)
        if m: # filename pattern "_[IPv4]_" found 
            ip = m.group(0)
            try:
                f = openpyxl.load_workbook(filename,read_only=False,data_only=True)
                ws = f.active
                office = []
                Antivirus = ""
                for row in ws.iter_rows(min_row=2):
                    if row[1].value and ("OfficeScan".upper() in row[1].value.upper() or "Apex One Security Agent".upper() in row[1].value.upper()):
                        Antivirus = row[1].value + "_" + row[2].value
                    elif row[0].value and row[1].value and ("Microsoft" in row[0].value) and ("Office" in row[1].value):
                        office.append(row[1].value + "_" + row[2].value)
                    IPs = ip.split(",")
                    for p in IPs:
                        GCBSW[p] =  {MERGED_HEADER['D']:";".join(office),MERGED_HEADER['N']:Antivirus}
                f.close()
            except:
                print(f'Unable to open {filename}--', sys.exc_info()[0])
                raise
    return GCBSW
def getGCBOS(file_gcbos):
    GCBOS = {}
    ws = file_gcbos.active    
    for row in ws.iter_rows(min_row=2): # ignore the first row
        IPs = row[0].value.split(",")
        host_name = row[1].value
        os_version = row[4].value
        for ip in IPs:
            GCBOS[ip.strip()] = {MERGED_HEADER['A']:host_name,MERGED_HEADER['C']:os_version}
    return GCBOS
def getmerged_data(GCBOS,GCBSW,MBSA):
    merged_data={}
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
    return merged_data

def main():
    global AV_BASE_VER,RECORD_PREFIX
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--read", help = "來源檔案路徑")
    parser.add_argument("-o", "--output", help = "輸出TVMS檔案路徑")
    parser.add_argument("-n", "--number",help = "評估工具原廠之弱點編號",default="")
    parser.add_argument("-a", "--version",help = "防毒軟體基準版本",default='14.0.9204')
    parser.add_argument("-m", "--merge",help = "產生彙整檔案",action="store_true",default=False)
    
    args = parser.parse_args()
    INPUT_DIR = os.path.abspath(args.read)
    OUTPUT_DIR      = args.output
    OUTPUT_FILE     = os.path.join(OUTPUT_DIR,"TVMS_Winserv_" + os.path.basename(INPUT_DIR)+".csv")
    AV_BASE_VER     = args.version
    RECORD_PREFIX   = args.number
    if args.merge:
        MERGE_FILE = os.path.join(OUTPUT_DIR,"MERGED_" + os.path.basename(INPUT_DIR)+".csv")
    else:
        MERGE_FILE = None
    
    init_input(INPUT_DIR) # read input files
    
    if MERGE_FILE:
        try:
            merged_file = open(MERGE_FILE,encoding='utf-8-sig',mode='w')
            merged_file.write(",".join(list(MERGED_HEADER.values())) + '\n')
        except :
            print(f'Unable to open {MERGED_FILE}--', sys.exc_info()[0])
            raise
        MBSA = getMBSA({'adobe':        (R1,[MERGED_HEADER['E'],MERGED_HEADER['F'],MERGED_HEADER['G']]), \
                        'flashplayer':  (R2,[MERGED_HEADER['H'],MERGED_HEADER['I'],MERGED_HEADER['J']]), \
                        'java':         (R3,[MERGED_HEADER['K'],MERGED_HEADER['L'],MERGED_HEADER['M']])})
        GCBSW = getGCBSW(R5)
        GCBOS = getGCBOS(R6)
        merged_data = getmerged_data(GCBOS,GCBSW,MBSA)
        for ip,v in merged_data.items():
            line = list(v.values())
            line.insert(1, ip)
            merged_file.write(",".join(line) + '\n')
        merged_file.close()
    
    #開啟輸出檔案
    try:
        output_file = open(OUTPUT_FILE,encoding='utf-8-sig',mode='w')
    except :
        print(f'Unable to open {OUTPUT_FILE}--', sys.exc_info()[0])
        raise
    output_file.write(",".join(list(TVMS_HEADERS.values()))+"\n")
    
    output = []
    #挑出【作業系統安全性更新編號】 & 【Office應用程式安全性更新編號】列
    output.extend(process_R0(R0))
    #挑出【Adobe Reader未更新】列
    output.extend(process_R1(R1))
    #挑出【Flash Player未更新】列
    output.extend(process_R2(R2))
    #挑出【Java未更新】列
    output.extend(process_R3(R3))
    #挑出【防毒軟體病毒碼未更新】& 【防毒軟體未安裝】列
    output.extend(process_R4(R4))
    # 挑出【防毒軟體未更新】& 【Office軟體版本過舊】列
    output.extend(process_R5(R5))
    # 挑出【Windows作業系統版本過舊】列
    output.extend(process_R6(R6))
    output_file.write("\n".join(output))
    output_file.close()
    
    
    
if __name__ == '__main__':
    try:
        main()
    except:
        print(f'Failed--', sys.exc_info()[0])