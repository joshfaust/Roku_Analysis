import pandas as pd
from dateutil import parser
from tqdm import tqdm
import os
import glob
import csv
import socket


LOGS_FILE_PATH = '/opt/Roku_Analysis/logs'
CSV_FILE_PATH = '/opt/Roku_Analysis/all_logs.csv'
ROKU_IPS = ['192.168.1.58','192.168.1.99','192.168.1.209']
cooper = '34.224.239.208'
scribe = '52.21.174.189'
liberty = '52.6.86.101'


def logsToCSV():
    print("[+] Translating log to CSV")
    log_file = open(CSV_FILE_PATH, "w", newline='')
    csv_w = csv.writer(log_file)
    path, dirs, files = next(os.walk(LOGS_FILE_PATH))
    log_num = len(files)
    file_num = 0

    for filename in glob.glob(os.path.join(LOGS_FILE_PATH, '*.txt')):       # Find all files in path with .txt
        print("[i] Analyzing %s" % filename.strip())
        data_file = open(filename, "r")
        file_num +=1

        with open(filename, "r") as f:
            file_length = len(f.readlines())
        f.close()
        pbar = tqdm(total=file_length)

        for line in data_file:         
            new_line = line.strip().split(" ")
            date = str("%s %s %s" % (new_line[0], new_line[1], new_line[2])).strip()
            date = parser.parse(date)
            ip =str(new_line[5]).partition("/")
            ip = str(ip[0]).strip()
            try:
                url = str(new_line[7]).strip()
            except:
                url = None
            csv_w.writerow([date,ip,url])
            pbar.update(1)
        pbar.close()

        print(file_num)
        print(log_num)
        if (file_num == log_num):
            os.system("clear")


def uniqueIPCheck():
    data = open("wireshark.csv", "r")
    unique_ips = []
    df = pd.DataFrame(columns=["IP","HOST"])
    for line in data:
        dst_ip = line.split(",")
        dst_ip = str(dst_ip[3]).strip('"').strip()
        if (dst_ip not in unique_ips and dst_ip.isalpha() == False):
            unique_ips.append(dst_ip)
    print("Number of Unique IPs: %s" % str(len(unique_ips)))
    print("[+] Mapping IP to Hostname/Provider")
    print(unique_ips)
    df_index = 1

    for i in range(0, len(unique_ips)):

        try:
            host = (socket.gethostbyaddr(unique_ips[i]))[0]
            if (len(df) == 0):
                df.loc[0] = [unique_ips[i], host]
            else:
                df.loc[df_index] = [unique_ips[i], host]
                df_index += 1
        except Exception as e:
            print(e)



def RokuSearch():
    df = pd.read_csv(CSV_FILE_PATH, names=['Date', 'IP','URL'])
    IP_records = df.loc[df['IP'].isin(ROKU_IPS)]
    finalRecord = IP_records[IP_records['URL'].str.contains('roku')]

    finalRecord.to_csv('roku_logs.csv')

    all_records = len(df)
    roku_all_records = len(IP_records)
    roku_logging_records = len(finalRecord)
    

    roku_records_percent = ("{0:.0f}%".format(roku_all_records/all_records * 100))
    roku_logging_percent = ("{0:.0f}%".format(roku_logging_records/all_records * 100))
    print("[+] Roku Records make up: %s" % str(roku_records_percent))
    print("[+] Roku direct logging records make up: %s" % str(roku_logging_percent))


if __name__ == "__main__":
    logsToCSV()
    RokuSearch()
    #uniqueIPCheck()
    print("[+] Done")
