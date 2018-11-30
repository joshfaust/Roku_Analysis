import pandas as pd
import threading
import queue
import os
import glob
import csv
import socket

LOGS_FILE_PATH = 'C:/Users/Joshua/Documents/Python_Projects/pihole_analysis/logs'
CSV_FILE_PATH = 'C:/Users/Joshua/Documents/Python_Projects/pihole_analysis/logs.csv'
ROKU_IPS = ['192.168.1.58','192.168.1.99','192.168.1.209']
cooper = '34.224.239.208'
scribe = '52.21.174.189'
liberty = '52.6.86.101'


def logsToCSV():
    print("[+] Translating log to CSV")
    log_file = open('logs.csv', "w", newline='')
    csv_w = csv.writer(log_file)
    #csv_w.writerow(["Date","IP","URL"])
    for filename in glob.glob(os.path.join(LOGS_FILE_PATH, '*.txt')):
        data_file = open(filename, "r")
        for line in data_file:
            new_line = line.strip().split(" ")
            date = str("%s %s %s" % (new_line[0], new_line[1], new_line[2])).strip()
            ip =str(new_line[5]).partition("/")
            ip = str(ip[0]).strip()
            url = str(new_line[7]).strip()
            csv_w.writerow([date,ip,url])


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

    print(df)





def RokuSearch():
    df = pd.read_csv(CSV_FILE_PATH, names=['Date', 'IP','URL'])
    IP_records = df.loc[df['IP'].isin(ROKU_IPS)]
    finalRecord = IP_records[IP_records['URL'].str.contains('roku')]

    finalRecord.to_csv('report.csv')
    print("[+] All Records Count: %s"% str(len(df)))
    print("[+] IP Records Count: %s" % str(len(IP_records)))
    print("[+] FINAL Records Count: %s" % str(len(finalRecord)))


if __name__ == "__main__":
    logsToCSV()
    #RokuSearch()
    uniqueIPCheck()
    print("[+] Done")
