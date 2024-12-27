#!/usr/bin/env python

import requests
from scapy.all import ARP, Ether, srp
import os, sys
import socket
import pyfiglet
import time

#COLORS
RED = '\033[1;31m'
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
WHITE = '\033[1;37m'
CYAN = '\033[1;36m'
END = '\033[0m'

os.system("clear")

banner = pyfiglet.figlet_format("ZEROES-Scanner")
copyright = ("BY: \033[1;37m Omer-Secure \033[0m")
print(banner)
print(copyright)


# عرض الخيارات
def menu():
    print("""
\033[1;37m[\033[1;31m1\033[1;37m] \033[0;32mCheck your internet connection\033[0m
\033[1;37m[\033[1;31m2\033[1;37m] \033[0;32mGet Public address of Websites\033[0m
\033[1;37m[\033[1;31m3\033[1;37m] \033[0;32mPort scanner\033[0m
\033[1;37m[\033[1;31m4\033[1;37m] \033[0;32mScan your Local Network \033[0;33m(IP's and MAC's)\033[0m
\033[1;37m[\033[1;31m5\033[1;37m] \033[0;32mDirectories Search\033[0m
\033[1;37m[\033[1;31m6\033[1;37m]\033[0m \033[0;32mWeb Vulnerabilities Scanner \033[0;33m(XSS and SQLi)\033[0m
\033[1;37m[\033[1;31m0\033[1;37m] \033[0;32mExit\033[0m
""")

# n الخروج من البرنامج عن ادخال
def restart():
    if input("\n\033[1;37mBack to main menu \033[0;32my\033[1;37m/\033[0;31mn\033[0;m\n\033[1;37m->\033[0m ").upper() != "Y":
        time.sleep(1)
        os.system("clear")
        print(banner)
        print(copyright)
        print("\n\033[1;32mGoodbye, Friend\033[0;m\033[1;37m!\033[0;m")
        tool = exit(0)
    os.system("python3 zeroes.py")    	

# (1) داله للتحقق من اتصال الانترنت
def check_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Checking connection...\n")
    s.settimeout(2)
    try:
        s.connect(('nmap.org',443))
        print("\033[0;32m[Connected]\033[0m")

    except:
        print("\033[0;31m[Disconnected]")

# (2) معرفة عنوان الايـبـي العام للموقع
def Public_IP():
    hostName = input("Target (example.com): ")
    start_time = time.time() # بدء تسجيل الوقت هنا

    ipaddress = socket.gethostbyname(hostName)
    print("IP Address:\033[0;32m {}\033[0m".format(ipaddress))

    end_time = time.time() # تسجيل وقت النهاية هنا
    time_taken = end_time - start_time
    print(f"Time taken: {time_taken:.2f} seconds")

# (3:1) فحص منفذ واحد
def ScanSinglePort():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(2)

    target = input("Target (IP or URL): ")
    try:
        port = int(input("Port: "))
        print("")

        if 1 <= port <= 65536:
            start_time = time.time() # بدء تسجيل الوقت هنا
            def scan(port):
                if sock.connect_ex((target,port)):
                    print("-" * 30, "\nPort", port, "is \033[0;31mclosed\033[0m")
                    print("-" * 30)
                else:
                    print("-" * 30)
                    print("Port", port, "is \033[0;32mopen\033[0m")
                    print("-" * 30)

                sock.close()  # تأكد من إغلاق المقبس بعد كل عملية فحص

            scan(port)
            end_time = time.time() # تسجيل وقت النهاية هنا
            time_taken = end_time - start_time
            print(f"Time taken: {time_taken:.2f} seconds")

        else:
            print("Invalid Port, must be between (1-65536).")
            restart()

    except ValueError:
        print("Invalid input. Please enter a valid Port number.")
        restart() 

# (3:2) فحص كل او بعض المنافذ
def ScanMultiplePorts():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)

    target = input("Target (IP or URL): ")
    try:
        port_first = int(input("Port First (1-65536): "))
        port_end = int(input("Port End (1-65536): "))
        print("")

        if 1 <= port_first <= 65536 and 1 <= port_end <= 65536:
            start_time = time.time() # بدء تسجيل الوقت هنا
            def scanning(port):
                if sock.connect_ex((target,port)):
                    print("-" * 30, "\nPort", port, "is \033[0;31mclosed\033[0m")
                    print("-" * 30)
                else:
                    print("-" * 30)
                    print("Port", port, "is \033[0;32mopen\033[0m")
                    print("-" * 30)
                
                sock.close()  # تأكد من إغلاق المقبس بعد كل عملية فحص

            for port in range(port_first,port_end):
                scanning(port)
                
            end_time = time.time() # تسجيل وقت النهاية هنا
            time_taken = end_time - start_time
            print(f"Time taken: {time_taken:.2f} seconds")

        else:
            print("Invalid Port, must be between (1-65536).")
            restart()

    except ValueError:
        print("Invalid input. Please enter a valid Port number.")
        restart() 
    
# (4) فحص كل الاجهزة في الشبكة المحليه
def NetworkScan():
    target = input("Enter the IP and range (ex \033[0;33m192.168.1.1/24\033[0m): ")
    print("\n", "-" * 40)
    start_time = time.time()  # بدء تسجيل الوقت هنا
    
    arp = ARP(pdst=target)
    etherMAC = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = etherMAC/arp

    r = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in r:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    print(" IP" + " "*18+" MAC")
    print("-" * 40)
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
    
    end_time = time.time() # تسجيل وقت النهاية هنا
    time_taken = end_time - start_time
    print(f"\nTime taken: {time_taken:.2f} seconds")

# 
def searchfordirs():
    url = input("Enter the URL to search directories (http://example.com): ")
    wordlist = "wordlist.txt"

    with open(wordlist, 'r') as f:
        directories = f.read().splitlines()

    for directory in directories:
        full_url = f"{url}/{directory}"
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"Directory is FOUND!: {full_url}")
        elif response.status_code == 404:
            pass  # تجاوز هذا الشرط دون طباعة أي شيء
        else:
            pass
            #print(f"Status code: {response.status_code} for the page that could not get reached: {full_url}")


menu() 
option = (input("\033[1;37m-> \033[0m"))

if option == "1":
    check_network()
    restart()

elif option == "2":
    Public_IP()
    restart()

elif option == "4":
    NetworkScan()
    restart()

elif option == "5":
    searchfordirs()
    restart()

elif option == "6":
    os.system("python3 xss-sqli.py")

elif option == "0":
    print("\n\033[1;32mGoodbye, Friend\033[0;m\033[1;37m!\033[0;m")
    exit(0)		

while option == "3":
    os.system("clear")
    print(banner)
    print(copyright)
    print("\n\033[1;37m[\033[1;31m1\033[1;37m]\033[0m \033[0;32m Single Port scan")
    print("\033[1;37m[\033[1;31m2\033[1;37m]\033[0m \033[0;32m Multiple Ports scan (\033[0;33m1\033[0;37m,\033[0;33m65536\033[0;32m)\033[0m")
    print("\033[1;37m[\033[1;31m0\033[1;37m]\033[0m \033[0;32m Restart OR Exit")
    option = (input("\n\033[1;37m-> \033[0m"))

    if option == "1":
        ScanSinglePort()

    elif option == "2":
        ScanMultiplePorts()

    elif option == "0":
        pass

    else:
        print("inValid Option, Must be (0-2)")
    
    restart()

else:
    print("inValid Option, Must be (0-5)")
    restart()

