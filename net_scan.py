# # import pyfiglet 
# # import sys 
# # import socket 
# # from datetime import datetime 

# # ascii_banner = pyfiglet.figlet_format("PORT SCANNER") 
# # print(ascii_banner) 

# # # Defining a target 
# # if len(sys.argv) == 3: 
	
# # 	# translate hostname to IPv4 
# # 	target = socket.gethostbyname(sys.argv[2]) 
# # else: 
# # 	print("Invalid ammount of Argument") 

# # # Add Banner 
# # print("-" * 50) 
# # print("Scanning Target: " + target) 
# # print("Scanning started at:" + str(datetime.now())) 
# # print("-" * 50) 

# # try: 
	
# # 	# will scan ports between 1 to 65,535 
# # 	for port in range(1,1024): 
# # 		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
# # 		socket.setdefaulttimeout(1) 
		
# # 		# returns an error indicator 
# # 		result = s.connect_ex((target,port)) 
# # 		if result ==0: 
# # 			print("Port {}  <open>".format(port))
# # 		else:
# # 		   print("Port {}  <closed>".format(port))
# # 		s.close() 
# # except KeyboardInterrupt: 
# #         print("\n Exitting Program !!!!") 
# #         sys.exit() 
# # except socket.gaierror: 
# #         print("\n Hostname Could Not Be Resolved !!!!") 
# #         sys.exit() 
# # except socket.error: 
# #         print("\ Server not responding !!!!") 
# #         sys.exit() 














# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# from scapy.all import *

# dst_ip = "10.0.0.1”
# src_port = RandShort()
# dst_port=80

# window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=”A”),timeout=10)
# if (str(type(window_scan_resp))==”<type ‘NoneType’>”):
# print "No response”
# elif(window_scan_resp.haslayer(TCP)):
# if(window_scan_resp.getlayer(TCP).window == 0):
# print "Closed”
# elif(window_scan_resp.getlayer(TCP).window > 0):
# print "Open”
# [/python]



from scapy.all import *
from pyfiglet import Figlet
logo = Figlet(font='graffiti')
print(logo.renderText('%R%\nfs0c131y..%'))
ip = input("Enter the ip address or url:\n")
port = int(input("Enter the port number:\n"))
def checkhost():
    ping = IP(dst=ip)/ICMP()
    res = sr1(ping,timeout=1,verbose=0)
    if res == None:
        print("This host is down")
    else:
        print("This host is up")

#function to check open port
def checkport():
    tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
    tcpResponse = sr1(tcpRequest,timeout=1,verbose=0)
    try:
        if tcpResponse.getlayer(TCP).flags == "SA":
            print(port,"is listening")
    except AttributeError:
        print(port,"is not listening")

checkhost()
checkport()