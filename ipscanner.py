#Step 1
#Ping sweep to identify live host

from scapy.all import *
import sys

def ping_sweep(ip_range):
    live_hosts = []
    for ip in ip_range:
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            live_hosts.append(ip)
            print(f"Host {ip} is live.")
    return live_hosts

#As our system's ip is 192.168.17.10, We will look for this range.
ip_range = [f"192.168.17.{i}" for i in range(1, 255)]
live_hosts = ping_sweep(ip_range)

#Step 2
#Port Scanning

import nmap
def port_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024')  # Scanning ports 1-1024
    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            print(f"Port {port} is open on {ip}.")

for host in live_hosts:
    port_scan(host)

#Step 3 - Service detection using NMAP
def service_detection(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV')  # -sV for version detection
    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            service = scanner[ip][proto][port]['name']
            version = scanner[ip][proto][port].get('version', 'unknown')
            print(f"Port {port}: {service} {version}")
            
for host in live_hosts:
    service_detection(host)

 		   	 
  		   	
 		 			 
  		 	  
 			  	 
 				  	
 	 					
  		  		
 		 			 
 		   		
  		    
 		  	  
  		  		
 		  	  
 					 	
