import socket                                # networking functionality
import threading                             # for multi-threaded scanning
import queue                                 # queue structure for managing thread tasks
import time                                  # used for timing and progress
from datetime import datetime                # for timestamps
import sys                                   # system-specific functions
import os                                    # for clearing screen and file handling

# Try to import colorama for colored output
try:
    from colorama import Fore, Style, init    # used for coloring output
    init(autoreset=True)                      # reset colors automatically
    COLOR_AVAILABLE = True                    # flag indicating color support
except:
    COLOR_AVAILABLE = False                   # fallback if colorama is missing

# ---------------------------------------------
# Function to print colored text safely
# ---------------------------------------------
def color(text, color_name):                   # function to color text only if colorama installed
    if COLOR_AVAILABLE:                        # if colorama is available
        return getattr(Fore, color_name) + text + Style.RESET_ALL  # return colored text
    else:
        return text                             # return plain if no color support

# ---------------------------------------------
# Function to get banner (service info) of open port
# ---------------------------------------------
def grab_banner(ip, port):                      # attempts to read banner (server info)
    try:
        s = socket.socket()                     # create simple socket
        s.settimeout(1)                         # 1 second timeout for banner grab
        s.connect((ip, port))                   # try connect to port
        banner = s.recv(1024).decode().strip()  # read up to 1024 bytes and decode
        s.close()                               # close socket
        return banner                            # return banner text
    except:
        return None                              # no banner received

# ---------------------------------------------
# Function to check if host is alive by DNS + reverse lookup
# ---------------------------------------------
def host_info(target):                          # gets extra info about host
    info = {}                                    # dictionary to store info
    try:
        info['resolved_ip'] = socket.gethostbyname(target)  # DNS resolution
    except:
        info['resolved_ip'] = None               # failed DNS resolution

    try:
        info['reverse_dns'] = socket.getfqdn(target)  # reverse DNS (IP → hostname)
    except:
        info['reverse_dns'] = None               # failed reverse lookup

    return info                                  # return collected details

# ---------------------------------------------
# Basic OS guessing via common port fingerprint
# ---------------------------------------------
def guess_os(open_ports):                        # guesses OS from port pattern
    if 135 in open_ports or 445 in open_ports:   # Windows ports (SMB/RPC)
        return "Windows (likely)"
    if 22 in open_ports and 111 in open_ports:   # Linux SSH + RPC
        return "Linux/Unix (likely)"
    return "Unknown OS"                          # fallback guess

# ---------------------------------------------
# Multi-threaded Port Scanner Worker Function
# ---------------------------------------------
def scan_worker(ip, results, q):                 # worker that processes queue of ports
    while True:
        port = q.get()                           # get one port from the queue
        if port is None:                         # None means stop thread
            break                                # break loop, exit thread

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # TCP socket
        s.settimeout(0.5)                        # half-second timeout
        try:
            result = s.connect_ex((ip, port))    # attempt connection
            if result == 0:                      # port is open
                banner = grab_banner(ip, port)   # try to grab banner
                results.append((port, banner))   # store results with banner
                print(color(f"[OPEN] Port {port}", "GREEN"))   # print in green
            else:
                pass                              # port closed, ignore
        except:
            pass                                  # ignore errors
        finally:
            s.close()                             # always close socket
            q.task_done()                         # mark queue task as done

# ---------------------------------------------
# Function to save scan report to text file
# ---------------------------------------------
def save_report(filename, target, ip, open_ports, banners):
    with open(filename, "w") as f:               # open file for writing
        f.write("=== Advanced Port Scan Report ===\n")
        f.write(f"Target: {target}\n")
        f.write(f"Resolved IP: {ip}\n")
        f.write(f"Scan Time: {datetime.now()}\n")
        f.write("---------------------------------\n\n")
        for port, banner in zip(open_ports, banners):
            f.write(f"Port {port} OPEN\n")
            if banner:
                f.write(f"Banner: {banner}\n")
            f.write("\n")

# ---------------------------------------------
# Main Scanner Function
# ---------------------------------------------
def advanced_scan(target, start_port, end_port, thread_count=100):

    print(color("\n=== ADVANCED PYTHON PORT SCANNER ===\n", "CYAN"))
    info = host_info(target)                     # collect host info

    if info['resolved_ip'] is None:              # if DNS failed
        print(color("Could not resolve target! Invalid hostname!", "RED"))
        return

    ip = info['resolved_ip']                     # resolved IP

    print(f"Resolved IP: {ip}")                  # print IP
    print(f"Reverse DNS: {info['reverse_dns']}") # print reverse lookup info
    print(f"Scanning Ports: {start_port} to {end_port}") # print range
    print(f"Threads Used: {thread_count}")       # print thread count
    print("-------------------------------------------\n")

    q = queue.Queue()                             # queue for port tasks
    results = []                                   # store open ports & banners
    threads = []                                   # list of worker threads

    # Start worker threads
    for _ in range(thread_count):
        t = threading.Thread(target=scan_worker, args=(ip, results, q))
        t.daemon = True                           # daemon thread ends with main program
        t.start()                                 # start thread
        threads.append(t)                         # store thread reference

    # Add ports to queue
    for port in range(start_port, end_port + 1):
        q.put(port)                               # queue each port

    # Progress indicator
    total_ports = end_port - start_port + 1       # total number of ports
    while not q.empty():                          # while queue is not empty
        remaining = q.qsize()                     # how many left
        done = total_ports - remaining            # how many done
        percent = (done / total_ports) * 100      # percentage
        sys.stdout.write(f"\rProgress: {percent:.2f}%")  # print progress dynamically
        sys.stdout.flush()                        # force print update
        time.sleep(0.1)                           # slight delay to avoid spam

    q.join()                                      # wait for all tasks to complete

    # Stop worker threads
    for _ in range(thread_count):
        q.put(None)                               # send stop signal

    for t in threads:
        t.join()                                  # wait for all threads to exit

    print(color("\n\nScan Completed!\n", "GREEN"))

    # Extract port numbers & banners
    open_ports = [p for p, b in results]
    banners = [b for p, b in results]

    print("Open Ports Found:", open_ports)        # print open port list

    print("Guessing Operating System:", guess_os(open_ports))  # print OS guess

    # Save report
    filename = f"scan_report_{target}.txt"         # file name
    save_report(filename, target, ip, open_ports, banners)
    print(color(f"\nReport saved as {filename}\n", "CYAN"))

# ---------------------------------------------
# Program Entry
# ---------------------------------------------
if __name__ == "__main__":                       # only run if executed directly
    target = input("Enter target hostname/IP: ") # ask user for target
    start_port = int(input("Enter start port: ")) # ask start port
    end_port = int(input("Enter end port: "))     # ask end port

    thread_count = int(input("Enter number of threads (50-500 recommended): "))

    advanced_scan(target, start_port, end_port, thread_count)
