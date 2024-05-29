
import psutil
import tkinter as tk
from tkinter import messagebox
import socket
import requests
import threading
import queue
import json

api_key = "7c014c9e3e5a1633f2b46b5918ded1980f3303e1f43fe76bea05f61b085d1eeb2d55284050f921b6"

network_info = {}
checked_ips = set()
filter_state = {
    'children': False,
    'internet': False,
}
current_processes = []
process_queue = queue.Queue()

def list_all_processes():
    all_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'connections']):
        try:
            proc_info = proc.info
            children = list(proc.children())
            if children:
                proc_info['children'] = [{'pid': child.pid, 'name': child.name(), 'connections': child.connections()} for child in children]
            all_processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return all_processes

def get_network_info():
    for proc in psutil.process_iter(['pid', 'connections']):
        try:
            proc_info = proc.info
            connections = proc_info.get('connections', [])
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.family == socket.AF_INET:
                    remote_ip = conn.raddr[0] if hasattr(conn, 'raddr') and len(conn.raddr) > 0 else None
                    if remote_ip:
                        if remote_ip not in network_info:
                            try:
                                remote_host = socket.gethostbyaddr(remote_ip)[0]
                            except socket.herror:
                                remote_host = remote_ip
                            network_info[remote_ip] = remote_host
                        network_info[proc_info['pid']] = {'ip': remote_ip, 'host': network_info[remote_ip]}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return network_info

def search_processes(search_term):
    all_processes = list_all_processes()
    search_results = [proc for proc in all_processes if search_term.lower() in proc['name'].lower()]
    return search_results

def check_suspicious_ip(ip, proc):
    if ip not in checked_ips:
        checked_ips.add(ip)
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {"Key": api_key, "Accept": "application/json"}
            response = requests.get(url, headers=headers)
            data = response.json()
            if 'data' in data:
                show_abuseipdb_results(data['data'], proc)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while checking IP address: {e}")

def check_suspicious_process(proc):
    if proc['pid'] in network_info:
        ip = network_info[proc['pid']]['ip']
        check_suspicious_ip(ip, proc)
    if 'children' in proc:
        for child in proc['children']:
            child_connections = child.get('connections', [])
            for conn in child_connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.family == socket.AF_INET:
                    remote_ip = conn.raddr[0] if hasattr(conn, 'raddr') and len(conn.raddr) > 0 else None
                    if remote_ip:
                        check_suspicious_ip(remote_ip, child)

def show_abuseipdb_results(data, proc):
    result_window = tk.Toplevel(root)
    result_window.title(f"AbuseIPDB Results for {proc['name']} (PID: {proc['pid']})")
    text = tk.Text(result_window, wrap=tk.WORD, width=80, height=20)
    text.pack(padx=10, pady=10)
    text.insert(tk.END, json.dumps(data, indent=4))

def filter_processes_with_children():
    global filter_state, current_processes
    filter_state['children'] = not filter_state['children']
    apply_filters()

def filter_processes_with_internet_access():
    global filter_state, current_processes
    filter_state['internet'] = not filter_state['internet']
    apply_filters()

def apply_filters():
    global current_processes
    processes = list_all_processes()
    if filter_state['children']:
        processes = [proc for proc in processes if 'children' in proc]
    if filter_state['internet']:
        processes = [proc for proc in processes if proc['pid'] in network_info]
    current_processes = processes
    display_processes(current_processes, network_info)

def display_processes(processes, network_info):
    text.delete(1.0, tk.END)
    for proc in processes:
        if 'children' in proc and proc['pid'] in network_info:
            line = (f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, "
                    f"CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}, "
                    f"Network: {network_info[proc['pid']]['host']} ({network_info[proc['pid']]['ip']})")
            text.insert(tk.END, line + "\n", "normal")
            process_queue.put(proc)
        else:
            line = (f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, "
                    f"CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}")
            text.insert(tk.END, line + "\n")
        if 'children' in proc:
            text.insert(tk.END, " (click to expand)", "highlight")
        text.insert(tk.END, "\n__________________________________________________\n")

def expand_process(event):
    index = text.index(tk.CURRENT)
    line = text.get(index + " linestart", index + " lineend")
    pid = int(line.split("PID: ")[1].split(",")[0])
    for proc in current_processes:
        if proc['pid'] == pid and 'children' in proc:
            text.delete(1.0, tk.END)
            text.insert(tk.END, f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}\n")
            text.insert(tk.END, "\nChild Processes:\n")
            for child_proc in proc['children']:
                text.insert(tk.END, f"  Child PID: {child_proc['pid']}, Name: {child_proc['name']}\n")
            break

def return_to_processes_list():
    apply_filters()

def search_and_display():
    search_term = search_entry.get()
    search_results = search_processes(search_term)
    display_processes(search_results, network_info)

def process_check_thread():
    while True:
        proc = process_queue.get()
        check_suspicious_process(proc)
        process_queue.task_done()

# Create main application window
root = tk.Tk()
root.title("Process Explorer")

# Create a frame for the search bar
search_frame = tk.Frame(root)
search_frame.pack()

# Create a label and entry for the search bar
search_label = tk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame)
search_entry.pack(side=tk.LEFT)
search_button = tk.Button(search_frame, text="Search", command=search_and_display)
search_button.pack(side=tk.LEFT)

# Create buttons for filtering
filter_children_button = tk.Button(search_frame, text="Filter with Sub-processes", command=filter_processes_with_children)
filter_children_button.pack(side=tk.LEFT)

filter_internet_button = tk.Button(search_frame, text="Filter with Internet Access", command=filter_processes_with_internet_access)
filter_internet_button.pack(side=tk.LEFT)

# Create a text widget to display processes
text = tk.Text(root)
text.pack()

# Add a tag for highlighting
text.tag_configure("highlight", background="yellow")

# Bind click event to expand_process function
text.bind("<Button-1>", expand_process)

# Create a "Return" button to go back to the list of all processes
return_button = tk.Button(root, text="Return to Processes List", command=return_to_processes_list)
return_button.pack()

# Display all processes initially
all_processes = list_all_processes()
network_info = get_network_info()
current_processes = all_processes  # Initialize current_processes
display_processes(all_processes, network_info)

# Start thread for checking suspicious processes
thread = threading.Thread(target=process_check_thread, daemon=True)
thread.start()

# Run the application
root.mainloop()
