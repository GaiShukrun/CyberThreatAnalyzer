import psutil
import tkinter as tk
import socket

network_info = {}
filter_state = {
    'children': False,
    'internet': False,
}
current_processes = []

def list_all_processes():
    all_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'connections']):
        try:
            proc_info = proc.info
            children = list(proc.children())
            if children:
                proc_info['children'] = children
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
                if hasattr(conn, 'status') and hasattr(conn, 'family') and conn.family == socket.AF_INET:
                    remote_ip = conn.raddr[0] if hasattr(conn, 'raddr') and len(conn.raddr) > 0 else None
                    if remote_ip:
                        try:
                            remote_host = socket.gethostbyaddr(remote_ip)[0]
                        except socket.herror:
                            remote_host = remote_ip
                        network_info[proc_info['pid']] = remote_host
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return network_info

def search_processes(search_term):
    all_processes = list_all_processes()
    search_results = []
    for proc in all_processes:
        if search_term.lower() in proc['name'].lower():
            search_results.append(proc)
    return search_results

def filter_processes_with_children():
    global filter_state, current_processes
    filter_state['children'] = not filter_state['children']
    if filter_state['children']:
        current_processes = [proc for proc in current_processes if 'children' in proc]
    else:
        current_processes = list_all_processes()
        apply_filters()
    display_processes(current_processes, network_info)

def filter_processes_with_internet_access():
    global filter_state, current_processes
    filter_state['internet'] = not filter_state['internet']
    if filter_state['internet']:
        current_processes = [proc for proc in current_processes if proc['pid'] in network_info]
    else:
        current_processes = list_all_processes()
        apply_filters()
    display_processes(current_processes, network_info)

def apply_filters():
    global current_processes
    if filter_state['children']:
        current_processes = [proc for proc in current_processes if 'children' in proc]
    if filter_state['internet']:
        current_processes = [proc for proc in current_processes if proc['pid'] in network_info]

def display_processes(processes, network_info):
    text.delete(1.0, tk.END)
    for proc in processes:
        line = f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}"
        if proc['pid'] in network_info:
            line += f", Network: {network_info[proc['pid']]}"
        if 'children' in proc:
            line += " (click to expand)"
            text.insert(tk.END, line + "\n", "highlight")
        else:
            text.insert(tk.END, line + "\n")
        # Add separator line
        text.insert(tk.END, "__________________________________________________\n")

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
                text.insert(tk.END, f"  Child PID: {child_proc.pid}, Name: {child_proc.name()}\n")
            break

def return_to_processes_list():
    global current_processes
    current_processes = all_processes
    display_processes(all_processes, network_info)

def search_and_display():
    search_term = search_entry.get()
    search_results = search_processes(search_term)
    display_processes(search_results, network_info)

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

# Run the application
root.mainloop()
