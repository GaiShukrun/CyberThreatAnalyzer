import tkinter as tk
from tkinter import ttk, messagebox
import requests
import shodan
import json

def search_ip(search_engine):
    ip = ip_entry.get()
    api_key = api_key_entry.get()
    
    if not ip:
        messagebox.showwarning("Warning", "Please enter an IP address.")
        return
    
    if not api_key:
        messagebox.showwarning("Warning", "Please enter a Shodan API key.")
        return
    
    try:
        if search_engine == "AbuseIPDB":
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {
                "Key": api_key,
                "Accept": "application/json"
            }
            response = requests.get(url, headers=headers)
            data = response.json()
            if 'data' in data:
                info_text.delete(1.0, tk.END)
                info_text.insert(tk.END, json.dumps(data['data'], indent=4))
            else:
                messagebox.showwarning("Warning", "No information available for this IP.")
        elif search_engine == "Shodan":
            api = shodan.Shodan(api_key)
            host = api.host(ip)
            info_text.delete(1.0, tk.END)
            info_text.insert(tk.END, json.dumps(host, indent=4))
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("IP Information Panel")

# IP entry
ip_label = tk.Label(root, text="Enter IP Address:")
ip_label.grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(root, width=20)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

# API key entry
api_key_label = tk.Label(root, text="Enter API Key:")
api_key_label.grid(row=1, column=0, padx=5, pady=5)
api_key_entry = tk.Entry(root, width=50)
api_key_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

# Search engine selection
search_engine_label = tk.Label(root, text="Select Search Engine:")
search_engine_label.grid(row=2, column=0, padx=5, pady=5)
search_engine_var = tk.StringVar()
search_engine_var.set("AbuseIPDB")
search_engine_dropdown = ttk.OptionMenu(root, search_engine_var, "AbuseIPDB", "AbuseIPDB", "Shodan")
search_engine_dropdown.grid(row=2, column=1, padx=5, pady=5)

# Search IP button
search_button = ttk.Button(root, text="Search IP", command=lambda: search_ip(search_engine_var.get()))
search_button.grid(row=0, column=2, padx=5, pady=5)

# Info text
info_text = tk.Text(root, wrap=tk.WORD, width=50, height=10)
info_text.grid(row=3, columnspan=3, padx=5, pady=5)

root.mainloop()
