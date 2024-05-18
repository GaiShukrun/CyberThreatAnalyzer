import subprocess
import re
import tkinter as tk
from tkinter import filedialog, messagebox

def export_ipconfig_displaydns(output_file):
    # Run ipconfig /displaydns command and capture the output
    result = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True)

    # Write the output to a text file
    with open(output_file, 'w') as file:
        file.write(result.stdout)

def check_for_suspicious_domains(output_file, suspicious_domains_file):
    # Read suspicious domains from the text file
    with open(suspicious_domains_file, 'r') as file:
        suspicious_domains = [line.strip() for line in file]

    # Read the output of ipconfig /displaydns
    with open(output_file, 'r') as file:
        output = file.read()

    # Search for matches between the output and suspicious domains
    matches = []
    for domain in suspicious_domains:
        if re.search(domain, output):
            matches.append(domain)

    return matches

def run_check():
    output_file = output_entry.get()
    suspicious_domains_file = domains_entry.get()
    export_ipconfig_displaydns(output_file)
    matches = check_for_suspicious_domains(output_file, suspicious_domains_file)
    if matches:
        messagebox.showinfo("Suspicious Domains Found", "Found matches to suspicious domains:\n" + "\n".join(matches))
    else:
        messagebox.showinfo("No Suspicious Domains", "No matches found.")

def select_output_file():
    output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if output_file:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, output_file)

def select_domains_file():
    domains_file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if domains_file:
        domains_entry.delete(0, tk.END)
        domains_entry.insert(0, domains_file)

# Create the main window
root = tk.Tk()
root.title("Suspicious Domains Checker")

# Output file entry
output_label = tk.Label(root, text="Output File:")
output_label.grid(row=0, column=0, sticky="w")
output_entry = tk.Entry(root, width=50)
output_entry.grid(row=0, column=1, padx=5, pady=5)
output_button = tk.Button(root, text="Select", command=select_output_file)
output_button.grid(row=0, column=2)

# Suspicious domains file entry
domains_label = tk.Label(root, text="Suspicious Domains File:")
domains_label.grid(row=1, column=0, sticky="w")
domains_entry = tk.Entry(root, width=50)
domains_entry.grid(row=1, column=1, padx=5, pady=5)
domains_button = tk.Button(root, text="Select", command=select_domains_file)
domains_button.grid(row=1, column=2)

# Run button
run_button = tk.Button(root, text="Run Check", command=run_check)
run_button.grid(row=2, column=1, pady=10)

root.mainloop()
