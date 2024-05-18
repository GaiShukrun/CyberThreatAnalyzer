import tkinter as tk
import os

# Define the directory where the scripts are located
SCRIPTS_DIRECTORY = r"C:\Users\gaiso\OneDrive\Desktop\Cyber_Use_Cases-main"

def run_script(script_name):
    script_path = os.path.join(SCRIPTS_DIRECTORY, f"{script_name}.py")
    if os.path.exists(script_path):
        os.system(f"python {script_path}")
    else:
        print(f"Script '{script_name}' not found.")

# Create main application window
root = tk.Tk()
root.title("Cyber Threats Analyzer")

# Set the size of the main window
root.geometry("400x300")  # Width x Height

# Function to create a button for a script
def create_script_button(button_label, script_name):
    return tk.Button(root, text=button_label, command=lambda: run_script(script_name))

# Dictionary mapping button labels to script names
script_button_labels = {
    "View Running Processes On This Machine": "Processes",
    "Check File Hashes Via Virus Total": "VTHashesCheck",
    "Check IP on AbuseIPDB": "AbuseIPDBCheck",
    "Display DNS Info": "DnsDisplay"
}

# Create buttons for each script
for button_label, script_name in script_button_labels.items():
    button = create_script_button(button_label, script_name)
    button.pack(pady=5)

# Run the application
root.mainloop()
