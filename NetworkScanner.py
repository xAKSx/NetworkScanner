from requirements import *
import tkinter as tk
from tkinter import ttk
import customtkinter
import nmap
import socket
import threading
from tkinter import messagebox
from ttkthemes import ThemedStyle

def get_network_address():
    # Get local IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Connect to Google's DNS server
    local_ip = s.getsockname()[0]
    s.close()
    
    # Get network address based on local IP and subnet mask
    network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
    
    return network

def clear_results():
    for item in tree.get_children():
        tree.delete(item)

def scan_network():
    # Change cursor to loading
    root.configure(cursor="wait")
    
    # Get network address
    network_address = get_network_address()
    
    # Perform network scan using Nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=str(network_address), arguments='-sn')
    
    devices = []
    for host in nm.all_hosts():
        mac_address = nm[host]['addresses'].get('mac', 'N/A')  # Use 'N/A' if 'mac' key is not present
        
        # Determine annotation based on device characteristics
        annotation = ""
        if nm[host].state() == "up":
            annotation += "p"  # Device is pingable
        if host == network_address.split('/')[0]:
            annotation += "s"  # Device is the scanning device
        if nm[host].get('vendor', '') == "Gateway":
            annotation += "g"  # Device is the gateway
        if nm[host].get('http', '') or nm[host].get('https', ''):
            annotation += "h"  # Device has HTTP or HTTPS service running
        
        devices.append({"ip": host, "mac": mac_address, "annotation": annotation})
    
    clear_results()
    for idx, device in enumerate(devices):
        tree.insert("", idx, text=f"Device {idx+1}", values=(device["ip"], device["mac"], device["annotation"]))
    
    # Revert cursor back to normal
    root.configure(cursor="")

def scan_network_thread():
    threading.Thread(target=scan_network).start()

def update_result_text(result_text, services):
    result_text.configure(state=tk.NORMAL)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, "\n".join(services))
    result_text.configure(state=tk.DISABLED)

def scan_services(ip, ports, result_text):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=ports, arguments='-sV')
        services = []
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    service_name = nm[host]['tcp'][port]['name']
                    service_version = nm[host]['tcp'][port]['version']
                    services.append(f"{port} - {service_name} ({service_version})")
        
        if services:
            result_text.after(0, update_result_text, result_text, services)
        else:
            result_text.after(0, lambda: messagebox.showinfo("No Services Found", "No services found on the specified IP address and port(s)."))
    except Exception as e:
        result_text.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))

def scan_services_window():
    # Create a new window for scanning services
    service_window = customtkinter.CTkToplevel(root)
    service_window.title("Scan Services")

    # Apply the same theme as the main window
    style = ThemedStyle(service_window)
    style.set_theme("equilux")

    # IP Address label and entry
    ip_label = customtkinter.CTkLabel(service_window, text="Enter IP Address:")
    ip_label.pack(pady=5)
    ip_entry = customtkinter.CTkEntry(service_window)
    ip_entry.pack(pady=5)

    # Ports selection
    ports_label = customtkinter.CTkLabel(service_window, text="Select Ports:")
    ports_label.pack(pady=5)
    ports_var = tk.StringVar()
    ports_var.set("common")
    ports_radio1 = customtkinter.CTkRadioButton(service_window, text="Common Ports (1-1023)", variable=ports_var, value="common")
    ports_radio1.pack()
    ports_radio2 = customtkinter.CTkRadioButton(service_window, text="Top 100 Ports", variable=ports_var, value="top100")
    ports_radio2.pack()
    ports_radio3 = customtkinter.CTkRadioButton(service_window, text="Specific Port(s)", variable=ports_var, value="specific")
    ports_radio3.pack()

    specific_ports_entry = customtkinter.CTkEntry(service_window, state=tk.DISABLED)
    specific_ports_entry.pack(pady=5)

    # Result Text
    result_text = tk.Text(service_window, height=10, width=50, state=tk.DISABLED)
    result_text.pack(pady=5)

    def on_ports_radio_change():
        if ports_var.get() == "specific":
            specific_ports_entry.configure(state=tk.NORMAL)
        else:
            specific_ports_entry.configure(state=tk.DISABLED)

    ports_var.trace("w", lambda name, index, mode, sv=ports_var: on_ports_radio_change())

    def start_scan():
        scan_button.configure(state=tk.DISABLED)
        threading.Thread(target=scan_services, args=(ip_entry.get(), specific_ports_entry.get() or "1-65535", result_text)).start()

    # Scan Button
    scan_button = customtkinter.CTkButton(service_window, text="Scan", command=start_scan)
    scan_button.pack(pady=10)

# GUI setup
root = customtkinter.CTk()
root.title("Network Scanner")

# Apply the 'equilux' theme (dark theme)
style = ThemedStyle(root)
style.set_theme("equilux")

# Create a treeview widget to display scan results
tree = ttk.Treeview(root)
tree["columns"] = ("IP Address", "MAC Address", "Annotation")
tree.heading("#0", text="Device")
tree.heading("IP Address", text="IP Address")
tree.heading("MAC Address", text="MAC Address")
tree.heading("Annotation", text="Annotation")
tree.pack(pady=10)

# Button to start the scan
scan_button = customtkinter.CTkButton(root, text="Scan Network", command=scan_network_thread)
scan_button.pack(side=tk.LEFT, padx=20, pady=10)

# Button to clear results
clear_button = customtkinter.CTkButton(root, text="Clear Results", command=clear_results)
clear_button.pack(side=tk.LEFT, padx=20, pady=5)

# Button to scan services
scan_services_button = customtkinter.CTkButton(root, text="Scan Services", command=scan_services_window)
scan_services_button.pack(side=tk.LEFT, padx=20, pady=5)

# Create a legend for annotations
legend_label = tk.Label(root, text="g = gateway,\t p = pingable,\t s = scanning device", justify=tk.LEFT, padx=10, pady=10, fg="white", bg="#333333")
legend_label.pack(side=tk.BOTTOM, padx=20, pady=10)

root.mainloop()