from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END, messagebox, ttk, BooleanVar, Checkbutton
from core.IDORChecker import IDORChecker
import threading

def interactive_mode():
    root = Tk()
    root.title("IDOR Vulnerability Scanner")
    stop_flag = False

    def stop_scan():
        nonlocal stop_flag
        stop_flag = True
        messagebox.showinfo("Info", "Scan stopped by user.")

    Label(root, text="Target URL:").grid(row=0, column=0, padx=10, pady=10)
    url_entry = Entry(root, width=50)
    url_entry.grid(row=0, column=1, padx=10, pady=10)

    Label(root, text="Test Values (comma-separated):").grid(row=1, column=0, padx=10, pady=10)
    test_values_entry = Entry(root, width=50)
    test_values_entry.grid(row=1, column=1, padx=10, pady=10)

    Label(root, text="Output File:").grid(row=2, column=0, padx=10, pady=10)
    output_file_entry = Entry(root, width=50)
    output_file_entry.grid(row=2, column=1, padx=10, pady=10)

    Label(root, text="Select Payload Types:").grid(row=3, column=0, padx=10, pady=10, sticky="w")

    sql_var = BooleanVar()
    Checkbutton(root, text="SQL Injection", variable=sql_var).grid(row=4, column=0, padx=10, pady=2, sticky="w")

    xss_var = BooleanVar()
    Checkbutton(root, text="XSS (Cross-site Scripting)", variable=xss_var).grid(row=5, column=0, padx=10, pady=2, sticky="w")

    xml_var = BooleanVar()
    Checkbutton(root, text="XML Injection", variable=xml_var).grid(row=6, column=0, padx=10, pady=2, sticky="w")

    output_text = Text(root, height=20, width=80)
    output_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    scrollbar = Scrollbar(root, command=output_text.yview)
    scrollbar.grid(row=7, column=2, sticky="ns")
    output_text.config(yscrollcommand=scrollbar.set)

    progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress.grid(row=8, column=0, columnspan=2, pady=10)

    def log_message(message):
        output_text.insert(END, message + "\n")
        output_text.yview(END)
        root.update_idletasks()

    def get_selected_payloads(checker, param, values):
        all_payloads = checker._generate_payloads(param, values)
        selected_payloads = []
        for payload in all_payloads:
            if any(key in payload for key in ["random_str", "random_num", "base64", "special_chars", "uuid", "json"]):
                selected_payloads.append(payload)
            if sql_var.get() and "sql_injection" in payload:
                selected_payloads.append(payload)
            if xss_var.get() and "xss" in payload:
                selected_payloads.append(payload)
            if xml_var.get() and "xml" in payload:
                selected_payloads.append(payload)
        return selected_payloads if selected_payloads else all_payloads

    def run_scan():
        nonlocal stop_flag
        stop_flag = False
        url = url_entry.get()
        test_values = [value.strip() for value in test_values_entry.get().split(",") if value.strip()]
        output_file = output_file_entry.get()

        if not url or not test_values:
            messagebox.showerror("Error", "Please provide a URL and test values.")
            return

        checker = IDORChecker(url, verbose=True, logger=log_message)  # Pass log_message as logger
        log_message(f"Scanning URL: {url}")
        log_message(f"Test Values: {test_values}")
        log_message("-" * 40)

        progress["maximum"] = len(checker.params.keys()) * len(test_values)
        progress["value"] = 0

        for param in checker.params.keys():
            if stop_flag:
                log_message("Scan stopped by user.")
                break

            log_message(f"Scanning parameter: {param}")
            selected_payloads = get_selected_payloads(checker, param, test_values)

            # Run scan and collect results
            results = checker.check_idor(param, selected_payloads, method="GET")
            if results is None:  # Handle case where results might still be None
                results = []

            # Display results in GUI
            for result in results:
                log_message(f"Payload: {result['payload']}, Status Code: {result['status_code']}, Sensitive Data Detected: {result['sensitive_data_detected']}")

            progress["value"] += len(selected_payloads)
            root.update_idletasks()

        log_message("Scan complete!")

    Button(root, text="Run Scan", command=lambda: threading.Thread(target=run_scan, daemon=True).start()).grid(row=9, column=0, columnspan=2, pady=10)
    Button(root, text="Stop Scan", command=stop_scan).grid(row=10, column=0, columnspan=2, pady=10)

    root.mainloop()
