import argparse
import requests
from urllib.parse import urlparse, parse_qs
import time
import json
import concurrent.futures
import csv
import sys
from typing import Dict, List, Optional, Union
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END, messagebox, ttk
from core.banner import banner
import threading
from bs4 import BeautifulSoup
import random
import string
import uuid
import base64
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class IDORChecker:
    def __init__(
        self,
        url: str,
        delay: float = 1,
        headers: Optional[Dict] = None,
        proxy: Optional[Dict] = None,
        verbose: bool = False,
        sensitive_keywords: Optional[List[str]] = None,
        timeout: int = 10,
        max_retries: int = 3,
    ):
        """
        Initialize the IDORChecker with the target URL, delay between requests, custom headers, proxy, verbose mode, and sensitive keywords.
        """
        self.url = url
        self.base_url, self.params = self._parse_url(url)
        self.delay = delay  # Delay between requests to avoid rate limiting
        self.headers = headers or {}  # Custom headers for requests
        self.proxy = proxy  # Proxy configuration
        self.verbose = verbose  # Verbose mode for detailed output
        self.sensitive_keywords = sensitive_keywords or [
            "password",
            "email",
            "token",
            "ssn",
            "credit_card",
        ]  # Sensitive keywords to detect
        self.session = requests.Session()  # Use a session for persistent connections
        self.rate_limit_detected = False  # Flag to detect rate limiting
        self.timeout = timeout  # Timeout for requests
        self.max_retries = max_retries  # Maximum number of retries for failed requests
        self.payload_history = []  # Track all tested payloads

    def _parse_url(self, url: str) -> tuple:
        """
        Parse the URL into base URL and query parameters.
        """
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            params = parse_qs(parsed_url.query)
            return base_url, params
        except Exception as e:
            print(f"{Fore.RED}Error parsing URL: {e}{Style.RESET_ALL}")
            raise

    def _generate_payloads(self, param: str, values: List[str]) -> List[Dict]:
        """
        Generate dynamic payloads by replacing the specified parameter with the given values.
        Includes advanced payloads like random strings, numbers, special characters, UUIDs, and encoded values.
        """
        payloads = []
        for value in values:
            # Convert value to string if it's not already
            value_str = str(value)

            # Basic payload
            new_params = self.params.copy()
            new_params[param] = value_str
            payloads.append(new_params)

            # Advanced payloads
            payloads.append({**new_params, "random_str": self._generate_random_string(10)})  # Random string
            payloads.append({**new_params, "random_num": random.randint(1000, 9999)})  # Random number
            payloads.append({**new_params, "special_chars": "!@#$%^&*()"})  # Special characters
            payloads.append({**new_params, "uuid": str(uuid.uuid4())})  # UUID
            payloads.append({**new_params, "base64": base64.b64encode(value_str.encode()).decode()})  # Base64 encoded
            payloads.append({**new_params, "sql_injection": "' OR '1'='1"})  # SQL injection payload
            payloads.append({**new_params, "xss": "<script>alert('XSS')</script>"})  # XSS payload
        return payloads


    def _generate_random_string(self, length: int) -> str:
        """
        Generate a random string of the specified length.
        """
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _send_request(self, params: Dict, method: str = "GET") -> Optional[requests.Response]:
        """
        Send a request with the given parameters and HTTP method.
        """
        retries = 0
        while retries < self.max_retries:
            try:
                request_args = {
                    "headers": self.headers,
                    "proxies": self.proxy,
                    "timeout": self.timeout,
                }
                if method.upper() == "GET":
                    response = self.session.get(self.base_url, params=params, **request_args)
                elif method.upper() == "POST":
                    response = self.session.post(self.base_url, data=params, **request_args)
                elif method.upper() == "PUT":
                    response = self.session.put(self.base_url, data=params, **request_args)
                elif method.upper() == "DELETE":
                    response = self.session.delete(self.base_url, data=params, **request_args)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                return response
            except requests.RequestException as e:
                retries += 1
                print(f"{Fore.YELLOW}Request failed (Attempt {retries}/{self.max_retries}): {e}{Style.RESET_ALL}")
                time.sleep(self.delay * retries)  # Increase delay with each retry
        return None

    def _detect_sensitive_data(self, response_text: str) -> bool:
        """
        Detect sensitive data in the response text.
        """
        for keyword in self.sensitive_keywords:
            if keyword in response_text.lower():
                return True
        return False

    def _detect_rate_limiting(self, response: requests.Response) -> bool:
        """
        Detect rate limiting based on response status code and headers.
        """
        if response.status_code == 429:  # Too Many Requests
            return True
        if "Retry-After" in response.headers:  # Retry-After header
            return True
        return False

    def _test_payload(self, payload: Dict, method: str) -> Dict:
        """
        Test a single payload and return the result.
        """
        if self.verbose:
            print(f"{Fore.CYAN}Testing payload: {payload}{Style.RESET_ALL}")
        response = self._send_request(payload, method)
        if response is None:
            return {}

        # Detect rate limiting
        if self._detect_rate_limiting(response):
            self.rate_limit_detected = True
            print(f"{Fore.YELLOW}Rate limiting detected. Adjusting delay...{Style.RESET_ALL}")
            time.sleep(self.delay * 2)  # Increase delay to avoid further rate limiting

        result = {
            "payload": payload,
            "status_code": response.status_code,
            "response_content": response.text[:200],  # Save first 200 chars of response
            "sensitive_data_detected": self._detect_sensitive_data(response.text),
        }

        if self.verbose:
            print(f"{Fore.GREEN}Status Code: {response.status_code}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Response Content: {result['response_content']}...{Style.RESET_ALL}")
            if result["sensitive_data_detected"]:
                print(f"{Fore.RED}Sensitive data detected!{Style.RESET_ALL}")
            print("-" * 40)

        # Delay between requests to avoid rate limiting
        time.sleep(self.delay)
        return result

    def check_idor(
        self,
        param: str,
        test_values: List[str],
        method: str = "GET",
        output_file: Optional[str] = None,
        output_format: str = "txt",
    ):
        """
        Check for IDOR vulnerabilities by testing different values for the specified parameter.
        """
        payloads = self._generate_payloads(param, test_values)
        results = []

        # Use threading for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self._test_payload, payload, method) for payload in payloads]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    self.payload_history.append(result)  # Track payload history

        # Save results to file if output file is provided
        if output_file:
            if output_format == "csv":
                self._save_results_csv(results, output_file)
            else:
                self._save_results_txt(results, output_file)
            print(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

        # Display summary
        self._display_summary(results)

    def _save_results_txt(self, results: List[Dict], output_file: str):
        """
        Save results to a text file.
        """
        with open(output_file, "w") as f:
            for result in results:
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status Code: {result['status_code']}\n")
                f.write(f"Response Content: {result['response_content']}\n")
                f.write(f"Sensitive Data Detected: {result['sensitive_data_detected']}\n")
                f.write("-" * 40 + "\n")

    def _save_results_csv(self, results: List[Dict], output_file: str):
        """
        Save results to a CSV file.
        """
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Payload", "Status Code", "Response Content", "Sensitive Data Detected"])
            for result in results:
                writer.writerow(
                    [
                        result["payload"],
                        result["status_code"],
                        result["response_content"],
                        result["sensitive_data_detected"],
                    ]
                )

    def _display_summary(self, results: List[Dict]):
        """
        Display a summary of the scan results.
        """
        vulnerabilities = [result for result in results if result["sensitive_data_detected"]]
        print(f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total Payloads Tested: {len(results)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerabilities Found: {len(vulnerabilities)}{Style.RESET_ALL}")
        if vulnerabilities:
            print(f"{Fore.RED}Vulnerable Payloads:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"{Fore.RED}- {vuln['payload']}{Style.RESET_ALL}")

# Rest of the code remains the same...
def interactive_mode():
    """
    Launch an interactive GUI for IDOR testing.
    """
    root = Tk()
    root.title("IDOR Vulnerability Scanner")

    Label(root, text="Target URL:").grid(row=0, column=0, padx=10, pady=10)
    url_entry = Entry(root, width=50)
    url_entry.grid(row=0, column=1, padx=10, pady=10)

    Label(root, text="Test Values (comma-separated):").grid(row=1, column=0, padx=10, pady=10)
    test_values_entry = Entry(root, width=50)
    test_values_entry.grid(row=1, column=1, padx=10, pady=10)

    Label(root, text="Output File:").grid(row=2, column=0, padx=10, pady=10)
    output_file_entry = Entry(root, width=50)
    output_file_entry.grid(row=2, column=1, padx=10, pady=10)

    output_text = Text(root, height=20, width=80)
    output_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
    scrollbar = Scrollbar(root, command=output_text.yview)
    scrollbar.grid(row=3, column=2, sticky="ns")
    output_text.config(yscrollcommand=scrollbar.set)

    progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress.grid(row=4, column=0, columnspan=2, pady=10)

    def run_scan():
        url = url_entry.get()
        test_values = test_values_entry.get().split(",")
        output_file = output_file_entry.get()

        if not url or not test_values:
            messagebox.showerror("Error", "Please provide a URL and test values.")
            return

        checker = IDORChecker(url, verbose=True)
        output_text.insert(END, f"Scanning URL: {url}\n")
        output_text.insert(END, f"Test Values: {test_values}\n")
        output_text.insert(END, "-" * 40 + "\n")

        progress["maximum"] = len(checker.params.keys()) * len(test_values)
        progress["value"] = 0

        for param in checker.params.keys():
            output_text.insert(END, f"Scanning parameter: {param}\n")
            checker.check_idor(param, test_values, output_file=output_file, output_text=output_text)
            progress["value"] += len(test_values)
            root.update_idletasks()

        output_text.insert(END, "Scan complete!\n")

    Button(root, text="Run Scan", command=run_scan).grid(row=5, column=0, columnspan=2, pady=10)

    root.mainloop()

def main():
    banner()
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Ultimate IDOR Vulnerability Checker")
    parser.add_argument("-u", "--url", help="Target URL to test for IDOR vulnerabilities")
    parser.add_argument("-p", "--parameters", action="store_true", help="Scan all parameters in the URL")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method to use (GET, POST, PUT, DELETE)")
    parser.add_argument("-d", "--delay", type=float, default=1, help="Delay between requests (in seconds)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--output-format", choices=["txt", "csv"], default="txt", help="Output file format (txt or csv)")
    parser.add_argument("--headers", help="Custom headers in JSON format")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--test-values", help="Custom test values in JSON format")
    parser.add_argument("--sensitive-keywords", help="Custom sensitive keywords in JSON format")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive GUI mode")
    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
        return

    # Parse custom headers
    headers = {}
    if args.headers:
        try:
            headers = json.loads(args.headers)  # Convert JSON string to dictionary
        except json.JSONDecodeError as e:
            print(f"Error parsing headers: {e}")
            return

    # Parse proxy configuration
    proxy = None
    if args.proxy:
        proxy = {"http": args.proxy, "https": args.proxy}

    # Parse custom test values
    test_values = [1, 2, 3, 4, 5]  # Default test values
    if args.test_values:
        try:
            test_values = json.loads(args.test_values)  # Convert JSON string to list
        except json.JSONDecodeError as e:
            print(f"Error parsing test values: {e}")
            return

    # Parse custom sensitive keywords
    sensitive_keywords = None
    if args.sensitive_keywords:
        try:
            sensitive_keywords = json.loads(args.sensitive_keywords)
        except json.JSONDecodeError as e:
            print(f"Error parsing sensitive keywords: {e}")
            return

    # Initialize IDORChecker
    checker = IDORChecker(
        args.url,
        delay=args.delay,
        headers=headers,
        proxy=proxy,
        verbose=args.verbose,
        sensitive_keywords=sensitive_keywords,
    )

    # If -p switch is used, scan all parameters in the URL
    if args.parameters:
        for param in checker.params.keys():
            print(f"Scanning parameter: {param}")
            checker.check_idor(param, test_values, method=args.method, output_file=args.output, output_format=args.output_format)
    else:
        # If -p is not used, test a single parameter (e.g., 'id')
        param_to_test = "id"
        checker.check_idor(param_to_test, test_values, method=args.method, output_file=args.output, output_format=args.output_format)

if __name__ == "__main__":
    main()
