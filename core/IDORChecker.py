import matplotlib.pyplot as plt
from tabulate import tabulate
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
from threading import Lock
import base64
from colorama import Fore, Style, init
from difflib import SequenceMatcher  # Added for response comparison

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
        logger=None,
        max_workers: int = 5,
    ):
        """
        Initialize the IDORChecker with the target URL, delay between requests, custom headers, proxy, verbose mode, and sensitive keywords.
        """
        self.url = url
        self.base_url, self.params = self._parse_url(url)
        self.delay = delay
        self.headers = headers or {}
        self.proxy = proxy
        self.verbose = verbose
        self.sensitive_keywords = sensitive_keywords or [
            "password",
            "email",
            "token",
            "ssn",
            "credit_card",
        ]
        self.session = requests.Session()
        self.rate_limit_detected = False
        self.timeout = timeout
        self.max_retries = max_retries
        self.payload_history = []
        self.logger = logger if logger else print
        self.payload_history_lock = Lock()
        self.max_workers = max_workers
        self.baseline_response = None  # Store baseline response for comparison

    def login(self, login_url: str, credentials: Dict, method: str = "POST") -> bool:
        """
        Perform a login request to obtain session cookies or tokens.
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=login_url,
                data=credentials,
                headers=self.headers,
                proxies=self.proxy,
                timeout=self.timeout,
            )
            if response.status_code == 200 or response.status_code == 302:
                print(f"{Fore.GREEN}Login successful.{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}Login failed. Status Code: {response.status_code}{Style.RESET_ALL}")
                return False
        except requests.RequestException as e:
            print(f"{Fore.RED}Error during login: {e}{Style.RESET_ALL}")
            return False

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

    def _load_payloads_from_file(self, filename: str) -> List[str]:
        """
        Load payloads from a file, each line representing a separate payload.
        """
        try:
            with open(filename, "r", encoding="utf-8") as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Warning: Payload file {filename} not found. Using default values.{Style.RESET_ALL}")
            return []

    def _generate_payloads(self, param: str, values: List[str]) -> List[Dict]:
        """
        Generate dynamic payloads by replacing the specified parameter with the given values.
        Includes SQL injection, XSS, and XML payloads from external files.
        """
        if not hasattr(self, "_payload_cache"):
            self._payload_cache = {
                "sql": self._load_payloads_from_file("core/sql.txt"),
                "xss": self._load_payloads_from_file("core/xss.txt"),
                "xml": self._load_payloads_from_file("core/xml.txt"),
            }

        payloads = []
        for value in values:
            value_str = str(value)
            new_params = self.params.copy()
            new_params[param] = value_str

            payloads.append(new_params)
            payloads.append({**new_params, "random_str": self._generate_random_string(10)})
            payloads.append({**new_params, "random_num": random.randint(1000, 9999)})
            payloads.append({**new_params, "special_chars": "!@#$%^&*()"})
            payloads.append({**new_params, "uuid": str(uuid.uuid4())})
            payloads.append({**new_params, "base64": base64.b64encode(value_str.encode()).decode()})
            payloads.append({**new_params, "json": json.dumps({"key": value_str})})

            for sql in self._payload_cache["sql"]:
                payloads.append({**new_params, "sql_injection": sql})

            for xss in self._payload_cache["xss"]:
                payloads.append({**new_params, "xss": xss})

            for xml in self._payload_cache["xml"]:
                payloads.append({**new_params, "xml": xml})

        return payloads

    def _generate_random_string(self, length: int) -> str:
        """
        Generate a random string of the specified length.
        """
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _send_request(self, params: Dict, method: str = "GET") -> Optional[requests.Response]:
        """
        Send a request with the given parameters and HTTP method.
        Implements exponential backoff for retries.
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
                delay = self.delay * (2 ** retries)
                print(f"{Fore.YELLOW}Request failed (Attempt {retries}/{self.max_retries}): {e}{Style.RESET_ALL}")
                time.sleep(delay)
        return None

    def _contains_sensitive_data(self, response_content: str) -> bool:
        """
        Check if the response contains any sensitive keywords.
        """
        return any(keyword.lower() in response_content.lower() for keyword in self.sensitive_keywords)

    def _is_rate_limited(self, response: requests.Response) -> bool:
        """
        Check if the response indicates rate limiting.
        """
        return response.status_code == 429 or "rate limit" in response.text.lower()

    def _compare_responses(self, response1: str, response2: str) -> float:
        """
        Compare two responses and return a similarity score (0 to 1).
        Uses SequenceMatcher from difflib for text comparison.
        """
        return SequenceMatcher(None, response1, response2).ratio()

    def _test_payload(self, payload: Dict, method: str = "GET") -> Optional[Dict]:
        """
        Test a single payload for IDOR vulnerabilities.
        """
        try:
            response = self.session.request(
                method=method.upper(),
                url=self.base_url,
                params=payload if method.upper() == "GET" else None,
                data=payload if method.upper() != "GET" else None,
                headers=self.headers,
                proxies=self.proxy,
                timeout=self.timeout,
            )

            if self._is_rate_limited(response):
                self.rate_limit_detected = True
                self.logger(f"{Fore.YELLOW}Rate limit detected.{Style.RESET_ALL}")
                return None

            sensitive_data_detected = self._contains_sensitive_data(response.text)
            idor_detected = False

            # Compare with baseline response for IDOR detection
            if self.baseline_response is not None:
                similarity = self._compare_responses(self.baseline_response.text, response.text)
                # If responses are different (less than 90% similar) and not an error, potential IDOR
                if similarity < 0.9 and response.status_code == 200:
                    idor_detected = True
                    self.logger(f"{Fore.RED}Potential IDOR detected: Different response for payload {payload} (Similarity: {similarity:.2f}){Style.RESET_ALL}")

            result = {
                "payload": payload,
                "status_code": response.status_code,
                "response_content": response.text[:50] + "...",
                "sensitive_data_detected": sensitive_data_detected,
                "idor_detected": idor_detected,
            }

            if sensitive_data_detected:
                self.logger(f"{Fore.RED}Sensitive data detected with payload: {payload}{Style.RESET_ALL}")
            elif idor_detected:
                self.logger(f"{Fore.RED}Potential IDOR detected with payload: {payload}{Style.RESET_ALL}")
            else:
                self.logger(f"{Fore.GREEN}Payload tested: {payload} (Status Code: {response.status_code}){Style.RESET_ALL}")

            return result
        except requests.RequestException as e:
            self.logger(f"{Fore.RED}Request failed for payload {payload}: {e}{Style.RESET_ALL}")
            return None

    def check_idor(
        self,
        param: str,
        test_values: List[str],
        method: str = "GET",
        output_file: Optional[str] = None,
        output_format: str = "txt",
        max_workers: int = 5,
    ):
        """
        Check for IDOR vulnerabilities by testing different values for the specified parameter.
        """
        payloads = self._generate_payloads(param, test_values)
        results = []

        # Set baseline response using the first test value
        baseline_payload = {param: str(test_values[0])}
        self.baseline_response = self._send_request(baseline_payload, method)
        if self.baseline_response:
            self.logger(f"{Fore.CYAN}Baseline response set with payload: {baseline_payload}{Style.RESET_ALL}")
        else:
            self.logger(f"{Fore.RED}Failed to set baseline response{Style.RESET_ALL}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._test_payload, payload, method) for payload in payloads]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    with self.payload_history_lock:
                        self.payload_history.append(result)

        if output_file:
            if output_format == "csv":
                self._save_results_csv(results, output_file)
            elif output_format == "json":
                self._save_results_json(results, output_file)
            else:
                self._save_results_txt(results, output_file)
            print(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

        self._display_summary(results)
        return results

    def _save_results_json(self, results: List[Dict], output_file: str):
        """
        Save results to a JSON file.
        """
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)

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
                f.write(f"IDOR Detected: {result['idor_detected']}\n")
                f.write("-" * 40 + "\n")

    def _save_results_csv(self, results: List[Dict], output_file: str):
        """
        Save results to a CSV file.
        """
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Payload", "Status Code", "Response Content", "Sensitive Data Detected", "IDOR Detected"])
            for result in results:
                writer.writerow(
                    [
                        result["payload"],
                        result["status_code"],
                        result["response_content"],
                        result["sensitive_data_detected"],
                        result["idor_detected"],
                    ]
                )

    def generate_report(self, results: List[Dict], output_file: str, format_type: str = "txt"):
        """
        Generate a detailed report of the scan results in the specified format.
        """
        if format_type == "json":
            self._save_results_json(results, output_file)
        elif format_type == "csv":
            self._save_results_csv(results, output_file)
        elif format_type == "txt":
            self._save_results_txt(results, output_file)
        else:
            print(f"{Fore.RED}Unsupported format: {format_type}. Using default (txt).{Style.RESET_ALL}")
            self._save_results_txt(results, output_file)

        print(f"{Fore.GREEN}Report generated: {output_file}{Style.RESET_ALL}")

    def visualize_results(self, results: List[Dict]):
        """
        Visualize the scan results using matplotlib.
        """
        vulnerable_count = sum(1 for result in results if result["sensitive_data_detected"] or result["idor_detected"])
        safe_count = len(results) - vulnerable_count

        labels = ["Vulnerable", "Safe"]
        sizes = [vulnerable_count, safe_count]
        colors = ["red", "green"]

        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.title("IDOR Vulnerability Summary")
        plt.axis('equal')
        plt.show()

        table_data = [
            [result["payload"], result["status_code"], result["sensitive_data_detected"], result["idor_detected"]]
            for result in results
        ]
        headers = ["Payload", "Status Code", "Sensitive Data Detected", "IDOR Detected"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    def _display_summary(self, results: List[Dict]):
        """
        Display a summary of the scan results with enhanced formatting.
        """
        vulnerabilities = [result for result in results if result["sensitive_data_detected"] or result["idor_detected"]]
        print(f"\n{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total Payloads Tested: {len(results)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerabilities Found: {len(vulnerabilities)}{Style.RESET_ALL}")

        if vulnerabilities:
            print(f"{Fore.RED}Vulnerable Payloads:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"- {Fore.RED}{vuln['payload']} (Sensitive: {vuln['sensitive_data_detected']}, IDOR: {vuln['idor_detected']}){Style.RESET_ALL}")

        if len(results) > 0:
            visualize = input("\nDo you want to visualize the results? (y/n): ").strip().lower()
            if visualize == "y":
                self.visualize_results(results)
