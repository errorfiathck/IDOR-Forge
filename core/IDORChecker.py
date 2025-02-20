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
        logger=None,  # New parameter for logging
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
        self.logger = logger if logger else print  # Use logger if provided, otherwise default to print
        self.payload_history_lock = Lock()  # Thread-safe lock for payload history


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
        # Cache payloads from files
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

            # Base payload
            payloads.append(new_params)

            # Dynamic payloads
            payloads.append({**new_params, "random_str": self._generate_random_string(10)})
            payloads.append({**new_params, "random_num": random.randint(1000, 9999)})
            payloads.append({**new_params, "special_chars": "!@#$%^&*()"})
            payloads.append({**new_params, "uuid": str(uuid.uuid4())})
            payloads.append({**new_params, "base64": base64.b64encode(value_str.encode()).decode()})
            payloads.append({**new_params, "json": json.dumps({"key": value_str})})

            # Add SQL Injection, XSS, and XML payloads
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
                delay = self.delay * (2 ** retries)  # Exponential backoff
                print(f"{Fore.YELLOW}Request failed (Attempt {retries}/{self.max_retries}): {e}{Style.RESET_ALL}")
                time.sleep(delay)
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

        # Thread-safe addition to payload history
        with self.payload_history_lock:
            self.payload_history.append(result)

        if self.verbose:
            print(f"{Fore.GREEN}Status Code: {result['status_code']}{Style.RESET_ALL}")
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
        max_workers: int = 5,  # Configurable number of threads
    ):
        """
        Check for IDOR vulnerabilities by testing different values for the specified parameter.
        """
        payloads = self._generate_payloads(param, test_values)
        results = []

        # Use ThreadPoolExecutor with configurable max_workers
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._test_payload, payload, method) for payload in payloads]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:  # Ensure the result is not empty
                    results.append(result)
                    self.payload_history.append(result)  # Track payload history

        # Save results to file if output file is provided
        if output_file:
            if output_format == "csv":
                self._save_results_csv(results, output_file)
            elif output_format == "json":
                self._save_results_json(results, output_file)
            else:
                self._save_results_txt(results, output_file)
            print(f"{Fore.GREEN}Results saved to {output_file}{Style.RESET_ALL}")

        # Display summary
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
