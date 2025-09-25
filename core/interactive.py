from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QDialog, QFormLayout, QDialogButtonBox,
    QLineEdit, QRadioButton, QCheckBox, QLabel, QFileDialog, QMessageBox, QTextEdit, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QFont
from PyQt5 import uic
from core.IDORChecker import IDORChecker
import sys
import logging
import json
import re
import time
import os

# Setting up the logger for file-based logging
logging.basicConfig(
    filename="idor_forge_scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


class ScanWorker(QThread):
    """Worker thread for running the scan in the background."""
    log_message = pyqtSignal(str)  # Signal for logging messages
    progress_update = pyqtSignal(int)  # Signal for updating progress
    finished = pyqtSignal()  # Signal when the scan is complete

    def __init__(
        self,
        url,
        param,
        test_values,
        output_file,
        output_format,
        payload_types,
        method="GET",
        proxy=None,
        multi_threaded=False,
        login_url=None,
        credentials=None,
        multi_credentials=None,
        thresholds=None,
        evasion=False,
        request_type="query",
        auth_type="basic"
    ):
        super().__init__()
        self.url = url
        self.param = param
        self.test_values = test_values
        self.output_file = output_file
        self.output_format = output_format
        self.payload_types = payload_types
        self.method = method
        self.proxy = proxy
        self.multi_threaded = multi_threaded
        self.login_url = login_url
        self.credentials = credentials
        self.multi_credentials = multi_credentials
        self.thresholds = thresholds
        self.evasion = evasion
        self.request_type = request_type
        self.auth_type = auth_type
        self.stop_flag = False

    def stop(self):
        """Set the stop flag to terminate the scan."""
        self.stop_flag = True

    def run(self):
        """Run the IDOR vulnerability scan."""
        try:
            checker = IDORChecker(
                self.url,
                verbose=True,
                logger=self.log_message.emit,
                proxy=self.proxy,
                sensitive_keywords=[
                    "password", "email", "display_name", "token", "ssn",
                    "credit_card", "phone", "address", "dob"
                ],
                multi_credentials=self.multi_credentials,
                thresholds=self.thresholds,
                evasion=self.evasion,
                request_type=self.request_type,
                auth_type=self.auth_type,
            )

            # Perform login if credentials are provided
            if self.login_url and self.credentials:
                success = checker.login(self.login_url, self.credentials, method="POST")
                if not success:
                    self.log_message.emit("Login failed. Continuing without authentication.")

            # Run the scan with simple progress demo (emit every 20%)
            results = checker.check_idor(
                param=self.param,
                test_values=self.test_values,
                method=self.method,
                output_file=self.output_file,
                output_format=self.output_format,
                max_workers=10 if self.multi_threaded else 1
            )
            for i in range(0, 101, 20):  # Demo progress
                self.progress_update.emit(i)
                time.sleep(0.5)  # Simulate

            self.log_message.emit("Scan complete!")
        except Exception as e:
            self.log_message.emit(f"Error during scan: {e}")
        finally:
            self.finished.emit()


class PreferencesDialog(QDialog):
    """Dialog for setting preferences (e.g., theme, multi-threaded scanning)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        layout = QFormLayout()

        # Theme selection
        self.theme_label = QLabel("Select Theme:")
        self.light_radio = QRadioButton("Pinterest Theme")
        self.pentest_radio = QRadioButton("Pentest Theme")
        layout.addRow(self.theme_label, self.light_radio)
        layout.addRow("", self.pentest_radio)

        # Multi-threaded scanning checkbox
        self.multi_threaded_checkbox = QCheckBox("Enable Multi-threaded Scanning")
        layout.addRow(self.multi_threaded_checkbox)

        # Evasion checkbox
        self.evasion_checkbox = QCheckBox("Enable Evasion Techniques")
        layout.addRow(self.evasion_checkbox)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)

        self.setLayout(layout)

    def get_theme(self):
        """Return the selected theme."""
        if self.pentest_radio.isChecked():
            return "pentest"
        return "pinterest"

    def is_multi_threaded(self):
        """Return whether multi-threaded scanning is enabled."""
        return self.multi_threaded_checkbox.isChecked()

    def is_evasion(self):
        """Return whether evasion is enabled."""
        return self.evasion_checkbox.isChecked()


class ProxySettingsDialog(QDialog):
    """Dialog for setting proxy configurations."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Proxy Settings")
        layout = QFormLayout()

        # HTTP Proxy
        self.http_proxy_label = QLabel("HTTP Proxy (e.g., http://proxy:port):")
        self.http_proxy_input = QLineEdit()
        layout.addRow(self.http_proxy_label, self.http_proxy_input)

        # HTTPS Proxy
        self.https_proxy_label = QLabel("HTTPS Proxy (e.g., http://proxy:port):")
        self.https_proxy_input = QLineEdit()
        layout.addRow(self.https_proxy_label, self.https_proxy_input)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)

        self.setLayout(layout)

    def get_proxies(self):
        """Return the proxy settings as a dictionary."""
        proxies = {}
        if self.http_proxy_input.text().strip():
            proxies["http"] = self.http_proxy_input.text().strip()
        if self.https_proxy_input.text().strip():
            proxies["https"] = self.https_proxy_input.text().strip()
        return proxies or None


class LoginDialog(QDialog):
    """Dialog for entering login credentials. Supports multi-user."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login Settings")
        layout = QFormLayout()

        # Login URL
        self.login_url_label = QLabel("Login URL:")
        self.login_url_input = QLineEdit()
        layout.addRow(self.login_url_label, self.login_url_input)

        # Multi-credentials list
        self.multi_creds_label = QLabel("Multi-Credentials (JSON list):")
        self.multi_creds_input = QTextEdit()  # For JSON input
        layout.addRow(self.multi_creds_label, self.multi_creds_input)

        # Single Username/Password as fallback
        self.username_label = QLabel("Username (for single):")
        self.username_input = QLineEdit()
        layout.addRow(self.username_label, self.username_input)

        self.password_label = QLabel("Password (for single):")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow(self.password_label, self.password_input)

        # Auth type
        self.auth_type_label = QLabel("Auth Type:")
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["basic", "oauth", "jwt"])
        layout.addRow(self.auth_type_label, self.auth_type_combo)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)

        self.setLayout(layout)

    def get_login_settings(self):
        """Return the login settings."""
        login_url = self.login_url_input.text().strip()
        multi_creds_str = self.multi_creds_input.toPlainText().strip()
        try:
            multi_credentials = json.loads(multi_creds_str) if multi_creds_str else None
        except json.JSONDecodeError:
            QMessageBox.warning(self, "Input Error", "Invalid JSON for multi-credentials.")
            multi_credentials = None
        single_creds = {
            "username": self.username_input.text().strip(),
            "password": self.password_input.text().strip()
        } if self.username_input.text().strip() and self.password_input.text().strip() else None
        auth_type = self.auth_type_combo.currentText()
        credentials = multi_credentials or single_creds
        return login_url, credentials, auth_type


class ThresholdsDialog(QDialog):
    """Dialog for setting similarity thresholds."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Similarity Thresholds")
        layout = QFormLayout()

        self.structure_label = QLabel("Structure Similarity:")
        self.structure_input = QLineEdit("0.8")
        layout.addRow(self.structure_label, self.structure_input)

        self.content_label = QLabel("Content Similarity:")
        self.content_input = QLineEdit("0.9")
        layout.addRow(self.content_label, self.content_input)

        self.text_label = QLabel("Text Similarity:")
        self.text_input = QLineEdit("0.8")
        layout.addRow(self.text_label, self.text_input)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)

        self.setLayout(layout)

    def get_thresholds(self):
        """Return thresholds as dict."""
        try:
            return {
                "structure": float(self.structure_input.text()),
                "content": float(self.content_input.text()),
                "text": float(self.text_input.text())
            }
        except ValueError:
            return None


class IDORScannerGUI(QMainWindow):
    """Main GUI window for the IDOR Vulnerability Scanner."""
    def __init__(self):
        super().__init__()
        # Determine the path to main.ui relative to interactive.py
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ui_file = os.path.join(base_dir, "ui/main.ui")

        # Check if the UI file exists
        if not os.path.exists(ui_file):
            QMessageBox.critical(
                self, "UI File Error",
                f"Cannot find 'main.ui' at {ui_file}. Please ensure the file is in the same directory as interactive.py."
            )
            sys.exit(1)

        # Load UI from main.ui
        uic.loadUi(ui_file, self)

        # Load settings
        self.settings = QSettings("IDORScanner", "Preferences")
        self.load_settings()

        # Connect signals
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.browse_button.clicked.connect(self.select_output_file)
        self.actionSave_Results.triggered.connect(self.select_output_file)
        self.actionProxy_Settings.triggered.connect(self.show_proxy_settings)
        self.actionLogin_Settings.triggered.connect(self.show_login_settings)
        self.actionExit.triggered.connect(self.close)
        self.actionPreferences.triggered.connect(self.show_preferences)
        self.actionClear_Log.triggered.connect(self.clear_log)
        self.actionAbout.triggered.connect(self.show_about)
        # Add menu for thresholds
        self.actionThresholds = self.menuEdit.addAction("Similarity Thresholds")
        self.actionThresholds.triggered.connect(self.show_thresholds)

        # Request type combo in UI (added dynamically to method_layout)
        self.request_type_label = QLabel("Request Type:")
        self.request_type_combo = QComboBox()
        self.request_type_combo.addItems(["query", "json", "graphql"])
        self.request_type_combo.setToolTip("Select request type: query params, JSON body, or GraphQL.")
        self.method_layout.addWidget(self.request_type_label)
        self.method_layout.addWidget(self.request_type_combo)

        # Add tooltips for guidance
        self.url_input.setToolTip("Enter the target URL, e.g., http://example.com/profile?user_id=1")
        self.param_input.setToolTip("Parameter to test, e.g., user_id. If blank, auto-detects common params like 'id'.")
        self.test_values_input.setToolTip("Comma-separated test values, e.g., 1,2,3. Use num-range in CLI for large ranges.")
        self.output_input.setToolTip("Path to save results. Browse to select.")
        self.sql_check.setToolTip("Include SQL injection payloads in scan.")
        self.xss_check.setToolTip("Include XSS payloads in scan.")
        self.xml_check.setToolTip("Include XML injection (e.g., XXE) payloads in scan.")
        self.method_combo.setToolTip("HTTP method for requests.")

        # Worker thread
        self.worker = None
        self.login_url = None
        self.credentials = None
        self.multi_credentials = None
        self.thresholds = None
        self.auth_type = "basic"

    def load_settings(self):
        """Load user preferences from QSettings."""
        theme = self.settings.value("theme", "pinterest")
        if theme == "pentest":
            self.apply_pentest_theme()
        else:
            self.apply_pinterest_theme()

        self.proxy_settings = self.settings.value("proxy", {"http": "", "https": ""})
        self.multi_threaded = self.settings.value("multi_threaded", False, type=bool)
        self.evasion = self.settings.value("evasion", False, type=bool)

    def apply_pinterest_theme(self):
        """Apply Pinterest-inspired theme with glassy effects."""
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #F5F5F5;
                color: #333333;
                font-family: 'Arial', sans-serif;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: rgba(255, 255, 255, 0.7);
                color: #333333;
                border: 2px solid rgba(230, 0, 35, 0.5);
                border-radius: 10px;
                padding: 6px;
                font-family: 'Arial', sans-serif;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #E60023;
                background-color: rgba(255, 255, 255, 0.9);
            }
            QPushButton {
                background-color: rgba(230, 0, 35, 0.7);
                color: #FFFFFF;
                border: 2px solid rgba(230, 0, 35, 0.5);
                border-radius: 12px;
                padding: 8px;
                font-family: 'Arial', sans-serif;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(230, 0, 35, 0.9);
                border: 2px solid #E60023;
            }
            QPushButton:disabled {
                background-color: rgba(200, 200, 200, 0.5);
                color: #666666;
                border: 2px solid rgba(200, 200, 200, 0.5);
            }
            QLabel {
                color: #333333;
                font-family: 'Arial', sans-serif;
            }
            QCheckBox, QRadioButton {
                color: #333333;
                font-family: 'Arial', sans-serif;
            }
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.7);
                color: #333333;
                border: 2px solid rgba(230, 0, 35, 0.5);
                border-radius: 10px;
                text-align: center;
                font-family: 'Arial', sans-serif;
            }
            QProgressBar::chunk {
                background-color: #E60023;
                border-radius: 10px;
            }
            QMenuBar {
                background-color: rgba(255, 255, 255, 0.7);
                color: #333333;
                font-family: 'Arial', sans-serif;
            }
            QMenuBar::item {
                background-color: transparent;
                color: #333333;
            }
            QMenuBar::item:selected {
                background-color: #E60023;
                color: #FFFFFF;
            }
            QMenu {
                background-color: rgba(255, 255, 255, 0.7);
                color: #333333;
                border: 2px solid rgba(230, 0, 35, 0.5);
                border-radius: 10px;
            }
            QMenu::item:selected {
                background-color: #E60023;
                color: #FFFFFF;
            }
        """)
        self.log_area.setFont(QFont("Arial", 10))

    def apply_pentest_theme(self):
        """Apply Pentest Theme (cyberpunk/hacker style)."""
        self.setStyleSheet("""
            QMainWindow, QDialog {
                background-color: #1C2526;
                color: #00FF00;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: rgba(45, 56, 58, 0.7);
                color: #00FF00;
                border: 2px solid #FF2D00;
                border-radius: 10px;
                padding: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #00FF00;
                background-color: rgba(45, 56, 58, 0.9);
            }
            QPushButton {
                background-color: rgba(255, 45, 0, 0.7);
                color: #000000;
                border: 2px solid #00FF00;
                border-radius: 12px;
                padding: 8px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(0, 255, 0, 0.9);
                border: 2px solid #00FF00;
            }
            QPushButton:disabled {
                background-color: rgba(85, 85, 85, 0.5);
                color: #888888;
                border: 2px solid rgba(85, 85, 85, 0.5);
            }
            QLabel {
                color: #00FF00;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QCheckBox, QRadioButton {
                color: #00FF00;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QProgressBar {
                background-color: rgba(45, 56, 58, 0.7);
                color: #00FF00;
                border: 2px solid #FF2D00;
                border-radius: 10px;
                text-align: center;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QProgressBar::chunk {
                background-color: #00FF00;
                border-radius: 10px;
            }
            QMenuBar {
                background-color: rgba(45, 56, 58, 0.7);
                color: #00FF00;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QMenuBar::item {
                background-color: transparent;
                color: #00FF00;
            }
            QMenuBar::item:selected {
                background-color: #FF2D00;
                color: #000000;
            }
            QMenu {
                background-color: rgba(45, 56, 58, 0.7);
                color: #00FF00;
                border: 2px solid #FF2D00;
                border-radius: 10px;
            }
            QMenu::item:selected {
                background-color: #FF2D00;
                color: #000000;
            }
        """)
        self.log_area.setFont(QFont("Consolas", 10))

    def select_output_file(self):
        """Select output file for saving results."""
        options = QFileDialog.Options()
        file_types = {
            "json": "JSON Files (*.json)",
            "txt": "Text Files (*.txt)",
            "csv": "CSV Files (*.csv)"
        }
        output_file, _ = QFileDialog.getSaveFileName(
            self,
            "Save Results",
            "",
            file_types.get(self.output_format_combo.currentText(), "All Files (*)"),
            options=options
        )
        if output_file:
            self.output_input.setText(output_file)

    def show_preferences(self):
        """Show the preferences dialog."""
        preferences_dialog = PreferencesDialog(self)
        if preferences_dialog.exec_():
            self.settings.setValue("theme", preferences_dialog.get_theme())
            self.settings.setValue("multi_threaded", preferences_dialog.is_multi_threaded())
            self.settings.setValue("evasion", preferences_dialog.is_evasion())
            self.load_settings()

    def show_proxy_settings(self):
        """Show proxy settings dialog."""
        proxy_dialog = ProxySettingsDialog(self)
        if proxy_dialog.exec_():
            self.proxy_settings = proxy_dialog.get_proxies()
            self.settings.setValue("proxy", self.proxy_settings)

    def show_login_settings(self):
        """Show login settings dialog."""
        login_dialog = LoginDialog(self)
        if login_dialog.exec_():
            self.login_url, self.credentials, self.auth_type = login_dialog.get_login_settings()
            self.multi_credentials = (
                self.credentials if isinstance(self.credentials, list) else None
            )

    def show_thresholds(self):
        """Show thresholds dialog."""
        thresholds_dialog = ThresholdsDialog(self)
        if thresholds_dialog.exec_():
            self.thresholds = thresholds_dialog.get_thresholds()
            if not self.thresholds:
                QMessageBox.warning(self, "Input Error", "Invalid threshold values.")

    def validate_inputs(self):
        """Validate input fields before starting the scan."""
        url = self.url_input.text().strip()
        param = self.param_input.text().strip()
        test_values = self.test_values_input.text().strip()

        # Validate URL
        if not url or not re.match(r"^https?://", url):
            QMessageBox.critical(
                self,
                "Input Error",
                "Please enter a valid URL starting with http:// or https://"
            )
            return False

        # Validate parameter (with guidance if empty)
        if not param:
            QMessageBox.critical(
                self,
                "Input Error",
                "Please enter a parameter to test (e.g., user_id). Or use CLI for auto-detect."
            )
            return False

        # Validate test values
        if not test_values:
            QMessageBox.critical(
                self,
                "Input Error",
                "Please enter comma-separated test values (e.g., 1,2,3)"
            )
            return False

        return True

    def start_scan(self):
        """Start the scan."""
        if not self.validate_inputs():
            return

        url = self.url_input.text().strip()
        param = self.param_input.text().strip()
        test_values = [
            val.strip() for val in self.test_values_input.text().strip().split(",")
            if val.strip()
        ]
        output_file = self.output_input.text().strip()
        output_format = self.output_format_combo.currentText()
        payload_types = []
        if self.sql_check.isChecked():
            payload_types.append("sql")
        if self.xss_check.isChecked():
            payload_types.append("xss")
        if self.xml_check.isChecked():
            payload_types.append("xml")
        method = self.method_combo.currentText()
        multi_threaded = self.multi_threaded
        request_type = self.request_type_combo.currentText()

        self.worker = ScanWorker(
            url,
            param,
            test_values,
            output_file,
            output_format,
            payload_types,
            method=method,
            proxy=self.proxy_settings,
            multi_threaded=multi_threaded,
            login_url=self.login_url,
            credentials=self.credentials,
            multi_credentials=self.multi_credentials,
            thresholds=self.thresholds,
            evasion=self.evasion,
            request_type=request_type,
            auth_type=self.auth_type
        )
        self.worker.log_message.connect(self.log_message)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.finished.connect(self.scan_finished)

        self.run_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.worker.start()

    def stop_scan(self):
        """Stop the ongoing scan."""
        if self.worker:
            self.worker.stop()
            self.log_message("Scan stopped by user.")

    def log_message(self, message):
        """Log messages to the GUI log."""
        self.log_area.append(message)

    def update_progress(self, progress):
        """Update the progress bar."""
        self.progress_bar.setValue(progress)

    def scan_finished(self):
        """Handle the completion of the scan."""
        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("Scan completed.")

    def clear_log(self):
        """Clear the log area."""
        self.log_area.clear()

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About IDOR-Forge",
            "IDOR Vulnerability Scanner v2.0\nDeveloped by errorfiat\n\nThe interactive section is designed to make IDOR-Forge accessible to users who prefer a graphical interface over the CLI, particularly for pentesters and security analysts who need to configure complex scans, visualize results in real-time, and manage multiple scan configurations. It leverages PyQt5 for cross-platform GUI rendering and integrates with the core IDORChecker class to perform Insecure Direct Object Reference (IDOR) and related vulnerability scans (e.g., SQL injection, XSS, XXE).\n\nTelegram ID: @Error_fiat\nTwitter(X): @ErrorFiat\n\nerrorfiathck@Gmail.com"
        )


def interactive_mode():
    app = QApplication(sys.argv)
    window = IDORScannerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    interactive_mode()
