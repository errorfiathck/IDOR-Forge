from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QCheckBox, QProgressBar, QMessageBox,
    QFileDialog, QComboBox, QMenuBar, QAction, QMenu, QDialog, QRadioButton,
    QDialogButtonBox, QColorDialog, QFormLayout 
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QColor, QPalette
from core.IDORChecker import IDORChecker
import sys

class ScanWorker(QThread):
    """Worker thread for running the scan in the background."""
    log_message = pyqtSignal(str)  # Signal for logging messages
    progress_update = pyqtSignal(int)  # Signal for updating progress
    finished = pyqtSignal()  # Signal when the scan is complete

    def __init__(self, url, test_values, output_file, payload_types, method="GET", proxy=None):
        super().__init__()
        self.url = url
        self.test_values = test_values
        self.output_file = output_file
        self.payload_types = payload_types
        self.method = method
        self.proxy = proxy
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
                proxy=self.proxy  # Pass the proxy configuration
            )

            # Generate payloads based on selected types
            all_payloads = checker._generate_payloads("id", self.test_values)
            selected_payloads = []
            for payload in all_payloads:
                if any(key in payload for key in ["random_str", "random_num", "base64", "special_chars", "uuid", "json"]):
                    selected_payloads.append(payload)
                if "sql" in self.payload_types and "sql_injection" in payload:
                    selected_payloads.append(payload)
                if "xss" in self.payload_types and "xss" in payload:
                    selected_payloads.append(payload)
                if "xml" in self.payload_types and "xml" in payload:
                    selected_payloads.append(payload)

            # Run the scan
            total_payloads = len(selected_payloads)
            results = []
            for i, payload in enumerate(selected_payloads):
                if self.stop_flag:
                    self.log_message.emit("Scan stopped by user.")
                    break
                self.log_message.emit(f"Testing payload: {payload}")
                result = checker._test_payload(payload, self.method)
                results.append(result)
                self.progress_update.emit(int((i + 1) * 100 / total_payloads))

            # Save results to file if specified
            if self.output_file:
                checker._save_results_json(results, self.output_file)
                self.log_message.emit(f"Results saved to {self.output_file}")

            self.log_message.emit("Scan complete!")
        except Exception as e:
            self.log_message.emit(f"Error during scan: {e}")
        finally:
            self.finished.emit()

class PreferencesDialog(QDialog):
    """Dialog for setting preferences (e.g., theme)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        layout = QVBoxLayout()

        # Theme selection
        self.theme_label = QLabel("Select Theme:")
        layout.addWidget(self.theme_label)

        self.light_radio = QRadioButton("Light Mode")
        self.dark_radio = QRadioButton("Dark Mode")
        layout.addWidget(self.light_radio)
        layout.addWidget(self.dark_radio)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def get_theme(self):
        """Return the selected theme."""
        if self.dark_radio.isChecked():
            return "dark"
        return "light"

class ProxySettingsDialog(QDialog):
    """Dialog for setting proxy configurations."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Proxy Settings")
        layout = QFormLayout()

        # HTTP Proxy
        self.http_proxy_label = QLabel("HTTP Proxy:")
        self.http_proxy_input = QLineEdit()
        layout.addRow(self.http_proxy_label, self.http_proxy_input)

        # HTTPS Proxy
        self.https_proxy_label = QLabel("HTTPS Proxy:")
        self.https_proxy_input = QLineEdit()
        layout.addRow(self.https_proxy_label, self.https_proxy_input)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def get_proxies(self):
        """Return the proxy settings as a dictionary."""
        return {
            "http": self.http_proxy_input.text().strip(),
            "https": self.https_proxy_input.text().strip(),
        }

class IDORScannerGUI(QMainWindow):
    """Main GUI window for the IDOR Vulnerability Scanner."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDOR Vulnerability Scanner")
        self.setGeometry(100, 100, 800, 600)

        # Load settings
        self.settings = QSettings("IDORScanner", "Preferences")
        self.load_settings()

        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Add Menu Bar
        self.menu_bar = self.menuBar()

        # File Menu
        file_menu = self.menu_bar.addMenu("File")
        save_action = QAction("Save Results", self)
        save_action.triggered.connect(self.select_output_file)
        proxy_action = QAction("Proxy Settings", self)
        proxy_action.triggered.connect(self.show_proxy_settings)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(save_action)
        file_menu.addAction(proxy_action)
        file_menu.addAction(exit_action)

        # Edit Menu
        edit_menu = self.menu_bar.addMenu("Edit")
        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(self.show_preferences)
        edit_menu.addAction(preferences_action)

        # View Menu
        view_menu = self.menu_bar.addMenu("View")
        clear_log_action = QAction("Clear Log", self)
        clear_log_action.triggered.connect(self.clear_log)
        view_menu.addAction(clear_log_action)

        # Help Menu
        help_menu = self.menu_bar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        # Input fields
        input_layout = QHBoxLayout()
        layout.addLayout(input_layout)

        # URL input
        self.url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        input_layout.addWidget(self.url_label)
        input_layout.addWidget(self.url_input)

        # Test values input
        test_values_layout = QHBoxLayout()
        layout.addLayout(test_values_layout)
        self.test_values_label = QLabel("Test Values (comma-separated):")
        self.test_values_input = QLineEdit()
        test_values_layout.addWidget(self.test_values_label)
        test_values_layout.addWidget(self.test_values_input)

        # Output file input
        output_layout = QHBoxLayout()
        layout.addLayout(output_layout)
        self.output_label = QLabel("Output File:")
        self.output_input = QLineEdit()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.select_output_file)
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(self.browse_button)

        # Payload types selection
        payload_layout = QVBoxLayout()
        layout.addLayout(payload_layout)
        self.payload_label = QLabel("Select Payload Types:")
        self.sql_check = QCheckBox("SQL Injection")
        self.xss_check = QCheckBox("XSS (Cross-site Scripting)")
        self.xml_check = QCheckBox("XML Injection")
        payload_layout.addWidget(self.payload_label)
        payload_layout.addWidget(self.sql_check)
        payload_layout.addWidget(self.xss_check)
        payload_layout.addWidget(self.xml_check)

        # HTTP method selection
        method_layout = QHBoxLayout()
        layout.addLayout(method_layout)
        self.method_label = QLabel("HTTP Method:")
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE"])
        method_layout.addWidget(self.method_label)
        method_layout.addWidget(self.method_combo)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Buttons
        button_layout = QHBoxLayout()
        layout.addLayout(button_layout)
        self.run_button = QPushButton("Run Scan")
        self.run_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.run_button)
        button_layout.addWidget(self.stop_button)

        # Worker thread
        self.worker = None

    def load_settings(self):
        """Load user preferences from QSettings."""
        theme = self.settings.value("theme", "light")
        if theme == "dark":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

        self.proxy_settings = self.settings.value("proxy", {"http": "", "https": ""})

    def apply_dark_theme(self):
        """Apply Dark Mode theme."""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

    def apply_light_theme(self):
        """Apply Light Mode theme."""
        palette = QPalette()
        palette.setColor(QPalette.Window, Qt.white)
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(240, 240, 240))
        palette.setColor(QPalette.AlternateBase, QColor(220, 220, 220))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.black)
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.Button, Qt.white)
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(0, 0, 255))
        palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)

    def show_preferences(self):
        """Show the preferences dialog."""
        dialog = PreferencesDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            theme = dialog.get_theme()
            self.settings.setValue("theme", theme)
            if theme == "dark":
                self.apply_dark_theme()
            else:
                self.apply_light_theme()

    def show_proxy_settings(self):
        """Show the proxy settings dialog."""
        dialog = ProxySettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.proxy_settings = dialog.get_proxies()
            self.settings.setValue("proxy", self.proxy_settings)

    def select_output_file(self):
        """Open file dialog to select an output file."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Output File", "", "JSON Files (*.json);;All Files (*)", options=options)
        if file_name:
            self.output_input.setText(file_name)

    def start_scan(self):
        """Start the scan process."""
        url = self.url_input.text().strip()
        test_values = [value.strip() for value in self.test_values_input.text().split(",") if value.strip()]
        output_file = self.output_input.text().strip()
        payload_types = []
        if self.sql_check.isChecked():
            payload_types.append("sql")
        if self.xss_check.isChecked():
            payload_types.append("xss")
        if self.xml_check.isChecked():
            payload_types.append("xml")
        method = self.method_combo.currentText()

        if not url or not test_values:
            QMessageBox.critical(self, "Error", "Please provide a URL and test values.")
            return

        self.run_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.worker = ScanWorker(url, test_values, output_file, payload_types, method=method, proxy=self.proxy_settings)
        self.worker.log_message.connect(self.update_log)
        self.worker.progress_update.connect(self.update_progress)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()

    def stop_scan(self):
        """Stop the scan process."""
        if self.worker:
            self.worker.stop()
            self.worker.wait()  # Wait for the thread to finish
        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_log(self, message):
        """Update the log area with a new message."""
        self.log_area.append(message)

    def update_progress(self, value):
        """Update the progress bar value."""
        self.progress_bar.setValue(value)

    def scan_finished(self):
        """Handle actions when the scan is finished."""
        self.run_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        QMessageBox.information(self, "Info", "Scan completed.")

    def clear_log(self):
        """Clear the log area."""
        self.log_area.clear()

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About IDOR-Forge", "IDOR Vulnerability Scanner v1.3.1\nDeveloped by errorfiat\n\nIt`s an advanced and versatile tool designed to detect Insecure Direct Object Reference (IDOR) vulnerabilities in web applications.")

def interactive_mode():
    app = QApplication(sys.argv)
    window = IDORScannerGUI()
    window.show()
    sys.exit(app.exec_())
