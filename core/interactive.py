import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QCheckBox, QProgressBar, QMessageBox,
    QFileDialog, QComboBox, QMenuBar, QAction, QMenu
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from core.IDORChecker import IDORChecker

class ScanWorker(QThread):
    """Worker thread for running the scan in the background."""
    log_message = pyqtSignal(str)  # Signal for logging messages
    progress_update = pyqtSignal(int)  # Signal for updating progress
    finished = pyqtSignal()  # Signal when the scan is complete

    def __init__(self, url, test_values, output_file, payload_types, method="GET"):
        super().__init__()
        self.url = url
        self.test_values = test_values
        self.output_file = output_file
        self.payload_types = payload_types
        self.method = method
        self.stop_flag = False

    def stop(self):
        """Set the stop flag to terminate the scan."""
        self.stop_flag = True

    def run(self):
        """Run the IDOR vulnerability scan."""
        try:
            checker = IDORChecker(self.url, verbose=True, logger=self.log_message.emit)

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

class IDORScannerGUI(QMainWindow):
    """Main GUI window for the IDOR Vulnerability Scanner."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDOR Vulnerability Scanner")
        self.setGeometry(100, 100, 800, 600)

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
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(save_action)
        file_menu.addAction(exit_action)

        # View Menu
        view_menu = self.menu_bar.addMenu("View")
        clear_log_action = QAction("Clear Log", self)
        clear_log_action.triggered.connect(self.clear_log)
        view_menu.addAction(clear_log_action)

        # Edit Menu
        edit_menu = self.menu_bar.addMenu("Edit")
        preferences_action = QAction("Preferences", self)
        preferences_action.triggered.connect(self.show_preferences)
        edit_menu.addAction(preferences_action)

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
        self.worker = ScanWorker(url, test_values, output_file, payload_types, method=method)
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

    def show_preferences(self):
        """Show preferences dialog (placeholder)."""
        QMessageBox.information(self, "Preferences", "Preferences dialog will be implemented soon.")

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About IDOR-Forge", "IDOR Vulnerability Scanner v1.3\nDeveloped by errorfiat\n\nIt`s an advanced and versatile tool designed to detect Insecure Direct Object Reference (IDOR) vulnerabilities in web applications.")

def interactive_mode():
    app = QApplication(sys.argv)
    window = IDORScannerGUI()
    window.show()
    sys.exit(app.exec_())
