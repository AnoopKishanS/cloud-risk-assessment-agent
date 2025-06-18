import unittest
import json
import os
from unittest.mock import patch, mock_open
from prettytable import PrettyTable
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

import sys
import os
from pathlib import Path
current_dir = Path(__file__).resolve().parent
src_path = current_dir.parent / "src"
sys.path.insert(0, str(src_path))

from src.scan.image import (
    scan_image,
    read_image_full_report,
    get_image_summary,
    get_image_cve_table,
    container_info,
    container_footprint,
)


class TestImageScan(unittest.TestCase):
    def setUp(self):
        self.sample_report = {
            "ArtifactName": "sample_image:latest",
            "CreatedAt": "2025-06-15T12:34:56Z",
            "Metadata": {
                "OS": {
                    "Family": "debian",
                    "Name": "11"
                }
            },
            "Results": [
                {
                    "Target": "library/sample_image:latest (debian 11)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1234-5678",
                            "PkgName": "libc6",
                            "InstalledVersion": "2.31-13+deb11u5",
                            "FixedVersion": "2.31-13+deb11u6",
                            "Severity": "High",
                            "Title": "Sample Vulnerability",
                            "Description": "A sample vulnerability description.",
                            "CVSS": {
                                "nvd": {
                                    "V3Score": 7.5
                                }
                            }
                        },
                        {
                            "VulnerabilityID": "CVE-8765-4321",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1n-0+deb11u3",
                            "FixedVersion": "1.1.1n-0+deb11u4",
                            "Severity": "Critical",
                            "Title": "Critical Vulnerability",
                            "Description": "A critical vulnerability description.",
                            "CVSS": {
                                "ghsa": {
                                    "V3Score": 9.8
                                }
                            }
                        }
                    ]
                }
            ]
        }
        sample_report=self.sample_report
        self.mock_file_path = "/tmp/trivy_container_full.json"

    @patch("src.scan.image.os.path.exists")
    @patch("src.scan.image.run_command_and_read_output")
    def test_scan_image(self, mock_run_command, mock_exists):
        mock_exists.return_value = True
        mock_run_command.return_value = True

        result = scan_image(image_path="sample_image", report=self.mock_file_path)
        self.assertTrue(result)
        mock_run_command.assert_called_once()

    # @patch("builtins.open", new_callable=mock_open)
    def test_read_image_full_report(self):
        mock_file = mock_open(read_data=json.dumps(self.sample_report))
        with patch("src.scan.image.open", mock_file):
            report = read_image_full_report()
        self.assertEqual(report["ArtifactName"], "sample_image:latest")
        self.assertIn("Results", report)


    def test_get_image_summary(self):
        mock_file = mock_open(read_data=json.dumps(self.sample_report))
        with patch("src.scan.image.open", mock_file):
            summary = get_image_summary()
        self.assertIsInstance(summary, str)
        self.assertIn("ArtifactName: sample_image:latest", summary)

    @patch("builtins.open", new_callable=mock_open)
    def test_get_image_cve_table(self, mock_file):
        mock_file.return_value.read.return_value = json.dumps(self.sample_report)
        with patch("src.scan.image.open", mock_file):
            table = get_image_cve_table()
        self.assertIsInstance(table, str)
        self.assertIn("CVE-1234-5678", table)
        self.assertIn("CVE-8765-4321", table)

    def test_container_info(self):
        meta_info = container_info(self.sample_report)
        self.assertIn("ArtifactName: sample_image:latest", meta_info)
        self.assertIn("OS_Family: debian", meta_info)

    def test_container_footprint_table_format(self):
        footprint = container_footprint(self.sample_report, output_format="table")
        self.assertIsInstance(footprint, str)
        self.assertIn("CVE-1234-5678", footprint)

    def test_container_footprint_dataframe_format(self):
        footprint = container_footprint(self.sample_report, output_format="dataframe")
        self.assertIsInstance(footprint, pd.DataFrame)
        self.assertEqual(len(footprint), 2)
        self.assertIn("CVE-1234-5678", footprint["ID"].values)
        self.assertIn("CVE-8765-4321", footprint["ID"].values)

    def test_container_footprint_invalid_format(self):
        with self.assertRaises(ValueError):
            container_footprint(self.sample_report, output_format="invalid")

if __name__ == "__main__":
    unittest.main()
