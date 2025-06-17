import unittest
import pandas as pd
import json
from src.scan.aws import process_aws_scan  # Update this path to match your codebase


class TestProcessAwsScan(unittest.TestCase):
    def test_valid_input(self):
        """Test normal case with valid misconfig and cause metadata."""
        report = {
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS001",
                            "AVDID": "AVD-AWS-0001",
                            "Title": "S3 bucket is public",
                            "Description": "The S3 bucket is publicly accessible",
                            "Resolution": "Make the bucket private",
                            "Severity": "HIGH",
                            "Message": "Bucket allows public read access",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "S3",
                                "Resource": "my-public-bucket"
                            }
                        }
                    ]
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["resource_name"], "my-public-bucket")

    def test_deduplication(self):
        """Ensure duplicate misconfigurations are removed based on id and resource_name."""
        report = {
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS001",
                            "AVDID": "AVD-AWS-0001",
                            "Title": "S3 bucket is public",
                            "Description": "The S3 bucket is public",
                            "Resolution": "Restrict access",
                            "Severity": "HIGH",
                            "Message": "Public access detected",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "S3",
                                "Resource": "bucket-123"
                            }
                        },
                        {
                            "ID": "AWS001",
                            "AVDID": "AVD-AWS-0001",
                            "Title": "S3 bucket is public",
                            "Description": "The S3 bucket is public",
                            "Resolution": "Restrict access",
                            "Severity": "HIGH",
                            "Message": "Public access detected",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "S3",
                                "Resource": "bucket-123"
                            }
                        }
                    ]
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertEqual(len(df), 1)

    def test_missing_cause_metadata(self):
        """Test when CauseMetadata is missing — should fallback gracefully."""
        report = {
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS002",
                            "AVDID": "AVD-AWS-0002",
                            "Title": "IAM policy too permissive",
                            "Description": "Policy allows *:*",
                            "Resolution": "Restrict permissions",
                            "Severity": "MEDIUM",
                            "Message": "Wildcards used"
                            # CauseMetadata missing
                        }
                    ]
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertEqual(df.iloc[0]["resource_name"], "_")  # Fallback
        self.assertEqual(df.iloc[0]["service_name"], "")

    def test_missing_resource_in_cause_metadata(self):
        """Test fallback to Provider_Service when Resource is missing."""
        report = {
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS003",
                            "AVDID": "AVD-AWS-0003",
                            "Title": "Unencrypted EBS volume",
                            "Description": "Volume not encrypted",
                            "Resolution": "Enable encryption",
                            "Severity": "LOW",
                            "Message": "Detected unencrypted volume",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "EBS"
                            }
                        }
                    ]
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertEqual(df.iloc[0]["resource_name"], "AWS_EBS")
        self.assertEqual(df.iloc[0]["service_name"], "EBS")

    def test_missing_misconfigurations(self):
        """Should skip results with no misconfigurations."""
        report = {
            "Results": [
                {
                    # No Misconfigurations key
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertTrue(df.empty)

    def test_empty_results(self):
        """Should return empty DataFrame if Results list is empty."""
        report = {
            "Results": []
        }
        df = process_aws_scan(report)
        self.assertTrue(df.empty)

    def test_missing_results_key(self):
        """Should handle completely missing Results key."""
        report = {}
        with self.assertRaises(KeyError):
            process_aws_scan(report)

    def test_multiple_valid_results(self):
        """Handles multiple results with multiple misconfigurations."""
        report = {
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS004",
                            "AVDID": "AVD-AWS-004",
                            "Title": "Security group open to world",
                            "Description": "Port 22 open to 0.0.0.0/0",
                            "Resolution": "Restrict inbound rules",
                            "Severity": "CRITICAL",
                            "Message": "0.0.0.0/0 detected",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "EC2",
                                "Resource": "sg-123"
                            }
                        }
                    ]
                },
                {
                    "Misconfigurations": [
                        {
                            "ID": "AWS005",
                            "AVDID": "AVD-AWS-005",
                            "Title": "CloudTrail not enabled",
                            "Description": "No audit trail",
                            "Resolution": "Enable CloudTrail",
                            "Severity": "MEDIUM",
                            "Message": "No trails found",
                            "CauseMetadata": {
                                "Provider": "AWS",
                                "Service": "CloudTrail",
                                "Resource": "us-east-1"
                            }
                        }
                    ]
                }
            ]
        }
        df = process_aws_scan(report)
        self.assertEqual(len(df), 2)
        self.assertSetEqual(set(df["id"]), {"AWS004", "AWS005"})


if __name__ == "__main__":
    unittest.main()
