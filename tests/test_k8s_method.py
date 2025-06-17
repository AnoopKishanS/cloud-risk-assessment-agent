import unittest
import pandas as pd
import json
from src.scan.kubernetes import process_k8s_scan


class TestProcessK8sScan(unittest.TestCase):

    def setUp(self):
        self.base_report = {
            "Resources": [
                {
                    "Kind": "Pod",
                    "Name": "nginx-pod",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 1},
                            "Misconfigurations": [
                                {
                                    "ID": "K8S001",
                                    "AVDID": "AVD-K8S-0001",
                                    "Title": "Run as non-root user",
                                    "Description": "Containers should not run as root",
                                    "Resolution": "Set securityContext.runAsNonRoot to true",
                                    "Severity": "HIGH",
                                    "Message": "Container is running as root",
                                    "CauseMetadata": {
                                        "Provider": "Kubernetes",
                                        "Service": "Pod",
                                        "Resource": "nginx-pod"
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_no_grouping_include_metadata(self):
        """Test without grouping and including metadata."""
        df = process_k8s_scan(self.base_report, exclude_metadata=False, grouping=False)
        self.assertEqual(len(df), 1)
        self.assertIn("cause_metadata", df.columns)
        metadata = json.loads(df.iloc[0]["cause_metadata"])
        self.assertEqual(metadata["Provider"], "Kubernetes")

    def test_no_grouping_exclude_metadata(self):
        """Test without grouping and excluding metadata."""
        df = process_k8s_scan(self.base_report, exclude_metadata=True, grouping=False)
        self.assertEqual(len(df), 1)
        self.assertEqual(json.loads(df.iloc[0]["cause_metadata"]), {})

    def test_grouping_with_metadata(self):
        """Test with grouping enabled and including metadata."""
        df = process_k8s_scan(self.base_report, exclude_metadata=False, grouping=True)
        self.assertEqual(len(df), 1)
        self.assertIn("Details", df.columns)
        details = df.iloc[0]["Details"]
        self.assertIsInstance(details, list)
        self.assertEqual(details[0]["resource_name"], "nginx-pod")
        metadata = json.loads(details[0]["cause_metadata"])
        self.assertEqual(metadata["Provider"], "Kubernetes")

    def test_grouping_exclude_metadata(self):
        """Test with grouping enabled and excluding metadata."""
        df = process_k8s_scan(self.base_report, exclude_metadata=True, grouping=True)
        self.assertEqual(len(df), 1)
        details = df.iloc[0]["Details"]
        self.assertEqual(json.loads(details[0]["cause_metadata"]), {})

    def test_multiple_resources_multiple_kinds(self):
        """Test grouping with multiple resources and kinds."""
        report = {
            "Resources": [
                {
                    "Kind": "Pod",
                    "Name": "pod-1",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 1},
                            "Misconfigurations": [
                                {
                                    "ID": "K8S002",
                                    "AVDID": "AVD-K8S-0002",
                                    "Title": "Privileged container",
                                    "Description": "Avoid privileged containers",
                                    "Resolution": "Disable privileged mode",
                                    "Severity": "MEDIUM",
                                    "Message": "Privileged = true",
                                    "CauseMetadata": {"Provider": "Kubernetes"}
                                }
                            ]
                        }
                    ]
                },
                {
                    "Kind": "Service",
                    "Name": "svc-1",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 1},
                            "Misconfigurations": [
                                {
                                    "ID": "K8S003",
                                    "AVDID": "AVD-K8S-0003",
                                    "Title": "Service without selector",
                                    "Description": "Missing selector",
                                    "Resolution": "Add selector to Service",
                                    "Severity": "LOW",
                                    "Message": "No selector found",
                                    "CauseMetadata": {"Provider": "Kubernetes"}
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        df = process_k8s_scan(report, exclude_metadata=False, grouping=True)
        self.assertEqual(len(df), 2)
        self.assertSetEqual(set(df["severity"]), {"MEDIUM", "LOW"})

    def test_zero_failures_ignored(self):
        """Ensure results with 0 failures are ignored."""
        report = {
            "Resources": [
                {
                    "Kind": "Pod",
                    "Name": "pod-healthy",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 0}
                        }
                    ]
                }
            ]
        }
        df = process_k8s_scan(report,grouping=False)
        self.assertTrue(df.empty)

    def test_missing_misconfigurations_key(self):
        """Handle result with no Misconfigurations key."""
        report = {
            "Resources": [
                {
                    "Kind": "Pod",
                    "Name": "missing-key-pod",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 1}
                            # No Misconfigurations
                        }
                    ]
                }
            ]
        }
        df = process_k8s_scan(report,grouping=False)
        self.assertTrue(df.empty)

    def test_empty_report(self):
        """Empty report with no resources."""
        report = {"Resources": []}
        df = process_k8s_scan(report, grouping=False)
        self.assertTrue(df.empty)

    def test_missing_results_key(self):
        """Handle resource with no Results key."""
        report = {
            "Resources": [
                {"Kind": "Pod", "Name": "broken-pod"}
            ]
        }
        df = process_k8s_scan(report,grouping=False)
        self.assertTrue(df.empty)

    def test_missing_cause_metadata_key(self):
        """Missing CauseMetadata should not break the function."""
        report = {
            "Resources": [
                {
                    "Kind": "Pod",
                    "Name": "pod-no-cause",
                    "Results": [
                        {
                            "MisconfSummary": {"Failures": 1},
                            "Misconfigurations": [
                                {
                                    "ID": "K8S004",
                                    "AVDID": "AVD-K8S-004",
                                    "Title": "Example",
                                    "Description": "Example desc",
                                    "Resolution": "Do something",
                                    "Severity": "LOW",
                                    "Message": "Some issue"
                                    # Missing CauseMetadata
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        df = process_k8s_scan(report,grouping=False)
        self.assertEqual(len(df), 1)
        self.assertTrue("cause_metadata" in df.columns)

if __name__ == "__main__":
    unittest.main()
