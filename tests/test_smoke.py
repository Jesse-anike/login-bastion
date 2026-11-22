import unittest
from main import analyze


class BruteForceDetectorTests(unittest.TestCase):
    def test_flags_source_at_threshold(self):
        sample = "\n".join([
            f"Failed password for admin from 203.0.113.10 port {2200+i} ssh2"
            for i in range(5)
        ])
        report = analyze(sample, threshold=5)
        self.assertEqual(report["total_failed_events"], 5)
        self.assertEqual(report["suspicious_sources"][0]["ip"], "203.0.113.10")

    def test_below_threshold_not_flagged(self):
        sample = "Failed password for root from 203.0.113.12 port 22 ssh2"
        report = analyze(sample, threshold=2)
        self.assertEqual(report["suspicious_sources"], [])

    def test_allowlist_excludes_source(self):
        sample = "Failed password for root from 203.0.113.12 port 22 ssh2"
        report = analyze(sample, threshold=1, allowlist={"203.0.113.12"})
        self.assertEqual(report["total_failed_events"], 0)

    def test_ipv6_is_supported(self):
        sample = "Failed password for root from 2001:db8::1 port 22 ssh2"
        report = analyze(sample, threshold=1)
        self.assertEqual(report["suspicious_sources"][0]["ip"], "2001:db8::1")

    def test_threshold_must_be_positive(self):
        with self.assertRaises(ValueError):
            analyze("", threshold=0)


if __name__ == "__main__":
    unittest.main()
