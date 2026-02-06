import unittest

from agents.threat_detection import ThreatDetectionAgent


class ThreatDetectionAgentTests(unittest.TestCase):
    def test_detects_bruteforce(self):
        agent = ThreatDetectionAgent(failed_login_threshold=3)
        logs = [
            {"event_type": "login_failed", "source_ip": "203.0.113.5", "message": "fail"},
            {"event_type": "login_failed", "source_ip": "203.0.113.5", "message": "fail"},
            {"event_type": "login_failed", "source_ip": "203.0.113.5", "message": "fail"},
        ]
        result = agent.detect(logs)
        self.assertTrue(result.alert)
        self.assertIn("Multiple failed login attempts", result.reason)

    def test_no_alert_for_normal_activity(self):
        agent = ThreatDetectionAgent(failed_login_threshold=3)
        logs = [
            {"event_type": "login_success", "source_ip": "203.0.113.5", "message": "ok"},
        ]
        result = agent.detect(logs)
        self.assertFalse(result.alert)


if __name__ == "__main__":
    unittest.main()
