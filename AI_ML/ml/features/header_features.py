"""Header-based feature extraction using rule-based analysis."""

import re
from typing import TypedDict

from ml.config import CONFIG


class HeaderAnomaly(TypedDict):
    feature: str
    value: str
    contribution: float


class HeaderFeatureResult(TypedDict):
    score: float
    anomalies: list[HeaderAnomaly]
    auth_explanations: dict[str, str]
    iocs: dict


AUTH_PASS_WEIGHT = 0.0
AUTH_FAIL_WEIGHT = 35.0
AUTH_SOFTFAIL_WEIGHT = 15.0
AUTH_NONE_WEIGHT = 10.0


class HeaderFeatures:
    """Extract features from email headers for threat detection."""

    def __init__(self):
        self.cfg = CONFIG.get("features", {}).get("header", {})

    def explain_spf(self, result: str) -> str:
        """Provide plain-English explanation of SPF result."""
        if result == "pass":
            return "The sender's IP is authorized to send for this domain."
        elif result == "fail":
            return "The sender's IP is NOT authorized. Possible spoofing."
        elif result == "softfail":
            return "The sender's IP is not authorized but the policy is not strict. Likely forwarded or moderate risk."
        elif result == "none":
            return "No SPF record published for this domain. Cannot verify sender."
        else:
            return "SPF result could not be determined."

    def explain_dkim(self, result: str) -> str:
        """Provide plain-English explanation of DKIM result."""
        if result == "pass":
            return "Digital signature verified. Email was not altered in transit."
        elif result == "fail":
            return "Digital signature invalid. Email may have been tampered with or is forged."
        elif result == "none":
            return "No DKIM signature present. Cannot verify authenticity."
        else:
            return "DKIM result could not be determined."

    def explain_dmarc(self, result: str) -> str:
        """Provide plain-English explanation of DMARC result."""
        if result == "pass":
            return "Email passes both SPF and DKIM alignment. Sender is authenticated."
        elif result == "fail":
            return "Email fails alignment checks. Common with forwarded mail or spoofing. Note: forwarded mail may legitimately fail DMARC."
        elif result == "none":
            return "No DMARC policy published. Domain does not have explicit authentication requirements."
        else:
            return "DMARC result could not be determined."

    def check_reply_to_mismatch(self, from_address: str, reply_to: str | None) -> HeaderAnomaly | None:
        """Check if Reply-To domain differs from From domain."""
        if not reply_to:
            return None
        from_match = re.search(r"@([^>]+)", from_address)
        reply_match = re.search(r"@([^>]+)", reply_to)
        if from_match and reply_match:
            if from_match.group(1).lower() != reply_match.group(1).lower():
                return HeaderAnomaly(
                    feature="reply_to_domain_mismatch",
                    value=f"From: {from_match.group(1)}, Reply-To: {reply_match.group(1)}",
                    contribution=30.0
                )
        return None

    def check_display_name_spoof(self, from_address: str, display_name: str) -> HeaderAnomaly | None:
        """Check for display name spoofing (name contains address-like pattern)."""
        if not display_name or not from_address:
            return None
        address_local = re.search(r"^([^@]+)", from_address)
        if address_local and address_local.group(1).lower() in display_name.lower():
            return HeaderAnomaly(
                feature="display_name_contains_address",
                value=f"Display name '{display_name}' contains address local part '{address_local.group(1)}'",
                contribution=20.0
            )
        return None

    def check_message_id(self, message_id: str, from_address: str) -> HeaderAnomaly | None:
        """Check Message-ID for anomalies."""
        if not message_id:
            return HeaderAnomaly(
                feature="missing_message_id",
                value="No Message-ID header found",
                contribution=15.0
            )
        if message_id.startswith("<>"):
            return HeaderAnomaly(
                feature="empty_message_id",
                value="Message-ID is empty",
                contribution=15.0
            )
        return None

    def check_x_mailer(self, headers_raw: dict) -> HeaderAnomaly | None:
        """Check for suspicious X-Mailer values."""
        x_mailer = headers_raw.get("X-Mailer", "").lower()
        suspicious_mailers = ["phpmailer", "sendmail", "mailer", "bulk", "bounce"]
        for mailer in suspicious_mailers:
            if mailer in x_mailer and "microsoft" not in x_mailer and "outlook" not in x_mailer:
                return HeaderAnomaly(
                    feature="suspicious_x_mailer",
                    value=f"Non-standard mailer: {headers_raw.get('X-Mailer')}",
                    contribution=15.0
                )
        return None

    def check_received_chain(self, received_chain: list) -> list[HeaderAnomaly]:
        """Check for anomalies in received chain."""
        anomalies = []
        if len(received_chain) == 0:
            return anomalies
        
        for i, hop in enumerate(received_chain):
            if hop.get("from_ip") and not hop.get("from_host"):
                anomalies.append(HeaderAnomaly(
                    feature="received_chain_missing_host",
                    value=f"Hop {i+1} has IP but no hostname",
                    contribution=10.0
                ))
        
        if len(received_chain) > 8:
            anomalies.append(HeaderAnomaly(
                feature="received_chain_excessive_hops",
                value=f"Email passed through {len(received_chain)} hops (unusual)",
                contribution=20.0
            ))
        return anomalies

    def check_originating_ip(self, headers_raw: dict) -> tuple[HeaderAnomaly | None, str | None]:
        """Check for X-Originating-IP which can indicate geographic anomalies."""
        x_originating = headers_raw.get("X-Originating-IP", "")
        if x_originating:
            return HeaderAnomaly(
                feature="x_originating_ip_present",
                value=x_originating,
                contribution=10.0
            ), x_originating.strip()
        return None, None

    def extract(self, email_dict: dict) -> dict:
        """Extract all header features."""
        anomalies = []
        iocs = {"ips": [], "domains": []}
        score = 0.0

        auth_results = email_dict.get("auth_results")
        if auth_results:
            spf = auth_results.get("spf", "unknown")
            dkim = auth_results.get("dkim", "unknown")
            dmarc = auth_results.get("dmarc", "unknown")

            if spf == "fail":
                score += AUTH_FAIL_WEIGHT
            elif spf == "softfail":
                score += AUTH_SOFTFAIL_WEIGHT
            elif spf == "none":
                score += AUTH_NONE_WEIGHT

            if dkim == "fail":
                score += AUTH_FAIL_WEIGHT
            elif dkim == "none":
                score += AUTH_NONE_WEIGHT

            if dmarc == "fail":
                score += AUTH_FAIL_WEIGHT
            elif dmarc == "none":
                score += AUTH_NONE_WEIGHT
        else:
            score += 20.0

        reply_to_mismatch = self.check_reply_to_mismatch(
            email_dict.get("from_address", ""),
            email_dict.get("reply_to")
        )
        if reply_to_mismatch:
            anomalies.append(reply_to_mismatch)
            score += reply_to_mismatch["contribution"]

        display_spoof = self.check_display_name_spoof(
            email_dict.get("from_address", ""),
            email_dict.get("from_display_name", "")
        )
        if display_spoof:
            anomalies.append(display_spoof)
            score += display_spoof["contribution"]

        msg_id_anomaly = self.check_message_id(
            email_dict.get("message_id", ""),
            email_dict.get("from_address", "")
        )
        if msg_id_anomaly:
            anomalies.append(msg_id_anomaly)
            score += msg_id_anomaly["contribution"]

        x_mailer_anomaly = self.check_x_mailer(email_dict.get("headers_raw", {}))
        if x_mailer_anomaly:
            anomalies.append(x_mailer_anomaly)
            score += x_mailer_anomaly["contribution"]

        chain_anomalies = self.check_received_chain(email_dict.get("received_chain", []))
        for a in chain_anomalies:
            anomalies.append(a)
            score += a["contribution"]

        orig_ip_anomaly, orig_ip = self.check_originating_ip(email_dict.get("headers_raw", {}))
        if orig_ip_anomaly:
            anomalies.append(orig_ip_anomaly)
            score += orig_ip_anomaly["contribution"]
        if orig_ip:
            iocs["ips"].append(orig_ip)

        for hop in email_dict.get("received_chain", []):
            if hop.get("from_ip"):
                iocs["ips"].append(hop["from_ip"])

        auth_explanations = {}
        if auth_results:
            auth_explanations["spf"] = self.explain_spf(auth_results.get("spf", "unknown"))
            auth_explanations["dkim"] = self.explain_dkim(auth_results.get("dkim", "unknown"))
            auth_explanations["dmarc"] = self.explain_dmarc(auth_results.get("dmarc", "unknown"))

        return {
            "score": min(100.0, score),
            "anomalies": anomalies[:5],
            "auth_explanations": auth_explanations,
            "iocs": iocs
        }
