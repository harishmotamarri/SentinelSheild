class ReportGenerator:
    @staticmethod
    def format_scan_report(scan_type, input_data, result_dict):
        """
        Formats a scan result dictionary into a clean, professional WhatsApp text message.
        """
        # Emoji mapping
        result_str = result_dict.get('result') or result_dict.get('label') or 'Unknown'
        emoji = "✅"
        if any(word in result_str.lower() for word in ['phishing', 'malware', 'scam', 'suspicious', 'danger', 'malicious']):
            emoji = "🚨" if 'malware' in result_str.lower() or 'phishing' in result_str.lower() else "⚠️"
        
        confidence = result_dict.get('confidence', 0.0)
        reason = result_dict.get('reason', 'No specific details provided.')
        
        # Determine Status/Risk
        status = "MALICIOUS" if emoji == "🚨" else ("SUSPICIOUS" if emoji == "⚠️" else "SAFE")
        
        report = f"""🛡️ *Sentinel Shield Scan Result*

*Type:* {scan_type}
*Input:* {input_data[:50] + ("..." if len(input_data) > 50 else "")}
*Status:* {emoji} {status} ({result_str})

*Risk Score:* {round(result_dict.get('risk_score', confidence * 100), 1)}%
*Confidence:* {round(confidence * 100, 1)}%

*Expert Analysis:*
"{reason}"

⚠️ *Recommendation:*
{ReportGenerator._get_recommendation(status)}

---
_Secured by Sentinel Shield AI_"""
        return report

    @staticmethod
    def _get_recommendation(status):
        if status == "MALICIOUS":
            return "DO NOT interact with this. Immediate threat detected. Delete or block the source."
        elif status == "SUSPICIOUS":
            return "Proceed with extreme caution. This content shows indicators of potential risk."
        else:
            return "This content appears safe according to our initial analysis. Always remain vigilant."
