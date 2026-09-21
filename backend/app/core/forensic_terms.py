"""
Forensic language guardrails ensuring evidentiary neutrality and SIH compliance.
"""

FORENSIC_GUARDRAILS = {
    "ALLOWED_ORIGIN_TERMS": [
        "Probable Origin",
        "Origin Confidence",
        "Observed Infrastructure",
        "Approximate IP-associated Location",
        "Observed Relay Sequence",
        "Header Timestamp Chronology"
    ],
    "PROHIBITED_TERMS": [
        "Attacker Location",
        "Attacker Identity",
        "Attacker Server",
        "Culprit Address"
    ],
    "DISCLAIMERS": {
        "GEO_DISCLAIMER": "Geolocation represents approximate geographical registration of the observed IP address and does not imply physical location of the human sender.",
        "AI_DISCLAIMER": "AI-generated forensic draft — analyst verification required before official evidentiary citation."
    }
}
