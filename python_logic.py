import hashlib


def process_alert(alert):

    src_ip = alert.get("src_ip", "Unknown")
    username = alert.get("username", "Unknown")
    status = alert.get("status", "Failed")

    count = int(alert.get("count", 0))

    threat_hash = hashlib.md5(
        f"{src_ip}{username}{status}".encode()
    ).hexdigest()[:6]

    threat_id = f"THREAT-{threat_hash.upper()}"

    severity = "Low"
    risk_score = 25
    attack_type = "Failed Login"
    mitre = "T1110"

    if status == "Accepted":

        severity = "Critical"
        risk_score = 95
        attack_type = "Successful SSH Compromise"
        mitre = "T1078"

    elif username.lower() == "root":

        severity = "Critical"
        risk_score = 90
        attack_type = "Root Account Attack"

    elif username.lower() == "admin":

        severity = "High"
        risk_score = 80
        attack_type = "Admin Account Attack"

    elif count >= 8:

        severity = "High"
        risk_score = 75
        attack_type = "SSH Brute Force"

    elif count >= 4:

        severity = "Medium"
        risk_score = 50
        attack_type = "Repeated Login Attempts"

    return {
        "Threat_ID": threat_id,
        "Source_IP": src_ip,
        "Username": username,
        "Severity": severity,
        "Risk_Score": risk_score,
        "MITRE_ID": mitre,
        "Attack_Type": attack_type,
        "Event_Count": count
    }