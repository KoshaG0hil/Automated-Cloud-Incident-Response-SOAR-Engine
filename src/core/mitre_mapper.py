"""
MITRE ATT&CK Cloud Matrix Mapper.
Maps AWS GuardDuty and Security Hub findings to standardized MITRE ATT&CK tactics, techniques, and IDs.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class MitreTactics:
    """MITRE ATT&CK classification details."""

    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    sub_technique_id: Optional[str] = None
    url: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "sub_technique_id": self.sub_technique_id or "",
            "url": self.url,
        }


class MitreMapper:
    """Enriches normalized findings with MITRE ATT&CK Cloud Matrix mapping."""

    # Curated knowledgebase of AWS threat patterns mapped to MITRE ATT&CK
    _MAPPINGS: Dict[str, MitreTactics] = {
        # Credential Access & Valid Accounts
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": MitreTactics(
            tactic="Credential Access",
            tactic_id="TA0006",
            technique="Steal Application Access Token",
            technique_id="T1528",
            url="https://attack.mitre.org/techniques/T1528/",
        ),
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccessNotice": MitreTactics(
            tactic="Initial Access",
            tactic_id="TA0001",
            technique="Valid Accounts: Cloud Accounts",
            technique_id="T1078",
            sub_technique_id="T1078.004",
            url="https://attack.mitre.org/techniques/T1078/004/",
        ),
        "PenTest:IAMUser/KaliLinux": MitreTactics(
            tactic="Initial Access",
            tactic_id="TA0001",
            technique="Valid Accounts: Cloud Accounts",
            technique_id="T1078",
            sub_technique_id="T1078.004",
            url="https://attack.mitre.org/techniques/T1078/004/",
        ),
        # Defense Evasion
        "Stealth:IAMUser/CloudTrailLoggingDisabled": MitreTactics(
            tactic="Defense Evasion",
            tactic_id="TA0005",
            technique="Impair Defenses: Disable Cloud Logs",
            technique_id="T1562",
            sub_technique_id="T1562.001",
            url="https://attack.mitre.org/techniques/T1562/001/",
        ),
        "Stealth:IAMUser/PasswordPolicyChange": MitreTactics(
            tactic="Defense Evasion",
            tactic_id="TA0005",
            technique="Modify Authentication Process",
            technique_id="T1556",
            url="https://attack.mitre.org/techniques/T1556/",
        ),
        # Persistence & Privilege Escalation
        "PrivilegeEscalation:IAMUser/AdministrativePermissionsGranted": MitreTactics(
            tactic="Privilege Escalation",
            tactic_id="TA0004",
            technique="Account Manipulation: Additional Cloud Roles",
            technique_id="T1098",
            sub_technique_id="T1098.001",
            url="https://attack.mitre.org/techniques/T1098/001/",
        ),
        # Resource Hijacking & CryptoMining
        "CryptoCurrency:EC2/BitcoinTool.B!DNS": MitreTactics(
            tactic="Impact",
            tactic_id="TA0040",
            technique="Resource Hijacking",
            technique_id="T1496",
            url="https://attack.mitre.org/techniques/T1496/",
        ),
        "CryptoCurrency:EC2/BitcoinTool.B": MitreTactics(
            tactic="Impact",
            tactic_id="TA0040",
            technique="Resource Hijacking",
            technique_id="T1496",
            url="https://attack.mitre.org/techniques/T1496/",
        ),
        # Command & Control
        "Trojan:EC2/BlackholeTraffic": MitreTactics(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Application Layer Protocol: Web Protocols",
            technique_id="T1071",
            sub_technique_id="T1071.001",
            url="https://attack.mitre.org/techniques/T1071/001/",
        ),
        "Backdoor:EC2/Spambot": MitreTactics(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Non-Standard Port",
            technique_id="T1571",
            url="https://attack.mitre.org/techniques/T1571/",
        ),
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom": MitreTactics(
            tactic="Command and Control",
            tactic_id="TA0011",
            technique="Application Layer Protocol",
            technique_id="T1071",
            url="https://attack.mitre.org/techniques/T1071/",
        ),
        # Exfiltration & Collection
        "Policy:S3/BucketPublicReadWriteGranted": MitreTactics(
            tactic="Exfiltration",
            tactic_id="TA0010",
            technique="Exfiltration Over Web Service: Cloud Storage",
            technique_id="T1567",
            sub_technique_id="T1567.002",
            url="https://attack.mitre.org/techniques/T1567/002/",
        ),
        "Policy:S3/BucketBlockPublicAccessDisabled": MitreTactics(
            tactic="Defense Evasion",
            tactic_id="TA0005",
            technique="Impair Defenses: Disable Cloud Security Controls",
            technique_id="T1562",
            url="https://attack.mitre.org/techniques/T1562/",
        ),
        "Exfiltration:S3/ObjectReads.Unusual": MitreTactics(
            tactic="Collection",
            tactic_id="TA0009",
            technique="Data from Cloud Storage Object",
            technique_id="T1530",
            url="https://attack.mitre.org/techniques/T1530/",
        ),
        "AnomalousBehavior:S3/BulkObjectRetrieval": MitreTactics(
            tactic="Collection",
            tactic_id="TA0009",
            technique="Data from Cloud Storage Object",
            technique_id="T1530",
            url="https://attack.mitre.org/techniques/T1530/",
        ),
    }

    @classmethod
    def map_finding(cls, finding_type: str) -> MitreTactics:
        """
        Maps a finding type to a MitreTactics entry.
        Falls back to intelligent prefix matching if exact match not found.
        """
        if finding_type in cls._MAPPINGS:
            return cls._MAPPINGS[finding_type]

        # Partial matching by namespace prefix
        if "IAMUser" in finding_type or "IAMRole" in finding_type:
            if "Credential" in finding_type or "Token" in finding_type:
                return cls._MAPPINGS["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"]
            if "Stealth" in finding_type or "Disabled" in finding_type:
                return cls._MAPPINGS["Stealth:IAMUser/CloudTrailLoggingDisabled"]
            return cls._MAPPINGS["UnauthorizedAccess:IAMUser/ConsoleLoginSuccessNotice"]

        if "EC2" in finding_type:
            if "Crypto" in finding_type or "Bitcoin" in finding_type:
                return cls._MAPPINGS["CryptoCurrency:EC2/BitcoinTool.B!DNS"]
            return cls._MAPPINGS["Trojan:EC2/BlackholeTraffic"]

        if "S3" in finding_type:
            if "Exfiltration" in finding_type or "Object" in finding_type:
                return cls._MAPPINGS["Exfiltration:S3/ObjectReads.Unusual"]
            return cls._MAPPINGS["Policy:S3/BucketPublicReadWriteGranted"]

        # Default fallback
        return MitreTactics(
            tactic="Initial Access",
            tactic_id="TA0001",
            technique="Valid Accounts: Cloud Accounts",
            technique_id="T1078",
            sub_technique_id="T1078.004",
            url="https://attack.mitre.org/techniques/T1078/",
        )
