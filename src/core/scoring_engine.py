"""
Incident Scoring & Prioritization Engine.
Calculates compound risk score, blast radius, and assigns operational priority tiers.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any
from .finding_parser import SecurityFinding


class IncidentPriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


@dataclass
class TriageAssessment:
    """Triage calculation output with score breakdown."""

    priority: IncidentPriority
    composite_score: float  # 0.0 to 100.0
    auto_remediate_recommended: bool
    requires_human_approval: bool
    blast_radius: str  # ISOLATED, SERVICE, ACCOUNT_WIDE
    score_breakdown: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority.value,
            "composite_score": self.composite_score,
            "auto_remediate_recommended": self.auto_remediate_recommended,
            "requires_human_approval": self.requires_human_approval,
            "blast_radius": self.blast_radius,
            "score_breakdown": self.score_breakdown,
        }


class IncidentScoringEngine:
    """Calculates multidimensional risk score factoring in production tags and asset criticality."""

    @classmethod
    def evaluate(cls, finding: SecurityFinding) -> TriageAssessment:
        base_score = finding.severity_score
        modifiers = {}

        current_score = base_score

        # Modifier 1: Production Environment
        if finding.is_production:
            current_score += 15.0
            modifiers["production_environment"] = +15.0

        # Modifier 2: Identity & Administrative Privilege Blast Radius
        blast_radius = "ISOLATED"
        if finding.resource_type in ["AwsIamUser", "AwsIamRole"]:
            res_id_lower = finding.resource_id.lower()
            if "admin" in res_id_lower or "root" in res_id_lower:
                current_score += 25.0
                modifiers["admin_or_root_identity"] = +25.0
                blast_radius = "ACCOUNT_WIDE"
            else:
                blast_radius = "SERVICE"

        elif finding.resource_type == "AwsS3Bucket":
            if "prod" in finding.resource_id.lower() or "data" in finding.resource_id.lower():
                current_score += 10.0
                modifiers["critical_s3_data_store"] = +10.0
                blast_radius = "SERVICE"

        elif finding.resource_type == "AwsEc2Instance":
            if finding.is_production:
                blast_radius = "SERVICE"

        # Cap score at 100.0
        final_score = min(100.0, max(0.0, round(current_score, 1)))

        # Determine Priority Tier
        if final_score >= 85.0:
            priority = IncidentPriority.P1_CRITICAL
            auto_remediate = True
            requires_approval = False
        elif final_score >= 65.0:
            priority = IncidentPriority.P2_HIGH
            auto_remediate = True
            requires_approval = False
        elif final_score >= 40.0:
            priority = IncidentPriority.P3_MEDIUM
            auto_remediate = False
            requires_approval = True
        else:
            priority = IncidentPriority.P4_LOW
            auto_remediate = False
            requires_approval = False

        breakdown = {
            "base_severity_score": base_score,
            "severity_label": finding.severity,
            "applied_modifiers": modifiers,
            "final_composite_score": final_score,
        }

        return TriageAssessment(
            priority=priority,
            composite_score=final_score,
            auto_remediate_recommended=auto_remediate,
            requires_human_approval=requires_approval,
            blast_radius=blast_radius,
            score_breakdown=breakdown,
        )
