"""
Automated Report Generation for Red Team Operations
"""

from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import json


class Finding:
    """Represents a security finding"""

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        affected_systems: List[str],
        evidence: Dict,
        remediation: str,
        cvss_score: Optional[float] = None
    ):
        self.title = title
        self.severity = severity  # Critical, High, Medium, Low, Info
        self.description = description
        self.affected_systems = affected_systems
        self.evidence = evidence
        self.remediation = remediation
        self.cvss_score = cvss_score
        self.mitre_tactics = []
        self.mitre_techniques = []

    def to_dict(self) -> Dict:
        return {
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'affected_systems': self.affected_systems,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'mitre_attack': {
                'tactics': self.mitre_tactics,
                'techniques': self.mitre_techniques
            }
        }


class ReportGenerator:
    """
    Automated Red Team Report Generation

    Features:
    - Finding templates
    - Screenshot management
    - Evidence collection
    - MITRE ATT&CK mapping
    - Executive summary generation
    - Technical report generation
    """

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or './reports')
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.findings: List[Finding] = []
        self.screenshots: List[str] = []
        self.evidence: Dict[str, List] = {}

    def add_finding(self, finding: Finding):
        """Add finding to report"""
        self.findings.append(finding)
        print(f"[ReportGen] Added finding: {finding.title} ({finding.severity})")

    def add_screenshot(self, screenshot_path: str, description: str):
        """Add screenshot evidence"""
        self.screenshots.append({
            'path': screenshot_path,
            'description': description,
            'timestamp': datetime.utcnow().isoformat()
        })

    def map_to_mitre_attack(self, finding: Finding, tactics: List[str], techniques: List[str]):
        """
        Map finding to MITRE ATT&CK framework

        Args:
            finding: Finding object
            tactics: MITRE ATT&CK tactics
            techniques: MITRE ATT&CK technique IDs
        """
        finding.mitre_tactics = tactics
        finding.mitre_techniques = techniques

    def generate_executive_summary(self) -> str:
        """Generate executive summary"""
        summary = f"""
# Executive Summary

**Assessment Date**: {datetime.utcnow().strftime('%Y-%m-%d')}

## Overview
This report summarizes the findings from the authorized red team engagement.

## Key Statistics
- Total Findings: {len(self.findings)}
- Critical: {len([f for f in self.findings if f.severity == 'Critical'])}
- High: {len([f for f in self.findings if f.severity == 'High'])}
- Medium: {len([f for f in self.findings if f.severity == 'Medium'])}
- Low: {len([f for f in self.findings if f.severity == 'Low'])}

## Risk Rating
{self._calculate_overall_risk()}

## Recommendations
{self._generate_recommendations()}
"""
        return summary

    def generate_technical_report(self) -> str:
        """Generate detailed technical report"""
        report = f"""
# Red Team Assessment - Technical Report

**Report Generated**: {datetime.utcnow().isoformat()}

## Methodology
This assessment followed industry-standard red team methodologies including:
- Reconnaissance and OSINT
- Network and application scanning
- Vulnerability assessment
- Exploitation and post-exploitation
- Persistence and lateral movement testing

## Findings

"""
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity, 5)
        )

        for i, finding in enumerate(sorted_findings, 1):
            report += self._format_finding(i, finding)

        report += "\n## MITRE ATT&CK Mapping\n"
        report += self._generate_mitre_matrix()

        report += "\n## Evidence\n"
        report += self._format_evidence()

        return report

    def _format_finding(self, number: int, finding: Finding) -> str:
        """Format individual finding"""
        return f"""
### {number}. {finding.title}

**Severity**: {finding.severity}
{f'**CVSS Score**: {finding.cvss_score}' if finding.cvss_score else ''}

**Description**:
{finding.description}

**Affected Systems**:
{chr(10).join(f'- {sys}' for sys in finding.affected_systems)}

**Evidence**:
```
{json.dumps(finding.evidence, indent=2)}
```

**Remediation**:
{finding.remediation}

**MITRE ATT&CK**:
- Tactics: {', '.join(finding.mitre_tactics)}
- Techniques: {', '.join(finding.mitre_techniques)}

---
"""

    def _calculate_overall_risk(self) -> str:
        """Calculate overall risk rating"""
        critical = len([f for f in self.findings if f.severity == 'Critical'])
        high = len([f for f in self.findings if f.severity == 'High'])

        if critical >= 3 or high >= 5:
            return "**CRITICAL** - Immediate action required"
        elif critical >= 1 or high >= 3:
            return "**HIGH** - Urgent remediation needed"
        elif len(self.findings) >= 5:
            return "**MEDIUM** - Remediation recommended"
        else:
            return "**LOW** - Monitor and improve"

    def _generate_recommendations(self) -> str:
        """Generate high-level recommendations"""
        recommendations = [
            "1. Address all Critical and High severity findings immediately",
            "2. Implement defense-in-depth security controls",
            "3. Enhance security monitoring and logging",
            "4. Conduct regular security awareness training",
            "5. Perform periodic security assessments"
        ]
        return '\n'.join(recommendations)

    def _generate_mitre_matrix(self) -> str:
        """Generate MITRE ATT&CK coverage matrix"""
        all_tactics = set()
        all_techniques = set()

        for finding in self.findings:
            all_tactics.update(finding.mitre_tactics)
            all_techniques.update(finding.mitre_techniques)

        matrix = f"""
**Tactics Observed**: {', '.join(sorted(all_tactics)) if all_tactics else 'None'}

**Techniques Observed**: {', '.join(sorted(all_techniques)) if all_techniques else 'None'}
"""
        return matrix

    def _format_evidence(self) -> str:
        """Format evidence section"""
        evidence_text = f"\n**Screenshots**: {len(self.screenshots)} captured\n\n"

        for screenshot in self.screenshots:
            evidence_text += f"- {screenshot['description']} ({screenshot['timestamp']})\n"

        return evidence_text

    def export_json(self, filename: str) -> str:
        """Export report as JSON"""
        output_path = self.output_dir / filename

        report_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'screenshots': self.screenshots,
            'statistics': {
                'total_findings': len(self.findings),
                'by_severity': {
                    'Critical': len([f for f in self.findings if f.severity == 'Critical']),
                    'High': len([f for f in self.findings if f.severity == 'High']),
                    'Medium': len([f for f in self.findings if f.severity == 'Medium']),
                    'Low': len([f for f in self.findings if f.severity == 'Low']),
                    'Info': len([f for f in self.findings if f.severity == 'Info'])
                }
            }
        }

        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"[ReportGen] Exported JSON report: {output_path}")
        return str(output_path)

    def export_markdown(self, filename: str) -> str:
        """Export report as Markdown"""
        output_path = self.output_dir / filename

        report = self.generate_executive_summary()
        report += "\n\n" + self.generate_technical_report()

        with open(output_path, 'w') as f:
            f.write(report)

        print(f"[ReportGen] Exported Markdown report: {output_path}")
        return str(output_path)

    def export_html(self, filename: str) -> str:
        """Export report as HTML"""
        output_path = self.output_dir / filename

        # In production: use proper HTML templating
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Red Team Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .critical {{ color: #d9534f; }}
        .high {{ color: #f0ad4e; }}
        .medium {{ color: #5bc0de; }}
        .low {{ color: #5cb85c; }}
    </style>
</head>
<body>
    <h1>Red Team Assessment Report</h1>
    <p>Generated: {datetime.utcnow().isoformat()}</p>
    <!-- Report content here -->
</body>
</html>
"""

        with open(output_path, 'w') as f:
            f.write(html)

        print(f"[ReportGen] Exported HTML report: {output_path}")
        return str(output_path)
