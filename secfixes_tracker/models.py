from . import app, db
from .version import APKVersion

import json
from flask import request


@app.cli.command('init-db', help='Initializes the database.')
def init_db():
    """Initialize the database."""
    db.create_all()


class Vulnerability(db.Model):
    """Model for vulnerabilities."""

    vuln_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = db.Column(db.String(80), index=True, unique=True)
    description = db.Column(db.Text)
    cvss3_score = db.Column(db.Numeric)
    cvss3_vector = db.Column(db.String(80))
    
    def __repr__(self):
        return f'<Vulnerability {self.cve_id}>'

    def to_nvd_severity(self):
        """Convert CVSS3 score to NVD severity."""
        if not self.cvss3_score:
            return 'unknown'
        if self.cvss3_score > 8.0:
            return 'high'
        if self.cvss3_score > 4.0:
            return 'medium'
        return 'low'

    @classmethod
    def find_or_create(cls, cve_id: str):
        """Find or create a vulnerability."""
        vuln = cls.query.filter_by(cve_id=cve_id).first()
        if not vuln:
            vuln = cls(cve_id=cve_id)
        return vuln

    @property
    def json_ld_id(self):
        """Generate JSON-LD ID for the vulnerability."""
        return f'https://{request.host}/vuln/{self.cve_id}'

    def to_json_ld(self):
        """Convert vulnerability to JSON-LD format."""
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'type': 'Vulnerability',
            'id': self.json_ld_id,
            'description': self.description,
            'cvss3': {
                 'score': float(self.cvss3_score) if self.cvss3_score else None,
                 'vector': self.cvss3_vector,
            },
            'ref': [ref.to_json_ld() for ref in self.references],
            'state': [state.to_json_ld() for state in self.states],
            'cpeMatch': [cpe_match.to_json_ld() for cpe_match in self.cpe_matches],
        }

    def to_json(self):
        """Convert vulnerability to JSON format."""
        score = float(self.cvss3_score) if self.cvss3_score else 0
        return {
            'type': 'Vulnerability',
            'id': self.cve_id,
            'description': self.description,
            'cvss3': {
                'score': score,
                'vector': self.cvss3_vector,
            },
            'ref': [ref.to_json() for ref in self.references],
            'state': [state.to_json() for state in self.published_states],
            'cpeMatch': [cpe_match.to_json() for cpe_match in self.cpe_matches],
        }

    @property
    def published_states(self):
        """Get published vulnerability states."""
        return [state for state in self.states if state.package_version.published]


class VulnerabilityReference(db.Model):
    """Model for vulnerability references."""

    vuln_ref_id = db.Column(db.Integer, primary_key=True, index=True, autoincrement=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerability.vuln_id'), nullable=False, index=True)
    vuln = db.relationship('Vulnerability', backref='references')
    ref_type = db.Column(db.String(80))
    ref_uri = db.Column(db.Text, index=True)

    def __repr__(self):
        return f'<VulnerabilityReference {self.ref_uri} ({self.ref_type}) for {self.vuln}>'

    @classmethod
    def find_or_create(cls, vuln: Vulnerability, ref_type: str, ref_uri: str):
        """Find or create a vulnerability reference."""
        ref = cls.query.filter_by(vuln_id=vuln.vuln_id, ref_uri=ref_uri).first()
        if not ref:
            ref = cls(vuln_id=vuln.vuln_id, ref_type=ref_type, ref_uri=ref_uri)
        return ref

    @property
    def json_ld_id(self):
        """Generate JSON-LD ID for the vulnerability reference."""
        return f'{self.vuln.json_ld_id}#ref/{self.vuln_ref_id}'

    def to_json_ld(self):
        """Convert vulnerability reference to JSON-LD format."""
        return {
            '@context': f'https://{request.host}/static/context.jsonld',
            'type': 'Reference',
            'referenceType': self.ref_type,
            'id': self.json_ld_id,
            'rel': self.ref_uri,
        }

    def to_json(self):
        """Convert vulnerability reference to JSON format."""
        return {
            'type': 'Reference',
            'referenceType': self.ref_type,
            'id': self.vuln_ref_id,
            'rel': self.ref_uri,
        }

# Implement other classes similarly...
