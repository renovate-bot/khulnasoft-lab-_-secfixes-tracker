import click
import json
import gzip
import requests
import yaml
import tarfile
import tempfile
from io import TextIOWrapper
from . import app, db
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch, VulnerabilityReference
from .version import APKVersion


LANGUAGE_REWRITERS = {
    'python': lambda x: 'py3-' + x.replace('_', '-').lower(),
    'ruby': lambda x: 'ruby-' + x.replace('_', '-').lower(),
    'perl': lambda x: 'perl-' + x.replace('_', '-').replace('::', '-').lower(),
    'lua': lambda x: 'lua-' + x.replace('_', '-').lower(),
    'visual_studio_code': lambda x: 'vscode-' + x.replace('_', '-').lower(),
}


def download_data(uri: str) -> bytes:
    """Download data from the given URI."""
    r = requests.get(uri)
    return r.content


def decompress_data(data: bytes) -> str:
    """Decompress gzip data and return as string."""
    return gzip.decompress(data).decode()


def import_nvd_cve_item(item: dict):
    """Process a single CVE item from the NVD feed."""
    cve = item.get('cve', {})
    cve_id = cve.get('CVE_data_meta', {}).get('ID')

    if not cve_id:
        return

    description = cve.get('description', {}).get('description_data', [])
    if not description:
        return

    description_text = description[0].get('value')

    impact = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})

    cvss3_score = impact.get('baseScore')
    cvss3_vector = impact.get('vectorString')

    vuln = Vulnerability.find_or_create(cve_id)
    vuln.description = description_text
    vuln.cvss3_score = cvss3_score
    vuln.cvss3_vector = cvss3_vector

    db.session.add(vuln)
    db.session.commit()

    if 'configurations' in item:
        process_nvd_cve_configurations(vuln, item['configurations'])

    if 'references' in cve:
        process_nvd_cve_references(vuln, cve['references']['reference_data'])


def process_nvd_cve_references(vuln: Vulnerability, refs: list):
    """Process CVE references."""
    for item in refs:
        ref_type = item.get('refsource', item.get('tags', [])[0])
        ref_uri = item.get('url')

        if ref_uri:
            ref = VulnerabilityReference.find_or_create(vuln, ref_type, ref_uri)
            db.session.add(ref)

    db.session.commit()


def process_nvd_cve_configurations(vuln: Vulnerability, configuration: dict):
    """Process CVE configurations."""
    if 'nodes' not in configuration or not configuration['nodes']:
        return

    nodes = configuration['nodes']
    if not nodes or 'cpe_match' not in nodes[0]:
        return

    cpe_match = nodes[0]['cpe_match']

    for match in cpe_match:
        if 'cpe23Uri' not in match:
            continue

        cpe_uri = match['cpe23Uri']
        vulnerable = match.get('vulnerable', True)

        cpe_parts = cpe_uri.split(':')[3:6]
        cpe_language = cpe_uri.split(':')[10].lower()

        language_rewriter = LANGUAGE_REWRITERS.get(cpe_language)

        source_pkgname = cpe_parts[1]
        if language_rewriter:
            source_pkgname = language_rewriter(source_pkgname)

        cpe_vendor = cpe_parts[0]

        custom_rewriters = app.config.get('CUSTOM_REWRITERS', {})
        custom_rewriter_key = f'{cpe_vendor}:{source_pkgname}'
        custom_rewriter = custom_rewriters.get(custom_rewriter_key,
                                               custom_rewriters.get(f'{cpe_vendor}:*', None))
        if custom_rewriter:
            source_pkgname = custom_rewriter(source_pkgname)

        source_version = cpe_parts[2] if cpe_parts[2] != '*' else None

        using_version_ranges = any(key in match for key in ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'])

        max_version = match.get('versionEndIncluding', match.get('versionEndExcluding', source_version))
        min_version = match.get('versionStartIncluding', match.get('versionStartExcluding', None))

        min_version_op = '>=' if using_version_ranges else '=='
        max_version_op = '<=' if using_version_ranges else '=='

        process_nvd_cve_configuration_item(vuln, source_pkgname, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)


def process_nvd_cve_configuration_item(vuln: Vulnerability, source_pkgname: str,
                                       min_version: str, min_version_op: str,
                                       max_version: str, max_version_op: str, vulnerable: bool, cpe_uri: str):
    """Process individual CVE configuration item."""
    pkg = Package.find_or_create(source_pkgname)
    db.session.add(pkg)
    db.session.commit()

    cm = CPEMatch.find_or_create(pkg, vuln, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)
    db.session.add(cm)
    db.session.commit()


@app.cli.command('import-nvd', help='Import a NVD feed.')
@click.argument('name')
def import_nvd_cve(name: str):
    """Import NVD CVE feed."""
    uri = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{name}.json.gz'
    click.echo(f'I: Importing NVD feed [{name}] from [{uri}].')

    payload = download_data(uri)
    click.echo(f'I: Downloaded {len(payload)} bytes.')

    data = decompress_data(payload)
    data = json.loads(data)

    if 'CVE_Items' not in data:
        click.echo('E: CVE_Items not found in NVD feed.')
        return

    for item in data['CVE_Items']:
        import_nvd_cve_item(item)

    click.echo('I: Imported NVD feed successfully.')
