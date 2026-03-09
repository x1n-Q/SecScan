"""Scanner tool adapters."""

from secscan.tools.npm_audit import NpmAuditTool
from secscan.tools.bandit_scan import BanditTool
from secscan.tools.dependency_check import DependencyCheckTool
from secscan.tools.osv_scanner import OsvScannerTool
from secscan.tools.grype_scan import GrypeTool
from secscan.tools.cyclonedx_sbom import CycloneDxSbomTool
from secscan.tools.gitleaks import GitleaksTool
from secscan.tools.semgrep import SemgrepTool
from secscan.tools.trivy import TrivyTool
from secscan.tools.checkov import CheckovTool
from secscan.tools.web_headers import WebHeadersTool
from secscan.tools.tls_check import TlsCheckTool
from secscan.tools.zap import ZapTool
from secscan.tools.nikto import NiktoTool
from secscan.tools.dirb import DirbTool
from secscan.tools.nmap import NmapTool
from secscan.tools.sqlmap import SqlmapTool
from secscan.tools.xsspy import XssPyTool
from secscan.tools.pip_audit import PipAuditTool
from secscan.tools.safety_scan import SafetyScanTool
from secscan.tools.kube_bench import KubeBenchTool
from secscan.tools.lynis_scan import LynisTool
from secscan.tools.amass_scan import AmassTool

ALL_TOOLS = [
    NpmAuditTool(),
    BanditTool(),
    DependencyCheckTool(),
    OsvScannerTool(),
    GrypeTool(),
    CycloneDxSbomTool(),
    GitleaksTool(),
    SemgrepTool(),
    TrivyTool(),
    CheckovTool(),
    WebHeadersTool(),
    TlsCheckTool(),
    ZapTool(),
    NiktoTool(),
    DirbTool(),
    NmapTool(),
    SqlmapTool(),
    XssPyTool(),
    PipAuditTool(),
    SafetyScanTool(),
    KubeBenchTool(),
    LynisTool(),
    AmassTool(),
]
