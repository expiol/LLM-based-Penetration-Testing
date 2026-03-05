from pathlib import Path

from autopentest.tools.parsers.nmap import parse_nmap_xml


def test_parse_nmap_xml(tmp_path: Path) -> None:
    xml = """
    <nmaprun>
      <host>
        <address addr=\"127.0.0.1\" />
        <ports>
          <port protocol=\"tcp\" portid=\"80\">
            <state state=\"open\" />
            <service name=\"http\" product=\"Apache\" version=\"2.4\" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    path = tmp_path / "nmap.xml"
    path.write_text(xml, encoding="utf-8")
    results = parse_nmap_xml(path)
    assert results
    assert results[0].port == 80
    assert results[0].service == "http"
