from pathlib import Path
from textwrap import dedent

from scapy import all as scapy_all

from cipmaster.cip import config as cip_config


def test_string_fields_use_byte_defaults(tmp_path: Path) -> None:
    xml_content = dedent(
        """
        <cip>
          <assembly id="AS_OT" dir="in" size="64" subtype="OT_EO">
            <usint id="Value" offset="0" length="1" />
            <string id="Label" offset="8" length="4" />
          </assembly>
          <assembly id="AS_TO" dir="out" size="16" subtype="TO">
            <usint id="Command" offset="0" length="1" />
          </assembly>
        </cip>
        """
    ).strip()

    xml_path = tmp_path / "minimal.xml"
    xml_path.write_text(xml_content)

    validation = cip_config.validate_cip_config(str(xml_path))
    assert validation.overall_status is True
    assert validation.ot_info is not None

    packet_class = validation.ot_info.packet_class
    string_field = next(
        field for field in packet_class.fields_desc if field.name == "Label"
    )

    assert isinstance(string_field, scapy_all.StrFixedLenField)
    assert isinstance(string_field.default, (bytes, bytearray))
