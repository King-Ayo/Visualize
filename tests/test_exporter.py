from pathlib import Path
import csv
import xml.etree.ElementTree as ET

from zigbee_activity_viewer import ExportConfig, export_activity_fields
from zigbee_activity_viewer.cli import main


def _write_sample_csv(path: Path) -> None:
    rows = [
        {
            "time_rel": "0.0",
            "LayerZBEENWKSource": "0x1001",
            "LayerZBEENWKDestination": "0x2001",
            "PacketLength": "64",
            "Timedeltafrompreviouscapturedframe": "0.5",
            "Wpan_Security": "1",
            "transformer_ids_score": "0.05",
            "target": "normal",
        },
        {
            "time_rel": "2.0",
            "LayerZBEENWKSource": "0x1002",
            "LayerZBEENWKDestination": "0x2001",
            "PacketLength": "128",
            "Timedeltafrompreviouscapturedframe": "0.25",
            "ZBEENWK_Frame_type": "1",
            "transformer_ids_score": "0.91",
            "target": "attack",
        },
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted({key for row in rows for key in row}))
        writer.writeheader()
        writer.writerows(rows)


def test_export_activity_fields_writes_paraview_files(tmp_path: Path) -> None:
    input_csv = tmp_path / "capture.csv"
    _write_sample_csv(input_csv)

    outputs = export_activity_fields(
        input_csv,
        tmp_path / "out",
        ExportConfig(score_column="transformer_ids_score", volume_bins=(4, 4, 4)),
    )

    assert set(outputs) == {"csv", "vtp", "vti"}
    for path in outputs.values():
        assert path.exists()

    with outputs["csv"].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[1]["score_norm"] == "1.0"
    assert rows[0]["protocol_family"] == "zigbee_encrypted"

    vtp_root = ET.parse(outputs["vtp"]).getroot()
    assert vtp_root.attrib["type"] == "PolyData"
    assert vtp_root.find(".//Piece").attrib["NumberOfPoints"] == "2"

    vti_root = ET.parse(outputs["vti"]).getroot()
    assert vti_root.attrib["type"] == "ImageData"
    assert vti_root.find(".//DataArray[@Name='packet_count']") is not None


def test_cli_exports_files(tmp_path: Path) -> None:
    input_csv = tmp_path / "capture.csv"
    output_dir = tmp_path / "cli_out"
    _write_sample_csv(input_csv)

    status = main([str(input_csv), "--output-dir", str(output_dir), "--volume-bins", "3,3,3"])

    assert status == 0
    assert (output_dir / "capture_activity_points.vtp").exists()
    assert (output_dir / "capture_activity_volume.vti").exists()
