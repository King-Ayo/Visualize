from pathlib import Path
import csv
import xml.etree.ElementTree as ET

from zigbee_activity_viewer import ExportConfig, export_activity_fields
from zigbee_activity_viewer.paraview_scene import ParaViewSceneConfig, write_paraview_scene_script
from zigbee_activity_viewer.cli import main


def _write_sample_csv(path: Path, *, include_score: bool = True) -> None:
    rows = [
        {
            "time_rel": "0.0",
            "LayerZBEENWKSource": "0x1001",
            "LayerZBEENWKDestination": "0x2001",
            "PacketLength": "64",
            "Timedeltafrompreviouscapturedframe": "0.5",
            "Wpan_Security": "1",
            "target": "device_announce",
        },
        {
            "time_rel": "2.0",
            "LayerZBEENWKSource": "0x1002",
            "LayerZBEENWKDestination": "0x2001",
            "PacketLength": "128",
            "Timedeltafrompreviouscapturedframe": "0.25",
            "ZBEENWK_Frame_type": "1",
            "target": "data_transmission",
        },
    ]
    if include_score:
        rows[0]["transformer_ids_score"] = "0.05"
        rows[1]["transformer_ids_score"] = "0.91"

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

    assert set(outputs) == {"csv", "vtp", "vti", "paraview_script"}
    for path in outputs.values():
        assert path.exists()

    with outputs["csv"].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[1]["score_norm"] == "1.0"
    assert rows[0]["activity_label"] == "device_announce"
    assert rows[1]["activity_label"] == "data_transmission"
    assert rows[0]["protocol_family"] == "zigbee_encrypted"

    vtp_root = ET.parse(outputs["vtp"]).getroot()
    assert vtp_root.attrib["type"] == "PolyData"
    assert vtp_root.find(".//Piece").attrib["NumberOfPoints"] == "2"
    assert vtp_root.find(".//DataArray[@Name='activity_id']") is not None

    vti_root = ET.parse(outputs["vti"]).getroot()
    assert vti_root.attrib["type"] == "ImageData"
    assert vti_root.find(".//DataArray[@Name='packet_count']") is not None
    assert vti_root.find(".//DataArray[@Name='dominant_activity_id']") is not None

    scene_text = outputs["paraview_script"].read_text(encoding="utf-8")
    assert "XMLPolyDataReader" in scene_text
    assert "XMLImageDataReader" in scene_text
    assert 'ColorBy(points_display, ("POINTS", POINT_COLOR_BY))' in scene_text
    assert "SaveScreenshot" in scene_text


def test_target_column_is_activity_class_when_no_score_exists(tmp_path: Path) -> None:
    input_csv = tmp_path / "activity_only.csv"
    _write_sample_csv(input_csv, include_score=False)

    outputs = export_activity_fields(input_csv, tmp_path / "out", ExportConfig(volume_bins=(3, 3, 3)))

    with outputs["csv"].open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["score"] == ""
    assert rows[0]["color_value"] == rows[0]["activity_id"]
    assert rows[1]["color_value"] == rows[1]["activity_id"]
    assert {row["activity_label"] for row in rows} == {"device_announce", "data_transmission"}


def test_cli_exports_files_with_dataset_column_names(tmp_path: Path) -> None:
    input_csv = tmp_path / "capture.csv"
    output_dir = tmp_path / "cli_out"
    _write_sample_csv(input_csv, include_score=False)

    status = main(
        [
            str(input_csv),
            "--output-dir",
            str(output_dir),
            "--time-column",
            "time_rel",
            "--source-column",
            "LayerZBEENWKSource",
            "--destination-column",
            "LayerZBEENWKDestination",
            "--length-column",
            "PacketLength",
            "--target-column",
            "target",
            "--volume-bins",
            "3,3,3",
        ]
    )

    assert status == 0
    assert (output_dir / "capture_activity_points.vtp").exists()
    assert (output_dir / "capture_activity_volume.vti").exists()
    assert (output_dir / "capture_paraview_scene.py").exists()


def test_write_paraview_scene_script_can_customize_color_fields(tmp_path: Path) -> None:
    script_path = tmp_path / "scene.py"
    vtp_path = tmp_path / "points.vtp"
    vti_path = tmp_path / "volume.vti"

    written = write_paraview_scene_script(
        script_path,
        vtp_path=vtp_path,
        vti_path=vti_path,
        config=ParaViewSceneConfig(point_color_by="packet_rate", volume_color_by="packet_count"),
    )

    assert written == script_path
    scene_text = script_path.read_text(encoding="utf-8")
    assert "POINT_COLOR_BY = 'packet_rate'" in scene_text
    assert "VOLUME_COLOR_BY = 'packet_count'" in scene_text
    assert "SaveState" in scene_text
