"""Export PCAP-derived Zigbee activity rows into ParaView field formats.

The exporter intentionally uses only the Python standard library so it can run
inside capture-processing notebooks or SOC sandboxes before heavier scientific
packages are installed.  It accepts CSVs produced from pandas pipelines and emits
CSV, VTP point clouds, and VTI activity volumes that ParaView can load directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib
import math
import xml.etree.ElementTree as ET


_ADDRESS_COLUMNS = (
    "LayerZBEENWKSource",
    "LayerZBEENWKDestination",
    "src_role",
    "dst_role",
    "src_device_type",
    "dst_device_type",
)

_DEFAULT_SCORE_COLUMNS = (
    "anomaly_score",
    "autoencoder_score",
    "isolation_forest_score",
    "transformer_ids_score",
    "attention_weight",
    "target",
)


@dataclass(frozen=True)
class ExportConfig:
    """Options for mapping tabular Zigbee traffic into visualization fields."""

    time_column: str = "time_rel"
    source_column: str = "LayerZBEENWKSource"
    destination_column: str = "LayerZBEENWKDestination"
    score_column: str | None = None
    volume_bins: tuple[int, int, int] = (96, 32, 32)


def export_activity_fields(input_csv: Path, output_dir: Path, config: ExportConfig) -> dict[str, Path]:
    """Export one Zigbee activity CSV to CSV, VTP, and VTI visualization files."""

    rows = _read_csv(input_csv)
    if not rows:
        raise ValueError(f"No rows found in {input_csv}")

    score_column = config.score_column or _choose_score_column(rows[0])
    points = [_row_to_point(row, config, score_column) for row in rows]
    _normalize_points(points)

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = input_csv.stem
    point_csv = output_dir / f"{stem}_activity_points.csv"
    vtp_path = output_dir / f"{stem}_activity_points.vtp"
    vti_path = output_dir / f"{stem}_activity_volume.vti"

    _write_point_csv(point_csv, points)
    _write_vtp(vtp_path, points)
    _write_vti(vti_path, points, config.volume_bins)

    return {"csv": point_csv, "vtp": vtp_path, "vti": vti_path}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _choose_score_column(header_row: dict[str, str]) -> str:
    for name in _DEFAULT_SCORE_COLUMNS:
        if name in header_row:
            return name
    return "activity_score"


def _row_to_point(row: dict[str, str], config: ExportConfig, score_column: str) -> dict[str, float | str]:
    source = _first_text(row, config.source_column, _ADDRESS_COLUMNS) or "src_unknown"
    destination = _first_text(row, config.destination_column, _ADDRESS_COLUMNS) or "dst_unknown"
    time_value = _as_float(row.get(config.time_column), default=0.0)
    score = _score_value(row.get(score_column), row.get("target"))
    packet_length = _as_float(row.get("PacketLength"), default=_as_float(row.get("Data_size"), default=0.0))
    delta = _as_float(row.get("Timedeltafrompreviouscapturedframe"), default=0.0)

    return {
        "x": time_value,
        "y": _stable_unit_hash(source),
        "z": _stable_unit_hash(destination),
        "t": time_value,
        "score": score,
        "packet_length": packet_length,
        "packet_rate": 1.0 / max(delta, 1.0e-6) if delta >= 0.0 else 0.0,
        "source": source,
        "destination": destination,
        "protocol_family": _protocol_family(row),
        "label": str(row.get("target") or row.get("label_source") or "unknown"),
    }


def _first_text(row: dict[str, str], preferred: str, fallbacks: tuple[str, ...]) -> str:
    for key in (preferred, *fallbacks):
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _stable_unit_hash(value: str) -> float:
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest()
    integer = int.from_bytes(digest, byteorder="big", signed=False)
    return integer / float((1 << 64) - 1)


def _as_float(value: str | None, default: float = math.nan) -> float:
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip().lower()
    if text in {"true", "yes", "attack", "malicious", "anomaly"}:
        return 1.0
    if text in {"false", "no", "benign", "normal"}:
        return 0.0
    try:
        return float(text)
    except ValueError:
        return default


def _score_value(raw_score: str | None, raw_target: str | None) -> float:
    numeric = _as_float(raw_score)
    if not math.isnan(numeric):
        return numeric
    return _as_float(raw_target, default=0.0)


def _protocol_family(row: dict[str, str]) -> str:
    if _as_float(row.get("ZBEESEC_Security_Level"), default=0.0) > 0.0 or _as_float(row.get("Wpan_Security"), default=0.0) > 0.0:
        return "zigbee_encrypted"
    if row.get("ZBEENWK_Frame_type"):
        return "zigbee_nwk"
    if row.get("Wpan_Frame_Type"):
        return "ieee802154"
    return "unknown"


def _normalize_points(points: list[dict[str, float | str]]) -> None:
    for axis in ("x", "score", "packet_length", "packet_rate"):
        values = [float(point[axis]) for point in points if not math.isnan(float(point[axis]))]
        if not values:
            continue
        minimum = min(values)
        maximum = max(values)
        scale = maximum - minimum
        for point in points:
            value = float(point[axis])
            if math.isnan(value):
                value = minimum
            point[f"{axis}_norm"] = 0.0 if scale == 0.0 else (value - minimum) / scale


def _write_point_csv(path: Path, points: list[dict[str, float | str]]) -> None:
    fieldnames = [
        "x",
        "y",
        "z",
        "t",
        "score",
        "score_norm",
        "packet_length",
        "packet_length_norm",
        "packet_rate",
        "packet_rate_norm",
        "source",
        "destination",
        "protocol_family",
        "label",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(points)


def _write_vtp(path: Path, points: list[dict[str, float | str]]) -> None:
    vtk_file = ET.Element("VTKFile", type="PolyData", version="0.1", byte_order="LittleEndian")
    poly_data = ET.SubElement(vtk_file, "PolyData")
    piece = ET.SubElement(
        poly_data,
        "Piece",
        NumberOfPoints=str(len(points)),
        NumberOfVerts=str(len(points)),
        NumberOfLines="0",
        NumberOfStrips="0",
        NumberOfPolys="0",
    )
    point_data = ET.SubElement(piece, "PointData", Scalars="score_norm")
    for name in ("score", "score_norm", "packet_length", "packet_rate", "t"):
        ET.SubElement(point_data, "DataArray", type="Float64", Name=name, format="ascii").text = _float_array(points, name)

    points_node = ET.SubElement(piece, "Points")
    ET.SubElement(points_node, "DataArray", type="Float64", NumberOfComponents="3", format="ascii").text = " ".join(
        f"{float(point['x_norm']):.9g} {float(point['y']):.9g} {float(point['z']):.9g}" for point in points
    )
    verts = ET.SubElement(piece, "Verts")
    ET.SubElement(verts, "DataArray", type="Int64", Name="connectivity", format="ascii").text = " ".join(str(i) for i in range(len(points)))
    ET.SubElement(verts, "DataArray", type="Int64", Name="offsets", format="ascii").text = " ".join(str(i + 1) for i in range(len(points)))
    _write_xml(path, vtk_file)


def _write_vti(path: Path, points: list[dict[str, float | str]], bins: tuple[int, int, int]) -> None:
    nx, ny, nz = bins
    cell_count = nx * ny * nz
    counts = [0] * cell_count
    score_max = [0.0] * cell_count
    bytes_sum = [0.0] * cell_count

    for point in points:
        ix = _bin_index(float(point["x_norm"]), nx)
        iy = _bin_index(float(point["y"]), ny)
        iz = _bin_index(float(point["z"]), nz)
        offset = ix + nx * (iy + ny * iz)
        counts[offset] += 1
        score_max[offset] = max(score_max[offset], float(point["score_norm"]))
        bytes_sum[offset] += float(point["packet_length"])

    vtk_file = ET.Element("VTKFile", type="ImageData", version="0.1", byte_order="LittleEndian")
    image = ET.SubElement(vtk_file, "ImageData", WholeExtent=f"0 {nx - 1} 0 {ny - 1} 0 {nz - 1}", Origin="0 0 0", Spacing="1 1 1")
    piece = ET.SubElement(image, "Piece", Extent=f"0 {nx - 1} 0 {ny - 1} 0 {nz - 1}")
    point_data = ET.SubElement(piece, "PointData", Scalars="score_max")
    ET.SubElement(point_data, "DataArray", type="Int32", Name="packet_count", format="ascii").text = " ".join(str(value) for value in counts)
    ET.SubElement(point_data, "DataArray", type="Float64", Name="score_max", format="ascii").text = " ".join(f"{value:.9g}" for value in score_max)
    ET.SubElement(point_data, "DataArray", type="Float64", Name="bytes_sum", format="ascii").text = " ".join(f"{value:.9g}" for value in bytes_sum)
    ET.SubElement(piece, "CellData")
    _write_xml(path, vtk_file)


def _bin_index(value: float, bins: int) -> int:
    return min(max(int(value * bins), 0), bins - 1)


def _float_array(points: list[dict[str, float | str]], name: str) -> str:
    return " ".join(f"{float(point[name]):.9g}" for point in points)


def _write_xml(path: Path, root: ET.Element) -> None:
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
