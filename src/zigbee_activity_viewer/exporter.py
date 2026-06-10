"""Export PCAP-derived Zigbee activity rows into ParaView field formats.

The exporter intentionally uses only the Python standard library so it can run
inside capture-processing notebooks or SOC sandboxes before heavier scientific
packages are installed. It accepts CSVs produced from pandas pipelines and emits
CSV, VTP point clouds, and VTI activity volumes that ParaView can load directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
import hashlib
import math
import xml.etree.ElementTree as ET

from .paraview_scene import write_paraview_scene_script


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
)


@dataclass(frozen=True)
class ExportConfig:
    """Options for mapping tabular Zigbee activity into visualization fields."""

    time_column: str = "time_rel"
    source_column: str = "LayerZBEENWKSource"
    destination_column: str = "LayerZBEENWKDestination"
    length_column: str = "PacketLength"
    target_column: str = "target"
    score_column: str | None = None
    volume_bins: tuple[int, int, int] = (96, 32, 32)


def export_activity_fields(input_csv: Path, output_dir: Path, config: ExportConfig) -> dict[str, Path]:
    """Export one Zigbee activity CSV to CSV, VTP, and VTI visualization files."""

    rows = _read_csv(input_csv)
    if not rows:
        raise ValueError(f"No rows found in {input_csv}")

    score_column = config.score_column or _choose_score_column(rows[0])
    activity_lookup = _activity_lookup(rows, config.target_column)
    points = [_row_to_point(row, config, score_column, activity_lookup) for row in rows]
    _normalize_points(points)

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = input_csv.stem
    point_csv = output_dir / f"{stem}_activity_points.csv"
    vtp_path = output_dir / f"{stem}_activity_points.vtp"
    vti_path = output_dir / f"{stem}_activity_volume.vti"
    paraview_script_path = output_dir / f"{stem}_paraview_scene.py"

    _write_point_csv(point_csv, points)
    _write_vtp(vtp_path, points)
    _write_vti(vti_path, points, config.volume_bins)
    write_paraview_scene_script(paraview_script_path, vtp_path=vtp_path, vti_path=vti_path)

    return {"csv": point_csv, "vtp": vtp_path, "vti": vti_path, "paraview_script": paraview_script_path}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _choose_score_column(header_row: dict[str, str]) -> str | None:
    for name in _DEFAULT_SCORE_COLUMNS:
        if name in header_row:
            return name
    return None


def _activity_lookup(rows: list[dict[str, str]], target_column: str) -> dict[str, int]:
    labels: dict[str, int] = {}
    for row in rows:
        label = _activity_label(row, target_column)
        if label not in labels:
            labels[label] = len(labels)
    return labels


def _row_to_point(
    row: dict[str, str],
    config: ExportConfig,
    score_column: str | None,
    activity_lookup: dict[str, int],
) -> dict[str, float | str]:
    source = _first_text(row, config.source_column, _ADDRESS_COLUMNS) or "src_unknown"
    destination = _first_text(row, config.destination_column, _ADDRESS_COLUMNS) or "dst_unknown"
    time_value = _as_float(row.get(config.time_column), default=0.0)
    activity_label = _activity_label(row, config.target_column)
    activity_id = float(activity_lookup[activity_label])
    score = _score_value(row.get(score_column)) if score_column else math.nan
    color_value = score if not math.isnan(score) else activity_id
    packet_length = _as_float(row.get(config.length_column), default=_as_float(row.get("Data_size"), default=0.0))
    delta = _as_float(row.get("Timedeltafrompreviouscapturedframe"), default=0.0)

    return {
        "x": time_value,
        "y": _stable_unit_hash(source),
        "z": _stable_unit_hash(destination),
        "t": time_value,
        "score": score,
        "color_value": color_value,
        "activity_id": activity_id,
        "packet_length": packet_length,
        "packet_rate": 1.0 / max(delta, 1.0e-6) if delta >= 0.0 else 0.0,
        "source": source,
        "destination": destination,
        "protocol_family": _protocol_family(row),
        "activity_label": activity_label,
    }


def _activity_label(row: dict[str, str], target_column: str) -> str:
    value = row.get(target_column)
    if value is not None and str(value).strip():
        return str(value).strip()
    value = row.get("label_source")
    if value is not None and str(value).strip():
        return str(value).strip()
    return "unknown_activity"


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
    try:
        return float(str(value).strip())
    except ValueError:
        return default


def _score_value(raw_score: str | None) -> float:
    return _as_float(raw_score, default=math.nan)


def _protocol_family(row: dict[str, str]) -> str:
    if _as_float(row.get("ZBEESEC_Security_Level"), default=0.0) > 0.0 or _as_float(row.get("Wpan_Security"), default=0.0) > 0.0:
        return "zigbee_encrypted"
    if row.get("ZBEENWK_Frame_type"):
        return "zigbee_nwk"
    if row.get("Wpan_Frame_Type"):
        return "ieee802154"
    return "unknown"


def _normalize_points(points: list[dict[str, float | str]]) -> None:
    for axis in ("x", "score", "color_value", "packet_length", "packet_rate"):
        values = [float(point[axis]) for point in points if not math.isnan(float(point[axis]))]
        if not values:
            for point in points:
                point[f"{axis}_norm"] = math.nan
            continue
        minimum = min(values)
        maximum = max(values)
        scale = maximum - minimum
        for point in points:
            value = float(point[axis])
            if math.isnan(value):
                point[f"{axis}_norm"] = math.nan
            else:
                point[f"{axis}_norm"] = 0.0 if scale == 0.0 else (value - minimum) / scale


def _write_point_csv(path: Path, points: list[dict[str, float | str]]) -> None:
    fieldnames = [
        "x",
        "y",
        "z",
        "t",
        "score",
        "score_norm",
        "color_value",
        "color_value_norm",
        "activity_id",
        "packet_length",
        "packet_length_norm",
        "packet_rate",
        "packet_rate_norm",
        "source",
        "destination",
        "protocol_family",
        "activity_label",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(_csv_safe_point(point) for point in points)


def _csv_safe_point(point: dict[str, float | str]) -> dict[str, float | str]:
    safe = dict(point)
    for key, value in point.items():
        if isinstance(value, float) and math.isnan(value):
            safe[key] = ""
    return safe


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
    point_data = ET.SubElement(piece, "PointData", Scalars="color_value")
    for name in ("score", "score_norm", "color_value", "color_value_norm", "activity_id", "packet_length", "packet_rate", "t"):
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
    color_max = [0.0] * cell_count
    bytes_sum = [0.0] * cell_count
    activity_counts: list[dict[int, int]] = [{} for _ in range(cell_count)]

    for point in points:
        ix = _bin_index(float(point["x_norm"]), nx)
        iy = _bin_index(float(point["y"]), ny)
        iz = _bin_index(float(point["z"]), nz)
        offset = ix + nx * (iy + ny * iz)
        activity_id = int(float(point["activity_id"]))
        counts[offset] += 1
        color_max[offset] = max(color_max[offset], _safe_float(point["color_value_norm"]))
        bytes_sum[offset] += _safe_float(point["packet_length"])
        activity_counts[offset][activity_id] = activity_counts[offset].get(activity_id, 0) + 1

    dominant_activity = [_dominant_activity_id(counts_by_activity) for counts_by_activity in activity_counts]

    vtk_file = ET.Element("VTKFile", type="ImageData", version="0.1", byte_order="LittleEndian")
    image = ET.SubElement(vtk_file, "ImageData", WholeExtent=f"0 {nx - 1} 0 {ny - 1} 0 {nz - 1}", Origin="0 0 0", Spacing="1 1 1")
    piece = ET.SubElement(image, "Piece", Extent=f"0 {nx - 1} 0 {ny - 1} 0 {nz - 1}")
    point_data = ET.SubElement(piece, "PointData", Scalars="color_value_max")
    ET.SubElement(point_data, "DataArray", type="Int32", Name="packet_count", format="ascii").text = " ".join(str(value) for value in counts)
    ET.SubElement(point_data, "DataArray", type="Float64", Name="color_value_max", format="ascii").text = " ".join(f"{value:.9g}" for value in color_max)
    ET.SubElement(point_data, "DataArray", type="Float64", Name="bytes_sum", format="ascii").text = " ".join(f"{value:.9g}" for value in bytes_sum)
    ET.SubElement(point_data, "DataArray", type="Int32", Name="dominant_activity_id", format="ascii").text = " ".join(str(value) for value in dominant_activity)
    ET.SubElement(piece, "CellData")
    _write_xml(path, vtk_file)


def _bin_index(value: float, bins: int) -> int:
    return min(max(int(value * bins), 0), bins - 1)


def _safe_float(value: float | str) -> float:
    numeric = float(value)
    if math.isnan(numeric):
        return 0.0
    return numeric


def _dominant_activity_id(counts_by_activity: dict[int, int]) -> int:
    if not counts_by_activity:
        return -1
    return max(counts_by_activity.items(), key=lambda item: (item[1], -item[0]))[0]


def _float_array(points: list[dict[str, float | str]], name: str) -> str:
    return " ".join(f"{_safe_float(point[name]):.9g}" for point in points)


def _write_xml(path: Path, root: ET.Element) -> None:
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
