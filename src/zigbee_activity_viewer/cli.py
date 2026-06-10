"""Command-line entry point for Zigbee activity field exports."""

from __future__ import annotations

import argparse
from pathlib import Path

from .exporter import ExportConfig, export_activity_fields


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Zigbee PCAP-derived activity CSV rows into ParaView CSV/VTP/VTI field files.",
    )
    parser.add_argument("input_csv", type=Path, help="CSV produced by the encrypted activity/model-frame pipeline.")
    parser.add_argument("--output-dir", type=Path, default=Path("paraview_exports"), help="Directory for generated visualization files.")
    parser.add_argument("--time-column", default="time_rel", help="Column used as the temporal/x coordinate.")
    parser.add_argument("--source-column", default="LayerZBEENWKSource", help="Source address/role column used for the y coordinate.")
    parser.add_argument("--destination-column", default="LayerZBEENWKDestination", help="Destination address/role column used for the z coordinate.")
    parser.add_argument("--score-column", default=None, help="Anomaly score column to color by; auto-detected when omitted.")
    parser.add_argument("--volume-bins", default="96,32,32", help="VTI grid bins as nx,ny,nz.")
    return parser


def _parse_bins(raw: str) -> tuple[int, int, int]:
    parts = [int(part.strip()) for part in raw.split(",")]
    if len(parts) != 3 or any(part <= 0 for part in parts):
        raise argparse.ArgumentTypeError("--volume-bins must be three positive integers, for example 96,32,32")
    return parts[0], parts[1], parts[2]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = ExportConfig(
        time_column=args.time_column,
        source_column=args.source_column,
        destination_column=args.destination_column,
        score_column=args.score_column,
        volume_bins=_parse_bins(args.volume_bins),
    )
    outputs = export_activity_fields(args.input_csv, args.output_dir, config)
    for kind, path in outputs.items():
        print(f"{kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
