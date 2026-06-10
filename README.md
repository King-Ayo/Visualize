# Network Flow Activity Field Viewer for Zigbee PCAPs

This repository contains a lightweight exporter for the workflow where analysts can turn Zigbee PCAP-derived activity rows into ParaView-ready fields. It is designed for CSVs produced by notebook pipelines that normalize encrypted Zigbee activity columns such as `time_rel`, `LayerZBEENWKSource`, `LayerZBEENWKDestination`, `PacketLength`, `Data_size`, RSSI/LQI values, IEEE 802.15.4 fields, Zigbee NWK fields, and Zigbee security fields.

## Pipeline fit

```text
Jupyter / pandas / NumPy / PyTorch
        ↓
features, embeddings, anomaly scores, attention weights
        ↓
CSV exported from the model/activity dataframe
        ↓
zigbee-activity-viewer
        ↓
CSV / VTP point cloud / VTI volume
        ↓
ParaView 3D visualization, time animation, filtering, slicing, volume rendering
```

The exporter maps each packet or flow row into a 3D/4D point:

- `x`: normalized `time_rel` (or a configured time column).
- `y`: stable hash of the Zigbee source address/role.
- `z`: stable hash of the Zigbee destination address/role.
- `t`: original time value for animation.
- `score` and `score_norm`: anomaly or IDS score used for coloring.
- `packet_length`, `packet_rate`, and `protocol_family`: context fields for filtering.

It also creates a VTI volume where voxels store packet count, maximum normalized score, and byte totals.

## Usage

```bash
python -m zigbee_activity_viewer.cli activity_model_frame.csv \
  --output-dir paraview_exports \
  --score-column transformer_ids_score \
  --volume-bins 128,48,48
```

If `--score-column` is omitted, the exporter searches for `anomaly_score`, `autoencoder_score`, `isolation_forest_score`, `transformer_ids_score`, `attention_weight`, then `target`. Text labels such as `attack`, `malicious`, or `anomaly` are treated as high scores, while `normal` and `benign` are treated as low scores.

## ParaView workflow

1. Open `*_activity_points.vtp` for packet/flow point-cloud inspection.
2. Color by `score_norm` or `packet_rate`.
3. Use `t` as the animation/time field when creating temporal views.
4. Open `*_activity_volume.vti` for volume rendering or slicing.
5. Slice the VTI volume along time (`x`) to inspect activity windows, or threshold by `score_max` to isolate abnormal regions.

## Python API

```python
from pathlib import Path
from zigbee_activity_viewer import ExportConfig, export_activity_fields

outputs = export_activity_fields(
    Path("activity_model_frame.csv"),
    Path("paraview_exports"),
    ExportConfig(score_column="autoencoder_score", volume_bins=(96, 32, 32)),
)
print(outputs)
```
