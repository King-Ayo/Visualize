# Network Flow Activity Field Viewer for Zigbee PCAPs

This repository contains a lightweight exporter for the workflow where SOC analysts turn Zigbee PCAP-derived activity rows into ParaView-ready fields. It is designed for CSVs produced by notebook pipelines that normalize encrypted Zigbee activity columns such as `time_rel`, `LayerZBEENWKSource`, `LayerZBEENWKDestination`, `PacketLength`, `Data_size`, RSSI/LQI values, IEEE 802.15.4 fields, Zigbee NWK fields, and Zigbee security fields.

The default dataset mapping is activity-centric rather than binary-classification centric:

```python
{
    "time_col": "time_rel",
    "src_col": "LayerZBEENWKSource",
    "dst_col": "LayerZBEENWKDestination",
    "len_col": "PacketLength",
    "target_col": "target",
}
```

## Pipeline fit

```text
Jupyter / pandas / NumPy / PyTorch
        ↓
features, embeddings, activity labels, optional scores, attention weights
        ↓
CSV exported from the model/activity dataframe
        ↓
zigbee-activity-viewer
        ↓
CSV / VTP point cloud / VTI volume / pvpython scene script
        ↓
ParaView 3D visualization, time animation, filtering, slicing, volume rendering
```

The exporter maps each packet or flow row into a 3D/4D point:

- `x`: normalized `time_rel` or a configured time column.
- `y`: stable hash of the Zigbee source address/role.
- `z`: stable hash of the Zigbee destination address/role.
- `t`: original time value for animation.
- `activity_label` and `activity_id`: categorical activity from `target`, suitable for coloring when no numeric model score is present.
- `score`, `score_norm`, `color_value`, and `color_value_norm`: optional model score fields. If no numeric score column exists, `color_value` falls back to `activity_id`.
- `packet_length`, `packet_rate`, and `protocol_family`: context fields for filtering.

It also creates a VTI volume where voxels store packet count, maximum color value, byte totals, and dominant activity id. Each export additionally writes a `*_paraview_scene.py` script that builds the 3D ParaView view, applies color maps, adds a volume/outline layer, saves a screenshot, and saves a reusable `.pvsm` state file.

## Usage

```bash
python -m zigbee_activity_viewer.cli activity_model_frame.csv \
  --output-dir paraview_exports \
  --time-column time_rel \
  --source-column LayerZBEENWKSource \
  --destination-column LayerZBEENWKDestination \
  --length-column PacketLength \
  --target-column target \
  --volume-bins 128,48,48

pvpython paraview_exports/activity_model_frame_paraview_scene.py
```

If `--score-column` is omitted, the exporter searches only for numeric model fields: `anomaly_score`, `autoencoder_score`, `isolation_forest_score`, `transformer_ids_score`, and `attention_weight`. The `target` column is treated as an activity class label, not as a numeric score.

## ParaView visualization code

The generated `*_paraview_scene.py` is executable ParaView Python code. Run it with `pvpython` to load the VTP point cloud and VTI volume, color the point cloud by `activity_id`, color the volume by `dominant_activity_id`, add an outline, set the camera, and write both `*_paraview_scene.png` and `*_paraview_scene.pvsm`. You can also open the script in ParaView's Python Shell if you prefer an interactive session.

## ParaView workflow

1. Run `pvpython *_paraview_scene.py` for an immediate 3D render, or open the generated `.pvsm` state file in ParaView.
2. Open `*_activity_points.vtp` manually for packet/flow point-cloud inspection if you want to customize the scene from scratch.
3. Color by `activity_id` or `color_value` for activity-class views, or by `score_norm` when a numeric score column is available.
4. Use `t` as the animation/time field when creating temporal views.
5. Open `*_activity_volume.vti` for volume rendering or slicing.
6. Slice the VTI volume along time (`x`) to inspect activity windows, or threshold by `dominant_activity_id` / `color_value_max` to isolate activity regions.

## Python API

```python
from pathlib import Path
from zigbee_activity_viewer import ExportConfig, export_activity_fields

outputs = export_activity_fields(
    Path("activity_model_frame.csv"),
    Path("paraview_exports"),
    ExportConfig(
        time_column="time_rel",
        source_column="LayerZBEENWKSource",
        destination_column="LayerZBEENWKDestination",
        length_column="PacketLength",
        target_column="target",
        volume_bins=(96, 32, 32),
    ),
)
print(outputs["paraview_script"])
```
