"""Persist and reuse one trained model per Zigbee activity target.

This module deliberately does not depend on scikit-learn or XGBoost. Random
Forest, XGBoost, or any other pickle-compatible estimator can be saved here after
training and looked up later by target column, activity class, model kind,
feature set, and an optional training-data fingerprint.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import hashlib
import json
import pickle
import re


@dataclass(frozen=True)
class ModelRecord:
    """Metadata for a persisted activity-specific model artifact."""

    target_column: str
    activity_class: str
    model_kind: str
    feature_columns: tuple[str, ...]
    artifact_path: str
    training_fingerprint: str | None = None
    metrics: dict[str, float] = field(default_factory=dict)
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ModelRecord":
        return cls(
            target_column=str(raw["target_column"]),
            activity_class=str(raw["activity_class"]),
            model_kind=str(raw["model_kind"]),
            feature_columns=tuple(str(column) for column in raw["feature_columns"]),
            artifact_path=str(raw["artifact_path"]),
            training_fingerprint=raw.get("training_fingerprint"),
            metrics={str(key): float(value) for key, value in raw.get("metrics", {}).items()},
            created_at_utc=str(raw.get("created_at_utc") or datetime.now(timezone.utc).isoformat()),
            notes=str(raw.get("notes") or ""),
        )


class ModelRegistry:
    """Small JSON-backed registry for reusable activity-class models."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.models_dir = root / "models"
        self.index_path = root / "model_index.json"

    def records(self) -> list[ModelRecord]:
        if not self.index_path.exists():
            return []
        with self.index_path.open(encoding="utf-8") as handle:
            raw_records = json.load(handle)
        return [ModelRecord.from_dict(raw_record) for raw_record in raw_records]

    def register(self, record: ModelRecord) -> ModelRecord:
        self.models_dir.mkdir(parents=True, exist_ok=True)
        records = [existing for existing in self.records() if not _same_model_slot(existing, record)]
        records.append(record)
        self.root.mkdir(parents=True, exist_ok=True)
        with self.index_path.open("w", encoding="utf-8") as handle:
            json.dump([asdict(item) for item in records], handle, indent=2, sort_keys=True)
            handle.write("\n")
        return record

    def find(
        self,
        *,
        target_column: str,
        activity_class: str,
        model_kind: str,
        feature_columns: tuple[str, ...],
        training_fingerprint: str | None = None,
    ) -> ModelRecord | None:
        for record in reversed(self.records()):
            if record.target_column != target_column:
                continue
            if record.activity_class != activity_class:
                continue
            if record.model_kind != model_kind:
                continue
            if record.feature_columns != feature_columns:
                continue
            if training_fingerprint is not None and record.training_fingerprint != training_fingerprint:
                continue
            if not self.resolve_artifact(record).exists():
                continue
            return record
        return None

    def resolve_artifact(self, record: ModelRecord) -> Path:
        path = Path(record.artifact_path)
        if path.is_absolute():
            return path
        return self.root / path


def save_pickle_model(
    model: Any,
    registry: ModelRegistry,
    *,
    target_column: str,
    activity_class: str,
    model_kind: str,
    feature_columns: tuple[str, ...],
    training_fingerprint: str | None = None,
    metrics: dict[str, float] | None = None,
    notes: str = "",
) -> ModelRecord:
    """Persist a trained estimator and register it for later reuse."""

    registry.models_dir.mkdir(parents=True, exist_ok=True)
    filename = _artifact_filename(
        target_column=target_column,
        activity_class=activity_class,
        model_kind=model_kind,
        feature_columns=feature_columns,
        training_fingerprint=training_fingerprint,
    )
    artifact_path = registry.models_dir / filename
    with artifact_path.open("wb") as handle:
        pickle.dump(model, handle)

    record = ModelRecord(
        target_column=target_column,
        activity_class=activity_class,
        model_kind=model_kind,
        feature_columns=feature_columns,
        artifact_path=str(artifact_path.relative_to(registry.root)),
        training_fingerprint=training_fingerprint,
        metrics=metrics or {},
        notes=notes,
    )
    return registry.register(record)


def load_pickle_model(registry: ModelRegistry, record: ModelRecord) -> Any:
    """Load a persisted estimator from a registry record."""

    with registry.resolve_artifact(record).open("rb") as handle:
        return pickle.load(handle)


def get_or_train_pickle_model(
    registry: ModelRegistry,
    *,
    target_column: str,
    activity_class: str,
    model_kind: str,
    feature_columns: tuple[str, ...],
    train_model: Callable[[], Any | tuple[Any, dict[str, float]]],
    training_fingerprint: str | None = None,
    notes: str = "",
) -> tuple[Any, ModelRecord, bool]:
    """Reuse an existing model when possible, otherwise train and save one.

    Returns ``(model, record, reused)``. ``reused`` is ``True`` when the model was
    loaded from disk and ``False`` when ``train_model`` was called.
    """

    existing = registry.find(
        target_column=target_column,
        activity_class=activity_class,
        model_kind=model_kind,
        feature_columns=feature_columns,
        training_fingerprint=training_fingerprint,
    )
    if existing is not None:
        return load_pickle_model(registry, existing), existing, True

    trained = train_model()
    if isinstance(trained, tuple):
        model, metrics = trained
    else:
        model, metrics = trained, {}
    record = save_pickle_model(
        model,
        registry,
        target_column=target_column,
        activity_class=activity_class,
        model_kind=model_kind,
        feature_columns=feature_columns,
        training_fingerprint=training_fingerprint,
        metrics=metrics,
        notes=notes,
    )
    return model, record, False


def fingerprint_file(path: Path, *, extra_values: tuple[str, ...] = ()) -> str:
    """Return a stable SHA-256 fingerprint for training data and settings."""

    digest = hashlib.sha256()
    for value in extra_values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_model_slot(left: ModelRecord, right: ModelRecord) -> bool:
    return (
        left.target_column == right.target_column
        and left.activity_class == right.activity_class
        and left.model_kind == right.model_kind
        and left.feature_columns == right.feature_columns
        and left.training_fingerprint == right.training_fingerprint
    )


def _artifact_filename(
    *,
    target_column: str,
    activity_class: str,
    model_kind: str,
    feature_columns: tuple[str, ...],
    training_fingerprint: str | None,
) -> str:
    feature_digest = hashlib.sha256("\0".join(feature_columns).encode("utf-8")).hexdigest()[:10]
    fingerprint_part = (training_fingerprint or "no_fingerprint")[:12]
    return "__".join(
        [
            _slug(model_kind),
            _slug(target_column),
            _slug(activity_class),
            feature_digest,
            fingerprint_part,
        ]
    ) + ".pkl"


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return slug.strip("._-") or "value"
