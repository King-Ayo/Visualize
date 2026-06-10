from pathlib import Path

from zigbee_activity_viewer.model_registry import (
    ModelRegistry,
    fingerprint_file,
    get_or_train_pickle_model,
    load_pickle_model,
    save_pickle_model,
)


def test_save_and_reuse_model_per_activity_class(tmp_path: Path) -> None:
    training_csv = tmp_path / "train.csv"
    training_csv.write_text("time_rel,PacketLength,target\n0,64,join\n1,80,join\n", encoding="utf-8")
    fingerprint = fingerprint_file(
        training_csv,
        extra_values=("target", "join", "random_forest", "time_rel", "PacketLength"),
    )
    registry = ModelRegistry(tmp_path / "registry")
    features = ("time_rel", "PacketLength")

    first_model, first_record, first_reused = get_or_train_pickle_model(
        registry,
        target_column="target",
        activity_class="join",
        model_kind="random_forest",
        feature_columns=features,
        training_fingerprint=fingerprint,
        train_model=lambda: ({"model": "rf-join"}, {"accuracy": 1.0}),
    )
    second_model, second_record, second_reused = get_or_train_pickle_model(
        registry,
        target_column="target",
        activity_class="join",
        model_kind="random_forest",
        feature_columns=features,
        training_fingerprint=fingerprint,
        train_model=lambda: (_ for _ in ()).throw(AssertionError("should reuse saved model")),
    )

    assert first_model == {"model": "rf-join"}
    assert first_reused is False
    assert second_model == first_model
    assert second_record == first_record
    assert second_reused is True
    assert registry.resolve_artifact(first_record).exists()


def test_different_activity_classes_are_different_model_slots(tmp_path: Path) -> None:
    registry = ModelRegistry(tmp_path / "registry")
    features = ("time_rel", "PacketLength")

    join_record = save_pickle_model(
        {"model": "xgb-join"},
        registry,
        target_column="target",
        activity_class="join",
        model_kind="xgboost",
        feature_columns=features,
    )
    leave_record = save_pickle_model(
        {"model": "xgb-leave"},
        registry,
        target_column="target",
        activity_class="leave",
        model_kind="xgboost",
        feature_columns=features,
    )

    assert join_record.artifact_path != leave_record.artifact_path
    assert load_pickle_model(registry, join_record) == {"model": "xgb-join"}
    assert load_pickle_model(registry, leave_record) == {"model": "xgb-leave"}
