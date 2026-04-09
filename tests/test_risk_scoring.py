import importlib.util
from pathlib import Path


def _load_engine_module():
    path = Path('services/analyzer-service/app/analyzers/engine.py')
    spec = importlib.util.spec_from_file_location('engine', path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_aggregate_score_malicious_verdict():
    engine = _load_engine_module()
    out = engine.aggregate_score([
        {"score": 100},
        {"score": 100},
        {"score": 100},
        {"score": 100},
    ])
    assert out["final_score"] >= 70
    assert out["verdict"] == "malicious"


def test_aggregate_score_clean_verdict():
    engine = _load_engine_module()
    out = engine.aggregate_score([
        {"score": 5},
        {"score": 10},
    ])
    assert out["final_score"] < 40
    assert out["verdict"] == "clean"
