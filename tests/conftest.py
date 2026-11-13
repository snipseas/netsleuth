import os

import pytest

from netsleuth.analysis.pipeline import analyze_capture
from netsleuth.config import Config
from netsleuth.storage.store import CaptureStore

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "netsleuth", "samples")


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


@pytest.fixture
def analyze(tmp_path):
    """Analyse a capture path or a CaptureBuilder; returns (summary, store)."""
    stores = []
    counter = [0]

    def run(source, config: Config | None = None):
        counter[0] += 1
        if not isinstance(source, str):
            path = str(tmp_path / f"built{counter[0]}.pcap")
            source.write_pcap(path)
            source = path
        db = str(tmp_path / f"analysis{counter[0]}.db")
        summary = analyze_capture(source, db, config)
        store = CaptureStore(db, readonly=True)
        stores.append(store)
        return summary, store

    yield run
    for s in stores:
        s.close()


@pytest.fixture(scope="session")
def incident(tmp_path_factory):
    """The bundled demo incident, analysed once per test session."""
    db = str(tmp_path_factory.mktemp("incident") / "analysis.db")
    summary = analyze_capture(os.path.join(SAMPLES, "demo-incident.pcapng"), db)
    store = CaptureStore(db, readonly=True)
    yield summary, store
    store.close()
