import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SHARED = REPO / "soc-env" / "shared"
DATA = REPO / "soc-env" / "data"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(SHARED))


@pytest.fixture(scope="session")
def export():
    return json.loads((DATA / "log_export.json").read_text())


@pytest.fixture(scope="session")
def ground_truth():
    return json.loads((DATA / "ground_truth.json").read_text())


@pytest.fixture(scope="session")
def incident():
    return json.loads((DATA / "incident.json").read_text())
