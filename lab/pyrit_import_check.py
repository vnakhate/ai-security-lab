#!/usr/bin/env python3
"""Validate an exported dataset with installed PyRIT. Does not run attacks."""
import argparse
import importlib.metadata
import json
from pathlib import Path

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    a = p.parse_args()
    from pyrit.models import SeedDataset
    dataset = SeedDataset.from_dict(json.loads(a.dataset.read_text()))
    print(f"PyRIT {importlib.metadata.version('pyrit')}: {len(dataset.seeds)} seeds accepted. No requests sent.")
