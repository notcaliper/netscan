"""Pytest configuration — ensure project root is on sys.path."""
import os
import sys
from pathlib import Path

# Force all tests to use the isolated in-memory test database
os.environ["NETSCAN_TEST"] = "1"

sys.path.insert(0, str(Path(__file__).resolve().parent))
