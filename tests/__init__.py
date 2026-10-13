"""Unit tests. Run from the repo root:  python -m unittest discover -s tests -t ."""
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
