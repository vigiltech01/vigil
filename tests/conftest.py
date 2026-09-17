import os
import sys
import tempfile

# Vigil reads its data directory at import time: point it at a throw-away folder before any test imports vigil.
_DATA = tempfile.mkdtemp(prefix='vigil-test-')
os.environ.update(VIGIL_DATA=_DATA, VIGIL_WARM='0', VIGIL_DEMO='0', VIGIL_TELEMETRY='off')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
