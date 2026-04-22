import sys, os
sys.path.insert(0, os.path.abspath("."))
from app.utils.logging_utils import setup_logging
setup_logging()

from app.capture.live_capture_service import LiveCaptureService
import time

svc = LiveCaptureService.get_instance()
print(svc.start())
time.sleep(5)
print(svc.stats.to_dict())
