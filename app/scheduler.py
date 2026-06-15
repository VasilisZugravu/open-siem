import logging
import threading
import time
from app.detection import RULES_DIR
from app.detection.engine import run_detection_cycle
from app.detection.rules_loader import load_rules

logger = logging.getLogger(__name__)


def run_one_cycle(app):
    """Load rules from RULES_DIR and run one detection cycle within the app's context."""
    with app.app_context():
        rules = load_rules(RULES_DIR)
        run_detection_cycle(rules)


def start_background_loop(app, interval=30):
    """Start a daemon thread that calls run_one_cycle every `interval` seconds."""
    def _loop():
        while True:
            try:
                run_one_cycle(app)
            except Exception:
                logger.exception("Detection cycle failed")
            time.sleep(interval)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return thread
