from ..base import BaseAdapter


class M2Adapter(BaseAdapter):
    """M2: behavioural ML detection and SHAP explanations.

    PROVISIONAL / M6 STUB. M6 never trains a model or calculates SHAP; it only shows what M2 returns.
    """

    module = "m2"

    def list_detections(self):
        """ML detections (see contracts.DETECTION), newest first."""
        raise NotImplementedError

    def get_shap(self, alert_id):
        """SHAP explanation (see contracts.SHAP) for one detection, or None if M2 has none."""
        raise NotImplementedError
