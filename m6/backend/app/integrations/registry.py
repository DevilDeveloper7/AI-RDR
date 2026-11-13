"""Chooses the adapter for each module from config (M1_MODE ... M5_MODE).

This is the ONLY place that imports the mock adapters. To plug in a real module later,
add its adapter class next to the mock (integrations/m2/real.py and m3/real.py are the first ones) and list it in _REAL.
"""
from .m1.mock import MockM1
from .m2.mock import MockM2
from .m2.real import RealM2
from .m3.mock import MockM3
from .m3.real import RealM3
from .m4.mock import MockM4
from .m4.real import RealM4
from .m5.mock import MockM5

_MOCKS = {"m1": MockM1, "m2": MockM2, "m3": MockM3, "m4": MockM4, "m5": MockM5}
_REAL = {"m2": RealM2, "m3": RealM3, "m4": RealM4}  # M2: M2_BASE_URL = OpenSearch URL of the M2 documents. M3: no transport yet, RealM3 needs an event source (see integrations/m3/real.py)


def build_adapters(integrations_config):
    adapters = {}
    for module, cfg in integrations_config.items():
        if cfg["mode"] == "real":
            if module not in _REAL:
                raise NotImplementedError(
                    f"{module.upper()}_MODE=real is not available: no real {module.upper()} "
                    "interface has been confirmed yet (PROVISIONAL / M6 STUB)."
                )
            adapters[module] = _REAL[module](cfg["base_url"])
        else:
            adapters[module] = _MOCKS[module]()
    return adapters