from __future__ import annotations

import sys
from pathlib import Path

if "__compiled__" in globals():
    sys.frozen = True
    sys._MEIPASS = str(Path(sys.executable).resolve().parent)

from desktop.main import main

raise SystemExit(main())
