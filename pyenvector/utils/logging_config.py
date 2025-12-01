# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

import os
import sys

from loguru import logger

# Configure logger based on environment variable
log_level = os.getenv("PYENVECTOR_LOG_LEVEL", os.getenv("ES2_LOG_LEVEL", "")).upper()
logger.remove()  # Remove default Loguru handlers to avoid duplicate logs
if log_level in ["DEBUG", "INFO", "ERROR"]:
    logger.add(
        sys.stdout,
        colorize=True,
        format="<green>{time:YY-MM-DD at HH:mm:ss}</green> | <level>{level}</level> | <cyan>{message}</cyan>",
        level=log_level,
    )
else:
    logger.disable("")

# Export the logger for use in other modules
__all__ = ["logger"]
