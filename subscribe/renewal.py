# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2022-04-05

import base64
import json
import os
import random
import re
import time
import traceback
import urllib
import urllib.parse
import urllib.request
import warnings
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime

import utils
from config.models import RenewJob
from logger import logger
from security.redaction import redact_mapping, redact_url

warnings.filterwarnings("ignore")

HEADER = {
    "user-agent": utils.USER_AGENT,
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9",
    "content-language": "zh-CN",
    "content-type": "application/x-www-form-urlencoded",
}

PATH = os.path.abspath(os.path.dirname(__file__))

PACKAGES = [
    "month_price",
    "quarter_price",
    "half_year_price",
    "year_price",
    "two_year_price",
    "three_year_price",
    "onetime_price",
]
