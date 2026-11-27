# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2022-07-15

import gzip
import json
import multiprocessing
import os
import platform
import random
import re
import socket
import ssl
import string
import subprocess
import sys
import time
import traceback
import typing
import urllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent import futures
from http.client import HTTPMessage, HTTPResponse

from logger import logger
from security.redaction import redact_mapping, redact_url, secret_from_env
from tqdm import tqdm
from urlvalidator import isurl

CTX = ssl.create_default_context()
_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", "").strip()
if _CA_BUNDLE:
    CTX.load_verify_locations(cafile=_CA_BUNDLE)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
FILEPATH_PROTOCAL = "file:///"
DEFAULT_HTTP_HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"}


def random_chars(length: int, punctuation: bool = False) -> str:
    length = max(length, 1)
    if punctuation:
        chars = "".join(random.sample(string.ascii_letters + string.digits + string.punctuation, length))
    else:
        chars = "".join(random.sample(string.ascii_letters + string.digits, length))
    return chars


def _should_retry_http(status_code: int, reason: object) -> bool:
    if isinstance(reason, (socket.timeout, TimeoutError, ssl.SSLError)):
        return True
    return status_code in {429, 500, 502, 503, 504}


def http_get(url, headers=None, params=None, retry=3, proxy="", interval=0, timeout=10, trace=False, max_size=None):
    if not isurl(url=url):
        logger.error(f"invalid url: {redact_url(url)}")
        return ""
    retry = max(0, retry)
    headers = DEFAULT_HTTP_HEADERS if not headers else headers
    interval = max(0, interval)
    timeout = max(1, timeout)
    length = None if max_size is None or max_size <= 0 else max_size
    safe_url = redact_url(encoding_url(url=url))
    for attempt in range(retry + 1):
        try:
            request_url = encoding_url(url=url)
            if params and isinstance(params, dict):
                query = urllib.parse.urlencode(params)
                request_url = f"{request_url}&{query}" if "?" in request_url else f"{request_url}?{query}"
            request = urllib.request.Request(url=request_url, headers=headers)
            if proxy and (proxy.startswith("https://") or proxy.startswith("http://")):
                host, protocol = "", ""
                if proxy.startswith("https://"):
                    host, protocol = proxy[8:], "https"
                else:
                    host, protocol = proxy[7:], "http"
                request.set_proxy(host=host, type=protocol)
            response = urllib.request.urlopen(request, timeout=timeout, context=CTX)
            raw = response.read(length)
            status_code = response.getcode()
            try:
                content = str(raw, encoding="utf8")
            except UnicodeDecodeError:
                content = gzip.decompress(raw).decode("utf8", errors="replace")
            if status_code != 200:
                if trace:
                    logger.error(f"request failed, url: {safe_url}, code: {status_code}")
                if status_code < 500:
                    return ""
            else:
                return content
        except urllib.error.HTTPError as e:
            message = ""
            try:
                message = e.read().decode("utf8", errors="replace")
            except Exception:
                message = "unknown error"
            if trace:
                logger.error(f"request failed, url: {safe_url}, code: {e.code}, message: {message[:200]}")
            if not _should_retry_http(e.code, e.reason) or attempt == retry:
                return ""
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, TimeoutError, OSError) as e:
            if trace:
                logger.error(f"request failed, url: {safe_url}, error: {type(e).__name__}")
            if attempt == retry:
                return ""
        except Exception as e:
            if trace:
                logger.error(f"request failed, url: {safe_url}, error: {type(e).__name__}")
            if attempt == retry:
                return ""
        if interval > 0:
            time.sleep(interval * (attempt + 1))
    return ""


def cmd(command: list[str], output: bool = False) -> tuple[bool, str]:
    if command is None or len(command) == 0:
        return False, ""
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) if output else subprocess.Popen(command)
    try:
        stdout, _ = p.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        stdout, _ = p.communicate()
        return False, ""
    success, content = p.returncode == 0, ""
    if output:
        try:
            content = stdout.decode("utf8", errors="replace")
        except Exception:
            content = ""
    return success, content
