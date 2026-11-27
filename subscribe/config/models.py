# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, TypeVar

import utils
from config.parse import Node, ObjectNode
from origin import Origin
from security.redaction import redact_mapping, secret_from_env

if TYPE_CHECKING:
    from push import PushTo

TValue = TypeVar("TValue")

CONVERT_TARGETS = [
    "clash", "v2ray", "singbox", "mixed", "clashr", "quan", "quanx", "loon",
    "ss", "sssub", "ssd", "ssr", "surfboard", "surge",
]


def _parse_source_rule(obj: ObjectNode) -> dict[str, object]:
    push_to = obj.string_list("push_to")
    task = TaskParams.parse(obj.field("task"))
    if task.push_to is None:
        task.push_to = list(push_to)
    return {
        "include": obj.regex("include", default=""),
        "exclude": obj.regex("exclude", default=""),
        "push_to": push_to,
        "task": task,
    }
