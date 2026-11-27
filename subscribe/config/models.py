# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, TypeVar

import utils
from config.parse import Node, ObjectNode
from origin import Origin
from security.redaction import secret_from_env

if TYPE_CHECKING:
    from push import PushTo

TValue = TypeVar("TValue")

CONVERT_TARGETS = ["clash", "v2ray", "singbox", "mixed", "clashr", "quan", "quanx", "loon", "ss", "sssub", "ssd", "ssr", "surfboard", "surge"]


def _parse_source_rule(obj: ObjectNode) -> dict[str, object]:
    push_to = obj.string_list("push_to")
    task = TaskParams.parse(obj.field("task"))
    if task.push_to is None:
        task.push_to = list(push_to)
    return {"include": obj.regex("include", default=""), "exclude": obj.regex("exclude", default=""), "push_to": push_to, "task": task}


@dataclass
class NodeInput:
    subscribe: str | list[str] = ""
    uris: list[str] = field(default_factory=list)
    proxies: list[dict[str, object]] = field(default_factory=list)

    def empty(self) -> bool:
        subs = self.subscribe if isinstance(self.subscribe, list) else [self.subscribe]
        return not any(utils.trim(str(item)) for item in subs if item is not None) and not self.uris and not self.proxies

    def subscribe_list(self) -> list[str]:
        if isinstance(self.subscribe, list):
            return [utils.trim(item) for item in self.subscribe if utils.trim(item)]
        text = utils.trim(self.subscribe)
        return [text] if text else []
