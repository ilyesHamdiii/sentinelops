"""Structured logging helpers used during local validation and later runtime phases."""

from __future__ import annotations

import json
import logging
from typing import Any


class StructuredLogger(logging.Logger):
    def makeRecord(
        self,
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,
        func=None,
        extra=None,
        sinfo=None,
        **kwargs,
    ):
        record = super().makeRecord(
            name,
            level,
            fn,
            lno,
            msg,
            args,
            exc_info,
            func,
            extra,
            sinfo,
            **kwargs,
        )

        if extra:
            context = " ".join(f"{key}={value}" for key, value in extra.items())
            if context:
                record.msg = f"{record.getMessage()} {context}".strip()
                record.args = ()

        return record


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "asctime",
            }:
                continue
            payload[key] = value

        return json.dumps(payload, default=str, separators=(",", ":"))


def get_logger(name: str) -> logging.Logger:
    logging.setLoggerClass(StructuredLogger)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)

    logger.propagate = True
    return logger
