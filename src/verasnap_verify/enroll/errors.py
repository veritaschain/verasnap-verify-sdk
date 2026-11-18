from __future__ import annotations


class EnrollmentError(Exception):
    """Enrollment was refused. `code` is stable and safe to log; `message` is for operators."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
