# graphspy/core/errors.py

# Built-in imports
import inspect


class AppError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        frame = inspect.stack()[1]
        self.func_name = frame.function
        self.line_number = frame.lineno
