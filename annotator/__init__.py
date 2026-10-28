"""Assembly annotation engine."""

from .analyzer import analyse, InputTooLarge, MAX_INPUT_CHARS

__all__ = ['analyse', 'InputTooLarge', 'MAX_INPUT_CHARS']
__version__ = '2.4.0'
