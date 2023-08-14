"""Base module for validators."""
from abc import ABC, abstractmethod


class ValidatorBase(ABC):
    """Base class for validators."""

    @abstractmethod
    def exists(self, config, header, **kwargs):
        """Validates that a header, directive or cookie exists in a set of headers.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def not_exists(self, config, header, **kwargs):
        """Validates that a header, directive or cookie does not exist in a set of headers.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value(self, config, header, **kwargs):
        """Validates that a header or directive matches a single expected value.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value_any_of(self, config, header, **kwargs):
        """Validates that a header or directive matches one or more of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def value_one_of(self, config, header, **kwargs):
        """Validates that a header or directive matches one of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_avoid(self, config, header, **kwargs):
        """Validates that a header, directive or cookie does not contain any of a list of disallowed values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_contain(self, config, header, **kwargs):
        """Validates that a header, directive or cookie contains all of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """

    @abstractmethod
    def must_contain_one(self, config, header, **kwargs):
        """Validates that a header, directive or cookie contains one or more of a list of expected values.

        Args:
            config (CaseInsensitiveDict): The configuration of the exists rule.
            header (str): The header to validate.

        Keyword Args:
            cookie (str): A named cookie in {header} to validate (only applicable for 'set-cookie').
            directive (str): A named directive in {header} to validate.
        """


class UnsupportedValidationError(Exception):
    """Exception to be raised when an unsupported validation is called.

    Attributes:
        message (string): A message describing the error.
    """

    def __init__(self, message):
        """Initialises an UnsupportedValidationError instance with a message."""
        self.message = message


def get_delimiter(config, delimiter_type):
    if delimiters := config.get('delimiters'):
        return delimiters.get(delimiter_type)


def get_expected_values(config, key, delimiter):
    if isinstance(config[key], list):
        return [str(item).strip() for item in config[key]]
    else:
        return [item.strip() for item in str(config[key]).split(delimiter)]
