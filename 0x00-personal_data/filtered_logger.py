#!/usr/bin/env python3
"""
Filter Module
"""
import logging
import os
from typing import List
import re

import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Filter Datum
    :param fields: list of str representing all fields to obfuscate
    :param redaction: str representing by what the fields will be obfuscated
    :param messgae: str representing the log line
    :param separator: str representing by which character
    is separating all fields in the log line
    :return: log message obfuscated
    """

    pattern = '|'.join([f'{field}=[^{separator}]+' for field in fields])
    return re.sub(pattern,
                  lambda match: match.group()
                  .split('=')[0] + '=' + redaction, message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format LogRecord
        :param record:
        :return:
        """
        message = record.getMessage()
        record.msg = filter_datum(self.fields,
                                  self.REDACTION,
                                  message, self.SEPARATOR)
        return logging.Formatter.format(self, record)


def get_logger() -> logging.Logger:
    """
    Get logger instance
    :return: a logger instance
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """"
    Get database connection
    """
    user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(user=user,
                                   password=password,
                                   host=host,
                                   database=database)


def main():
    """
    Main function
    :return:
    """
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")

    logger = get_logger()

    for row in cursor:
        message = "; ".join([f'{key} ={value}' for key, value in row.items()])
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
