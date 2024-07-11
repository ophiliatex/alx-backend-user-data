#!/usr/bin/env python3
"""
Encryption and Decryption module
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash the given password using SHA256
    :param password:
    :return:
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if the given password is valid
    :param hashed_password: the hashed password
    :param password: the original password
    :return: boolean indicating if the password is valid
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
