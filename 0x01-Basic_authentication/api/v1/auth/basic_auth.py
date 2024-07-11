#!/usr/bin/env python3
"""
The basic auth module
"""
import base64
from typing import TypeVar, Optional, Tuple
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    Basic authentication class for handling user authentication via Basic Auth.
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) \
            -> Optional[str]:
        """
        Extracts the Base64 part of the Authorization header.

        Args:
            authorization_header (str): The full Authorization header.

        Returns:
            Optional[str]: The Base64 encoded part of
            the Authorization header, or None if invalid.
        """
        if (isinstance(authorization_header, str) and
                authorization_header.startswith('Basic ')):
            return authorization_header.split(" ")[1]
        return None

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str)\
            -> Optional[str]:
        """
        Decodes the Base64 encoded Authorization header.

        Args:
            base64_authorization_header (str):
            The Base64 encoded Authorization header.

        Returns:
            Optional[str]: The decoded string, or None if decoding fails.
        """
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str)\
            -> Tuple[Optional[str], Optional[str]]:
        """
        Extracts user credentials from the decoded Authorization header.

        Args:
            decoded_base64_authorization_header (str):
            The decoded Authorization header.

        Returns:
            Tuple[Optional[str], Optional[str]]:
            A tuple containing the user email and
            password, or (None, None) if invalid.
        """
        if (isinstance(decoded_base64_authorization_header, str) and
                ":" in decoded_base64_authorization_header):
            email, password = decoded_base64_authorization_header.split(":", 1)
            return email, password
        return None, None

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str)\
            -> Optional[TypeVar('User')]:
        """
        Retrieves a User object based on the provided credentials.

        Args:
            user_email (str): The user's email.
            user_pwd (str): The user's password.

        Returns:
            Optional[User]: The User object
            if credentials are valid, otherwise None.
        """
        if not user_email or not user_pwd:
            return None

        user_list = User.search({"email": user_email})
        if not user_list:
            return None

        user = user_list[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> Optional[TypeVar('User')]:
        """
        Retrieves the current authenticated user based on the request.

        Args:
            request: The request object containing the Authorization header.

        Returns:
            Optional[User]: The authenticated
            User object, or None if authentication fails.
        """
        if not request:
            return None

        authorization_header = request.headers.get('Authorization')
        base64_authorization_header = (
            self.extract_base64_authorization_header(authorization_header))
        decoded_authorization_header = (
            self.decode_base64_authorization_header
            (base64_authorization_header))
        email, password = (
            self.extract_user_credentials(decoded_authorization_header))

        return self.user_object_from_credentials(email, password)
