### Task 0: Regex-ing

1. **Objective**: Write a function `filter_datum` to obfuscate log messages.
2. **Function Signature**:
    ```python
    def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    ```
3. **Implementation**:
    ```python
    import re

    def filter_datum(fields, redaction, message, separator):
        pattern = '|'.join([f'{field}=[^{separator}]+' for field in fields])
        return re.sub(pattern, lambda match: match.group().split('=')[0] + '=' + redaction, message)
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        fields = ["password", "date_of_birth"]
        messages = ["name=egg;email=eggmin@eggsample.com;password=eggcellent;date_of_birth=12/12/1986;", "name=bob;email=bob@dylan.com;password=bobbycool;date_of_birth=03/04/1993;"]
        
        for message in messages:
            print(filter_datum(fields, 'xxx', message, ';'))
    ```

### Task 1: Log Formatter

1. **Objective**: Update the `RedactingFormatter` class.
2. **Steps**:
    - Update the constructor to accept a list of fields.
    - Implement the `format` method.
3. **Implementation**:
    ```python
    import logging

    class RedactingFormatter(logging.Formatter):
        REDACTION = "***"
        FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
        SEPARATOR = ";"

        def __init__(self, fields):
            super(RedactingFormatter, self).__init__(self.FORMAT)
            self.fields = fields

        def format(self, record: logging.LogRecord) -> str:
            record.msg = filter_datum(self.fields, self.REDACTION, record.msg, self.SEPARATOR)
            return super(RedactingFormatter, self).format(record)
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        import logging
        message = "name=Bob;email=bob@dylan.com;ssn=000-123-0000;password=bobby2019;"
        log_record = logging.LogRecord("my_logger", logging.INFO, None, None, message, None, None)
        formatter = RedactingFormatter(fields=("email", "ssn", "password"))
        print(formatter.format(log_record))
    ```

### Task 2: Create Logger

1. **Objective**: Implement a `get_logger` function.
2. **Steps**:
    - Create a tuple `PII_FIELDS` containing fields from `user_data.csv`.
    - Implement `get_logger`.
3. **Implementation**:
    ```python
    import logging

    PII_FIELDS = ("name", "email", "phone", "ssn", "password")

    def get_logger() -> logging.Logger:
        logger = logging.getLogger("user_data")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        stream_handler = logging.StreamHandler()
        formatter = RedactingFormatter(fields=PII_FIELDS)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        return logger
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        logger = get_logger()
        logger.info("name=Bob; email=bob@dylan.com; phone=123456789; ssn=123-45-6789; password=my_password;")
    ```

### Task 3: Connect to Secure Database

1. **Objective**: Implement a `get_db` function.
2. **Steps**:
    - Use the `os` module to get credentials from environment variables.
    - Use `mysql-connector-python` to connect to the database.
3. **Implementation**:
    ```python
    import mysql.connector
    import os

    def get_db() -> mysql.connector.connection.MySQLConnection:
        user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
        password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
        host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
        database = os.getenv("PERSONAL_DATA_DB_NAME")

        return mysql.connector.connect(
            user=user,
            password=password,
            host=host,
            database=database
        )
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users;")
        for row in cursor:
            print(row[0])
        cursor.close()
        db.close()
    ```

### Task 4: Read and Filter Data

1. **Objective**: Implement a `main` function to read and filter data.
2. **Steps**:
    - Connect to the database and retrieve all rows from the `users` table.
    - Display each row with sensitive data filtered.
3. **Implementation**:
    ```python
    def main():
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users;")
        
        logger = get_logger()

        for row in cursor:
            message = "; ".join([f"{key}={value}" for key, value in row.items()])
            logger.info(message)

        cursor.close()
        db.close()

    if __name__ == "__main__":
        main()
    ```

### Task 5: Encrypting Passwords

1. **Objective**: Implement a `hash_password` function.
2. **Steps**:
    - Use the `bcrypt` package for hashing.
3. **Implementation**:
    ```python
    import bcrypt

    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        password = "MyAmazingPassw0rd"
        print(hash_password(password))
        print(hash_password(password))
    ```

### Task 6: Check Valid Password

1. **Objective**: Implement an `is_valid` function.
2. **Steps**:
    - Use the `bcrypt` package to validate the password.
3. **Implementation**:
    ```python
    def is_valid(hashed_password: bytes, password: str) -> bool:
        return bcrypt.checkpw(password.encode(), hashed_password)
    ```
4. **Testing**:
    ```python
    if __name__ == "__main__":
        password = "MyAmazingPassw0rd"
        encrypted_password = hash_password(password)
        print(encrypted_password)
        print(is_valid(encrypted_password, password))
    ```