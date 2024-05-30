#!/usr/bin/env python3
"""
Regex-ing
"""
import re
import logging
import os
import mysql.connector
import bcrypt

PII_FIELDS = ("name", "email", "ssn", "password", "phone")
 
def filter_datum(fields, redaction, message, separator):
    """a function called filter_datum 
    that returns the log message obfuscated:
    
    Keyword arguments:
    fields: a list of strings representing all fields to obfuscate
    redaction: a string representing by what the field will be obfuscated
    message: a string representing the log line
    separator: a string representing by which character 
    is separating all fields in the log line (message)
    Return: None
    """
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern, lambda m: f"{m.group(0).split('=')[0]}={redaction}", message)
    
class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self):
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        record.msg = filter_datum(self.fields, self.REDACTION, record.getMessage(),self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)
    
    def get_logger():
        """
        Creates and returns a logger named 
        'user_data' with a specified configuration
        """
        logger = logging.getLogger("user_data")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        
        # StreamHandler
        stream_handler = logging.StreamHandler()
        
        # set the fromatter with redactingformatter and PII_FIELDS
        formatter = RedactingFormatter(fields=PII_FIELDS)
        stream_handler.setFormatter(formatter)
        
        # add the handler to the logger
        logger.addHandler(stream_handler)
        
        return logger
    
    def get_db():
        """
         returns a connector to the database 
         (mysql.connector.connection.MySQLConnection object)
        """
        
        # set the environment variables
        username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
        password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
        host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
        database = os.getenv("PERSONAL_DATA_DB_NAME")
        
        # return the connector to the database
        return mysql.connector.connect(
            user=username,
            password=password,
            host=host,
            database=database
        )
        
    def main():
        """
        obtain a database connection using get_db and 
        retrieve all rows in the users table
        """
        db = RedactingFormatter.get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users;")
        
        logger = RedactingFormatter.get_logger()
        
        for row in cursor:
            message = '; '.join([f"{key}={value}" for key, value in row.items()])
            logger.info(message)
        
        cursor.close()
        db.close()
        
    def hash_password(password):
        """
        returns a salted, hashed password, which is a byte string.
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed_password
    
    def is_valid(hashed_password, password):
        """
        to validate that the provided password matches the hashed password
        """
        
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
    
if __name__ == "__main__":
    RedactingFormatter.main()
        
        