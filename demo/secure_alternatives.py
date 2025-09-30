#!/usr/bin/env python3
"""
Secure Alternatives Demo
This demonstrates secure coding practices that address the vulnerabilities
shown in the other demo files. This serves as a reference for developers
to understand how to fix common security issues.
"""

import os
import sys
import json
import sqlite3
import subprocess
import hashlib
import secrets
import hmac
import logging
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argparse
import shlex
import ast
from urllib.parse import urlparse
import re

# SECURE: Use environment variables for sensitive configuration
class SecureConfig:
    """Secure configuration management using environment variables"""

    def __init__(self):
        # Load sensitive values from environment variables
        self.aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.database_url = os.environ.get('DATABASE_URL')
        self.api_token = os.environ.get('API_TOKEN')
        self.jwt_secret = os.environ.get('JWT_SECRET_KEY')

        # Validate that required secrets are present
        self._validate_required_config()

    def _validate_required_config(self):
        """Validate that all required configuration is present"""
        required_vars = ['DATABASE_URL', 'API_TOKEN', 'JWT_SECRET_KEY']
        missing_vars = [var for var in required_vars if not os.environ.get(var)]

        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

class SecureWebApp:
    """Secure web application demonstrating best practices"""

    def __init__(self, config: SecureConfig):
        self.config = config
        self.db_connection = None
        self._setup_logging()

    def _setup_logging(self):
        """Set up secure logging configuration"""
        # Use structured logging with appropriate levels
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('app.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def hash_password(self, password: str) -> str:
        """SECURE: Use strong password hashing with salt"""
        # Use bcrypt or Argon2 in production
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """SECURE: Verify password against stored hash"""
        try:
            salt, hash_hex = stored_hash.split(':')
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(hash_hex, password_hash.hex())
        except ValueError:
            return False

    def generate_secure_token(self) -> str:
        """SECURE: Generate cryptographically secure random token"""
        return secrets.token_urlsafe(32)

    def execute_safe_query(self, query: str, params: tuple) -> List[tuple]:
        """SECURE: Use parameterized queries to prevent SQL injection"""
        if not self.db_connection:
            self.db_connection = sqlite3.connect(':memory:')  # Use proper DB connection in production

        cursor = self.db_connection.cursor()
        # Use parameterized query to prevent SQL injection
        cursor.execute(query, params)
        return cursor.fetchall()

    def safe_file_upload(self, uploaded_file, upload_dir: str) -> Optional[str]:
        """SECURE: Safe file upload with validation"""
        if not uploaded_file or not uploaded_file.filename:
            return None

        # Validate file extension
        allowed_extensions = {'.txt', '.csv', '.json', '.pdf', '.png', '.jpg', '.jpeg'}
        file_ext = Path(uploaded_file.filename).suffix.lower()
        if file_ext not in allowed_extensions:
            raise ValueError(f"File type not allowed: {file_ext}")

        # Use secure_filename equivalent
        filename = self._sanitize_filename(uploaded_file.filename)

        # Create safe upload path
        upload_path = Path(upload_dir) / filename
        upload_path = upload_path.resolve()  # Resolve any path traversal attempts

        # Ensure the file is within the upload directory
        if not str(upload_path).startswith(str(Path(upload_dir).resolve())):
            raise ValueError("Path traversal attempt detected")

        # Save file securely
        uploaded_file.save(upload_path)
        return str(upload_path)

    def _sanitize_filename(self, filename: str) -> str:
        """SECURE: Sanitize filename to prevent path traversal"""
        # Remove path separators and dangerous characters
        filename = re.sub(r'[^\w\.-]', '_', filename)
        filename = filename.strip('.')  # Remove leading/trailing dots

        # Ensure filename is not empty and not too long
        if not filename or len(filename) > 255:
            filename = f"file_{secrets.token_hex(8)}"

        return filename

class SecureDataProcessor:
    """Secure data processing demonstrating best practices"""

    def __init__(self, config: SecureConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def safe_yaml_load(self, yaml_content: str) -> Dict[Any, Any]:
        """SECURE: Use safe YAML loading"""
        try:
            # Use safe_load to prevent code execution
            return yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error: {e}")
            raise ValueError("Invalid YAML content")

    def safe_json_serialization(self, data: Any) -> str:
        """SECURE: Safe JSON serialization instead of pickle"""
        try:
            # Use JSON instead of pickle for data serialization
            return json.dumps(data, ensure_ascii=False, indent=2)
        except (TypeError, ValueError) as e:
            self.logger.error(f"JSON serialization error: {e}")
            raise ValueError("Data not serializable to JSON")

    def safe_deserialization(self, json_content: str) -> Any:
        """SECURE: Safe JSON deserialization instead of pickle"""
        try:
            # Use JSON instead of pickle for data deserialization
            return json.loads(json_content)
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parsing error: {e}")
            raise ValueError("Invalid JSON content")

    def safe_expression_evaluation(self, expression: str, allowed_names: Dict[str, Any]) -> Any:
        """SECURE: Safe expression evaluation using ast.literal_eval"""
        try:
            # Use ast.literal_eval for safe evaluation of literals only
            return ast.literal_eval(expression)
        except (ValueError, SyntaxError) as e:
            self.logger.error(f"Expression evaluation error: {e}")
            raise ValueError("Invalid or unsafe expression")

    def safe_subprocess_execution(self, command: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        """SECURE: Safe subprocess execution with argument list"""
        try:
            # Use list of arguments instead of shell=True
            # Validate command to ensure it's in allowed commands
            allowed_commands = {'ls', 'cat', 'grep', 'find', 'python3', 'git'}
            if command[0] not in allowed_commands:
                raise ValueError(f"Command not allowed: {command[0]}")

            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=30,  # Add timeout to prevent hanging
                check=True
            )
            return result
        except subprocess.SubprocessError as e:
            self.logger.error(f"Subprocess execution error: {e}")
            raise

    def secure_file_operations(self, operation: str, file_path: str) -> bool:
        """SECURE: Safe file operations with validation"""
        # Validate and sanitize file path
        safe_path = Path(file_path).resolve()

        # Define allowed directories
        allowed_dirs = {Path('/tmp').resolve(), Path('/var/tmp').resolve()}
        if not any(str(safe_path).startswith(str(allowed_dir)) for allowed_dir in allowed_dirs):
            raise ValueError("File path not in allowed directory")

        try:
            if operation == 'delete':
                if safe_path.exists() and safe_path.is_file():
                    safe_path.unlink()
                    return True
            elif operation == 'copy':
                # Use shutil for safe file operations
                backup_path = safe_path.with_suffix(safe_path.suffix + '.bak')
                shutil.copy2(safe_path, backup_path)
                return True
            elif operation == 'move':
                # Safe file moving
                new_path = safe_path.with_name(f"moved_{safe_path.name}")
                shutil.move(safe_path, new_path)
                return True
        except (OSError, shutil.Error) as e:
            self.logger.error(f"File operation error: {e}")
            raise

        return False

class SecureNetworkClient:
    """Secure network operations demonstrating best practices"""

    def __init__(self, config: SecureConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = 30  # Set default timeout
        self.logger = logging.getLogger(__name__)

    def safe_http_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """SECURE: Safe HTTP requests with SSL verification and validation"""
        # Validate URL
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            raise ValueError("Invalid URL scheme")

        # For production, only allow HTTPS
        if parsed_url.scheme != 'https':
            self.logger.warning(f"HTTP (non-encrypted) request to {url}")

        try:
            # Always verify SSL certificates (verify=True is default)
            response = self.session.request(
                method=method,
                url=url,
                verify=True,  # Always verify SSL certificates
                timeout=30,   # Set timeout to prevent hanging
                **kwargs
            )
            response.raise_for_status()  # Raise exception for bad status codes
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP request error: {e}")
            raise

    def secure_api_call(self, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """SECURE: API call with proper authentication and error handling"""
        headers = {
            'Authorization': f'Bearer {self.config.api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'SecureApp/1.0'
        }

        try:
            if data:
                response = self.safe_http_request(
                    endpoint,
                    method='POST',
                    headers=headers,
                    json=data
                )
            else:
                response = self.safe_http_request(
                    endpoint,
                    method='GET',
                    headers=headers
                )

            return response.json()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            self.logger.error(f"API call error: {e}")
            raise

class SecureCryptoOperations:
    """Secure cryptographic operations demonstrating best practices"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def generate_secure_hash(self, data: str, salt: Optional[bytes] = None) -> str:
        """SECURE: Generate secure hash using SHA-256 with salt"""
        if salt is None:
            salt = secrets.token_bytes(32)

        # Use SHA-256 or stronger hash functions
        hash_obj = hashlib.sha256()
        hash_obj.update(salt)
        hash_obj.update(data.encode('utf-8'))

        return f"{salt.hex()}:{hash_obj.hexdigest()}"

    def encrypt_sensitive_data(self, data: str, password: str) -> str:
        """SECURE: Encrypt sensitive data using Fernet (AES 128)"""
        # Derive key from password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=secrets.token_bytes(16),
            iterations=100000,
        )
        key = Fernet.generate_key()  # In practice, derive from password
        fernet = Fernet(key)

        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data.decode()

    def secure_random_generation(self, length: int = 32) -> str:
        """SECURE: Generate cryptographically secure random values"""
        return secrets.token_urlsafe(length)

class SecureConfigurationManager:
    """Secure configuration management demonstrating best practices"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config_cache = {}

    def load_secure_config(self, config_path: str) -> Dict:
        """SECURE: Load configuration with proper validation"""
        config_file = Path(config_path).resolve()

        # Validate configuration file path
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Check file permissions (should not be world-readable)
        if config_file.stat().st_mode & 0o044:
            self.logger.warning(f"Configuration file {config_path} is world-readable")

        try:
            with open(config_file, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    # Use safe_load for YAML
                    config_data = yaml.safe_load(f)
                else:
                    # Use JSON for other formats
                    config_data = json.load(f)

            # Validate configuration structure
            return self._validate_config(config_data)
        except (yaml.YAMLError, json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Configuration loading error: {e}")
            raise ValueError("Invalid configuration file")

    def _validate_config(self, config: Dict) -> Dict:
        """Validate configuration structure and values"""
        required_fields = ['database', 'api', 'security']
        missing_fields = [field for field in required_fields if field not in config]

        if missing_fields:
            raise ValueError(f"Missing required configuration fields: {missing_fields}")

        return config

    def template_config_safely(self, template: str, variables: Dict[str, str]) -> str:
        """SECURE: Safe configuration templating without eval"""
        # Use string.Template for safe substitution
        from string import Template

        # Validate template variables
        allowed_vars = {'env', 'app_name', 'version', 'port'}
        invalid_vars = set(variables.keys()) - allowed_vars
        if invalid_vars:
            raise ValueError(f"Invalid template variables: {invalid_vars}")

        template_obj = Template(template)
        return template_obj.safe_substitute(variables)

def secure_main():
    """SECURE: Main function demonstrating secure practices"""
    # Use argparse for secure command line argument parsing
    parser = argparse.ArgumentParser(description='Secure application demo')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--operation', required=True,
                       choices=['process', 'upload', 'api-call'],
                       help='Operation to perform')
    parser.add_argument('--input-file', help='Input file path')
    parser.add_argument('--output-dir', help='Output directory')

    try:
        args = parser.parse_args()

        # Load secure configuration
        config = SecureConfig()
        config_manager = SecureConfigurationManager()
        app_config = config_manager.load_secure_config(args.config)

        # Initialize secure components
        web_app = SecureWebApp(config)
        data_processor = SecureDataProcessor(config)
        network_client = SecureNetworkClient(config)
        crypto_ops = SecureCryptoOperations()

        # Perform requested operation securely
        if args.operation == 'process':
            if not args.input_file:
                raise ValueError("Input file required for process operation")

            # Safe file processing
            input_path = Path(args.input_file).resolve()
            with open(input_path, 'r') as f:
                data = json.load(f)

            # Process data safely
            processed_data = data_processor.safe_json_serialization(data)
            print(f"Processed data: {len(processed_data)} characters")

        elif args.operation == 'api-call':
            # Safe API interaction
            api_response = network_client.secure_api_call(
                app_config['api']['endpoint']
            )
            print(f"API response: {json.dumps(api_response, indent=2)}")

        elif args.operation == 'upload':
            if not args.input_file or not args.output_dir:
                raise ValueError("Input file and output directory required")

            # Simulate secure file upload
            print(f"Would upload {args.input_file} to {args.output_dir} securely")

    except Exception as e:
        logging.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Set up secure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    secure_main()