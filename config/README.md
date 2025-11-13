# Configuration

This folder contains the configuration files for the SecureChat system.

## Files

- `config.json` - Main configuration file (edit this to change settings)
- `config.json.example` - Example configuration template
- `config_loader.py` - Configuration loader module
- `__init__.py` - Package initialization

## Usage

### Basic Usage

The configuration is automatically loaded when you import from the `config` module:

```python
from config import get_config

config = get_config()
server_port = config.server.port
db_host = config.database.host
```

### Configuration Structure

The `config.json` file contains the following sections:

#### Server Configuration
```json
{
  "server": {
    "host": "localhost",
    "port": 8888,
    "cert_path": "certs/server-cert.pem",
    "key_path": "certs/server-key.pem"
  }
}
```

#### Client Configuration
```json
{
  "client": {
    "cert_path": "certs/client-cert.pem",
    "key_path": "certs/client-key.pem"
  }
}
```

#### CA Configuration
```json
{
  "ca": {
    "cert_path": "certs/ca-cert.pem"
  }
}
```

#### Database Configuration
```json
{
  "database": {
    "host": "localhost",
    "port": 3306,
    "name": "securechat",
    "user": "scuser",
    "password": "scpass"
  }
}
```

**Note:** Database credentials can be overridden with environment variables:
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_NAME` - Database name
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password (recommended for security)

#### Paths Configuration
```json
{
  "paths": {
    "certs_dir": "certs",
    "transcripts_dir": "transcripts"
  }
}
```

#### Crypto Configuration
```json
{
  "crypto": {
    "dh_key_size": 2048,
    "dh_generator": 2,
    "aes_key_size": 16
  }
}
```

## Setup

1. Copy the example configuration:
   ```bash
   cp config/config.json.example config/config.json
   ```

2. Edit `config/config.json` with your settings:
   ```bash
   # Edit with your preferred editor
   nano config/config.json
   # or
   notepad config/config.json
   ```

3. For production, set sensitive values via environment variables:
   ```bash
   export DB_USER=myuser
   export DB_PASSWORD=mypassword
   ```

## Security Notes

- **Database passwords**: Consider using environment variables instead of storing in `config.json`
- **Certificate paths**: Ensure certificate files exist at the specified paths
- **Port numbers**: Make sure ports are not already in use by other applications

## Reloading Configuration

To reload configuration at runtime:

```python
from config import reload_config

config = reload_config()  # Reloads from file
```

## Default Values

If a configuration value is missing, the system will use these defaults:

- Server host: `localhost`
- Server port: `8888`
- Database host: `localhost`
- Database port: `3306`
- Database name: `securechat`
- DH key size: `2048`
- DH generator: `2`
- AES key size: `16`

