# Teradata Encrypt

A clearer interface for encrypting password for a Teradata connection than. There are a number of issues with the encryption script provided in `teradatasql` which this aims to fix.


## Prerequisites

* Python 3.10+ (earlier versions probably work just fine)
* `git clone https://github.com/kpwhri/teradata_encrypt`
* `cd teradata_encrypt`
* (Optional) Create a virtual environment with `python -m venv .venv`
  * Activate with:
    * Powershell: `.venv/scripts/Activate.ps1`
    * Linux: `source .venv/bin/activate`
* `pip install -r requirements.txt` (install dependencies)

## Usage

* `cd /path/to/teradata_encrypt`
* If virtual environment, activate with:
    * Powershell: `.venv/scripts/Activate.ps1`
    * Linux: `source .venv/bin/activate`
* `python src/encrypt_password.py`
  * This will prompt for username, password, and hostname.
  * All other options will be set to default (see [Configuration, below](#configuration))
  * It will dump a `td_key.prop` and `td.pwd.prop` into your home directory
  * It will also run a test (the same, but fixed, test using teradatasql)

### Configuration

Here are the options to supply to the path to change the configuration. The first the multiple-choice options is the default. To alter the options, add the option to the command line (e.g., `--logmech`) followed by the preferred choice (e.g., `--logmech CRED`).

* `--logmech`: how to login
  * choices: `['LDAP', 'BEARER', 'CODE', 'BROWSER', 'CRED', 'JWT', 'KRBS', 'ROPC', 'SECRET', 'TD2', 'TDNEGO']`
* `--encrypted-key-path`: path where `td_key.prop` should be output (default: home directory)
* `--encrypted-pwd-path`: path where `td_pwd.prop` should be output (default: home directory)
* `--mode`: mode
  * choices: `['CBC', 'CFB', 'OFB']`
* `--padding`: padding
  * choices: `['NoPadding', 'PKCS5Padding']`
* `--mac`: mac
  * choices: `['HmacSHA256', 'HmacSHA1']`
* `--key-size`: size of key, defaults to 256
* `--skip-test`: do not automatically test after craeting the password encryption files, no argument
