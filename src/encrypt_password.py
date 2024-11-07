"""
This script with encrypt your password into `td_key.prop` and `td_pwd.prop` files to enable connection to teradata.
No parameters are required (unless you want to alter the defaults).
You will be prompted for usernmae, hostname, and password.

Prerequisites:
    pip install teradatasql click loguru
"""
import datetime
import sys
from datetime import timezone
from pathlib import Path

import click
from loguru import logger
import teradatasql

ALGORITHM_CHOICES = ['AES']
MODE_CHOICES = ['CBC', 'CFB', 'OFB']
PADDING_CHOICES = ['NoPadding', 'PKCS5Padding']
MAC_CHOICES = ['HmacSHA256', 'HmacSHA1']
LOGMECH_CHOICES = ['LDAP', 'BEARER', 'CODE', 'BROWSER', 'CRED', 'JWT', 'KRBS', 'ROPC', 'SECRET', 'TD2', 'TDNEGO']


@click.command()
@click.option('--username', prompt='Username')
@click.option('--password', prompt='Password')
@click.option('--algorithm', default=ALGORITHM_CHOICES[0], type=click.Choice(ALGORITHM_CHOICES))
@click.option('--mode', default=MODE_CHOICES[0], type=click.Choice(MODE_CHOICES))
@click.option('--padding', default=PADDING_CHOICES[0], type=click.Choice(PADDING_CHOICES))
@click.option('--mac', default=MAC_CHOICES[0], type=click.Choice(MAC_CHOICES))
@click.option('--hostname', prompt='Hostname')
@click.option('--key-size', default=256, type=int)
@click.option('--encrypted-key-path', default=Path('~/td_key.prop').expanduser(),
              type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option('--encrypted-pwd-path', default=Path('~/td_pwd.prop').expanduser(),
              type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option('--logmech', default=LOGMECH_CHOICES[0], type=click.Choice(LOGMECH_CHOICES))
@click.option('--test/--skip-test', default=True,
              help='Test connection; to skip the test, use `--skip-test`')
def main(**kwargs):
    samples_dir = Path(sys.prefix) / 'teradatasql' / 'samples'
    if not samples_dir.exists():
        raise ValueError(f'Expected encryption Python file at {samples_dir},'
                         f' is teradatasql installed in this environment?')
    sys.path.insert(0, str(samples_dir))
    for k, v in kwargs.items():
        if k == 'password':
            logger.info(f'* {k}: ********')
        else:
            logger.info(f'* {k}: {v}')
    tjencrypt_password_main_script(**kwargs)


def tjencrypt_password_main_script(algorithm, mode, padding, key_size, mac, encrypted_key_path, encrypted_pwd_path,
                                   hostname, username, password, logmech, test=True):
    """
    An improvement of TJEncryptPassword.py's script buried in the `__name__ == '__main__'` section
    """
    from TJEncryptPassword import createPasswordEncryptionKeyFile, createEncryptedPasswordFile, decryptPassword
    if algorithm not in ALGORITHM_CHOICES:
        raise ValueError('Unknown algorithm ' + algorithm)
    if mode not in MODE_CHOICES:
        raise ValueError('Unknown mode ' + mode)
    if padding not in PADDING_CHOICES:
        raise ValueError('Unknown padding ' + padding)
    if mac not in MAC_CHOICES:
        raise ValueError('Unknown MAC algorithm ' + mac)
    if not password:
        raise ValueError('Password cannot be zero length')
    password = password.encode().decode('unicode_escape')  # for backslash uXXXX escape sequences

    key_size = int(key_size)
    match = str(datetime.datetime.now(timezone.utc))
    transformation = '/'.join((algorithm, mode, padding))
    aby_key, aby_mac_key = createPasswordEncryptionKeyFile(transformation, algorithm, mode, padding, key_size,
                                                           match, mac, encrypted_key_path)

    createEncryptedPasswordFile(transformation, algorithm, mode, padding, match, aby_key, mac, aby_mac_key,
                                encrypted_pwd_path, password)

    decryptPassword(encrypted_key_path, encrypted_pwd_path)

    password = f'ENCRYPTED_PASSWORD(file:{encrypted_key_path.as_posix()},file:{encrypted_pwd_path.as_posix()})'
    logger.info(f'How to connect:')
    logger.info(f'>>> import teradatasql')
    logger.info(f">>> conn = teradatasql.connect(None, host='{hostname}', user='{username}', logmech='{logmech}',"
                f"password={password}, encryptdata=True)"
                )
    logger.info(f'>>> with conn.cursor() as cur:')
    logger.info(f">>>     result = cur.execute('select user, session').fetchone()")
    logger.info(f'>>>     print(result)')

    if test:
        logger.info(f'Running test...')
        with teradatasql.connect(None, host=hostname, user=username,
                                 password=password, logmech=logmech, encryptdata=True) as con:
            with con.cursor() as cur:
                cur.execute('select user, session')
                print(cur.fetchone())


if __name__ == '__main__':
    main()
