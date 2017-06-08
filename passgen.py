#!/usr/bin/env python
"""
    Creates a psasword hash file for input verification and backup passwords
"""
import argparse
import binascii
import hashlib
import getpass
import sys
import yaml


def parse_args():
    """
        Parses Arguments
    """
    parser = argparse.ArgumentParser(
        description='Make passwords harder to hack.')
    parser.add_argument(
        '-b', '--bcrypt',
        help='Use bcrypt',
        action='store_true',
        )
    return parser.parse_args()


def write_conf(cf, data):
    """
        writes config file
    """
    with open(cf, 'w') as config:
        yaml.dump(data, config, default_flow_style=False)


if __name__ == "__main__":
    args = parse_args()
    backup_pswds = []
    main_pswd = ''
    salt = None
    if not sys.stdin.isatty():
        main_pswd = str(sys.stdin.read().strip())
    else:
        print('Enter password')
        main_pswd = getpass.getpass(prompt='')
    main_pswd = main_pswd.encode('UTF-8')
    main_pswd = binascii.hexlify(main_pswd)
    main_pswd = str(int(main_pswd, 16)).encode('UTF-8')

    if args.bcrypt:
        try:
            import bcrypt
            salt = bcrypt.gensalt()
            passhash = bcrypt.hashpw(main_pswd, salt)
            storehash = bcrypt.hashpw(passhash, salt)

        except ImportError:
            print('Bcrypt not installed. A salt was not generated')
            sys.exit(1)

    else:
        passhash = hashlib.sha256(main_pswd)
        passhash = passhash.hexdigest()

        storehash = hashlib.sha256(passhash)
        storehash = storehash.hexdigest()

    if sys.stdin.isatty():
        while True:
            x = input('Do you want to set up a backup card? (y/N)')
            if x.lower() == 'y' or x.lower() == 'yes':
                print('Scan backup pswd')
                bak_pswd = getpass.getpass(prompt='')
                bak_pswd = bak_pswd.encode('UTF-8')
                bak_pswd = binascii.hexlify(bak_pswd)
                bak_pswd = str(int(bak_pswd, 16)).encode('UTF-8')

                bak_hash = hashlib.sha256(bak_pswd)
                bak_hash = bak_hash.hexdigest()
                bak_hash = hashlib.sha256(bak_pswd)
                bak_hash = bak_hash.hexdigest()
                bak_diff = int(bak_pswd) - int(main_pswd)
                backup_pswds.append('{}:{}'.format(bak_hash, bak_diff))

            else:
                break

    if salt is not None:
        conf = {'salt': salt, 'pswd': storehash, 'backups': backup_pswds}
    else:
        conf = {'pswd': storehash, 'backups': backup_pswds}

    write_conf('passwords.cfg', conf)
