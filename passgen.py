#!/usr/bin/env python
"""
    Creates a psasword hash file for input verification and backup passwords
"""
import binascii
import hashlib
import getpass
import sys
import yaml


def write_conf(cf, data):
    """
        writes config file
    """
    with open(cf, 'w') as config:
        yaml.dump(data, config, default_flow_style=False)


if __name__ == "__main__":
    backup_pswds = []
    main_pswd = ''
    if not sys.stdin.isatty():
        main_pswd = str(sys.stdin.read().strip())
    else:
        print('Enter password')
        main_pswd = getpass.getpass(prompt='')
    main_pswd = main_pswd.encode('UTF-8')
    main_pswd = binascii.hexlify(main_pswd)
    main_pswd = str(int(main_pswd, 16))

    main_hash = hashlib.sha256(main_pswd.encode('UTF-8'))
    main_hash = main_hash.hexdigest()

    main_hash_store = hashlib.sha256(main_hash.encode('UTF-8'))
    main_hash_store = main_hash_store.hexdigest()

    if sys.stdin.isatty():
        while True:
            x = input('Do you want to set up a backup card? (y/N)')
            if x.lower() == 'y' or x.lower() == 'yes':
                print('Scan backup pswd')
                bak_pswd = getpass.getpass(prompt='')
                bak_pswd = bak_pswd.encode('UTF-8')
                bak_pswd = binascii.hexlify(bak_pswd)
                bak_pswd = str(int(bak_pswd, 16))

                bak_hash = hashlib.sha256(bak_pswd.encode('UTF-8'))
                bak_hash = bak_hash.hexdigest()
                bak_hash = hashlib.sha256(bak_pswd.encode('UTF-8'))
                bak_hash = bak_hash.hexdigest()
                bak_diff = int(bak_pswd) - int(main_pswd)
                backup_pswds.append('{}:{}'.format(bak_hash, bak_diff))

            else:
                break

    conf = {'pswd': main_hash_store, 'backups': backup_pswds}
    write_conf('passwords.cfg', conf)
