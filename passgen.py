#!/usr/bin/env python
"""
    Writes config files for the main app
"""
import binascii
import hashlib
import getpass
import yaml

def write_conf(cf, data):
    """
        writes config file
    """
    with open(cf, 'w') as config:
        yaml.dump(data, config, default_flow_style=False)


if __name__ == "__main__":
    backup_tags = []
    print('Scan main tag')
    main_tag = getpass.getpass(prompt='')
    main_tag = main_tag.encode('UTF-8')
    main_tag = binascii.hexlify(main_tag)
    main_tag = str(int(main_tag, 16))

    main_hash = hashlib.sha256(main_tag.encode('UTF-8'))
    main_hash = main_hash.hexdigest()

    main_hash_store = hashlib.sha256(main_hash.encode('UTF-8'))
    main_hash_store = main_hash_store.hexdigest()

    while True:
        x = input('Do you want to set up a backup card? (y/N)')
        if x.lower() == 'y' or x.lower() == 'yes':
            print('Scan backup tag')
            bak_tag = getpass.getpass(prompt='')
            bak_tag = bak_tag.encode('UTF-8')
            bak_tag = binascii.hexlify(bak_tag)
            bak_tag = str(int(bak_tag, 16))

            bak_hash = hashlib.sha256(bak_tag.encode('UTF-8'))
            bak_hash = bak_hash.hexdigest()
            bak_hash = hashlib.sha256(bak_tag.encode('UTF-8'))
            bak_hash = bak_hash.hexdigest()
            bak_diff = int(bak_tag) - int(main_tag)
            backup_tags.append('{}:{}'.format(bak_hash, bak_diff))

        else:
            break

    conf = {'tag':main_hash_store, 'backups':backup_tags}
    write_conf('passwords.cfg', conf)
