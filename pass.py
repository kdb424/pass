#!/usr/bin/env python
"""
    Password strengthening based on encryption with fallback passwords
"""
import argparse
import binascii
import getpass
import hashlib
import sys
import yaml

def parse_args():
    """
        Parses Arguments
    """
    parser = argparse.ArgumentParser(
        description='Make passwords harder to hack.')
    parser.add_argument(
        '-c', '--clipboard',
        help='Puts output to clipboard',
        action='store_true',
        )
    parser.add_argument(
        '-C', '--config',
        help='Specifies a config file'
        )
    parser.add_argument(
        '-g', '--gui',
        help='GUI password input',
        action='store_true',
        )
    parser.add_argument(
        '-o', '--output',
        help='Output file',
        action='store_true',
        )
    return parser.parse_args()

def get_conf(config_file):
    """
        Returns a list of titles from config file
    """
    with open(config_file, 'r') as config:
        cfg = yaml.load(config)
        return cfg

def send_password(args, hash):
    if args.clipboard:
        import platform
        if platform.system() == 'Linux':
            from subprocess import Popen, PIPE
            p = Popen(['xsel', '-pib'], stdin=PIPE)
            p.communicate(input=str.encode(hash))
        elif platform.system == 'Darwin' or platform.system() == 'Windows':
            try: # Python 2
                from Tkinter import Tk
            except ImportError: # Python 3
                from tkinter import Tk
            r = Tk()
            r.withdraw()
            r.clipboard_clear()
            r.clipboard_append(hash)
            r.update()
            r.destroy()
    elif args.output:
        #TODO Change password store location and check platform
        file = open('/tmp/password.txt', 'w')
        file.write(hash)
        file.close()

def gui_password():
    try: # Python 2
        from Tkinter import Tk
        from tkSimpleDialog import askstring
    except ImportError: # Python 3
        from tkinter import Tk
        from tkinter.simpledialog import askstring
    root = Tk()
    root.withdraw()
    return askstring("Password", "Enter password:", show='*')

if __name__ == "__main__":
    args = parse_args()
    if not args.config:
        conf = get_conf("passwords.cfg")
    else:
        conf = get_conf(args.config)

    ip = ''
    if not sys.stdin.isatty():
        ip = str(sys.stdin.read().strip())
    elif args.gui:
        ip = gui_password()
    else:
        ip = getpass.getpass(prompt='')
    '''
        Password is encoded to UTF-8, converted to hex based on ASCII,
        then converted to a base 10 int for recovery options.
    '''
    ip = ip.encode('UTF-8')
    ip = binascii.hexlify(ip)
    ip = str(int(ip, 16))

    hash1 = hashlib.sha256(ip.encode('UTF-8'))
    hash1 = hash1.hexdigest()
    hash2 = hashlib.sha256(hash1.encode('UTF-8'))
    hash2 = hash2.hexdigest()
    if hash2 == conf['tag']:
        # Double hash if stored hash is correct.
        print("Correct")
        send_password(args, hash1)

    else:
        for i in conf['backups']:
            bakhash, diff = i.split(':')
            '''
            If a backup hash is found, apply the stored differential
            to create the correct input as recovery.
            '''
            hash1 = str(int(ip) - int(diff))

            hash1 = hashlib.sha256(hash1.encode('UTF-8'))
            hash1 = hash1.hexdigest()
            hash2 = hashlib.sha256(hash1.encode('UTF-8'))
            hash2 = hash2.hexdigest()
            if hash2 == conf['tag']:
                # Emergency exit
                print('Backup hash accepted')
                send_password(args, hash1)
