#!/usr/bin/env python
"""
    Password lengthening based on encryption with fallback passwords
"""
import argparse
import binascii
import getpass
import hashlib
import platform
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
    parser.add_argument(
        '-b', '--bcrypt',
        help='Use bcrypt',
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


def send_password(args, finalhash):
    '''
        Send password to the specified output
    '''
    if args.clipboard:
        if platform.system() == 'Linux':
            from subprocess import Popen, PIPE
            p = Popen(['xsel', '-pib'], stdin=PIPE)
            p.communicate(input=str.encode(finalhash))
        elif platform.system == 'Darwin' or platform.system() == 'Windows':
            try:  # Python 2
                from Tkinter import Tk
            except ImportError:  # Python 3
                from tkinter import Tk
            r = Tk()
            r.withdraw()
            r.clipboard_clear()
            r.clipboard_append(finalhash)
            r.update()
            r.destroy()
    elif args.output:
        if platform.system != 'Windows':
            file = open('/tmp/password.txt', 'w')
            file.write(hash)
            file.close()
        else:
            print('This function is only avaliable on POSIX compliant'
                  'operating sytems.')


def gui_password():
    '''
        Offers GUI input
    '''
    try:  # Python 2
        from Tkinter import Tk
        from tkSimpleDialog import askstring
    except ImportError:  # Python 3
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
    ip = str(int(ip, 16)).encode('UTF-8')

    passhash = None
    storehash = None
    if args.bcrypt:
        # bcrypt hashing
        # TODO Actually finish bcrypt
        try:
            import bcrypt
            passhash = bcrypt.hashpw(ip, conf['salt'])
            storehash = bcrypt.hashpw(passhash, conf['salt'])

        except ImportError:
            print('Bcrypt is not installed')
            sys.exit(1)

    else:
        # SHA256 by default
        passhash = hashlib.sha256(ip)
        passhash = passhash.hexdigest()
        storehash = hashlib.sha256(passhash.encode('UTF-8'))
        storehash = storehash.hexdigest()
    if storehash == conf['pswd']:
        # If double hash is correct (stored hash), pass correct hash along
        print("Correct")
        send_password(args, passhash)

    else:
        for i in conf['backups']:
            bakhash, diff = i.split(':')
            '''
            If a backup hash is found, apply the stored differential
            to create the correct input as recovery.
            '''
            passhash = str(int(ip) - int(diff))

            passhash = hashlib.sha256(passhash.encode('UTF-8'))
            passhash = passhash.hexdigest()
            storehash = hashlib.sha256(passhash.encode('UTF-8'))
            storehash = storehash.hexdigest()
            if storehash == conf['pswd']:
                # Emergency exit
                print('Backup hash accepted')
                send_password(args, passhash)
