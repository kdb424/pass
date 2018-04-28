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
    parser.add_argument(
        '-t', '--truncate',
        help='Truncate to length',
        )
    parser.add_argument(
        '-G', '--generate',
        help='Generate a new password',
        action='store_true',
        )
    return parser.parse_args()


def get_conf(config_file):
    """
        Returns a list of titles from config file
    """
    try:
        with open(config_file, 'r') as config:
            cfg = yaml.load(config)
            return cfg
    except OSError as e:
        print('Config file not found')
        return 0


def write_conf(cf, data):
    """
        Writes config file
    """
    try:
        with open(cf, 'w') as config:
            yaml.dump(data, config, default_flow_style=False)
    except OSError as e:
        print('Config file not written')
        return 0


def send_password(args, finalhash):
    '''
        Send password to the specified output
    '''
    if args.truncate is not None:
        truncate = int(args.truncate)
        #TODO Check if TTY and support GUI
        print('Truncating Password to {} characters'.format(truncate))
        finalhash = finalhash[:truncate]
    if args.clipboard:
        if platform.system() == 'Linux':
            from subprocess import Popen, PIPE
            p = Popen(['xsel', '-pib'], stdin=PIPE)
            p.communicate(input=str.encode(finalhash))
        elif platform.system() == 'Darwin':
            import subprocess
            process = subprocess.Popen(
                'pbcopy', env={'LANG': 'en_US.UTF-8'}, stdin=subprocess.PIPE)
            process.communicate(finalhash.encode('utf-8'))
        elif platform.system() == 'Windows':
            try:  # Python 3
                from tkinter import Tk
            except ImportError:  # Python 3
                from Tkinter import Tk
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
            #TODO Check if TTY and support GUI
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
    return askstring("Password", "Enter password: ", show='*')

def check_pass(args, input_pass):
    '''
        Validates password against the config file
    '''
    conf = get_conf(args.config)
    if conf is 0:
        sys.exit(1)
    '''
        Password is encoded to UTF-8, converted to hex based on ASCII,
        then converted to a base 10 int for recovery options.
    '''
    input_pass = input_pass.encode('UTF-8')
    input_pass = binascii.hexlify(input_pass)
    input_pass = str(int(input_pass, 16)).encode('UTF-8')

    passhash = None
    storehash = None
    if args.bcrypt:
        # bcrypt hashing
        try:
            import bcrypt
            passhash = bcrypt.hashpw(input_pass, conf['salt'])
            storehash = bcrypt.hashpw(passhash, conf['salt'])
            if storehash == conf['pswd']:
                #TODO Check if TTY and support GUI
                print('Correct')
                send_password(args, passhash.decode('UTF-8'))


        except ImportError:
            #TODO Check if TTY and support GUI
            print('Bcrypt is not installed')
            sys.exit(1)

    else:
        # SHA256 by default
        passhash = hashlib.sha256(input_pass)
        passhash = passhash.hexdigest()
        storehash = hashlib.sha256(passhash.encode('UTF-8'))
        storehash = storehash.hexdigest()
        if storehash == conf['pswd']:
            # If double hash is correct (stored hash), pass correct hash along
            #TODO Check if TTY and support GUI
            print("Correct")
            send_password(args, passhash)

        else:
            pass  #TODO handle incorrect passwords

def gen_pass(args, main_pswd):
    '''
        Generates a pasword and stores the hashed results
        to a configuration file.
    '''
    conf_file = args.config

    salt = None
    main_pswd = main_pswd.encode('UTF-8')
    main_pswd = binascii.hexlify(main_pswd)
    main_pswd = str(int(main_pswd, 16))
    main_pswd = main_pswd.encode('UTF-8')

    if args.bcrypt:
        try:
            import bcrypt
            if salt is None:
                salt = bcrypt.gensalt()

            passhash = bcrypt.hashpw(main_pswd, salt)
            storehash = bcrypt.hashpw(passhash, salt)

        except ImportError:
            #TODO Do check for GUI/TTY
            print('Bcrypt not installed. Program must exit.')
            sys.exit(1)

    else:
        passhash = hashlib.sha256(main_pswd)
        passhash = passhash.hexdigest()

        storehash = hashlib.sha256(passhash.encode('UTF-8'))
        storehash = storehash.hexdigest()


    if salt is not None:
        conf = {'salt': salt, 'pswd': storehash}
    else:
        conf = {'pswd': storehash}
    if write_conf(conf_file, conf) is 0:
        #TODO Handle fire write error better
        sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    if args.config is None:
        print('No config file specified')
        sys.exit(1)

    if args.generate:
        if not sys.stdin.isatty():
            main_pswd = str(sys.stdin.read().strip())
        else:
            print('Enter new password')
            main_pswd = getpass.getpass(prompt='')

        gen_pass(args, main_pswd)
    else:
        if args.gui:
            input_pass = gui_password()
        elif not sys.stdin.isatty():
            input_pass = str(sys.stdin.read().strip())
        else:
            input_pass = getpass.getpass(prompt='Enter password ->')
        check_pass(args, input_pass)