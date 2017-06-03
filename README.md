# pass
PASS: Passwords are super simple. Password encryption and strengthening.

Encrypts passwords to sha256 to be used as replacement password.
It will allow backup passwords to be stored on the system as backup passwords which are stored as a differential of the original to allow for backup passwords in case the original is lost, or more passwords are desired.

```
usage: pass.py [-h] [-c] [-C CONFIG] [-g]

Make passwords harder to hack.

optional arguments:
  -h, --help            show this help message and exit
  -c, --clipboard       Puts output to clipboard
  -C CONFIG, --config CONFIG
                        Specifies a config file
  -g, --gui             GUI password input
  -o, --output          Output file
```
