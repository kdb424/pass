# pass
PASS: Password encryption and strengthening.

Encrypts passwords to sha256 or bcrypt to be used as replacement password.

```
usage: pass.py [-h] [-c] [-C CONFIG] [-g] [-o] [-b] [-t TRUNCATE] [-G]

Make passwords harder to hack.

optional arguments:
  -h, --help            show this help message and exit
  -c, --clipboard       Puts output to clipboard
  -C CONFIG, --config CONFIG
                        Specifies a config file
  -g, --gui             GUI password input
  -o, --output          Output file
  -b, --bcrypt          Use bcrypt
  -t TRUNCATE, --truncate TRUNCATE
                        Truncate to length
  -G, --generate        Generate a new password
```
