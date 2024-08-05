# vex-reader
Utility to read Red Hat VEX files that are located at https://access.redhat.com/security/data/csaf/v2/vex/2024/

I'm (slowly) aiming to make this a bit more extensible so that it can be
used with other VEX files beyond just Red Hat, but I'm basing all of this
off of Red Hat VEX files to aim to make this a proper parsing library for
any VEX documents.

If you don't have Python requests installed you will need to install it.
If you want to use a virtualenv, you can install with:

```pip install -r requirements.txt```

