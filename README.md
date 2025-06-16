# vex-reader

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vdanen/vex-reader/badge)](https://scorecard.dev/viewer/?uri=github.com/vdanen/vex-reader)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/vdanen/vex-reader?sort=semver)

Utility to read Red Hat VEX files that are located at https://access.redhat.com/security/data/csaf/v2/vex/.

I'm (slowly) aiming to make this a bit more extensible so that it can be
used with other VEX files beyond just Red Hat, but I'm basing all of this
off of Red Hat VEX files to aim to make this a proper parsing library for
any VEX documents.

## Installation

Install [vex-reader](https://pypi.org/project/vex-reader/) from PyPI:

```shell
pip install vex-reader
```

Development setup:

```shell
git clone https://github.com/vdanen/vex-reader.git
cd vex-reader
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
```

## Usage

You can use the vex library in your own Python applications, or you can
clone this repo and use the `vex-reader` command to parse VEX files.

```
vex-reader --vex tests/cve-2002-2443.json
CVE-2002-2443
-------------

Public on : 2002-06-15
Impact    : Moderate
CVSS Score: 5.0

Vulnerability summary
krb5: UDP ping-pong flaw in kpasswd


Vulnerability description
schpw.c in the kpasswd service in kadmind in MIT Kerberos 5 (aka krb5) before 1.11.3 does not properly validate UDP packets before
sending responses, which allows remote attackers to cause a denial of service (CPU and bandwidth consumption) via a forged packet that
triggers a communication loop, as demonstrated by krb_pingpong.nasl, a related issue to CVE-1999-0103.


CVSS score applicability
The CVSS score(s) listed for this vulnerability do not reflect the associated product's status, and are included for informational
purposes to better understand the severity of this vulnerability.


Terms of Use
This content is licensed under the Creative Commons Attribution 4.0 International License
(https://creativecommons.org/licenses/by/4.0/). If you distribute this content, or a modified version of it, you must provide
attribution to Red Hat Inc. and provide a link to the original.


Additional Information
  Bugzilla: 962531

External References
  https://bugzilla.redhat.com/show_bug.cgi?id=962531
  https://www.cve.org/CVERecord?id=CVE-2002-2443
  https://nvd.nist.gov/vuln/detail/CVE-2002-2443

Red Hat affected packages and issued errata
  RHSA-2013:0942 -- Red Hat Enterprise Linux Workstation (v. 6)

CVSS v2 Vector
  Red Hat: AV:N/AC:L/Au:N/C:N/I:N/A:P
  NVD    : AV:N/AC:L/Au:N/C:N/I:N/A:P

CVSS v2 Score Breakdown
                           Red Hat    NVD
  CVSS v2 Base Score       5.0        5.0
  Access Vector            Network    Network
  Access Complexity        Low        Low
  Authentication           None       None
  Confidentiality Impact   None       None
  Integrity Impact         None       None
  Availability Impact      Partial    Partial

Copyright © Red Hat, Inc. All rights reserved
```

By default, `vex-reader` will pull the CVSS score from NVD's API.  If this
is undesirable (for testing, etc) you can pass the `--no-nvd` argument to
prevent lookups. Currently, `vex-reader` requires the VEX file to parse to
be on-disk.

When working from the git repository for development, use:

```
$ python -m vex.vex_reader --vex tests/cve-2002-2443.json
```

A good place to find some VEX documents to play with is here: https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json
