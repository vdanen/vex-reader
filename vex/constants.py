# Constants

try:
    from collections import OrderedDict
except ImportError:
    # noinspection PyUnresolvedReferences
    from ordereddict import OrderedDict

# Mapping of severity ratings to a numeric for easier comparison
SEVERITY_MAP = OrderedDict(
    [
        ("Critical", 4),
        ("Important", 3),
        ("Moderate", 2),
        ("Low", 1)
    ]
)

SEVERITIES = OrderedDict(
    [
        ("C", "Critical"),
        ("I", "Important"),
        ("M", "Moderate"),
        ("L", "Low")
    ]
)

VENDOR_ADVISORY = OrderedDict(
    [
        ("RHSA", "Red Hat"),
        ("USN", "Ubuntu"),
        ("SUSE-SU", "SUSE")
    ]
)

ARCHES = ['ppc64le', 'ppc64', 'ppc', 'i686', 's390x', 'x86_64', 'aarch64', 'noarch']

def get_rating(score):
    # map a CVSS score to a severity category
    if 0.1 <= score <= 3.9:
        return 'Low'
    elif 4.0 <= score <= 6.9:
        return 'Medium'
    elif 7.0 <= score <= 8.9:
        return 'High'
    elif score >= 9.0:
        return 'Critical'
    else:
        return 'None'

def filter_products(products):
    """
    strip out all arches from product listings
    """
    filtered = []

    for p in products:
        c = 0
        for a in ARCHES:
            if a in p:
                c += 1
        if c == 0:
            # remove the .src from the product listing
            filtered.append(p.replace('.src',''))

    return filtered