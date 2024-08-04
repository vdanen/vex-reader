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
        ("SUSE-SU", "SUSE"),
        ("GLSA", "Gentoo")
    ]
)

ARCHES = ['ppc64le', 'ppc64', 'ppc', 'i686', 's390x', 'x86_64', 'aarch64', 'noarch']

FORBIDDEN = ['debuginfo', 'kernel-headers']

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

def filter_components(components):
    """
    only look for the srpms, if these are missing default to x86_64
    """
    filtered = []

    for c in components:
        if '.src' in c:
            filtered.append(c.replace('.src', ''))

    if len(filtered) == 0:
        # there was no srpm
        for c in components:
            if 'x86_64' in c:
                skip = False
                # filter out any forbidden package names like debuginfo which will pollute our output
                for f in FORBIDDEN:
                    if f in c:
                        skip = True
                if not skip:
                    filtered.append(c.replace('.x86_64', ''))

    return filtered