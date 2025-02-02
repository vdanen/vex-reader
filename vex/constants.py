# Constants
from collections import OrderedDict  # Python 2.7+ has OrderedDict built-in

# Mapping of severity ratings to a numeric value for comparison
SEVERITY_MAP = {
    "Critical":  4,
    "Important": 3,
    "Moderate":  2,
    "Low":       1
}

# Display all times in US/Eastern
TZ = 'US/Eastern'

SEVERITY_COLOR = {
    "Critical":  'red',
    "Important": 'yellow',
    "Moderate":  'blue',
    "Low":       'green',
    "None":      'green'
}

SEVERITIES = {
    "C": "Critical",
    "I": "Important",
    "M": "Moderate",
    "L": "Low"
}

VENDOR_ADVISORY = {
    "RHSA":    "Red Hat",
    "RHEA":    "Red Hat",
    "RHBA":    "Red Hat",
    "USN":     "Ubuntu",
    "SUSE-SU": "SUSE",
    "GLSA":    "Gentoo"
}

ARCHES    = frozenset(['ppc64le', 'ppc64', 'ppc', 'i686', 's390x', 'x86_64', 'aarch64', 'noarch'])
FORBIDDEN = frozenset(['debuginfo', 'kernel-headers'])

def get_rating(score: float) -> str:
    """Map a CVSS score to a severity category.

    Args:
        score: CVSS score as float

    Returns:
        String representing severity rating
    """
    if score < 0.1:
        return 'None'
    elif score <= 3.9:
        return 'Low'
    elif score <= 6.9:
        return 'Medium'
    elif score <= 8.9:
        return 'High'
    else:
        return 'Critical'

def filter_components(components: list) -> list:
    """Filter component list to get base package names.

    Looks for source RPMs first, falls back to x86_64 packages if no source RPMs found.
    Filters out forbidden package types like debuginfo.

    Args:
        components: List of package names to filter

    Returns:
        Filtered list of base package names
    """
    # First try to find source RPMs
    filtered = [c.replace('.src', '') for c in components if '.src' in c]

    if not filtered:
        # No source RPMs found, try x86_64 packages
        filtered = [
            c.replace('.x86_64', '') for c in components
            if 'x86_64' in c and not any(f in c for f in FORBIDDEN)
        ]

    # If still empty, return original components (likely won't fix case)
    return filtered or components