"""``enlace_auth.__version__`` reports the installed distribution's version."""

from importlib.metadata import version

import enlace_auth


def test_version_matches_installed_metadata():
    assert enlace_auth.__version__ == version("enlace_auth")
