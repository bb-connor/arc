PACKAGE_NAME = "arc-sdk"
__version__ = "1.0.0"


def default_client_info() -> dict[str, str]:
    return {"name": PACKAGE_NAME, "version": __version__}
