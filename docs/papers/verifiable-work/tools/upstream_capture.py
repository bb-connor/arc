"""Verify compressed source captures against their unchanged upstream byte pins."""
import gzip
import hashlib
from pathlib import Path
import zlib

MAX_CAPTURE_BYTES = 1024 * 1024


def verify_capture(root, spec, source):
    root = Path(root).resolve()
    capture = spec.get('capture', {})
    name = capture.get('path', '')
    expected_size = source.get('bytes')
    if (not isinstance(name, str) or not name
            or capture.get('compression') != 'gzip'
            or type(expected_size) is not int
            or not 0 < expected_size <= MAX_CAPTURE_BYTES
            or capture.get('uncompressed_bytes') != expected_size
            or spec.get('sha256') != source.get('sha256')
            or spec.get('source_url') != source.get('url')
            or spec.get('git_commit') != source.get('version')):
        return ['invalid upstream capture metadata']
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        return ['upstream capture is outside its artifact root']
    try:
        with gzip.open(path, 'rb') as stream:
            raw = stream.read(expected_size + 1)
    except (OSError, EOFError, zlib.error) as error:
        return ['unreadable upstream capture: ' + str(error)]
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != spec['sha256']:
        return ['upstream capture differs from the pinned source bytes']
    return []
