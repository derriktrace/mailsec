"""Isolated, bounded local email inspection. No URL fetching or payload execution."""
import hashlib
from pathlib import Path

# Invalidate static/attachment caches whenever any deployed inspector code changes.
_source = hashlib.sha256()
for _path in sorted(Path(__file__).parent.glob('*.py')):
    _source.update(_path.name.encode()+b'\0'+_path.read_bytes())
_visibility = Path(__file__).parents[1] / 'html_visibility.py'
_source.update(_visibility.read_bytes())
# Epoch2 invalidates every pre-confinement message/document/antivirus cache key,
# including results produced before the native dependency security rebuild.
PARSER_VERSION = 'inspection-v2.'+_source.hexdigest()[:16]
