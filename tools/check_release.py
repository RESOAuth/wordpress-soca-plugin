#!/usr/bin/env python3
"""Fail when release metadata or the bundled JWT drifts from Composer's lock."""
import json
import pathlib
import re

root = pathlib.Path(__file__).resolve().parents[1]
header = (root / 'simple-oauth-cimd-access/simple-oauth-cimd-access.php').read_text()
readme = (root / 'simple-oauth-cimd-access/readme.txt').read_text()
build = (root / 'tools/build.py').read_text()
version = re.search(r'^ \* Version: (\S+)$', header, re.M).group(1)
assert version == '0.3.0', f'unexpected release version {version}'
assert f'Stable tag: {version}' in readme
assert f"version='{version}'" in build
assert 'Author: RESOAuth' in header
assert 'Plugin URI: https://github.com/RESOAuth/wordpress-soca-plugin' in header
assert len(re.search(r'^ \* Description: (.+)$', header, re.M).group(1)) < 140

manifest = json.loads((root / 'composer.json').read_text())
assert manifest['name'] == 'resoauth/simple-oauth-cimd-access'
lock = json.loads((root / 'composer.lock').read_text())
vendor = json.loads((root / 'simple-oauth-cimd-access/vendor/VERSION.json').read_text())
packages = [p for p in lock['packages'] if p['name'] == vendor['package']]
assert len(packages) == 1
package = packages[0]
assert manifest['require'][vendor['package']] == vendor['version']
assert package['version'].lstrip('v') == vendor['version']
assert package['source']['reference'] == vendor['commit']
assert len(vendor['archive_sha256']) == 64
print(f'SOCA {version}; bundled {vendor["package"]} {vendor["version"]} matches lockfile')
