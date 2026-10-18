#!/usr/bin/env python3
"""Vendor one pinned dependency under a private namespace; no runtime downloads."""
import hashlib, io, pathlib, subprocess, zipfile
REF = '0501f5729b9e2448516674aff07c7d1727869b8e'
url = f'https://api.github.com/repos/googleapis/php-jwt/zipball/{REF}'
b = subprocess.check_output(['curl','-fsSL',url])
assert hashlib.sha256(b).hexdigest() == '22aac93a4ef3d44eac8c97880937b495d8a9af30b3e3c2930f05c4ee53c16c02', 'Pinned dependency archive checksum changed; review upstream before updating.'
z = zipfile.ZipFile(io.BytesIO(b))
root = pathlib.Path(__file__).resolve().parents[1] / 'simple-oauth-cimd-access/vendor'
root.mkdir(exist_ok=True)
for n in z.namelist():
    rel = n.split('/',1)[-1]
    if rel.startswith('src/') and rel.endswith('.php') or rel == 'LICENSE':
        target = root / ('php-jwt/' + rel)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(z.read(n).replace(b'Firebase\\JWT',b'OCIMD\\Vendor\\JWT'))
(root/'autoload.php').write_text('''<?php
// Private namespace prevents dependency collisions with other WordPress plugins.
spl_autoload_register(static function (string $class): void {
    $prefix = 'OCIMD\\\\Vendor\\\\JWT\\\\';
    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/php-jwt/src/' . substr($class, strlen($prefix)) . '.php';
        if (is_file($file)) { require_once $file; }
    }
});
''')
(root/'VERSION.json').write_text(__import__('json').dumps({'package':'firebase/php-jwt','version':'7.2.1','commit':REF,'archive_sha256':hashlib.sha256(b).hexdigest(),'change':'Namespace Firebase\\JWT replaced with OCIMD\\Vendor\\JWT only.'},indent=2)+'\n')
print(root)
