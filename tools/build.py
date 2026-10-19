#!/usr/bin/env python3
"""Build deterministic, installable plugin and source ZIPs; never package work/test runtime data."""
import hashlib, json, pathlib, re, zipfile
root=pathlib.Path(__file__).resolve().parents[1]
out=root/'dist';out.mkdir(exist_ok=True)
version='0.2.0'
def archive(path,items):
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for target,source in sorted(items):
            data=source.read_bytes()
            if source.suffix in ['.php','.json','.md','.txt']:
                assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',data),f'Private material in {source}'
            info=zipfile.ZipInfo(target,(2026,10,19,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,data)
    return {'file':path.name,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
slug='simple-oauth-cimd-access'
plugin=[(slug+'/'+str(p.relative_to(root/slug)),p) for p in (root/slug).rglob('*') if p.is_file()]
plugin += [(slug+'/composer.json',root/'composer.json')]
assert not any('/tests/' in name or '/work/' in name or name.endswith('wp-config.php') for name,_ in plugin)
source=[]
for folder in [slug,'docs','tools','tests','.github']:
    source += [('wordpress-simple-oauth-cimd-access/'+str(p.relative_to(root)),p) for p in (root/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
for file in ['README.md','LICENSE','composer.json','composer.lock','docker-compose.yml','.gitignore']:
    source.append(('wordpress-simple-oauth-cimd-access/'+file,root/file))
manifest=[archive(out/f'{slug}-{version}.zip',plugin),archive(out/f'{slug}-{version}-source.zip',source)]
(out/'SHA256SUMS').write_text(''.join(f"{r['sha256']}  {r['file']}\n" for r in manifest))
print(json.dumps(manifest,indent=2))
