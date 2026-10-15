#!/usr/bin/env python3
"""Check local Markdown links; optionally probe external links in maintenance."""
import pathlib,re,sys,urllib.request
root=pathlib.Path(__file__).resolve().parents[1]
failed=[]
for file in [root/'README.md',*sorted((root/'docs').glob('*.md'))]:
 if not file.exists():failed.append(str(file));continue
 for url in re.findall(r'(?<!!)\[[^\]]+\]\(([^ )]+)(?:[^)]*)\)',file.read_text()):
  if url.startswith(('http:','https:')):
   if '--external' in sys.argv:
    try:
     with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'openpgp-sign-kms-doc-check'}),timeout=30):pass
    except Exception as e:failed.append(f'{url}: {e}')
  elif not url.startswith('#') and not (file.parent/url.split('#')[0]).exists():failed.append(f'{file}: {url}')
if failed:raise SystemExit('\n'.join(failed))
print('Documentation links passed')
