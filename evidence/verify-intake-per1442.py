import json, os, hashlib, pathlib, re
root=pathlib.Path.cwd()
scratch=pathlib.Path(os.environ['PAPERCLIP_RUN_SCRATCH_DIR'])
items=json.loads((root/'evidence/intake-per1442-github.json').read_text())['items']
assert len(items)==61 and len({(i['repo'],i['kind'],i['number']) for i in items})==61
assert all(i['state']=='open' for i in items)
assert all(i['merged'] is False and i['merged_at'] is None for i in items if i['kind']=='pr')
previous_doc=json.loads((scratch/'PER-1438-documents.json').read_text(encoding='utf-8-sig'))
previous=(previous_doc[0] if isinstance(previous_doc,list) else previous_doc)['body']
for i in items:
    kind=i['kind']
    pattern=r'\| '+re.escape(i['repo'])+r' \| '+kind+r' \| '+str(i['number'])+r' \| open \| ([^|]*) \| ([^|]*) \|'
    match=re.search(pattern, previous)
    assert match, (i['repo'],kind,i['number'],'missing previous row')
    assert match[1].strip()==i.get('head_sha',''), (i['number'],'head delta')
    assert set(x.strip() for x in match[2].split(',') if x.strip())=={x['name'] for x in (i['labels'] or [])}, (i['number'],'label delta')
sources=json.loads((root/'evidence/intake-per1442-source-hashes.json').read_text(encoding='utf-8-sig'))
assert len(sources['sources'])==10
assert sources['runId']==os.environ['PAPERCLIP_RUN_ID']
for s in sources['sources']:
    assert s['unchanged'] and s['ledgerPresent'],s['path']
    assert all(a['matches'] for a in s['verifiedAnchors']),s['path']
assert hashlib.sha256((root/'.audit/deep-audit.tsv').read_bytes()).hexdigest()=='139461ab9607df5f2a1c8b17d618f78c8078f357f74365c9444b96ba146977ac'
print('PASS: 61 unique frozen identities OPEN, 28 unmerged heads and 61 labels unchanged; 10 source hashes/ledger/heading anchors unchanged; tracked audit hash unchanged.')
