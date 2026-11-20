#!/usr/bin/env python3
"""Exercise the npm transaction owner in real terminals with owned fake managers."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import tempfile

NAME='cli::tool::tests::npm_terminal_consent_binds_the_transaction_and_keeps_signatures_mandatory'
CASES=('accept','generic-yes','blank','wrong-review','eof','no-tty','lock-change','runtime-change','manager-library-change','manager-metadata-change','evidence-change','signature-reject','scripts-permitted','interrupt','terminate','hangup')
MARKER=b'OMG_NPM_ADVISORY_RESULT='

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit',type=Path,required=True)
    parser.add_argument('--case',choices=CASES)
    args=parser.parse_args()
    unit=args.unit.resolve(strict=True)
    spec=importlib.util.spec_from_file_location('arch_consent',Path(__file__).with_name('test-arch-advisory-consent.py'))
    terminal=importlib.util.module_from_spec(spec); spec.loader.exec_module(terminal)
    terminal.NAME=NAME
    records=[]
    with tempfile.TemporaryDirectory(prefix='omg-npm-consent-') as scratch:
        for case in ((args.case,) if args.case else CASES):
            root=Path(scratch)/case; root.mkdir(mode=0o700)
            environment=os.environ|{'OMG_NPM_ADVISORY_CASE':case,'OMG_NPM_ADVISORY_ROOT':str(root)}
            for key in list(environment):
                if key.startswith('SUDO_') or key.startswith('OMG_TOOL_'): environment.pop(key)
            def mutate():
                if case=='lock-change':
                    locks=list((root/'tools/npm').glob('.*.staging-*/package-lock.json'))
                    assert len(locks)==1
                    value=json.loads(locks[0].read_text()); value['review_change']=True
                    locks[0].write_text(json.dumps(value))
                elif case=='runtime-change':
                    node=root/'versions/node/24.22.3/bin/node'
                    with node.open('a') as stream: stream.write('\n# changed during review\n')
                elif case=='manager-library-change':
                    imported=root/'versions/node/24.22.3/lib/node_modules/npm/imported.js'
                    imported.write_text('module.exports = 2;\n')
                elif case=='manager-metadata-change':
                    metadata=root/'versions/node/24.22.3/lib/node_modules/npm/package.json'
                    metadata.write_text('{"version":"11.16.0"}')
            code,transcript=terminal.terminal_case(unit,case,environment,expected=(b'fixture-tool',b'1.0.0',b'CVE-2021-23337',b'https://www.cve.org/CVERecord?id=CVE-2021-23337'),before_answer=mutate)
            accepted=case in ('accept','scripts-permitted')
            phases=(root/'managers/phases').read_text().splitlines()
            assert b'--yes' in transcript or case!='no-tty', transcript.decode(errors='replace')
            if case in ('interrupt','terminate','hangup'):
                assert code==-{'interrupt':signal.SIGINT,'terminate':signal.SIGTERM,'hangup':signal.SIGHUP}[case], (case,code,transcript.decode(errors='replace'))
                assert phases==['install']
            else:
                assert code==0 and b'test result: ok. 1 passed; 0 failed; 0 ignored;' in transcript, transcript.decode(errors='replace')
                values=re.findall(MARKER+rb'(\{[^\r\n]*\})',transcript)
                assert len(values)==1
                result=json.loads(values[0]); assert result['case']==case and result['installed']==accepted
            binary=root/'bin/fixture-tool'
            if accepted:
                assert binary.read_bytes()==b'#!/bin/sh\necho accepted-version\n'
                receipt=json.loads((root/'tools/npm/fixture-tool/.omg-npm-advisory-review.json').read_text())
                assert receipt['risk_accepted'] and receipt['assessments'][0]['findings'][0]['id']=='CVE-2021-23337'
                assert phases==['install','ci','audit']+(['rebuild'] if case=='scripts-permitted' else [])
            else:
                assert binary.read_bytes()==b'previous tool'
                assert phases==(['install','ci','audit'] if case=='signature-reject' else ['install'])
            assert not any(value in transcript for value in (b'LLVM Profile Error',b'LLVM Profile Warning',b'[omg-skip]',b'skipped:'))
            records.append(dict(case=case,exit_code=code,installed=accepted,phases=phases))
    assert len(records)==(1 if args.case else len(CASES))
    print(json.dumps(dict(scope='real PTY and actual npm transaction owner with simulated registry manager and source; not live publisher/runtime acceptance',passed=len(records),unit_sha256=terminal.sha(unit),cases=records)))

if __name__=='__main__': main()
