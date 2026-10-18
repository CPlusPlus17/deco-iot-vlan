#!/usr/bin/env python3
"""Validate local source inputs or one generated bundle; never contacts a device."""
import argparse
import json
from pathlib import Path

import build_alpha as build


def validate_bundle(directory):
    raw=build.read(directory/'manifest.json');manifest=json.loads(raw);files=manifest['files']
    if (manifest.get('schema')!=1 or manifest.get('source_only')is not True
            or manifest.get('installer_included')is not False or manifest.get('live_result_claimed')is not False
            or manifest.get('runtime_files')!=35 or manifest.get('main_ui_files')!=14):
        raise ValueError('Fixed experimental source-only alpha manifest required')
    _,inputs=build.sources()
    required=set(inputs)|{'NOTICE'}|{p.relative_to(build.ROOT).as_posix()for p in(build.ROOT/'LICENSES').rglob('*')if p.is_file()}
    if type(files)is not dict or set(files)!=required:
        raise ValueError('Bundle must contain the exact runtime35/UI14/plan/notice registry')
    actual={p.relative_to(directory).as_posix()for p in directory.rglob('*')if p.is_file()}
    if any(p.is_symlink()for p in directory.rglob('*'))or actual!=set(files)|{'manifest.json','SHA256SUMS'}:
        raise ValueError('Unexpected bundle file or link')
    for name,descriptor in files.items():
        build.safe_name(name)
        if build.descriptor(build.read(directory/name))!=descriptor:raise ValueError('Bundle checksum changed: '+name)
    wanted={n:r['sha256']for n,r in files.items()};wanted['manifest.json']=build.descriptor(raw)['sha256']
    if (directory/'SHA256SUMS').read_text()!=''.join(wanted[n]+'  '+n+'\n'for n in sorted(wanted)):
        raise ValueError('Bundle checksum list differs')
    return dict(local_bundle_verified=True,runtime_files=35,main_ui_files=14,example_only=manifest['example_only'],device_contact=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',type=Path);args=parser.parse_args()
    if args.bundle:result=validate_bundle(args.bundle)
    else:
        inventory,payload=build.sources()
        result=dict(local_templates_verified=True,runtime_files=inventory['runtime_files'],main_ui_files=inventory['main_ui_files'],
            source_input_files=len(payload),deployment_validated=False,device_contact=False)
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except(ValueError,OSError,KeyError,TypeError)as error:raise SystemExit('Local validation refused: '+str(error))
