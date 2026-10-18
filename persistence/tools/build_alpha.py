#!/usr/bin/env python3
"""Build a deterministic local source bundle. No device access or installation."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path,PurePosixPath
import re

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.1.0-alpha'
TOKENS={'main_device_id':b'@MAIN_DEVICE_ID@','bedroom_device_id':b'@BEDROOM_DEVICE_ID@',
    'cellar_device_id':b'@CELLAR_DEVICE_ID@','gateway_ipv4':b'@GATEWAY_IPV4@'}


def descriptor(body):
    return dict(bytes=len(body),sha1=hashlib.sha1(body).hexdigest(),sha256=hashlib.sha256(body).hexdigest())


def encoded(value,*,sort_keys=True):
    return (json.dumps(value,sort_keys=sort_keys,indent=2,ensure_ascii=False)+'\n').encode('utf-8')


def safe_name(name):
    p=PurePosixPath(name)
    if not isinstance(name,str)or p.is_absolute()or '..'in p.parts or str(p)!=name:
        raise ValueError('Unsafe package-relative path')
    return p


def read(path):
    if path.is_symlink()or not path.is_file():raise ValueError('Regular source file required: '+path.name)
    body=path.read_bytes()
    if len(body)>1048576:raise ValueError('Source input exceeds fixed local bound')
    return body


def apply_exact_patch(original,delta,relative):
    """Apply unified hunks at their exact offsets; no search, fuzz or commands."""
    lines=[]
    for line in delta.splitlines(keepends=True):
        if line==b'\\ No newline at end of file\n':
            if not lines or not lines[-1].endswith(b'\n'):raise ValueError('Malformed final-line marker')
            lines[-1]=lines[-1][:-1]
        else:lines.append(line)
    if lines[:2]!=[('--- a/'+relative+'\n').encode(),('+++ b/'+relative+'\n').encode()]:
        raise ValueError('Fixed stock patch headers differ')
    old=original.splitlines(keepends=True);result=[];cursor=0;at=2
    while at<len(lines):
        header=re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[at])
        if header is None:raise ValueError('Fixed unified hunk required')
        first,count,newfirst,newcount=(int(v)if v is not None else 1 for v in header.groups())
        start=first-1 if count else first
        if not cursor<=start<=len(old):raise ValueError('Overlapping or out-of-range patch hunk')
        result.extend(old[cursor:start]);cursor=start;at+=1;removed=added=0
        if len(result)!=(newfirst-1 if newcount else newfirst):raise ValueError('New hunk offset differs')
        while at<len(lines)and not lines[at].startswith(b'@@ '):
            line=lines[at];at+=1
            if not line or line[:1]not in(b' ',b'-',b'+'):raise ValueError('Malformed patch content')
            tag,content=line[:1],line[1:]
            if tag in(b' ',b'-'):
                if cursor>=len(old)or old[cursor]!=content:raise ValueError('Exact stock hunk context differs')
                cursor+=1;removed+=1
            if tag in(b' ',b'+'):result.append(content);added+=1
        if (removed,added)!=(count,newcount):raise ValueError('Unified hunk counts differ')
    result.extend(old[cursor:]);return b''.join(result)


def apply_exact_byte_edits(original,delta,relative):
    """Exact original-byte offsets; inserted text only, never a stock-line copy."""
    value=json.loads(delta)
    if (type(value)is not dict or set(value)!={'schema','kind','path','edits'}
            or type(value['schema'])is not int or value['schema']!=1
            or value['kind']!='deco_exact_stock_byte_edits'or value['path']!=relative
            or type(value['edits'])is not list or not 1<=len(value['edits'])<=128):
        raise ValueError('Exact stock byte-edit schema/path required')
    result=[];cursor=0;previous=-1;inserted=removed=0
    for edit in value['edits']:
        if type(edit)is not dict or set(edit)!={'offset','remove_bytes','insert_text'}:
            raise ValueError('Exact byte-edit fields required')
        offset,count,text=edit['offset'],edit['remove_bytes'],edit['insert_text']
        if (type(offset)is not int or type(count)is not int or type(text)is not str
                or not cursor<=offset<=len(original)or offset<=previous or not 0<=count<=len(original)-offset
                or '\0'in text or count==0 and text==''):
            raise ValueError('Bounded ordered nonoverlapping byte edits required')
        body=text.encode('utf-8');inserted+=len(body);removed+=count
        if inserted>131072:raise ValueError('Byte-edit insertion bound exceeded')
        result.extend((original[cursor:offset],body));cursor=offset+count;previous=offset
    if len(original)-removed+inserted>131072:raise ValueError('Byte-edit result bound exceeded')
    result.append(original[cursor:]);return b''.join(result)


def sources(stock_rootfs=None):
    inventory=json.loads(read(ROOT/'source-inventory.json'));rows=inventory['files'];payload={}
    if inventory.get('schema')!=1 or inventory.get('runtime_files')!=35 or inventory.get('main_ui_files')!=14:
        raise ValueError('Fixed alpha35/UI14 source inventory required')
    folders=('runtime35','ui14','vendor-patches')
    actual={p.relative_to(ROOT).as_posix()for folder in folders for p in(ROOT/folder).rglob('*')if p.is_file()}
    wanted={row['source_path']if row['storage']=='source'else row['patch_path']for row in rows.values()}
    wanted.discard('ui-patch-plan.json')
    if actual!=wanted or len(rows)!=50 or any((ROOT/folder).is_symlink()for folder in folders)or any(p.is_symlink()for folder in folders for p in(ROOT/folder).rglob('*')):
        raise ValueError('Unexpected or missing runtime/UI source file')
    for name,row in rows.items():
        safe_name(name)
        if row['storage']=='source':
            safe_name(row['source_path']);body=read(ROOT/row['source_path'])
        elif row['storage']=='exact_stock_patch':
            safe_name(row['patch_path']);safe_name(row['stock_relative_path']);delta=read(ROOT/row['patch_path'])
            if descriptor(delta)!=row['patch']:raise ValueError('Vendor patch checksum changed: '+name)
            if row.get('patch_format')not in('unified_exact_v1','exact_byte_edits_v1'):
                raise ValueError('Unknown exact stock patch format')
            if stock_rootfs is None:payload[name]=None;continue
            stock_path=stock_rootfs/row['stock_relative_path']
            if not stock_path.resolve().is_relative_to(stock_rootfs.resolve()):raise ValueError('Stock input escapes supplied rootfs')
            original=read(stock_path)
            if descriptor(original)!=row['stock']:raise ValueError('Wrong exact stock firmware input: '+row['stock_relative_path'])
            if row['patch_format']=='unified_exact_v1':body=apply_exact_patch(original,delta,row['stock_relative_path'])
            elif row['patch_format']=='exact_byte_edits_v1':body=apply_exact_byte_edits(original,delta,row['stock_relative_path'])
            else:raise ValueError('Unknown exact stock patch format')
        else:raise ValueError('Unknown source storage method')
        if descriptor(body)!=row['template']:raise ValueError('Source template checksum changed: '+name)
        if b'\0'in body or body.startswith((b'\x7fELF',b'\x1bLua')):raise ValueError('Compiled binaries are excluded')
        if set(re.findall(rb'@[A-Z_]+@',body))-set(TOKENS.values()):raise ValueError('Unknown template substitution')
        for token,count in row['profile_tokens'].items():
            if body.count(token.encode('ascii'))!=count:raise ValueError('Profile substitution count changed')
        payload[name]=body
    names=re.findall(rb'"([^"]+)"',re.search(rb'local FILES=\{(.*?)\}',payload['runtime35/runtime_install.lua'],re.S)[1])
    if len(names)!=35 or {'runtime35/'+n.decode('ascii')for n in names}!={n for n in payload if n.startswith('runtime35/')}:
        raise ValueError('Runtime installer35 dependency set differs')
    expected={'runtime35/kernel_platform.lua':'520d9eac39545fb82e40ce78ec9da23da077ac60980c64b8e6ab24b5e667cb78',
        'runtime35/worker.lua':'1b39d5e5d31c5947b531654b970fea8629e2c7712777abd2e8fd2ae793fc840c',
        'runtime35/patches/guest-eth.sh':'7f13f2d741183d0d67e050b2e12869ebbe495c179ba936a846c6dd7eac2b9b1c',
        'runtime35/native_hooks.sh':'55665808767910eabbaa2f4e5d646d6f49fb8af37be9f8bace95dafafb5f5606'}
    if any(rows[n]['verified_source']['sha256']!=digest for n,digest in expected.items()):
        raise ValueError('Wrong production runtime version or diagnostic guest hooks')
    if any(b'deco_iot_guest_trace'in b for n,b in payload.items()if n.startswith('runtime35/')and b is not None):
        raise ValueError('Diagnostic tracing is excluded from the production alpha')
    return inventory,payload


def profile_values(path,*,allow_example=False):
    value=json.loads(read(path));required={'schema',*TOKENS};allowed=required|{'example_only'}
    if type(value)is not dict or set(value)-allowed or not required<=set(value)or type(value['schema'])is not int or value['schema']!=1:
        raise ValueError('Exact profile schema1 and four explicit values required')
    ids=[value[k]for k in TOKENS if k.endswith('_id')]
    if any(type(v)is not str or re.fullmatch('[0-9A-F]{40}',v)is None or int(v,16)==0 for v in ids)or len(set(ids))!=3:
        raise ValueError('Three distinct uppercase40-hex device IDs required')
    if type(value['gateway_ipv4'])is not str:raise ValueError('Explicit IPv4 gateway required')
    address=ipaddress.IPv4Address(value['gateway_ipv4'])
    if str(address)!=value['gateway_ipv4']or address.is_multicast or address.is_unspecified or address.is_loopback or int(address)==4294967295:
        raise ValueError('Canonical unicast IPv4 gateway required')
    example=value.get('example_only',False)
    if type(example)is not bool:raise ValueError('Typed example_only marker required')
    documentation=any(address in ipaddress.IPv4Network(n)for n in('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'))
    fixture_ids=set(ids)=={str(i).zfill(40)for i in(1,2,3)}
    if (example or documentation or fixture_ids)and not(allow_example and example):
        raise ValueError('Fictional example profile requires example_only:true and --allow-example')
    return value


def render(profile,stock_rootfs):
    inventory,templates=sources(stock_rootfs);payload={}
    for name,body in templates.items():
        for key,token in TOKENS.items():body=body.replace(token,profile[key].encode('ascii'))
        if re.search(rb'@[A-Z_]+@',body):raise ValueError('Unresolved profile substitution')
        payload[name]=body
    # Recompute dependent UI checksums after the MAIN/device substitutions.
    # Preserve formatting. Native35 can reproduce the private reviewed bytes;
    # public UI labels/migration policy intentionally differ from that baseline.
    plan=json.loads(payload['ui-patch-plan.json'])
    if encoded(plan,sort_keys=False)!=payload['ui-patch-plan.json']:raise ValueError('Reviewed UI plan formatting changed')
    for row in plan['files']:
        body=payload['ui14/assets/'+row['path']];row.update(bytes=len(body),patched_sha256=descriptor(body)['sha256'])
    payload['ui-patch-plan.json']=encoded(plan,sort_keys=False)
    plan_hash=descriptor(payload['ui-patch-plan.json'])['sha256']
    boot=json.loads(payload['ui14/ui-boot-manifest.json'])
    for name,row in boot['assets'].items():row.update(descriptor(payload['ui14/assets/'+name]))
    old_hash=boot['package_manifest_sha256'];boot['package_manifest_sha256']=plan_hash
    payload['ui14/ui-boot-manifest.json']=encoded(boot)
    module=payload['ui14/ui_boot_install.lua']
    if module.count(old_hash.encode('ascii'))!=1:raise ValueError('Exact UI bootstrap package hash binding required')
    payload['ui14/ui_boot_install.lua']=module.replace(old_hash.encode('ascii'),plan_hash.encode('ascii'),1)
    matches={name:descriptor(body)==inventory['files'][name]['verified_source']for name,body in payload.items()}
    return inventory,payload,matches


def build(profile_path,output,stock_rootfs,*,allow_example=False,require_reference=False):
    profile=profile_values(profile_path,allow_example=allow_example)
    if not stock_rootfs.is_dir():raise ValueError('Owner-provided exact stock rootfs directory required')
    inventory,payload,matches=render(profile,stock_rootfs)
    runtime_match=all(ok for n,ok in matches.items()if n.startswith('runtime35/'))
    if require_reference and not runtime_match:
        raise ValueError('Profile does not reproduce exact reviewed runtime35 bytes: '+','.join(n for n,ok in matches.items()if n.startswith('runtime35/')and not ok))
    output=Path(output)
    if output.is_symlink()or output.exists()and any(output.iterdir()):raise ValueError('Output must be a new or empty directory')
    if any(output.resolve().is_relative_to((ROOT/name).resolve())for name in('runtime35','ui14','tools')):
        raise ValueError('Output cannot overwrite source inputs')
    for name in('NOTICE',):payload[name]=read(ROOT/name)
    for path in sorted((ROOT/'LICENSES').rglob('*')):
        if path.is_file():payload[path.relative_to(ROOT).as_posix()]=read(path)
    output.mkdir(parents=True,exist_ok=True)
    for name,body in payload.items():
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
    manifest=dict(schema=1,kind='deco_iot_vlan_alpha_source_bundle',version=VERSION,source_only=True,
        experimental=True,installer_included=False,installation_metadata_included=False,
        device_contact=False,live_result_claimed=False,diagnostic_trace_included=False,
        runtime_files=35,main_ui_files=14,native_bindings=9,main_ui_parent_mounts=7,
        fixed_vlan_id=30,wired_port=2,cpu_port=6,native_iot_enable_required='0',
        example_only=profile.get('example_only',False),profile_sha256=descriptor(encoded(profile))['sha256'],
        source_inventory_sha256=descriptor(read(ROOT/'source-inventory.json'))['sha256'],
        private_reference_runtime35_reproduced=runtime_match,public_ui_differs_from_deployed_baseline=True,
        files={n:descriptor(b)for n,b in sorted(payload.items())})
    raw=encoded(manifest);(output/'manifest.json').write_bytes(raw)
    sums={n:descriptor(b)['sha256']for n,b in payload.items()};sums['manifest.json']=descriptor(raw)['sha256']
    (output/'SHA256SUMS').write_text(''.join(sums[n]+'  '+n+'\n'for n in sorted(sums)),encoding='ascii')
    return dict(built=True,version=VERSION,runtime_files=35,main_ui_files=14,example_only=manifest['example_only'],
        private_reference_runtime35_reproduced=runtime_match,device_contact=False,manifest_sha256=descriptor(raw)['sha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--stock-rootfs',type=Path,required=True,help='Owner-provided exact extracted supported firmware; never copied wholesale')
    parser.add_argument('--allow-example',action='store_true');parser.add_argument('--require-reference-match',action='store_true')
    args=parser.parse_args();print(json.dumps(build(args.profile,args.output,args.stock_rootfs,allow_example=args.allow_example,require_reference=args.require_reference_match)))


if __name__=='__main__':
    try:main()
    except(ValueError,OSError,KeyError,TypeError)as error:raise SystemExit('Source build refused: '+str(error))
