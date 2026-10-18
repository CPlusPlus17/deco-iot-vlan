"""Offline alpha boundary tests; no stock firmware, network or device is used.

Can run here before copying, or from persistence/tests/ in the public tree.
Bundle fixtures exercise registry/checksum validation only: they are explicitly
synthetic and are never a reconstructed or deployable firmware payload.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE=Path(__file__).resolve()
CANDIDATES=(HERE.parents[1],HERE.parents[1]/'alpha-repo/persistence')
PACKAGE=next((p for p in CANDIDATES if (p/'tools/build_alpha.py').is_file()),None)
if PACKAGE is None:
    raise RuntimeError('Place this test under persistence/tests, or beside alpha-repo in alpha-tests')
sys.path.insert(0,str(PACKAGE/'tools'))
import build_alpha as build
import validate_alpha as validate


def json_bytes(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode('utf-8')


def hashes(body):
    return {'bytes':len(body),'sha1':hashlib.sha1(body).hexdigest(),
        'sha256':hashlib.sha256(body).hexdigest()}


class ExactPatchTests(unittest.TestCase):
    relative='lib/example.sh'
    original=b'zero\none\ntwo\nthree\nfour\nfive\nsix'
    delta=(b'--- a/lib/example.sh\n+++ b/lib/example.sh\n'
        b'@@ -1,3 +1,3 @@\n zero\n-one\n+ONE\n two\n'
        b'@@ -3,0 +4 @@\n+inserted\n'
        b'@@ -6,2 +7,2 @@\n five\n-six\n\\ No newline at end of file\n'
        b'+SIX\n\\ No newline at end of file\n')

    def test_multiple_hunks_insertion_and_missing_final_newline(self):
        self.assertEqual(build.apply_exact_patch(self.original,self.delta,self.relative),
            b'zero\nONE\ntwo\ninserted\nthree\nfour\nfive\nSIX')
        self.assertEqual(self.original,b'zero\none\ntwo\nthree\nfour\nfive\nsix')

    def test_empty_input_and_deleting_unterminated_last_line(self):
        insert=b'--- a/lib/example.sh\n+++ b/lib/example.sh\n@@ -0,0 +1,2 @@\n+one\n+two\n'
        self.assertEqual(build.apply_exact_patch(b'',insert,self.relative),b'one\ntwo\n')
        remove=(b'--- a/lib/example.sh\n+++ b/lib/example.sh\n@@ -1,2 +1 @@\n'
            b' alpha\n-omega\n\\ No newline at end of file\n')
        self.assertEqual(build.apply_exact_patch(b'alpha\nomega',remove,self.relative),b'alpha\n')

    def test_wrong_context_counts_offsets_and_headers_are_refused(self):
        bad={
            'context':self.delta.replace(b'-one\n',b'-wrong\n',1),
            'old_count':self.delta.replace(b'@@ -1,3 +1,3 @@',b'@@ -1,4 +1,3 @@',1),
            'new_count':self.delta.replace(b'@@ -1,3 +1,3 @@',b'@@ -1,3 +1,4 @@',1),
            'old_offset':self.delta.replace(b'@@ -1,3 +1,3 @@',b'@@ -99,3 +1,3 @@',1),
            'new_offset':self.delta.replace(b'@@ -1,3 +1,3 @@',b'@@ -1,3 +2,3 @@',1),
            'wrong_old_header':self.delta.replace(b'--- a/lib/example.sh',b'--- a/lib/other.sh',1),
            'wrong_new_header':self.delta.replace(b'+++ b/lib/example.sh',b'+++ b/../example.sh',1),
            'malformed_hunk':self.delta.replace(b'@@ -1,3 +1,3 @@',b'@@ malformed @@',1),
            'malformed_line':self.delta.replace(b' zero\n',b'?zero\n',1),
        }
        for name,delta in bad.items():
            with self.subTest(name=name),self.assertRaises(ValueError):
                build.apply_exact_patch(self.original,delta,self.relative)

    def test_matching_context_at_a_different_offset_is_not_searched(self):
        with self.assertRaises(ValueError):
            build.apply_exact_patch(b'extra\n'+self.original,self.delta,self.relative)
        overlap=self.delta+b'@@ -1 +1 @@\n-zero\n+again\n'
        with self.assertRaises(ValueError):build.apply_exact_patch(self.original,overlap,self.relative)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='alpha-profile-test-')
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'profile.json'
        # Reserved benchmarking network; no address is contacted.
        self.valid=dict(schema=1,main_device_id='A'*40,bedroom_device_id='B'*40,
            cellar_device_id='C'*40,gateway_ipv4='198.18.0.1',example_only=False)

    def values(self,value,**options):
        self.path.write_bytes(json_bytes(value))
        return build.profile_values(self.path,**options)

    def test_explicit_distinct_profile_and_fictional_example_opt_in(self):
        self.assertEqual(self.values(self.valid),self.valid)
        example=json.loads((PACKAGE/'profile.example.json').read_bytes())
        with self.assertRaises(ValueError):self.values(example)
        self.assertEqual(self.values(example,allow_example=True),example)
        example['example_only']=False
        with self.assertRaises(ValueError):self.values(example,allow_example=True)

    def test_missing_wrong_duplicate_and_injectable_ids_are_refused(self):
        cases=[]
        for value in('A'*39,'a'*40,'0'*40,'A'*39+';',17,None):
            cases.append({**self.valid,'main_device_id':value})
        cases.append({**self.valid,'cellar_device_id':self.valid['main_device_id']})
        cases.append({k:v for k,v in self.valid.items()if k!='bedroom_device_id'})
        for index,value in enumerate(cases):
            with self.subTest(case=index),self.assertRaises(ValueError):self.values(value)

    def test_extra_fields_schema_and_gateway_are_refused(self):
        for changed in({'password':'fixture-not-a-secret'},{'unknown':'value'},{'schema':True},
                {'schema':2},{'example_only':'true'}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):self.values({**self.valid,**changed})
        for gateway in('0.0.0.0','127.0.0.1','224.0.0.1','255.255.255.255',
                '198.018.0.1','198.18.0.1;command','::1',None):
            with self.subTest(gateway=gateway),self.assertRaises(ValueError):
                self.values({**self.valid,'gateway_ipv4':gateway})


class ExactByteEditTests(unittest.TestCase):
    relative='www/webpages/locale/en_US/fixture.js'

    def delta(self,edits,**changes):
        value=dict(schema=1,kind='deco_exact_stock_byte_edits',path=self.relative,edits=edits)
        value.update(changes);return json_bytes(value)

    def apply(self,original,edits,**changes):
        return build.apply_exact_byte_edits(original,self.delta(edits,**changes),self.relative)

    def test_original_byte_offsets_with_unicode_insert_delete_and_eof(self):
        # These are original byte offsets, not Unicode indexes or cumulative
        # offsets after earlier edits. In particular, replacing a two-byte
        # character must not shift the later delete, insert and EOF positions.
        original=b'A\xc3\xa9BC\nTAIL'
        edits=[dict(offset=1,remove_bytes=2,insert_text='ø'),
            dict(offset=4,remove_bytes=1,insert_text=''),
            dict(offset=6,remove_bytes=0,insert_text='prefix:'),
            dict(offset=10,remove_bytes=0,insert_text='\nnew')]
        self.assertEqual(self.apply(original,edits),b'A\xc3\xb8B\nprefix:TAIL\nnew')
        self.assertEqual(self.apply(b'',[dict(offset=0,remove_bytes=0,insert_text='α')]),'α'.encode())
        self.assertEqual(self.apply(b'old',[dict(offset=0,remove_bytes=3,insert_text='')]),b'')

    def test_path_schema_and_exact_field_sets_are_required(self):
        edit=dict(offset=0,remove_bytes=1,insert_text='new')
        for changed in(dict(path='www/other.js'),dict(schema=True),dict(schema=2),
                dict(kind='unified_exact_v1'),dict(extra='unexpected')):
            with self.subTest(changed=changed),self.assertRaises(ValueError):self.apply(b'x',[edit],**changed)
        with self.assertRaises(ValueError):self.apply(b'x',[])
        with self.assertRaises(ValueError):
            self.apply(b'x',[{**edit,'unexpected':'field'}])
        with self.assertRaises(ValueError):
            build.apply_exact_byte_edits(b'x',b'{malformed',self.relative)

    def test_order_overlap_bounds_noop_and_types_are_refused(self):
        insert=lambda offset:dict(offset=offset,remove_bytes=0,insert_text='x')
        cases={
            'descending':[insert(3),insert(1)],
            'same_offset':[insert(1),insert(1)],
            'overlap':[dict(offset=1,remove_bytes=3,insert_text='x'),insert(2)],
            'negative_offset':[insert(-1)],
            'past_eof':[insert(5)],
            'remove_past_eof':[dict(offset=3,remove_bytes=2,insert_text='x')],
            'negative_remove':[dict(offset=0,remove_bytes=-1,insert_text='x')],
            'bool_offset':[insert(True)],
            'bool_remove':[dict(offset=0,remove_bytes=True,insert_text='x')],
            'float_offset':[insert(1.0)],
            'non_string_insert':[dict(offset=0,remove_bytes=0,insert_text=7)],
            'nul_insert':[dict(offset=0,remove_bytes=0,insert_text='x\0y')],
            'noop':[dict(offset=0,remove_bytes=0,insert_text='')],
        }
        for name,edits in cases.items():
            with self.subTest(name=name),self.assertRaises(ValueError):self.apply(b'abcd',edits)

    def test_edit_count_and_result_byte_caps(self):
        edits=[dict(offset=i,remove_bytes=0,insert_text='x')for i in range(128)]
        self.assertEqual(self.apply(b'.'*128,edits),b'x.'*128)
        with self.assertRaises(ValueError):self.apply(b'.'*128,edits+[dict(offset=128,remove_bytes=0,insert_text='x')])
        self.assertEqual(len(self.apply(b'',[dict(offset=0,remove_bytes=0,insert_text='x'*131072)])),131072)
        with self.assertRaises(ValueError):self.apply(b'',[dict(offset=0,remove_bytes=0,insert_text='x'*131073)])
        with self.assertRaises(ValueError):self.apply(b'.'*131072,[dict(offset=131072,remove_bytes=0,insert_text='x')])


class PublicSourceLayoutTests(unittest.TestCase):
    def test_actual_public_sources_are_complete_without_stock_inputs(self):
        inventory,payload=build.sources()
        self.assertEqual(len(payload),50)
        self.assertEqual(sum(n.startswith('runtime35/')for n in payload),35)
        self.assertEqual(sum(n.startswith('ui14/')for n in payload),14)
        self.assertIn('ui-patch-plan.json',payload)
        self.assertIs(inventory['diagnostic_trace_included'],False)
        self.assertIs(inventory['installation_authority_included'],False)
        for name,row in inventory['files'].items():
            with self.subTest(name=name):
                if row['storage']=='exact_stock_patch':
                    self.assertIsNone(payload[name])
                    self.assertTrue((PACKAGE/row['patch_path']).is_file())
                    self.assertFalse((PACKAGE/name).exists())
                else:self.assertEqual(hashes(payload[name]),row['template'])

    def test_unexpected_source_and_wrong_stock_bytes_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='alpha-layout-test-')as temporary:
            root=Path(temporary);copied=root/'inputs'
            shutil.copytree(PACKAGE,copied,ignore=shutil.ignore_patterns('dist','build','__pycache__'))
            (copied/'runtime35/unreviewed.lua').write_text('return {}\n',encoding='ascii')
            with patch.object(build,'ROOT',copied),self.assertRaises(ValueError):build.sources()
            (copied/'runtime35/unreviewed.lua').unlink()
            inventory=json.loads((PACKAGE/'source-inventory.json').read_bytes());stock=root/'wrong-stock'
            for row in inventory['files'].values():
                if row['storage']=='exact_stock_patch':
                    path=stock/row['stock_relative_path'];path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(b'deliberately wrong synthetic firmware input\n')
            with self.assertRaises(ValueError):build.sources(stock)

    def test_unknown_or_missing_patch_format_has_no_fallback(self):
        with tempfile.TemporaryDirectory(prefix='alpha-format-test-')as temporary:
            copied=Path(temporary)/'inputs'
            shutil.copytree(PACKAGE,copied,ignore=shutil.ignore_patterns('dist','build','__pycache__'))
            path=copied/'source-inventory.json';inventory=json.loads(path.read_bytes())
            row=inventory['files']['ui14/assets/www/webpages/locale/en_US/lan.js']
            for marker in('unknown',None):
                if marker is None:row.pop('patch_format',None)
                else:row['patch_format']=marker
                path.write_bytes(json_bytes(inventory))
                with patch.object(build,'ROOT',copied),self.assertRaises(ValueError):build.sources()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='alpha-bundle-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)/'bundle';self.directory.mkdir()
        inventory=json.loads((PACKAGE/'source-inventory.json').read_bytes())
        # Complete checksum/registry fixture only. No vendor code is reconstructed.
        self.payload={name:('synthetic non-deployable fixture: '+name+'\n').encode('ascii')
            for name in inventory['files']}
        self.payload['NOTICE']=(PACKAGE/'NOTICE').read_bytes()
        for path in(PACKAGE/'LICENSES').rglob('*'):
            if path.is_file():self.payload[path.relative_to(PACKAGE).as_posix()]=path.read_bytes()
        self.manifest=dict(schema=1,kind='deco_iot_vlan_alpha_source_bundle',source_only=True,
            installer_included=False,live_result_claimed=False,runtime_files=35,main_ui_files=14,
            example_only=True,files={name:hashes(body)for name,body in self.payload.items()})
        for name,body in self.payload.items():
            path=self.directory/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
        self.seal()

    def seal(self):
        raw=json_bytes(self.manifest);(self.directory/'manifest.json').write_bytes(raw)
        sums={name:row['sha256']for name,row in self.manifest['files'].items()}
        sums['manifest.json']=hashlib.sha256(raw).hexdigest()
        (self.directory/'SHA256SUMS').write_text(''.join(sums[n]+'  '+n+'\n'for n in sorted(sums)),encoding='ascii')

    def test_complete_checksum_fixture_is_accepted_without_deployment_claim(self):
        result=validate.validate_bundle(self.directory)
        self.assertTrue(result['local_bundle_verified'])
        self.assertTrue(result['example_only']);self.assertFalse(result['device_contact'])

    def test_empty_self_consistent_manifest_is_not_a_complete_bundle(self):
        for name in self.payload:(self.directory/name).unlink()
        self.manifest['files']={};self.seal()
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)

    def test_missing_runtime_cannot_be_hidden_by_resealing_manifest(self):
        name='runtime35/worker.lua';(self.directory/name).unlink()
        del self.manifest['files'][name];self.seal()
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)

    def test_tampered_bytes_and_checksum_list_are_refused(self):
        name='runtime35/worker.lua';target=self.directory/name;original=target.read_bytes()
        target.write_bytes(original+b'tampered\n')
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)
        target.write_bytes(original)
        with(self.directory/'SHA256SUMS').open('a',encoding='ascii')as output:output.write('unexpected\n')
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)

    def test_extra_file_and_symlink_substitution_are_refused(self):
        extra=self.directory/'unexpected.txt';extra.write_text('not registered\n',encoding='ascii')
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)
        extra.unlink();target=self.directory/'runtime35/worker.lua';body=target.read_bytes();target.unlink()
        outside=Path(self.temp.name)/'outside.lua';outside.write_bytes(body)
        try:target.symlink_to(outside)
        except(NotImplementedError,OSError):self.skipTest('Symlink creation is unavailable')
        with self.assertRaises(ValueError):validate.validate_bundle(self.directory)


if __name__=='__main__':unittest.main(verbosity=2)
