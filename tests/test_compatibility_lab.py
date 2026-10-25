"""Safety boundaries for the local lab runner; never invoke Docker or network."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE = Path(__file__).resolve().parents[1] / 'scripts/run_compatibility_lab.py'
spec = importlib.util.spec_from_file_location('compatibility_lab', MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LaboratorySafetyTests(unittest.TestCase):
    def test_only_launch_sandbox_failure_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            lab.write_json(root/'browser-failure.json',{'phase':'launch','code':'chromium_sandbox_unavailable'})
            self.assertEqual(lab.browser_failure(root)['status'],'BLOCKED')

    def test_functional_browser_failure_remains_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            lab.write_json(root/'browser-failure.json',{'phase':'checkout_submit','code':'browser_operation_failed'})
            self.assertEqual(lab.browser_failure(root)['status'],'FAIL')

    def test_browser_failure_cannot_publish_extra_or_free_text_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for value in ({'phase':'launch','code':'failed','extra':'private-diagnostic'},
                          {'phase':'checkout_fields','code':'free text with sensitive data'},
                          {'phase':'unknown_phase','code':'browser_operation_failed'},
                          {'phase':'checkout_fields','code':'secret_like_lowercase_code'},
                          {'phase':['launch'],'code':'browser_operation_failed'}):
                lab.write_json(root/'browser-failure.json',value)
                with self.assertRaises(RuntimeError): lab.browser_failure(root)

    def test_local_http_rejects_external_initial_urls(self):
        for value in ('https://127.0.0.1:18981/','http://example.invalid/',
                      'http://127.0.0.1:80/','http://user@127.0.0.1:18981/',
                      'file:///etc/passwd'):
            with self.subTest(value=value),self.assertRaises(ValueError):lab.local_url(value)
        self.assertEqual(lab.local_url('http://127.0.0.1:18981/?page_id=1'),'http://127.0.0.1:18981/?page_id=1')

    def test_local_http_ignores_proxy_environment(self):
        with patch.dict(os.environ,{'HTTP_PROXY':'http://example.invalid:9999','NO_PROXY':''}):
            opener=lab.local_client()
        self.assertTrue(all(getattr(handler,'proxies',{})=={} for handler in opener.handlers))

    def test_state_parent_cannot_place_secrets_in_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(lab,'ROOT',root):
                with self.assertRaises(ValueError): lab.state_parent(root/'private-runtime')
            self.assertFalse((root/'private-runtime').exists())

    def test_relative_state_parent_rejected(self):
        with self.assertRaises(ValueError): lab.state_parent(Path('relative-state'))

    def test_archive_traversal_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, name in enumerate(('../escaped', '/absolute', 'foo\\escape')):
                archive = root / f'{index}.zip'
                with zipfile.ZipFile(archive, 'w') as package:
                    package.writestr(name, 'test')
                with self.assertRaises(ValueError): lab.unpack(archive, root/'target')
            archive = root/'link.zip'
            with zipfile.ZipFile(archive, 'w') as package:
                entry = zipfile.ZipInfo('link')
                entry.create_system = 3
                entry.external_attr = 0o120777 << 16
                package.writestr(entry, '../outside')
            with self.assertRaises(ValueError): lab.unpack(archive, root/'target')
            self.assertFalse((root/'escaped').exists())

    def test_regular_archive_extracts_only_to_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with zipfile.ZipFile(root/'ok.zip','w') as package: package.writestr('folder/file.txt','safe')
            lab.unpack(root/'ok.zip',root/'target')
            self.assertEqual((root/'target/folder/file.txt').read_text(),'safe')

    def test_private_directory_rejects_public_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            lab.regular_private_directory(root)
            (root/'link').symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError): lab.regular_private_directory(root/'link')
            root.chmod(0o755)
            with self.assertRaises(ValueError): lab.regular_private_directory(root)

    def state(self, root):
        (root/'build').mkdir()
        (root/'tools').mkdir()
        (root/'compose.yaml').write_text('services: {}\n')
        (root/'build/Dockerfile').write_text('FROM placeholder\n')
        (root/'tools/package-lock.json').write_text('{}')
        (root/'tools/executable.cjs').write_text('module.exports=1;')
        info={'project':'menyona-compat-0123456789ab','source_hashes':lab.sources(),
              'lock':lab.LOCK,'material_hashes':lab.material(root),'chromium_sha256':'test-digest',
              'npm_lock_sha256':lab.hashlib.sha256((root/'tools/package-lock.json').read_bytes()).hexdigest()}
        lab.write_json(root/'state.json',info)
        return info

    def test_changed_copied_compose_or_tool_rejected_before_execution(self):
        for name in ('compose.yaml','build/Dockerfile','tools/executable.cjs'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); self.state(root)
                with patch.object(lab,'chromium_hash',return_value='test-digest'), patch.object(lab,'command') as execute:
                    lab.load_state(root)
                    (root/name).write_text('changed')
                    with self.assertRaises(ValueError): lab.load_state(root)
                    execute.assert_not_called()

    def test_material_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.state(root)
            (root/'tools/external').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): lab.material(root)

    def test_build_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.state(root)
            (root/'build').rename(root/'outside-build')
            (root/'build').symlink_to(root/'outside-build',target_is_directory=True)
            with self.assertRaises(ValueError): lab.material(root)

    def test_tools_root_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.state(root)
            (root/'tools').rename(root/'outside-tools')
            (root/'tools').symlink_to(root/'outside-tools',target_is_directory=True)
            with self.assertRaises(ValueError): lab.material(root)

    def test_equivalent_state_path_has_same_canonical_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.state(root)
            (root/'inner').mkdir()
            canonical=lab.regular_private_directory(root)
            alias=lab.regular_private_directory(root/'inner/..')
            self.assertEqual(canonical,alias)
            self.assertEqual(lab.hashlib.sha256(str(canonical).encode()).hexdigest(),
                             lab.hashlib.sha256(str(alias).encode()).hexdigest())

    def test_stop_can_load_changed_source_but_run_cannot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.state(root)
            with patch.object(lab,'sources',return_value={'changed':'source'}):
                with self.assertRaises(ValueError): lab.load_state(root)
                self.assertEqual(lab.load_state(root,verify_sources=False)[1]['project'],'menyona-compat-0123456789ab')

    def test_stop_uses_fixed_ids_and_labels_without_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); info=self.state(root)
            with patch.object(lab,'command',side_effect=['0123456789ab\n','']) as execute:
                lab.stop_state(root,info)
            calls=[call.args[0] for call in execute.call_args_list]
            self.assertIn('label=com.docker.compose.project='+info['project'],calls[0])
            self.assertEqual(calls[1],['docker','stop','--time','15','0123456789ab'])
            self.assertFalse(any('compose' in call for call in calls))

    def test_artifact_redirect_rejected_before_second_request(self):
        with self.assertRaises(ValueError): lab.NoRedirect().redirect_request(None,None,302,'redirect',{},'http://127.0.0.1/')


if __name__ == '__main__': unittest.main()
