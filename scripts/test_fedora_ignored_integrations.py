import configparser
import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('fedora_ignored', Path(__file__).with_name('run-fedora-ignored-integrations.py'))
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class FedoraIgnoredIntegrationTests(unittest.TestCase):
    def test_existing_libtest_artifact_keeps_dependency_feature_closure(self):
        manifest = dict(features=dict(fedora=['rusqlite'], pgp=['sequoia-openpgp'], license=[]),
                        dependencies={'rusqlite': {'optional': True}, 'sequoia-openpgp': {'optional': True}})
        features = SUBJECT.feature_closure(manifest, ['fedora', 'pgp', 'license'])
        self.assertEqual(features, {'fedora', 'pgp', 'license', 'rusqlite', 'sequoia-openpgp'})
        row = dict(reason='compiler-artifact', target=dict(name='omg_lib'), profile=dict(test=True),
                   executable='/work/target/debug/deps/omg_lib-1234', manifest_path='/work/Cargo.toml',
                   features=['fedora', 'license', 'pgp', 'rusqlite', 'sequoia-openpgp'])
        text = 'running tests\n'+json.dumps(row)+'\n'+json.dumps(dict(reason='build-finished', success=True))
        self.assertEqual(SUBJECT.select_libtest(text, Path('/work/Cargo.toml'), features)['executable'],
                         '/work/target/debug/deps/omg_lib-1234')
        for broken in (dict(row, features=['fedora', 'pgp', 'license']), dict(row, manifest_path='/foreign/Cargo.toml')):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                SUBJECT.select_libtest(json.dumps(broken)+'\n'+json.dumps(dict(reason='build-finished', success=True)), Path('/work/Cargo.toml'), features)
        with self.assertRaisesRegex(ValueError, 'one existing'):
            SUBJECT.select_libtest(text+'\n'+json.dumps(row), Path('/work/Cargo.toml'), features)
        with self.assertRaisesRegex(ValueError, 'build completion'):
            SUBJECT.select_libtest(json.dumps(row)+'\n'+json.dumps(dict(reason='build-finished', success=False)), Path('/work/Cargo.toml'), features)

    def test_exact_named_method_pass_rejects_zero_ignored_wrong_or_multiple_results(self):
        selector = 'package_managers::dnf::tests::native_removal_simulation_preserves_installed_inventory'
        summary = 'ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1700 filtered out; finished in 0.03s'
        intact = 'running 1 test\ntest '+selector+' ... ok\n\ntest result: '+summary+'\n'
        self.assertEqual(SUBJECT.require_exact_pass(selector, intact, 0), summary)
        cases = [(intact, 1), (intact.replace(selector, 'other::method'), 0),
                 (intact.replace('1 passed', '0 passed'), 0),
                 (intact.replace('0 ignored', '1 ignored'), 0),
                 (intact.replace('... ok', '... ignored'), 0), (intact+intact, 0)]
        for stdout, code in cases:
            with self.subTest(stdout=stdout, code=code), self.assertRaises(ValueError):
                SUBJECT.require_exact_pass(selector, stdout, code)

    def test_native_dnf_name_queries_preserve_literal_format_escape(self):
        cases = [
            (SUBJECT.explicit_inventory_args(),
             ['dnf', '--cacheonly', '--disable-repo=*', '--setopt=disable_excludes=*',
              'repoquery', '--userinstalled', '--qf', '%{name}\\n']),
            (SUBJECT.tree_dependents_args(),
             ['dnf', '--cacheonly', '--disable-repo=*', 'repoquery', '--installed',
              '--whatrequires', 'tree', '--qf', '%{name}\\n']),
        ]
        for actual, expected in cases:
            with self.subTest(query=actual):
                self.assertEqual(actual, expected)

    def test_fixture_config_is_private_and_keeps_native_signature_checks(self):
        config = SUBJECT.fixture_config(Path('/private/fixture'))
        self.assertIsInstance(config, configparser.ConfigParser)
        self.assertEqual(config['main']['reposdir'], '/private/fixture/repos')
        self.assertEqual(config['main']['cachedir'], '/private/fixture/cache')
        self.assertEqual(config['main']['system_cachedir'], '/private/fixture/cache')
        self.assertEqual(config['main']['persistdir'], '/private/fixture/persist')
        self.assertEqual(config['main']['logdir'], '/private/fixture/logs')
        for option in ('gpgcheck', 'repo_gpgcheck', 'localpkg_gpgcheck'):
            self.assertEqual(config['main'][option], '1')


if __name__ == '__main__':
    unittest.main()
