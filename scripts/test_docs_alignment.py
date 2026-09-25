"""Tests for the documentation alignment checker.

The fixtures are minimal repositories. They prove the checker reports broken
references and stays quiet on valid ones; they say nothing about the real docs.
"""
import importlib.util
import io
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'docs_alignment', Path(__file__).with_name('check-docs-alignment.py'))
ALIGNMENT = importlib.util.module_from_spec(SPEC)
sys.modules['docs_alignment'] = ALIGNMENT
SPEC.loader.exec_module(ALIGNMENT)

ARGS_RS = textwrap.dedent('''
    pub enum Commands {
        /// Search for packages
        #[command(visible_alias = "s")]
        Search {
            /// Package name
            query: String,
            /// Maximum number of results
            #[arg(short, long, default_value = "15")]
            limit: usize,
        },
        /// Install packages
        Install {
            /// Package names
            #[arg(short = 'y', long)]
            yes: bool,
            /// Show what would happen
            #[arg(long)]
            dry_run: bool,
        },
        /// Explicit count
        #[command(name = "ec")]
        ExplicitCount,
        /// Environment management
        Env {
            #[command(subcommand)]
            command: EnvCommands,
        },
        /// Optional account
        Account {
            #[command(subcommand)]
            command: Option<AccountCommands>,
        },
    }

    pub enum EnvCommands {
        /// Capture state
        Capture,
        /// Share state
        Share {
            /// Make it public
            #[arg(long)]
            public: bool,
        },
    }

    pub enum AccountCommands {
        /// Link the machine
        Link {
            /// Read the token from stdin
            #[arg(long)]
            token_stdin: bool,
        },
    }
''').lstrip()


def build_repo(root, docs, args_rs=None, extras=None):
    """Create a minimal repository fixture and return its path."""
    repo = Path(root)
    (repo / 'src' / 'cli').mkdir(parents=True, exist_ok=True)
    (repo / 'src' / 'cli' / 'args.rs').write_text(args_rs or ARGS_RS, encoding='utf-8')
    (repo / 'docs').mkdir(parents=True, exist_ok=True)
    for name, body in docs.items():
        target = repo / 'docs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(body).lstrip('\n'), encoding='utf-8')
    for name, body in (extras or {}).items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding='utf-8')
    return repo


def run(repo, *extra):
    """Run the checker over a fixture and return (exit code, stdout + stderr)."""
    stream = io.StringIO()
    with redirect_stdout(stream), redirect_stderr(stream):
        code = ALIGNMENT.main([str(repo), *extra])
    return code, stream.getvalue()


class ParserTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.enums = ALIGNMENT.parse_enums(ARGS_RS.splitlines())

    def test_parses_nested_commands_and_option_lists(self):
        self.assertIn('env', self.enums['Commands'])
        self.assertIn('capture', self.enums['EnvCommands'])
        self.assertIn('link', self.enums['AccountCommands'])
        self.assertEqual(self.enums['Commands']['search'].sub_enum, None)
        self.assertIn('limit', self.enums['Commands']['search'].options)
        self.assertIn('l', self.enums['Commands']['search'].options)
        self.assertIn('dry-run', self.enums['Commands']['install'].options)
        self.assertIn('y', self.enums['Commands']['install'].options)

    def test_keeps_explicit_command_names(self):
        self.assertIn('ec', self.enums['Commands'])
        self.assertNotIn('explicit-count', self.enums['Commands'])

    def test_keeps_aliases(self):
        self.assertEqual(self.enums['Commands']['search'].aliases, ['s'])

    def test_optional_subcommand_enum_is_resolved(self):
        self.assertEqual(self.enums['Commands']['account'].sub_enum, 'AccountCommands')


class ScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def repo(self, docs, **kwargs):
        return build_repo(self._tmp.name, docs, **kwargs)

    def test_valid_references_pass(self):
        repo = self.repo({'good.md': '''
            # Good

            ```bash
            omg search ripgrep --limit 5
            omg s ripgrep -l 5
            omg env capture
            omg env share --public
            omg ec
            omg install --dry-run ripgrep
            omg --version
            ```
        '''})
        code, output = run(repo)
        self.assertEqual(code, 0, output)
        self.assertIn('ok', output)

    def test_unknown_command_word_fails(self):
        repo = self.repo({'bad.md': '```bash\nomg searc ripgrep\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 1)
        self.assertIn('unknown command word', output)

    def test_option_the_command_does_not_accept_fails(self):
        repo = self.repo({'bad.md': '```bash\nomg search ripgrep --dry-run\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 1)
        self.assertIn('not accepted by', output)

    def test_unknown_option_fails(self):
        repo = self.repo({'bad.md': '```bash\nomg search ripgrep --frobnicate\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 1)
        self.assertIn('unknown', output)

    def test_trailing_shell_comment_is_ignored(self):
        repo = self.repo({
            'ok.md': '```bash\nomg search ripgrep --limit 5   # the best five\nomg --help  # what exists\n```\n'
        })
        code, output = run(repo)
        self.assertEqual(code, 0, output)

    def test_options_after_a_bare_double_dash_are_ignored(self):
        repo = self.repo({'ok.md': '```bash\nomg search ripgrep -- --release\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 0, output)

    def test_documented_removal_is_allowed(self):
        repo = self.repo({'ok.md': '```bash\nomg license check\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 0, output)

    def test_nested_subcommand_is_checked(self):
        repo = self.repo({'bad.md': '```bash\nomg env frobnicate\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 1)
        self.assertIn('frobnicate', output)

    def test_placeholder_and_shell_syntax_end_the_command_path(self):
        repo = self.repo({'ok.md': '```bash\nomg install <package> | tee log\n```\n'})
        code, output = run(repo)
        self.assertEqual(code, 0, output)

    def test_changelog_is_skipped_and_working_plans_are_checked(self):
        repo = self.repo({
            'changelog.md': '```bash\nomg frobnicate\n```\n',
            'superpowers/plan.md': '```bash\nomg frobnicate\n```\n',
        })
        code, output = run(repo)
        self.assertEqual(code, 1, output)
        self.assertIn('docs/superpowers/plan.md', output)
        self.assertNotIn('changelog.md:', output)

    def test_missing_args_rs_is_an_error(self):
        repo = Path(self._tmp.name)
        (repo / 'docs').mkdir(parents=True, exist_ok=True)
        code, output = run(repo)
        self.assertEqual(code, 2)
        self.assertIn('args.rs not found', output)




class EnvironmentVariableTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def repo(self, docs, extras):
        return build_repo(self._tmp.name, docs, extras=extras)

    def test_known_variable_passes(self):
        repo = self.repo(
            {'ok.md': 'Use `OMG_NO_UPDATE_CHECK=1` here.\n'},
            {'install.sh': 'OMG_VERSION=latest\nOMG_NO_UPDATE_CHECK=${OMG_NO_UPDATE_CHECK:-}\n',
             'scripts/run-tests.sh': 'OMG_RUN_SYSTEM_TESTS=1\n'})
        code, output = run(repo)
        self.assertEqual(code, 0, output)

    def test_unknown_variable_fails(self):
        repo = self.repo({'bad.md': 'Set `OMG_INVENTED_FLAG=1` first.\n'}, {})
        code, output = run(repo)
        self.assertEqual(code, 1)
        self.assertIn('OMG_INVENTED_FLAG', output)

    def test_skip_environment_leaves_variables_alone(self):
        repo = self.repo({'bad.md': 'Set `OMG_INVENTED_FLAG=1` first.\n'}, {})
        code, output = run(repo, '--skip-environment')
        self.assertEqual(code, 0, output)


if __name__ == '__main__':
    unittest.main()
