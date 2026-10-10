"""U2 isolation substrate: confinement invariants and fail-closed behavior."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import isolation
from isolation import EgressPolicy, SandboxSpec, IsolationUnavailable


def _spec(**changes):
    base = dict(image='lab/target:web', command=('serve',), scratch_dir='/tmp/scratch',
                network='lab-oob-1', egress=EgressPolicy(sink=('sink', 9000)))
    base.update(changes)
    return SandboxSpec(**base)


class IsolationTests(unittest.TestCase):
    def test_network_is_internal(self):
        argv = isolation.build_network_argv('lab-oob-1')
        self.assertIn('--internal', argv)
        self.assertEqual(argv[-1], 'lab-oob-1')

    def test_run_argv_carries_confinement(self):
        argv = isolation.build_run_argv(_spec())
        self.assertTrue(isolation.validate_run_argv(argv))
        for flag in ('--read-only', '--cap-drop', 'no-new-privileges', '--network', '--user'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('--user') + 1], isolation.NOBODY)
        self.assertNotIn('--privileged', argv)

    def test_validate_rejects_root_user(self):
        argv = isolation.build_run_argv(_spec(user='0:0'))
        with self.assertRaises(IsolationUnavailable):
            isolation.validate_run_argv(argv)

    def test_validate_rejects_host_network_privileged_and_socket(self):
        for bad in (['docker', 'run', '--user', '65534:65534', '--read-only', '--cap-drop',
                     'ALL', '--security-opt', 'no-new-privileges', '--network', 'host', 'img'],
                    ['docker', 'run', '--user', '65534:65534', '--read-only', '--cap-drop',
                     'ALL', '--security-opt', 'no-new-privileges', '--network', 'n',
                     '--privileged', 'img'],
                    ['docker', 'run', '--user', '65534:65534', '--read-only', '--cap-drop',
                     'ALL', '--security-opt', 'no-new-privileges', '--network', 'n',
                     '-v', '/var/run/docker.sock:/var/run/docker.sock', 'img']):
            with self.subTest(argv=bad), self.assertRaises(IsolationUnavailable):
                isolation.validate_run_argv(bad)

    def test_egress_policy_allows_sink_and_scope_denies_others(self):
        policy = EgressPolicy(sink=('sink', 9000), scope=(('target', 8080),))
        self.assertTrue(policy.check('sink', 9000))
        self.assertTrue(policy.check('target', 8080))
        self.assertFalse(policy.check('evil.example', 80))

    def test_build_run_argv_requires_sink(self):
        with self.assertRaises(IsolationUnavailable):
            isolation.build_run_argv(_spec(egress=EgressPolicy(sink=None)))

    def test_require_isolation_fails_closed_without_backend(self):
        with patch('isolation.docker_available', return_value=False):
            with self.assertRaises(IsolationUnavailable):
                isolation.require_isolation()
        with patch('isolation.docker_available', return_value=True):
            self.assertTrue(isolation.require_isolation())


if __name__ == '__main__':
    unittest.main()
