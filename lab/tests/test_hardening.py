"""Hardening checks for the lab's own code (U1)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from application_server import _append_jsonl


class AppendHardeningTests(unittest.TestCase):
    def test_append_writes_one_jsonl_line_each_call(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            _append_jsonl(path, {'a': 1})
            _append_jsonl(path, {'a': 2})
            values = [json.loads(line)['a'] for line in path.read_text().splitlines()]
            self.assertEqual(values, [1, 2])

    def test_append_refuses_pre_planted_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target.txt'
            target.write_text('')
            link = Path(directory) / 'audit.jsonl'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                _append_jsonl(link, {'a': 1})
            # The symlink target must not be written through.
            self.assertEqual(target.read_text(), '')


if __name__ == '__main__':
    unittest.main()
