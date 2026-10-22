import re,unittest
from pathlib import Path
EXPECTED=['sonroyaalmerol/docker-sogo:5.12.7@sha256:09dc69d5b9176864ea02efeef8178969aa549d108e05b39c58188b61809da616']
PINS=[['sonroyaalmerol/docker-sogo:5.12.7', '09dc69d5b9176864ea02efeef8178969aa549d108e05b39c58188b61809da616']]
def accept(ref,base,digest):
 if not re.fullmatch(r'[0-9a-f]{64}',digest) or ref!=base+'@sha256:'+digest:raise ValueError('unreviewed or mutable source reference')
class ImmutableRuntimeSource(unittest.TestCase):
 def test_actual_source_image_list(self):
  refs=re.findall(r'(?m)^\s*image:\s*["\']?([^"\'\s#]+)',(Path(__file__).parents[1]/'stack.runtime.yaml').read_text())
  self.assertEqual(EXPECTED,refs)
  for base,digest in PINS:accept(base+'@sha256:'+digest,base,digest)
 def test_floating_rejected(self):
  for base,digest in PINS:
   with self.subTest(base=base),self.assertRaises(ValueError):accept(base.rsplit(':',1)[0]+':latest',base,digest)
 def test_version_only_rejected(self):
  for base,digest in PINS:
   with self.subTest(base=base),self.assertRaises(ValueError):accept(base,base,digest)
 def test_malformed_digest_rejected(self):
  for base,digest in PINS:
   for bad in ['a'*63,'g'*64,'A'*64,'a'*65,'']:
    with self.subTest(base=base,bad=bad),self.assertRaises(ValueError):accept(base+'@sha256:'+bad,base,digest)
 def test_wrong_digest_rejected(self):
  for base,digest in PINS:
   with self.subTest(base=base),self.assertRaises(ValueError):accept(base+'@sha256:'+'0'*64,base,digest)
if __name__=='__main__':unittest.main()
