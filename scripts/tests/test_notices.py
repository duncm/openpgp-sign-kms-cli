import importlib.util
from pathlib import Path
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('notices',Path(__file__).resolve().parents[1]/'notices.py')
notices=importlib.util.module_from_spec(spec);spec.loader.exec_module(notices)
class Notices(unittest.TestCase):
    def test_spdx_named_files_inside_licenses_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=root/'crate';(package/'LICENSES').mkdir(parents=True)
            (package/'LICENSES/MIT.txt').write_text('MIT license contents')
            (package/'LICENSES/Apache-2.0.txt').write_text('Apache license contents')
            metadata={'packages':[{'name':'crate','version':'1','manifest_path':str(package/'Cargo.toml'),'license':'MIT OR Apache-2.0'}]}
            text=notices.collect(metadata,root/'project')
            self.assertIn('MIT license contents',text)
            self.assertIn('Apache license contents',text)
if __name__=='__main__':unittest.main()
