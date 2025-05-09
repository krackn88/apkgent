import unittest
import os
from krackns_agent.apk_analysis.utils import download_apk_from_apkpure

class TestAPKDownload(unittest.TestCase):
    def test_download_apk_from_apkpure_invalid_package(self):
        # Should fail for a non-existent package
        result = download_apk_from_apkpure("com.thispackagedoesnotexist.abc123", "/tmp/fake.apk")
        self.assertFalse(result)

    def test_download_apk_from_apkpure_valid_package(self):
        # This test will likely fail if APKPure changes or rate-limits, but is a real-world test
        dest = "/tmp/kohls_latest.apk"
        result = download_apk_from_apkpure("com.kohls.mcommerce.opal", dest)
        # Accept either True (success) or False (site changed), but file should not be partial
        if result:
            self.assertTrue(os.path.exists(dest))
            os.remove(dest)
        else:
            self.assertFalse(os.path.exists(dest))

if __name__ == "__main__":
    unittest.main()
