import unittest
import os
from krackns_agent.apk_analysis.utils import download_apk_from_apkcombo, download_apk_from_uptodown

class TestAPKDownload(unittest.TestCase):
    def test_download_apk_from_apkcombo_invalid_package(self):
        # Should fail for a non-existent package
        result = download_apk_from_apkcombo("com.thispackagedoesnotexist.abc123", "/tmp/fake.apk")
        self.assertFalse(result)

    def test_download_apk_from_apkcombo_valid_package(self):
        # This test will likely fail if apkcombo changes or rate-limits, but is a real-world test
        dest = "/tmp/kohls_latest.apk"
        result = download_apk_from_apkcombo("com.kohls.mcommerce.opal", dest)
        # Accept either True (success) or False (site changed), but file should not be partial
        if result:
            self.assertTrue(os.path.exists(dest))
            os.remove(dest)
        else:
            self.assertFalse(os.path.exists(dest))

class TestAPKDownloadUptodown(unittest.TestCase):
    def test_download_apk_from_uptodown_invalid_package(self):
        # Should fail for a non-existent package
        result = download_apk_from_uptodown("com.thispackagedoesnotexist.abc123", "/tmp/fake.apk")
        self.assertFalse(result)

    def test_download_apk_from_uptodown_valid_package(self):
        # This test will likely fail if Uptodown changes or rate-limits, but is a real-world test
        dest = "/tmp/kohls_latest.apk"
        result = download_apk_from_uptodown("com.kohls.mcommerce.opal", dest)
        # Accept either True (success) or False (site changed), but file should not be partial
        if result:
            self.assertTrue(os.path.exists(dest))
            os.remove(dest)
        else:
            self.assertFalse(os.path.exists(dest))

if __name__ == "__main__":
    unittest.main()
