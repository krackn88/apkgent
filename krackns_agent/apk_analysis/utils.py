import requests
import re

APK_MIRRORS = [
    "apkpure",
    "apkcombo"
]

def download_apk_from_apkpure(package_name: str, dest_path: str) -> bool:
    """
    Download the latest APK for the given package from APKPure.
    Returns True if successful, False otherwise.
    """
    try:
        url = f"https://apkpure.com/search?q={package_name}"
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return False
        match = re.search(r'/[a-z0-9\-]+/([a-zA-Z0-9\.]+)', resp.text)
        if not match:
            return False
        app_path = match.group(0)
        app_url = f"https://apkpure.com{app_path}"
        app_resp = requests.get(app_url, timeout=10)
        if app_resp.status_code != 200:
            return False
        match = re.search(r'href="(https://d.apkpure.com/[^\"]+\.apk)"', app_resp.text)
        if not match:
            return False
        apk_url = match.group(1)
        apk_resp = requests.get(apk_url, stream=True, timeout=30)
        if apk_resp.status_code == 200:
            with open(dest_path, 'wb') as f:
                for chunk in apk_resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return True
        return False
    except Exception as e:
        print(f"Error downloading APK: {e}")
        return False

def download_apk(package_name: str, dest_path: str, mirror: str = "apkpure") -> bool:
    """
    Download the latest APK for the given package from the specified mirror.
    Returns True if successful, False otherwise.
    """
    if mirror == "apkpure":
        return download_apk_from_apkpure(package_name, dest_path)
    elif mirror == "apkcombo":
        try:
            url = f"https://apkcombo.com/en/apk-downloader/?device=&arch=arm64-v8a&android=all&dpi=nodpi&package={package_name}"
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return False
            match = re.search(r'href=\"(https://download.apkcombo.com/[^\"]+\.apk)\"', resp.text)
            if not match:
                return False
            apk_url = match.group(1)
            apk_resp = requests.get(apk_url, stream=True, timeout=30)
            if apk_resp.status_code == 200:
                with open(dest_path, 'wb') as f:
                    for chunk in apk_resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                return True
            return False
        except Exception as e:
            print(f"Error downloading APK from apkcombo: {e}")
            return False
    else:
        return False
