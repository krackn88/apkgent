import requests
import re

APK_MIRRORS = [
    "apkpure",
    "apkcombo"
]

def download_apk_from_apkpure(package_name: str, dest_path: str) -> bool:
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("apkpure_download")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "https://apkpure.com/"
        }
        url = f"https://apkpure.com/search?q={package_name}"
        resp = requests.get(url, timeout=10, headers=headers)
        logger.debug(f"Search URL: {url}, Status: {resp.status_code}")
        if resp.status_code != 200:
            logger.error(f"Failed to fetch search page: {resp.status_code}")
            return False
        logger.debug(f"Search page content: {resp.text[:1000]}")
        match = re.search(r'/[a-z0-9\-]+/([a-zA-Z0-9\.]+)', resp.text)
        if not match:
            logger.error("No app path found in search page.")
            return False
        app_path = match.group(0)
        app_url = f"https://apkpure.com{app_path}"
        app_resp = requests.get(app_url, timeout=10, headers=headers)
        logger.debug(f"App URL: {app_url}, Status: {app_resp.status_code}")
        if app_resp.status_code != 200:
            logger.error(f"Failed to fetch app page: {app_resp.status_code}")
            return False
        logger.debug(f"App page content: {app_resp.text[:1000]}")
        match = re.search(r'href="(https://d.apkpure.com/[^\"]+\.apk)"', app_resp.text)
        if not match:
            logger.error("No APK download link found in app page.")
            return False
        apk_url = match.group(1)
        logger.debug(f"APK download URL: {apk_url}")
        apk_resp = requests.get(apk_url, stream=True, timeout=30, headers=headers)
        logger.debug(f"APK download status: {apk_resp.status_code}")
        if apk_resp.status_code == 200:
            with open(dest_path, 'wb') as f:
                for chunk in apk_resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            logger.info(f"APK downloaded to {dest_path}")
            return True
        logger.error(f"Failed to download APK: {apk_resp.status_code}")
        return False
    except Exception as e:
        logger.exception(f"Error downloading APK: {e}")
        return False

def download_apk_from_apkcombo(package_name: str, dest_path: str) -> bool:
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("apkcombo_download")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "https://apkcombo.com/"
        }
        url = f"https://apkcombo.com/en/apk-downloader/?device=&arch=arm64-v8a&android=all&dpi=nodpi&package={package_name}"
        resp = requests.get(url, timeout=10, headers=headers)
        logger.debug(f"APKCombo URL: {url}, Status: {resp.status_code}")
        if resp.status_code != 200:
            logger.error(f"Failed to fetch APKCombo page: {resp.status_code}")
            return False
        logger.debug(f"APKCombo page content: {resp.text[:1000]}")
        match = re.search(r'href=\"(https://download.apkcombo.com/[^\"]+\.apk)\"', resp.text)
        if not match:
            logger.error("No APK download link found in APKCombo page.")
            return False
        apk_url = match.group(1)
        logger.debug(f"APK download URL: {apk_url}")
        apk_resp = requests.get(apk_url, stream=True, timeout=30, headers=headers)
        logger.debug(f"APK download status: {apk_resp.status_code}")
        if apk_resp.status_code == 200:
            with open(dest_path, 'wb') as f:
                for chunk in apk_resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            logger.info(f"APK downloaded to {dest_path}")
            return True
        logger.error(f"Failed to download APK: {apk_resp.status_code}")
        return False
    except Exception as e:
        logger.exception(f"Error downloading APK from apkcombo: {e}")
        return False

def download_apk_from_uptodown(package_name: str, dest_path: str) -> bool:
    import logging
    import time
    from bs4 import BeautifulSoup
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("uptodown_download")
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "https://uptodown.com/"
        }
        # Step 1: Search for the app
        search_url = f"https://en.uptodown.com/android/search/{package_name}"
        resp = requests.get(search_url, headers=headers, timeout=10)
        logger.debug(f"Uptodown search URL: {search_url}, Status: {resp.status_code}")
        if resp.status_code != 200:
            logger.error(f"Failed to fetch search page: {resp.status_code}")
            return False
        soup = BeautifulSoup(resp.text, "html.parser")
        app_link = None
        for a in soup.find_all('a', href=True):
            if f"/{package_name}" in a['href']:
                app_link = a['href']
                break
        if not app_link:
            logger.error("No app link found in Uptodown search page.")
            return False
        app_url = f"https://en.uptodown.com{app_link}"
        logger.debug(f"App URL: {app_url}")
        # Step 2: Go to the app page and find the download button
        app_resp = requests.get(app_url, headers=headers, timeout=10)
        if app_resp.status_code != 200:
            logger.error(f"Failed to fetch app page: {app_resp.status_code}")
            return False
        soup = BeautifulSoup(app_resp.text, "html.parser")
        download_btn = soup.find('a', {"class": "download"})
        if not download_btn or not download_btn.get('href'):
            logger.error("No download button found on Uptodown app page.")
            return False
        download_url = download_btn['href']
        if not download_url.startswith('http'):
            download_url = f"https://en.uptodown.com{download_url}"
        logger.debug(f"Download URL: {download_url}")
        # Step 3: Download the APK
        time.sleep(2)  # Be polite to the server
        apk_resp = requests.get(download_url, stream=True, headers=headers, timeout=30)
        logger.debug(f"APK download status: {apk_resp.status_code}")
        if apk_resp.status_code == 200:
            with open(dest_path, 'wb') as f:
                for chunk in apk_resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            logger.info(f"APK downloaded to {dest_path}")
            return True
        logger.error(f"Failed to download APK: {apk_resp.status_code}")
        return False
    except Exception as e:
        logger.exception(f"Error downloading APK from Uptodown: {e}")
        return False

def download_apk(package_name: str, dest_path: str, mirror: str = "apkcombo") -> bool:
    """
    Download the latest APK for the given package from the specified mirror.
    Returns True if successful, False otherwise.
    """
    if mirror == "apkcombo":
        return download_apk_from_apkcombo(package_name, dest_path)
    elif mirror == "apkpure":
        return download_apk_from_apkpure(package_name, dest_path)
    elif mirror == "uptodown":
        return download_apk_from_uptodown(package_name, dest_path)
    else:
        return False
