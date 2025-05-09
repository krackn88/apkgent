import os
import zipfile
import json
import requests
import re
import jsbeautifier

def extract_apk(apk_path: str, extract_to: str) -> None:
    """Extracts the APK file to the specified directory."""
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def analyze_akamai_code(apk_directory: str) -> dict:
    """Analyzes Akamai-related code within the extracted APK directory."""
    akamai_data = {}
    
    # Example logic to analyze files for Akamai code
    for root, dirs, files in os.walk(apk_directory):
        for file in files:
            if file.endswith('.smali'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    if 'akamai' in content.lower():
                        akamai_data[file] = content
    
    return akamai_data

def send_analysis_report(chat_id: str, report: dict, bot_token: str) -> None:
    """Sends the analysis report to the specified Telegram chat."""
    message = json.dumps(report, indent=2)
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    requests.post(url, json=payload)

def load_apk_from_telegram(file_path: str, chat_id: str, bot_token: str) -> None:
    """Loads an APK file sent via Telegram and analyzes it."""
    extract_to = '/tmp/apk_analysis'  # Temporary directory for extraction
    os.makedirs(extract_to, exist_ok=True)
    
    extract_apk(file_path, extract_to)
    akamai_report = analyze_akamai_code(extract_to)
    
    send_analysis_report(chat_id, akamai_report, bot_token)

def extract_akamai_js(apk_path: str) -> dict:
    """
    Extract and deobfuscate Akamai/NuData JavaScript code from an APK.
    Returns a dict with findings and deobfuscated code samples.
    """
    findings = []
    js_samples = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk:
            for file in apk.namelist():
                if file.endswith('.js') or file.endswith('.html') or 'webview' in file.lower():
                    with apk.open(file) as f:
                        content = f.read().decode(errors='ignore')
                        # Look for Akamai/NuData patterns
                        if re.search(r'akamai|abck|sensor_data|_abck|nucaptcha|nudata', content, re.I):
                            beautified = jsbeautifier.beautify(content)
                            findings.append(f"Found Akamai/NuData code in {file}")
                            js_samples.append({'file': file, 'code': beautified[:2000]})
    except Exception as e:
        findings.append(f"Error extracting JS: {e}")
    return {'findings': findings, 'samples': js_samples}