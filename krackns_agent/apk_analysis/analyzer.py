import subprocess
import os
import glob
import yara
from androguard.core.apk import APK
from .akamai_tools import extract_akamai_js
from telegram import Update
from telegram.ext import CallbackContext, MessageHandler, Filters

def load_apk_file(file_path: str) -> dict:
    """Load and parse the APK file using Androguard."""
    try:
        apk = APK(file_path)
        return {
            "status": "success",
            "package": apk.get_package(),
            "app_name": apk.get_app_name(),
            "permissions": apk.get_permissions(),
            "message": f"APK {apk.get_app_name()} ({apk.get_package()}) loaded."
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to load APK: {e}"}

def decompile_apk(file_path: str) -> str:
    """
    Decompile the APK file using JADX and return the output directory.
    """
    output_dir = file_path + "_jadx"
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run(["jadx", "-d", output_dir, file_path], check=True)
        return output_dir
    except Exception as e:
        return f"Decompilation failed: {e}"

def extract_resources(apk_path: str) -> list:
    """
    Extract resource file names from the APK using Androguard.
    """
    try:
        apk = APK(apk_path)
        return apk.get_files()
    except Exception:
        return []

def analyze_code(decompiled_dir: str) -> dict:
    """
    Analyze the decompiled code for Akamai/NuData patterns using YARA.
    """
    yara_rule = '''
    rule Akamai_JS {
        strings:
            $ak1 = "abck"
            $ak2 = "sensor_data"
            $ak3 = "akamai"
            $ak4 = "nucaptcha"
            $ak5 = "nudata"
        condition:
            any of them
    }
    '''
    try:
        rule = yara.compile(source=yara_rule)
    except Exception as e:
        return {"issues_found": 0, "details": f"YARA compile error: {e}"}
    findings = []
    for js_file in glob.glob(os.path.join(decompiled_dir, "**/*.js"), recursive=True):
        try:
            matches = rule.match(js_file)
            if matches:
                findings.append(f"Akamai/NuData pattern found in {js_file}")
        except Exception as e:
            findings.append(f"YARA scan error in {js_file}: {e}")
    return {"issues_found": len(findings), "details": "\n".join(findings) if findings else "No Akamai/NuData patterns found."}

def format_analysis_result(result: dict) -> str:
    """Format the APK analysis result for user-friendly output."""
    lines = []
    if 'load_result' in result:
        lines.append(f"📦 Load: {result['load_result'].get('message', '')}")
        if 'permissions' in result['load_result']:
            lines.append(f"🔑 Permissions: {', '.join(result['load_result']['permissions'])}")
    if 'resources' in result:
        lines.append(f"🗂️ Resources: {', '.join(result['resources'][:10])}{' ...' if len(result['resources']) > 10 else ''}")
    if 'analysis_result' in result:
        ar = result['analysis_result']
        lines.append(f"🔍 Issues Found: {ar.get('issues_found', 0)}")
        details = ar.get('details', '')
        if details:
            lines.append(f"Details: {details}")
    if 'akamai_js' in result and result['akamai_js']['findings']:
        lines.append("🛡️ Akamai/NuData JS Findings:")
        for finding in result['akamai_js']['findings']:
            lines.append(f"- {finding}")
        for sample in result['akamai_js']['samples']:
            lines.append(f"File: {sample['file']}")
            lines.append(f"Sample Code:\n{sample['code'][:500]}...\n")
    return '\n'.join(lines)

def analyze_apk(file_path: str) -> dict:
    """Main function to analyze the APK file."""
    load_result = load_apk_file(file_path)
    if load_result["status"] != "success":
        return load_result
    decompiled_dir = decompile_apk(file_path)
    resources = extract_resources(file_path)
    analysis_result = analyze_code(decompiled_dir) if os.path.isdir(decompiled_dir) else {"issues_found": 0, "details": decompiled_dir}
    akamai_js = extract_akamai_js(file_path)
    return {
        "load_result": load_result,
        "decompiled_dir": decompiled_dir,
        "resources": resources,
        "analysis_result": analysis_result,
        "akamai_js": akamai_js
    }

def debug_document(update: Update, context: CallbackContext) -> None:
    update.message.reply_text(f"Received document: {update.message.document.file_name} (MIME: {update.message.document.mime_type})")
dispatcher.add_handler(MessageHandler(Filters.document, debug_document))