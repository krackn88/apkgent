import os
import sys
import logging
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../krackns_agent')))
from apk_analysis.utils import download_apk

def handle_apk_fetch_task(task):
    package_name = task.get('package_name')
    dest_dir = task.get('dest_dir', '../../mcp_workspace/artifacts')
    mirror = task.get('mirror', 'apkcombo')
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, f"{package_name}.apk")
    logging.info(f"[MCP Agent] Fetching APK for {package_name} from {mirror}...")
    success = download_apk(package_name, dest_path, mirror)
    if success:
        logging.info(f"[MCP Agent] APK for {package_name} downloaded to {dest_path}")
        return {"status": "success", "apk_path": dest_path}
    else:
        logging.error(f"[MCP Agent] Failed to download APK for {package_name} from {mirror}")
        return {"status": "error", "reason": f"Failed to download from {mirror}"}

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    # Example: simulate receiving a task from MCP
    if len(sys.argv) > 1:
        task = json.loads(sys.argv[1])
    else:
        task = {"package_name": "com.kohls.mcommerce.opal", "mirror": "uptodown"}
    result = handle_apk_fetch_task(task)
    print(json.dumps(result, indent=2))
