import os
import sys
import logging
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../krackns_agent')))
from apk_analysis.analyzer import analyze_apk, format_analysis_result
from apk_analysis.dynamic import run_frida_script, mobsf_dynamic_analysis

def handle_apk_analysis_task(task):
    apk_path = task.get('apk_path')
    dest_dir = task.get('dest_dir', '../../mcp_workspace/artifacts')
    os.makedirs(dest_dir, exist_ok=True)
    log_path = os.path.join('../../mcp_workspace/logs/', 'apk_analysis_agent.log')
    logging.basicConfig(filename=log_path, level=logging.INFO)
    if not apk_path or not os.path.exists(apk_path):
        logging.error(f"APK path not found: {apk_path}")
        return {"status": "error", "reason": "APK path not found"}
    # Static analysis
    logging.info(f"[MCP Agent] Analyzing APK: {apk_path}")
    result = analyze_apk(apk_path)
    formatted = format_analysis_result(result)
    result_file = os.path.join(dest_dir, os.path.basename(apk_path) + '.analysis.txt')
    with open(result_file, 'w') as f:
        f.write(formatted)
    # Dynamic analysis (optional, can be extended)
    dynamic_results = {}
    if task.get('dynamic') == 'frida':
        package_name = task.get('package_name')
        script_path = task.get('frida_script', '../../krackns_agent/telegram_bot/frida_script.js')
        dynamic_results['frida'] = run_frida_script(package_name, script_path)
    elif task.get('dynamic') == 'mobsf':
        dynamic_results['mobsf'] = mobsf_dynamic_analysis(apk_path)
    # Save dynamic results if any
    if dynamic_results:
        dyn_file = os.path.join(dest_dir, os.path.basename(apk_path) + '.dynamic.json')
        with open(dyn_file, 'w') as f:
            json.dump(dynamic_results, f, indent=2)
    logging.info(f"[MCP Agent] Analysis complete for {apk_path}")
    return {"status": "success", "static_result": result_file, "dynamic_result": dynamic_results}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1:
        task = json.loads(sys.argv[1])
    else:
        # Example: analyze a previously fetched APK
        task = {"apk_path": "../../mcp_workspace/artifacts/com.kohls.mcommerce.opal.apk", "dynamic": None}
    result = handle_apk_analysis_task(task)
    print(json.dumps(result, indent=2))
