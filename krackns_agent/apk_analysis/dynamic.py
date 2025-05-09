import frida
import sys
import os
import requests

def run_frida_script(package_name: str, script_path: str, device_id: str = None) -> str:
    """
    Run a Frida script against the given package on a connected device/emulator.
    Returns the script output or error message.
    """
    try:
        device = frida.get_usb_device() if not device_id else frida.get_device(device_id)
        pid = device.spawn([package_name])
        session = device.attach(pid)
        with open(script_path) as f:
            script = session.create_script(f.read())
        output = []
        def on_message(message, data):
            if message['type'] == 'send':
                output.append(message['payload'])
            elif message['type'] == 'error':
                output.append(str(message['stack']))
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        # Wait for script to finish or timeout
        import time
        time.sleep(10)
        session.detach()
        return '\n'.join(output) if output else 'No output from Frida script.'
    except Exception as e:
        return f"Frida error: {e}"

def mobsf_dynamic_analysis(apk_path, mobsf_url="http://localhost:8000", api_key="YOUR_API_KEY"):
    """
    Upload APK to MobSF and trigger dynamic analysis (stub).
    """
    try:
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f)}
            headers = {'Authorization': api_key}
            r = requests.post(f"{mobsf_url}/api/v1/upload", files=files, headers=headers)
            scan_res = r.json()
            scan_hash = scan_res.get('hash')
            # Start dynamic analysis (stub, MobSF needs emulator setup)
            r = requests.post(f"{mobsf_url}/api/v1/dynamic/start", data={'hash': scan_hash}, headers=headers)
            return r.json()
    except Exception as e:
        return {"error": str(e)}
