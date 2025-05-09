from telegram import Update, InputTextMessageContent, ParseMode
from telegram.ext import CommandHandler, MessageHandler, Filters, CallbackContext
import os
import logging
from krackns_agent.apk_analysis.utils import download_apk_from_apkpure

# Set up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a command handler for the /start command
def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text(
        "👋 Welcome to APK Agent!\n\n"
        "Send me an APK file or use these commands:\n"
        "• /apk <appname|package> [mirror] — Download & analyze any app\n"
        "• /dynamic <appname|package> <frida|mobsf> — Run dynamic analysis\n"
        "• /help — Show help info\n\n"
        "Try: /apk kohls or /dynamic kohls frida"
    )

# Define a command handler for the /help command
def help_command(update: Update, context: CallbackContext) -> None:
    update.message.reply_text(
        "ℹ️ *How to use APK Agent*\n\n"
        "• Send an APK file directly to analyze it.\n"
        "• /apk <appname|package> [mirror] — Download & analyze any app.\n"
        "• /dynamic <appname|package> <frida|mobsf> — Run dynamic analysis.\n\n"
        "_Example:_\n"
        "/apk kohls\n/dynamic kohls frida\n\n"
        "Supported mirrors: apkpure, apkcombo.\n"
        "Dynamic analysis requires a connected device/emulator for Frida, or MobSF running.\n\n"
        "*Commands:*\n"
        "• /start — Welcome message\n"
        "• /help — Show this help\n"
        "• /apk — Download & analyze APK\n"
        "• /dynamic — Run dynamic analysis\n"
        "• /getkohls — Quick demo with Kohl's app\n"
        , parse_mode=ParseMode.MARKDOWN)

def send_long_message(update, text, filename_prefix="analysis_result"):
    if len(text) < 4000:
        update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
    else:
        filename = f"{filename_prefix}.txt"
        with open(filename, "w") as f:
            f.write(text)
        with open(filename, "rb") as f:
            update.message.reply_document(f, filename=filename)
        os.remove(filename)

# Define a message handler for handling APK file uploads
def handle_apk_file(update: Update, context: CallbackContext) -> None:
    try:
        if update.message.document and update.message.document.mime_type == 'application/vnd.android.package-archive':
            file = update.message.document.get_file()
            file_path = os.path.join('apk_files', update.message.document.file_name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.download(file_path)
            update.message.reply_text(f"✅ APK '{update.message.document.file_name}' received. Analyzing...")
            from krackns_agent.apk_analysis.analyzer import analyze_apk, format_analysis_result
            result = analyze_apk(file_path)
            formatted = format_analysis_result(result)
            send_long_message(update, f"*Analysis result:*\n{formatted}", filename_prefix="analysis_result")
        else:
            update.message.reply_text("❗ Please send a valid APK file.")
    except Exception as e:
        update.message.reply_text(f"❗ Error during APK analysis: {e}")

def get_kohls(update: Update, context: CallbackContext) -> None:
    package_name = "com.kohls.mcommerce.opal"
    dest_path = os.path.join('apk_files', 'kohls_latest.apk')
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    update.message.reply_text("Downloading the latest Kohl's APK from APKPure...")
    success = download_apk_from_apkpure(package_name, dest_path)
    if success:
        update.message.reply_text("Kohl's APK downloaded and ready for analysis.")
        # Optionally, trigger analysis here
    else:
        update.message.reply_text("Failed to download Kohl's APK. Please try again later.")

def apk_command(update: Update, context: CallbackContext) -> None:
    """
    Usage: /apk <appname> [mirror]
    Example: /apk kohls apkpure
    """
    from krackns_agent.apk_analysis.utils import download_apk
    from krackns_agent.apk_analysis.analyzer import analyze_apk
    app_map = {
        "kohls": "com.kohls.mcommerce.opal",
        "bloomingdales": "com.bloomingdales.android.app",
        # Add more mappings as needed
    }
    args = context.args
    if not args:
        update.message.reply_text("Usage: /apk <appname> [mirror]. Example: /apk kohls apkpure")
        return
    appname = args[0].lower()
    mirror = args[1].lower() if len(args) > 1 else "apkpure"
    package_name = app_map.get(appname, appname if "." in appname else None)
    if not package_name:
        update.message.reply_text("Unknown app name. Use a known alias or provide a package name.")
        return
    dest_path = os.path.join('apk_files', f'{appname}_latest.apk')
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        update.message.reply_text(f"⬇️ Downloading {appname} APK from {mirror}...")
        success = download_apk(package_name, dest_path, mirror)
        if success:
            update.message.reply_text(f"✅ {appname} APK downloaded. Analyzing...")
            result = analyze_apk(dest_path)
            from krackns_agent.apk_analysis.analyzer import format_analysis_result
            formatted = format_analysis_result(result)
            send_long_message(update, f"*Analysis result:*\n{formatted}", filename_prefix=f"{appname}_analysis")
        else:
            update.message.reply_text(f"❗ Failed to download {appname} APK from {mirror}.")
    except Exception as e:
        update.message.reply_text(f"❗ Error during APK download/analysis: {e}")

def dynamic_command(update: Update, context: CallbackContext) -> None:
    """
    Usage: /dynamic <appname|package> <frida|mobsf>
    Example: /dynamic kohls frida
    """
    from krackns_agent.apk_analysis.utils import download_apk
    from krackns_agent.apk_analysis.dynamic import run_frida_script, mobsf_dynamic_analysis
    app_map = {
        "kohls": "com.kohls.mcommerce.opal",
        "bloomingdales": "com.bloomingdales.android.app",
        # Add more mappings as needed
    }
    args = context.args
    if len(args) < 2:
        update.message.reply_text("Usage: /dynamic <appname|package> <frida|mobsf>")
        return
    appname = args[0].lower()
    method = args[1].lower()
    package_name = app_map.get(appname, appname if "." in appname else None)
    if not package_name:
        update.message.reply_text("Unknown app name. Use a known alias or provide a package name.")
        return
    dest_path = os.path.join('apk_files', f'{appname}_latest.apk')
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    try:
        update.message.reply_text(f"⬇️ Downloading {appname} APK for dynamic analysis...")
        success = download_apk(package_name, dest_path)
        if not success:
            update.message.reply_text(f"❗ Failed to download {appname} APK.")
            return
        if method == "frida":
            script_path = os.path.join(os.path.dirname(__file__), "frida_script.js")
            update.message.reply_text(f"⚡ Running Frida script on {package_name}... (device/emulator required)")
            try:
                result = run_frida_script(package_name, script_path)
                send_long_message(update, f"*Frida result:*\n{result}", filename_prefix=f"{appname}_frida")
            except Exception as e:
                update.message.reply_text(f"❗ Frida error: {e}\nEnsure a device/emulator is connected and Frida server is running.")
        elif method == "mobsf":
            update.message.reply_text(f"⚡ Running MobSF dynamic analysis...")
            try:
                result = mobsf_dynamic_analysis(dest_path)
                send_long_message(update, f"*MobSF result:*\n{str(result)}", filename_prefix=f"{appname}_mobsf")
            except Exception as e:
                update.message.reply_text(f"❗ MobSF error: {e}\nEnsure MobSF is running and API key is set.")
        else:
            update.message.reply_text("❗ Unknown dynamic analysis method. Use 'frida' or 'mobsf'.")
    except Exception as e:
        update.message.reply_text(f"❗ Error during dynamic analysis: {e}")

# Define a function to register handlers
def register_handlers(dispatcher):
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("help", help_command))
    dispatcher.add_handler(CommandHandler("getkohls", get_kohls))
    dispatcher.add_handler(CommandHandler("apk", apk_command))
    dispatcher.add_handler(CommandHandler("dynamic", dynamic_command))
    dispatcher.add_handler(MessageHandler(Filters.document.mime_type("application/vnd.android.package-archive"), handle_apk_file))