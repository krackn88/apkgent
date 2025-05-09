import os
import logging
from telegram import Update, Bot
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from telegram.helpers import escape_markdown
from krackns_agent.apk_analysis.analyzer import analyze_apk
from krackns_agent.apk_analysis.akamai_tools import analyze_akamai_code

# Configure logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the Telegram bot token
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")

# Initialize the bot
bot = Bot(token=TELEGRAM_TOKEN)

def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text("Welcome to the APK Analysis Bot! Send me an APK file to analyze.")

def handle_document(update: Update, context: CallbackContext) -> None:
    file = update.message.document.get_file()
    file.download('uploaded_apk.apk')
    update.message.reply_text("APK file received! Analyzing...")

    # Analyze the APK file
    analysis_result = analyze_apk('uploaded_apk.apk')
    akamai_result = analyze_akamai_code('uploaded_apk.apk')

    # Send the analysis results back to the user
    update.message.reply_text(f"APK Analysis Result:\n{escape_markdown(analysis_result)}", parse_mode='MarkdownV2')
    update.message.reply_text(f"Akamai Code Analysis Result:\n{escape_markdown(akamai_result)}", parse_mode='MarkdownV2')

def main() -> None:
    updater = Updater(token=TELEGRAM_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(MessageHandler(Filters.document.mime_type("application/vnd.android.package-archive"), handle_document))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()