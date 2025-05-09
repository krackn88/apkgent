import os
import logging
from telegram.ext import Updater
from telegram import ParseMode
from dotenv import load_dotenv
from .handlers import register_handlers

# Load environment variables from .env
load_dotenv()
TELEGRAM_TOKEN = os.getenv("BOT_TOKEN")
BOT_VERSION = "1.0.0"

if not TELEGRAM_TOKEN:
    print("❗ ERROR: BOT_TOKEN not set in .env file. Please add BOT_TOKEN=<your-telegram-bot-token> to .env and restart.")
    exit(1)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def main() -> None:
    updater = Updater(token=TELEGRAM_TOKEN, use_context=True)
    dispatcher = updater.dispatcher
    register_handlers(dispatcher)
    logger.info(f"Bot started. APK Agent v{BOT_VERSION} ready for demo!")
    print(f"🤖 APK Agent v{BOT_VERSION} started. Listening for messages...")
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()