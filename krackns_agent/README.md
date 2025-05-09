# Krackn's Agent

## Overview
Krackn's Agent is a programming assistant designed to help users analyze APK files, particularly focusing on Akamai code. The project integrates a Streamlit web application and a Telegram bot, allowing users to interact with the assistant through both platforms.

## Features
- **Streamlit Interface**: A user-friendly web application that provides an interactive environment for programming assistance, code analysis, and APK analysis.
- **Telegram Bot**: A bot that allows users to interact with the assistant via Telegram, including the ability to load APK files for analysis.
- **APK Analysis Tools**: Functions for decompiling APKs, extracting resources, and analyzing code, with specific tools for interpreting Akamai-related data.

## Project Structure
```
krackns_agent
├── streamlit-agent.py        # Main application for the programming assistant
├── telegram_bot              # Package for the Telegram bot
│   ├── __init__.py          # Initializes the Telegram bot package
│   ├── bot.py                # Main logic for the Telegram bot
│   ├── handlers.py           # Handlers for various Telegram bot commands
│   └── utils.py              # Utility functions for the bot
├── apk_analysis               # Package for APK analysis
│   ├── __init__.py          # Initializes the APK analysis package
│   ├── analyzer.py           # Logic for analyzing APK files
│   └── akamai_tools.py       # Tools for analyzing Akamai code
├── requirements.txt           # Project dependencies
└── README.md                  # Project documentation
```

## Installation
1. Clone the repository:
   ```
   git clone <repository-url>
   cd krackns_agent
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
### Streamlit Application
To run the Streamlit application, execute:
```
streamlit run streamlit-agent.py
```
This will start the web application, accessible at `http://localhost:8501`.

### Telegram Bot
To use the Telegram bot, run the following command:
```
python telegram_bot/bot.py
```
Make sure to configure your bot token in the `bot.py` file.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.