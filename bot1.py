import httpx
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler

# Bot owner info
OWNER_INFO = "Bot Owner: Mr.Bhavani\nContact: bhavanidharan@example.com"

# Tokens
TELEGRAM_BOT_TOKEN = "7867502594:AAET8WqIC0mwsRKqD5F4O6JHQn0ydWRrIWs"
VT_API_KEY = "d8bd27ef91737552d6ec9e2bdfad3ca53652c78bc1ba15378e2d34859770a5d1"

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
CLIENT_TIMEOUT = httpx.Timeout(None)


# /start command with buttons
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔎 Scan URL", callback_data="scan")],
        [InlineKeyboardButton("ℹ️ Info", callback_data="info"),
         InlineKeyboardButton("📋 Menu", callback_data="menu")],
        [InlineKeyboardButton("🏠 Home", callback_data="home"),
         InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "👋 Welcome! I am your VirusTotal Scanner Bot.\nChoose an option below:",
        reply_markup=reply_markup,
    )


# Handle button presses
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "help":
        await query.edit_message_text(
            "Here are the commands:\n"
            "/start - Greet\n"
            "/scan <url> - Scan a URL\n"
            "/info - Bot info\n"
            "/menu - Show menu\n"
            "/home - Home menu"
        )

    elif query.data == "home":
        await query.edit_message_text("🏠 Home Menu:\nSend /scan <url> to scan.")

    elif query.data == "info":
        await query.edit_message_text(
            f"🤖 VirusTotal Scanner Bot v1.0\n{OWNER_INFO}\nThis bot scans URLs using VirusTotal."
        )

    elif query.data == "menu":
        await query.edit_message_text(
            "📋 Menu:\n"
            "- Scan URL\n"
            "- Info\n"
            "- Help\n"
            "- Home"
        )

    elif query.data == "scan":
        await query.edit_message_text("✍️ Please use the command:\n/scan https://example.com")


# /scan command
async def scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /scan https://example.com")
        return

    url = context.args[0]
    headers = {"x-apikey": VT_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT) as client:
            response = await client.post(VT_API_URL, data={"url": url}, headers=headers)

        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            await update.message.reply_text(f"✅ Submitted!\n⏳ Analyzing {url}...")

            await asyncio.sleep(10)  # wait before fetching report

            async with httpx.AsyncClient(timeout=CLIENT_TIMEOUT) as client:
                report_resp = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                )

            if report_resp.status_code == 200:
                report_data = report_resp.json()
                stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})

                harmless = stats.get("harmless", 0)
                suspicious = stats.get("suspicious", 0)
                malicious = stats.get("malicious", 0)
                undetected = stats.get("undetected", 0)

                await update.message.reply_text(
                    f"🔎 VirusTotal Report for {url}\n\n"
                    f"✅ Harmless: {harmless}\n"
                    f"⚠️ Suspicious: {suspicious}\n"
                    f"❌ Malicious: {malicious}\n"
                    f"❓ Undetected: {undetected}"
                )
            else:
                await update.message.reply_text(f"❌ Error fetching report: {report_resp.text}")

        else:
            await update.message.reply_text(f"❌ Error submitting URL: {response.text}")

    except Exception as e:
        await update.message.reply_text(f"⚠️ Exception: {str(e)}")


def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_url))
    app.add_handler(CallbackQueryHandler(button_handler))  # handle button presses

    app.run_polling()


if __name__ == "__main__":
    main()
