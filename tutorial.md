# 📘 Social URL Validation Tool - Beginner's Guide & Tutorial

Welcome! If you are reading this, you are working with the **Social URL Validation Tool**. This guide is written in plain English to help you understand exactly what this tool does, how it works under the hood, and how to fix it if things ever break.

---

## 🌟 1. What Does This Tool Do?
Imagine you have a list of 10,000 social media links (Facebook profiles, Twitter posts, YouTube videos). You need to know which ones are still **Active** and which ones have been **Deleted/Taken Down**.

Normally, doing this requires opening 10,000 browser tabs, which is incredibly slow and crashes computers. 

This tool does it **without a browser**. It uses lightning-fast, invisible HTTP requests (like how a search engine scans the web) to ask the social media servers if a page exists. 

It guarantees returning one of **three distinct results**:
1. ✅ **`active`**: We found the profile/content. It's live.
2. ❌ **`taken_down`**: We confirmed the page is deleted, suspended, or doesn't exist.
3. ⚠️ **`uncertain`**: The website threw up a security wall (like Cloudflare) or rate-limited us. We couldn't check it safely.

---

## 🕵️ 2. How Does It Detect Status for Each Platform?
Social media sites hate bots. If a Python script asks LinkedIn for a profile, LinkedIn immediately shows a "Please Log In" wall instead of the profile. 

To ensure **high accuracy** without getting blocked, our tool uses clever "disguises" (called User-Agents) and specific platform tricks:

### 📸 Instagram & 📘 Facebook
*   **The Trick**: Meta (Facebook/Instagram) blocks normal bots. But they *allow* links to be previewed on iMessage and WhatsApp. 
*   **How we do it**: We disguise our request as `facebookexternalhit` (Meta's own link preview crawler). 
*   **Accuracy Check**: If Instagram gives us a `<meta property="og:title">` with follower counts, it's **ACTIVE**. If they give us a generic "Login • Instagram" page, it's **TAKEN DOWN**.

### 💼 LinkedIn
*   **The Trick**: LinkedIn blocks almost everything. However, they allow Google and Bing to scan profiles for search results.
*   **How we do it**: We rotate between `Googlebot` and `Bingbot` disguises.
*   **Accuracy Check**: If we see the person's real name in the page title, it's **ACTIVE**. If LinkedIn forces a redirect loop or blocks us completely, we mark it **UNCERTAIN**.

### 🐦 X (Twitter)
*   **The Trick**: Twitter is notoriously hard to scrape. But they have a public, free tool for embedding tweets on news websites (called `oEmbed`).
*   **How we do it**: We bypass the main Twitter website entirely and ask the hidden `publish.twitter.com` API: *"Hey, give me the embed code for this profile/tweet."*
*   **Accuracy Check**: If the API replies with data, it's **ACTIVE**. If the API says "404 Not Found", it's **TAKEN DOWN**.

### 📺 YouTube
*   **The Trick**: YouTube never deletes a page. Even if a video is removed, YouTube serves a working webpage that says "Video unavailable".
*   **How we do it**: We download the page as `Googlebot`.
*   **Accuracy Check**: We specifically look for metadata. If there is no title or the video description is empty, we know it's a fake "ghost" page and mark it **TAKEN DOWN**.

### 📱 Telegram
*   **The Trick**: Telegram web pages are very simple.
*   **Accuracy Check**: We search the HTML for the class `tgme_page_title` (which holds the group name). If it exists, it's **ACTIVE**. If it says "Telegram: Contact @...", it's **TAKEN DOWN**.

### 🌐 Generic Websites & Blogs
*   **The Trick**: For random websites, we do a DNS check first. If the domain is dead, we instantly mark it taken down.
*   **Accuracy Check**: We follow redirects. If a website redirects to a known domain-seller (like `sedoparking.com`), we detect that the domain was seized/sold and mark it **TAKEN DOWN**.

### 📦 APK / App Store Sites (e.g., apkgk.com)
*   **The Limitation**: These sites are heavily guarded by Cloudflare. Cloudflare requires JavaScript to solve math puzzles to prove you are human.
*   **The Result**: Because we don't use heavy browsers, we cannot solve JavaScript puzzles. The tool will safely return **UNCERTAIN** (403 Forbidden) for these sites.

---

## 🛡️ 3. Long-Term Stability
This tool is **incredibly stable** for long-term use because:
1. **No Playwright/Selenium**: Browsers consume massive RAM and crash servers. This tool uses `aiohttp`—it can process 1,000 URLs in seconds using almost zero memory.
2. **Stateless Architecture**: It has no databases to corrupt and no cookies to expire. Java asks a question, Python answers it, and immediately forgets about it.
3. **Graceful Degradation**: If Instagram suddenly blocks your server's IP address, the tool doesn't crash. It simply catches the error and marks those URLs as `UNCERTAIN` in the JSON response.

---

## 🔧 4. What Goes Wrong & How to Debug It
Even the best scrapers face issues because social media sites constantly update their code. Here is how to handle problems like a pro.

### Scenario A: A platform marks everything as `UNCERTAIN`
**What happened:** Your server's IP address made too many requests too fast, and the platform (e.g., Facebook) temporarily banned your IP.
**How to fix:**
1. Do nothing. IP bans usually lift after 12-24 hours.
2. (Advanced) If you process millions of URLs daily, you will need to add a "Rotating Proxy" to `fast_checker.py` so your requests come from different IP addresses.

### Scenario B: A platform marks active accounts as `TAKEN_DOWN` (False Positives)
**What happened:** The platform changed their HTML structure. For example, Telegram used to use `<div class="tgme_page_title">` for active channels. If they rename it to `<div class="channel-title">`, our tool thinks the channel is gone!
**How to Debug & Fix:**
1. Open the **`validation.log`** file.
2. You will see extremely clear logs: 
   `[INFO] [TELEGRAM] status=TAKEN_DOWN | reason=Not found (title: Telegram: View @channel) | url=...`
3. Copy the URL from the log, open it in your own normal browser, right-click, and select **"View Page Source"**.
4. Look at the HTML. Did the title change?
5. Open `backend/fast_checker.py`, locate `def _check_telegram(...)`, and update the text it is searching for.

### Scenario C: The server crashes or returns 500 Errors to Java
**What happened:** A rare Python error or a severely malformed URL broke the worker.
**How to Debug:**
1. Our tool wraps every single check in a `try...except` block, meaning a bad URL *should never* crash the whole server.
2. If it does, look at your terminal console or `validation.log`.
3. You will see a giant red flag: `[FATAL CHECK ERROR] PLATFORM url=... error=...`. 
4. The log will tell you exactly which line of Python code caused the crash.

---

## 🎯 Summary for Beginners
1. **The tool only has 5 files**. The main brain is `backend/fast_checker.py`.
2. **Java speaks to Python via JSON**. Java sends URLs to `/api/check/json`, and Python sends back statuses.
3. **Check the logs.** If a result looks weird, check `validation.log`. It prints the exact reason for every single URL's status.
4. **When in doubt, `UNCERTAIN` is your friend.** If the tool cannot 100% guarantee a result, it returns `uncertain` to prevent your business from accidentally deleting valid user data.
