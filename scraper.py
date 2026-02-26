import requests
import json
import base64
import os
from Crypto.Cipher import AES

# 🔐 GitHub Secrets থেকে ভেরিয়েবলগুলো লোড করা
# লোকাল পিসিতে চালালে এই ভেরিয়েবলগুলো এনভায়রনমেন্টে সেট থাকতে হবে
APP_PASSWORD = os.getenv("APP_PASSWORD")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_FID = os.getenv("FIREBASE_FID")
FIREBASE_APP_ID = os.getenv("FIREBASE_APP_ID")
PROJECT_NUMBER = os.getenv("PROJECT_NUMBER")
PACKAGE_NAME = os.getenv("PACKAGE_NAME")
AES_SECRET = os.getenv("AES_SECRET") # আপনার নিজের ৩২ ক্যারেক্টারের সিক্রেট কী

# লিঙ্ক রিপ্লেসমেন্ট রুলস
REPLACE_STREAM = "https://video.twimg.com/amplify_video/1919602814160125952/pl/t5p2RHLI21i-hXga.m3u8?variant_version=1&tag=14"
NEW_STREAM = "https://raw.githubusercontent.com/TOUFIK2256/Feildfever/main/VN20251203_010347.mp4"

class SportzxScraper:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 13)",
            "Accept-Encoding": "gzip"
        })

    def _generate_aes_key_iv(self, s: str):
        """অ্যাপের নিজস্ব লজিক অনুযায়ী কী এবং আইভি জেনারেট করে"""
        CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+!@#$%&="
        def u32(x: int): return x & 0xFFFFFFFF
        data = s.encode("utf-8")
        n = len(data)
        
        # Key Generation
        u = 0x811c9dc5
        for b in data: u = u32((u ^ b) * 0x1000193)
        key = bytearray(16)
        for i in range(16):
            b = data[i % n]
            u = u32(u * 0x1f + (i ^ b))
            key[i] = CHARSET[u % len(CHARSET)]

        # IV Generation
        u = 0x811c832a
        for b in data: u = u32((u ^ b) * 0x1000193)
        iv = bytearray(16)
        idx, acc = 0, 0
        while idx != 0x30:
            b = data[idx % n]
            u = u32(u * 0x1d + (acc ^ b))
            iv[idx // 3] = CHARSET[u % len(CHARSET)]
            idx += 3
            acc = u32(acc + 7)
        return bytes(key), bytes(iv)

    def _decrypt_source_data(self, b64_data: str):
        """অরিজিনাল সোর্সের ডাটা ডিক্রিপ্ট করার ফাংশন"""
        try:
            ct = base64.b64decode(b64_data)
            key, iv = self._generate_aes_key_iv(APP_PASSWORD)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            pad = pt[-1]
            if 1 <= pad <= 16: pt = pt[:-pad]
            return pt.decode("utf-8", errors="replace")
        except:
            return ""

    def _get_api_url_from_firebase(self):
        """Firebase থেকে ডাইনামিক এপিআই ইউআরএল সংগ্রহ করা"""
        try:
            # Step 1: Get Firebase Installation Token
            r = self.session.post(
                f"https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_NUMBER}/installations",
                json={"fid": FIREBASE_FID, "appId": FIREBASE_APP_ID, "authVersion": "FIS_v2", "sdkVersion": "a:18.0.0"},
                headers={"x-goog-api-key": FIREBASE_API_KEY}
            )
            auth_token = r.json()["authToken"]["token"]

            # Step 2: Fetch Remote Config for API URL
            r2 = self.session.post(
                f"https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_NUMBER}/namespaces/firebase:fetch",
                json={"appVersion": "2.1", "appInstanceId": FIREBASE_FID, "appId": FIREBASE_APP_ID, "packageName": PACKAGE_NAME},
                headers={"X-Goog-Api-Key": FIREBASE_API_KEY, "X-Goog-Firebase-Installations-Auth": auth_token}
            )
            return r2.json().get("entries", {}).get("api_url")
        except:
            return None

    def _fetch_and_parse(self, url: str):
        try:
            r = self.session.get(url, timeout=self.timeout)
            decrypted = self._decrypt_source_data(r.json().get("data", ""))
            return json.loads(decrypted) if decrypted else []
        except:
            return []

    def scrape_all_data(self):
        """সোর্স থেকে ডাটা স্ক্র্যাপ করে মডিফাই করা"""
        api_url = self._get_api_url_from_firebase()
        if not api_url:
            print("❌ API URL পাওয়া যায়নি!")
            return []

        print(f"🔗 API URL Found: {api_url}")
        base_api = api_url.rstrip('/')
        
        # ইভেন্ট ডাটা স্ক্র্যাপ করা
        events = self._fetch_and_parse(f"{base_api}/events.json")
        if not isinstance(events, list): return []

        for event in events:
            # ফর্মাট ডিলিট করা
            if "formats" in event: del event["formats"]
            
            # চ্যানেলের ডাটা স্ক্র্যাপ করা
            eid = event.get("id")
            if eid:
                channels = self._fetch_and_parse(f"{base_api}/channels/{eid}.json")
                
                # রুলস অ্যাপ্লাই করা (নাম পরিবর্তন ও লিঙ্ক রিপ্লেস)
                for ch in channels:
                    ch["title"] = ch.get("title", "").replace("Sportzx", "SPORTIFy").replace("SPX", "SPY")
                    if ch.get("link") == REPLACE_STREAM:
                        ch["link"] = NEW_STREAM
                
                event["channels_data"] = channels
        
        return events

# 🔐 আপনার নিজের কী দিয়ে এনক্রিপ্ট করার ফাংশন
def save_with_encryption(data):
    if not data:
        print("⚠️ কোন ডাটা পাওয়া যায়নি, ফাইল সেভ করা হলো না।")
        return

    # আপনার সিক্রেট কী ৩২ বাইটের হতে হবে
    key = AES_SECRET.encode().ljust(32)[:32] 
    cipher = AES.new(key, AES.MODE_EAX)
    
    # ডাটা এনক্রিপ্ট করা
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
    
    # Nonce + Tag + Ciphertext একসাথে রাখা
    encrypted_blob = cipher.nonce + tag + ciphertext
    final_data = base64.b64encode(encrypted_blob).decode()

    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_data}, f, indent=4)
    print("✅ সফলভাবে ডাটা স্ক্র্যাপ এবং এনক্রিপ্ট করে Sportzx.json তৈরি করা হয়েছে!")

# --- মেন ফাংশন ---
if __name__ == "__main__":
    scraper = SportzxScraper()
    final_json_data = scraper.scrape_all_data()
    save_with_encryption(final_json_data)
