import requests
import json
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 🔐 GitHub Secrets থেকে ভেরিয়েবলগুলো লোড করা
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
        """অ্যাপের নিজস্ব লজিক অনুযায়ী কী এবং আইভি জেনারেট করে"""
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
            pad_val = pt[-1]
            if 1 <= pad_val <= 16: pt = pt[:-pad_val]
            return pt.decode("utf-8", errors="replace")
        except:
            return ""

    def _get_api_url_from_firebase(self):
        """Firebase থেকে ডাইনামিক এপিআই ইউআরএল সংগ্রহ করা"""
        try:
            r = self.session.post(
                f"https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_NUMBER}/installations",
                json={"fid": FIREBASE_FID, "appId": FIREBASE_APP_ID, "authVersion": "FIS_v2", "sdkVersion": "a:18.0.0"},
                headers={"x-goog-api-key": FIREBASE_API_KEY}
            )
            auth_token = r.json()["authToken"]["token"]

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
        api_url = self._get_api_url_from_firebase()
        if not api_url:
            print("❌ API URL পাওয়া যায়নি!")
            return []

        print(f"🔗 API URL Found: {api_url}")
        base_api = api_url.rstrip('/')
        
        events = self._fetch_and_parse(f"{base_api}/events.json")
        if not isinstance(events, list): return []

        for event in events:
            if "formats" in event: del event["formats"]
            eid = event.get("id")
            if eid:
                channels = self._fetch_and_parse(f"{base_api}/channels/{eid}.json")
                for ch in channels:
                    ch["title"] = (
                        ch.get("title", "")
                        .replace("S©portzX", "SportzUP")
                        .replace("S©PX", "SUP")
                        .replace("Sportzx", "SportzUP")
                        .replace("SPX", "SUP")
                        .replace("SPORTZX", "SportzUP")
                        .replace("sportzx", "SportzUP")
                    )
                    if ch.get("link") == REPLACE_STREAM:
                        ch["link"] = NEW_STREAM
                event["channels_data"] = channels
        
        return events

# 🔐 PHP ফ্রেন্ডলি এনক্রিপশন ফাংশন (AES-256-CBC)
def save_with_encryption(data):
    if not data:
        print("⚠️ কোন ডাটা পাওয়া যায়নি, ফাইল সেভ করা হলো না।")
        return

    # কি (Key) ৩২ বাইট নিশ্চিত করা
    key = AES_SECRET.encode('utf-8').ljust(32)[:32]
    
    # CBC মোড এবং র‍্যান্ডম IV তৈরি
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    
    # ডাটা প্যাডিং এবং এনক্রিপ্ট
    json_data = json.dumps(data).encode('utf-8')
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))
    
    # IV + Ciphertext একসাথে করে Base64 করা
    # প্রথম ১৬ বাইট হলো IV, যা ডিক্রিপ্ট করতে লাগবে
    final_blob = base64.b64encode(iv + ciphertext).decode('utf-8')

    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_blob}, f, indent=4)
    print("✅ সফলভাবে এনক্রিপ্ট করে Sportzx.json তৈরি করা হয়েছে (PHP Compatible)!")

if __name__ == "__main__":
    scraper = SportzxScraper()
    final_json_data = scraper.scrape_all_data()
    save_with_encryption(final_json_data)
