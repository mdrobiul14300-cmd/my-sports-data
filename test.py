import requests
import json
import re
import base64
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# এনভায়রনমেন্ট ভেরিয়েবল নিশ্চিত করুন
APP_PASSWORD = os.getenv("APP_PASSWORD", "default_password")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_FID = os.getenv("FIREBASE_FID")
FIREBASE_APP_ID = os.getenv("FIREBASE_APP_ID")
PROJECT_NUMBER = os.getenv("PROJECT_NUMBER")
PACKAGE_NAME = os.getenv("PACKAGE_NAME")
AES_SECRET = os.getenv("AES_SECRET", "default_secret")

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
        CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+!@#$%&="
        def u32(x: int): return x & 0xFFFFFFFF
        data = s.encode("utf-8")
        n = len(data)
        u = 0x811c9dc5
        for b in data: u = u32((u ^ b) * 0x1000193)
        key = bytearray(16)
        for i in range(16):
            b = data[i % n]
            u = u32(u * 0x1f + (i ^ b))
            key[i] = CHARSET[u % len(CHARSET)]
        
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
        if not b64_data:
            return ""
        try:
            # Base64URL to Standard Base64
            b64_data = b64_data.replace('-', '+').replace('_', '/')
            # প্যাডিং ঠিক করা
            missing_padding = len(b64_data) % 4
            if missing_padding:
                b64_data += '=' * (4 - missing_padding)

            ct = base64.b64decode(b64_data)
            key, iv = self._generate_aes_key_iv(APP_PASSWORD)
            
            # AES CBC ডিক্রিপশন
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            return pt.decode("utf-8", errors="replace")
        except Exception as e:
            print(f"Decrypt Error: {e}")
            return ""

    def _get_api_url_from_firebase(self):
        try:
            r = self.session.post(
                f"https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_NUMBER}/installations",
                json={"fid": FIREBASE_FID, "appId": FIREBASE_APP_ID, "authVersion": "FIS_v2", "sdkVersion": "a:18.0.0"},
                headers={"x-goog-api-key": FIREBASE_API_KEY}
            )
            auth_token = r.json()["authToken"]["token"]
            r2 = self.session.post(
                f"https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_NUMBER}/namespaces/firebase:fetch",
                json={"appVersion": "2.5", "appInstanceId": FIREBASE_FID, "appId": FIREBASE_APP_ID, "packageName": PACKAGE_NAME},
                headers={"X-Goog-Api-Key": FIREBASE_API_KEY, "X-Goog-Firebase-Installations-Auth": auth_token}
            )
            return r2.json().get("entries", {}).get("api_url")
        except:
            return None

    def _fetch_and_parse(self, url: str):
        try:
            r = self.session.get(url, timeout=self.timeout)
            data_str = r.json().get("data", "")
            decrypted = self._decrypt_source_data(data_str)
            return json.loads(decrypted) if decrypted else []
        except Exception as e:
            print(f"Fetch Parse Error: {e}")
            return []

    def _decode_api_key(self, api_val: str) -> str:
        # API Key decode logic remains same as per your requirement
        if not api_val or len(api_val) < 20: return api_val
        try:
            decoded = base64.b64decode(api_val).decode('utf-8')
            if ":" in decoded: api_val = decoded
        except: pass
        api_val = re.sub(r'[\u0010-\u001f]', lambda m: hex(ord(m.group()))[-1], api_val)
        correction_map = {'J': 'a', '$': '5', 'l': '2', 'Q': 'b', 'W': 'e', 'w': '4', ')': '2', 'Z': 'a', 'x': '5', '[': 'd', 'U': 'c', 'u': '3', 'S': 'a', 'A': 'a', 'D': 'd', 's': '0', 'X': 'a', 'y': '6', 'V': 'd', 'v': '3', 't': '1', 'z': '7', 'T': 'b', 'R': 'a', '+': '4', '(': '2', 'F': 'f', 'r': '1', '>': '1'}
        for wrong, right in correction_map.items(): api_val = api_val.replace(wrong, right)
        return api_val

    def _clean_channel(self, ch: dict) -> dict:
        ch["title"] = re.sub(r'S.?portz[xX]', 'SportzUP', ch.get("title", ""))
        if ch.get("api"): ch["api"] = self._decode_api_key(ch["api"])
        if ch.get("link") == REPLACE_STREAM: ch["link"] = NEW_STREAM
        return ch

    def scrape_all_data(self) -> list:
        api_url = self._get_api_url_from_firebase()
        if not api_url: return []
        base_api = api_url.rstrip('/')
        events = self._fetch_and_parse(f"{base_api}/events.json")
        for event in events:
            eid = str(event.get("id", ""))
            channels = self._fetch_and_parse(f"{base_api}/channels/{eid}.json")
            event["channels_data"] = [self._clean_channel(ch) for ch in (channels if isinstance(channels, list) else [])]
        return events

def save_with_encryption(data: list):
    key = AES_SECRET.encode('utf-8').ljust(32)[:32]
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(json.dumps(data).encode('utf-8'), AES.block_size))
    final_blob = base64.b64encode(iv + ciphertext).decode('utf-8')
    with open("Robiul.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_blob}, f, indent=4)

if __name__ == "__main__":
    scraper = SportzxScraper()
    final_data = scraper.scrape_all_data()
    if final_data:
        save_with_encryption(final_data)
        print("✅ সফলভাবে Robiul.json তৈরি হয়েছে!")
