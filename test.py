import requests
import json
import re
import base64
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

APP_PASSWORD = os.getenv("APP_PASSWORD")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_FID = os.getenv("FIREBASE_FID")
FIREBASE_APP_ID = os.getenv("FIREBASE_APP_ID")
PROJECT_NUMBER = os.getenv("PROJECT_NUMBER")
PACKAGE_NAME = os.getenv("PACKAGE_NAME")
AES_SECRET = os.getenv("AES_SECRET")

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
        try:
            ct = base64.b64decode(b64_data)
            key, iv = self._generate_aes_key_iv(APP_PASSWORD)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            pad_val = pt[-1]
            if 1 <= pad_val <= 16:
                pt = pt[:-pad_val]
            return pt.decode("utf-8", errors="replace")
        except:
            return ""

    def _get_api_url_from_firebase(self):
        try:
            r = self.session.post(
                f"https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_NUMBER}/installations",
                json={
                    "fid": FIREBASE_FID,
                    "appId": FIREBASE_APP_ID,
                    "authVersion": "FIS_v2",
                    "sdkVersion": "a:18.0.0"
                },
                headers={"x-goog-api-key": FIREBASE_API_KEY}
            )
            auth_token = r.json()["authToken"]["token"]
            r2 = self.session.post(
                f"https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_NUMBER}/namespaces/firebase:fetch",
                json={
                    "appVersion": "2.1",
                    "appInstanceId": FIREBASE_FID,
                    "appId": FIREBASE_APP_ID,
                    "packageName": PACKAGE_NAME
                },
                headers={
                    "X-Goog-Api-Key": FIREBASE_API_KEY,
                    "X-Goog-Firebase-Installations-Auth": auth_token
                }
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

    def _decode_api_key(self, api_val: str) -> str:
        if not api_val or len(api_val) < 20:
            return api_val
        try:
            decoded = base64.b64decode(api_val).decode('utf-8')
            if ":" in decoded and len(decoded) > 30:
                api_val = decoded
        except:
            pass
        correction_map = {
            'J': 'a',
            '$': '5',
            'l': '2',
            'Q': 'b',
            'W': 'f',
            ')': '2',
            'Z': 'a',
        }
        for wrong, right in correction_map.items():
            api_val = api_val.replace(wrong, right)
        return api_val

    def _clean_channel(self, ch: dict) -> dict:
        title = ch.get("title", "")
        title = re.sub(r'S.?portz[xX]', 'SportzUP', title)
        title = re.sub(r'S.?P[xX]', 'SUP', title)
        ch["title"] = title
        api_val = ch.get("api", "")
        if api_val:
            ch["api"] = self._decode_api_key(api_val)
        if ch.get("link") == REPLACE_STREAM:
            ch["link"] = NEW_STREAM
        return ch

    def _load_manual_data(self) -> dict:
        if not os.path.exists("manual_data.json"):
            return {}
        try:
            with open("manual_data.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}

    def _save_manual_data(self, manual: dict):
        try:
            with open("manual_data.json", "w", encoding="utf-8") as f:
                json.dump(manual, f, indent=4, ensure_ascii=False)
        except:
            pass

    def _apply_manual_data(self, events: list, manual: dict) -> list:
        if not manual:
            return events

        now_utc = datetime.utcnow()

        # মেয়াদ শেষ হয়নি এমন manual events রাখা
        valid_manual_events = []
        for m_ev in manual.get("manual_events", []):
            end_time_str = m_ev.get("eventInfo", {}).get("endTime", "")
            try:
                end_dt = datetime.strptime(end_time_str, "%Y/%m/%d %H:%M:%S +0000")
                if now_utc < end_dt:
                    valid_manual_events.append(m_ev)
                else:
                    print(f"⏰ Expired event বাদ: {m_ev.get('id')}")
            except:
                valid_manual_events.append(m_ev)

        # Live event id list
        live_ids = {str(ev.get("id")) for ev in events}

        # Manual events দিয়ে replace বা append
        for m_ev in valid_manual_events:
            m_id = str(m_ev.get("id"))
            if m_id in live_ids:
                for i, ev in enumerate(events):
                    if str(ev.get("id")) == m_id:
                        events[i] = m_ev
                        print(f"🔄 Replace: {m_id}")
                        break
            else:
                events.append(m_ev)
                print(f"➕ নতুন event যোগ: {m_id}")

        # Delete list অনুযায়ী বাদ দেওয়া
        delete_ids = {str(d) for d in manual.get("delete", [])}
        if delete_ids:
            before = len(events)
            events = [ev for ev in events if str(ev.get("id")) not in delete_ids]
            print(f"🗑️ {before - len(events)} টি event delete হলো।")

        # manual_data.json আপডেট করা
        manual["manual_events"] = valid_manual_events
        manual["id_mapping"] = {
            k: v for k, v in manual.get("id_mapping", {}).items()
            if k in live_ids
        }
        self._save_manual_data(manual)
        return events

    def scrape_all_data(self) -> list:
        api_url = self._get_api_url_from_firebase()
        if not api_url:
            print("❌ API URL পাওয়া যায়নি!")
            return []

        print(f"🔗 API URL: {api_url}")
        base_api = api_url.rstrip('/')

        # Events list fetch
        events = self._fetch_and_parse(f"{base_api}/events.json")
        if not isinstance(events, list) or not events:
            print("❌ Events data পাওয়া যায়নি!")
            return []

        print(f"📋 মোট {len(events)} টি event পাওয়া গেছে।")

        # Manual data লোড
        manual = self._load_manual_data()
        id_mapping = manual.get("id_mapping", {})

        # প্রতিটি event এর channel fetch
        for event in events:
            if "formats" in event:
                del event["formats"]
            eid = str(event.get("id", ""))
            if not eid:
                continue
            fetch_id = id_mapping.get(eid, eid)
            channels = self._fetch_and_parse(f"{base_api}/channels/{fetch_id}.json")
            if not isinstance(channels, list):
                channels = []
            event["channels_data"] = [self._clean_channel(ch) for ch in channels]
            if fetch_id != eid:
                print(f"🗺️ Event {eid} → {fetch_id} ({len(channels)} channels)")

        # Manual data apply
        events = self._apply_manual_data(events, manual)
        print(f"✅ মোট {len(events)} টি event প্রস্তুত।")
        return events


def save_with_encryption(data: list):
    if not data:
        print("⚠️ কোন ডাটা নেই।")
        return
    key = AES_SECRET.encode('utf-8').ljust(32)[:32]
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    json_data = json.dumps(data).encode('utf-8')
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))
    final_blob = base64.b64encode(iv + ciphertext).decode('utf-8')
    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_blob}, f, indent=4)
    print("✅ Sportzx.json তৈরি হয়েছে!")


if __name__ == "__main__":
    scraper = SportzxScraper()
    final_data = scraper.scrape_all_data()
    save_with_encryption(final_data)
