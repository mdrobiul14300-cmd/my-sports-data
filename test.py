import requests
import json
import re
import base64
import os
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 🔐 GitHub Secrets থেকে ভেরিয়েবলগুলো লোড করা
APP_PASSWORD = os.getenv("APP_PASSWORD")
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_FID = os.getenv("FIREBASE_FID")
FIREBASE_APP_ID = os.getenv("FIREBASE_APP_ID")
PROJECT_NUMBER = os.getenv("PROJECT_NUMBER")
PACKAGE_NAME = os.getenv("PACKAGE_NAME")
AES_SECRET = os.getenv("AES_SECRET")  # ৩২ ক্যারেক্টারের সিক্রেট কী

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
            if 1 <= pad_val <= 16:
                pt = pt[:-pad_val]
            return pt.decode("utf-8", errors="replace")
        except:
            return ""

    def _get_api_url_from_firebase(self):
        """Firebase থেকে ডাইনামিক এপিআই ইউআরএল সংগ্রহ করা"""
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
        """URL থেকে ডাটা fetch করে decrypt করে return করে"""
        try:
            r = self.session.get(url, timeout=self.timeout)
            decrypted = self._decrypt_source_data(r.json().get("data", ""))
            return json.loads(decrypted) if decrypted else []
        except:
            return []

    def _decode_api_key(self, api_val: str) -> str:
        """
        API key যদি Base64 encoded হয় তাহলে decode করে আসল key বের করে।
        তারপর corrupted character গুলো correction_map দিয়ে ঠিক করে।
        """
        if not api_val or len(api_val) < 20:
            return api_val

        # ১. Base64 decode করা
        try:
            decoded = base64.b64decode(api_val).decode('utf-8')
            if ":" in decoded and len(decoded) > 30:
                api_val = decoded
        except Exception:
            pass

        # ২. Corrupted character গুলো সঠিক hex character এ রূপান্তর করা
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
        """একটি channel এর title, api key ঠিক করে এবং link replace করে"""
        # ১. Brand name ঠিক করা
        title = ch.get("title", "")
        title = re.sub(r'S.?portz[xX]', 'SportzUP', title)
        title = re.sub(r'S.?P[xX]', 'SUP', title)
        ch["title"] = title

        # ২. API key Base64 decode করা (IPL/PSL fix)
        api_val = ch.get("api", "")
        if api_val:
            ch["api"] = self._decode_api_key(api_val)

        # ৩. Link replace করা
        if ch.get("link") == REPLACE_STREAM:
            ch["link"] = NEW_STREAM

        return ch

    def _load_manual_data(self) -> dict:
        """manual_data.json লোড করা, না থাকলে খালি dict return"""
        manual_file = "manual_data.json"
        if not os.path.exists(manual_file):
            return {}
        try:
            with open(manual_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}

    def _save_manual_data(self, manual: dict):
        """manual_data.json আপডেট করে save করা"""
        try:
            with open("manual_data.json", "w", encoding="utf-8") as f:
                json.dump(manual, f, indent=4, ensure_ascii=False)
        except:
            pass

    def _apply_manual_data(self, events: list, manual: dict) -> list:
        """
        manual_data.json এর নিয়ম অনুযায়ী events আপডেট করা:
        - manual_events: নতুন যোগ করা বা replace করা events
        - delete: বাদ দেওয়ার event id list
        - id_mapping: channel fetch এর জন্য আলাদা id ব্যবহার (IPL/PSL fix)
        এই ফাংশন id_mapping ছাড়া বাকি সব কাজ করে।
        id_mapping channel fetch এর সময় আলাদাভাবে handle হয়।
        """
        if not manual:
            return events

        now_utc = datetime.utcnow()

        # ১. মেয়াদ শেষ হয়নি এমন manual events রাখা
        manual_events = manual.get("manual_events", [])
        valid_manual_events = []
        for m_ev in manual_events:
            end_time_str = m_ev.get("eventInfo", {}).get("endTime", "")
            try:
                end_dt = datetime.strptime(end_time_str, "%Y/%m/%d %H:%M:%S +0000")
                if now_utc < end_dt:
                    valid_manual_events.append(m_ev)
                else:
                    print(f"⏰ Manual event মেয়াদ শেষ, বাদ দেওয়া হলো: {m_ev.get('id')}")
            except:
                valid_manual_events.append(m_ev)  # date parse না হলে রাখা

        # ২. Live events এর id list
        live_ids = {str(ev.get("id")) for ev in events}

        # ৩. Manual events দিয়ে replace বা append করা
        for m_ev in valid_manual_events:
            m_id = str(m_ev.get("id"))
            if m_id in live_ids:
                # replace করা
                for i, ev in enumerate(events):
                    if str(ev.get("id")) == m_id:
                        events[i] = m_ev
                        print(f"🔄 Event replace হলো: {m_id}")
                        break
            else:
                # নতুন যোগ করা
                events.append(m_ev)
                print(f"➕ নতুন manual event যোগ হলো: {m_id}")

        # ৪. Delete list অনুযায়ী বাদ দেওয়া
        delete_ids = {str(d) for d in manual.get("delete", [])}
        if delete_ids:
            before = len(events)
            events = [ev for ev in events if str(ev.get("id")) not in delete_ids]
            print(f"🗑️ {before - len(events)} টি event delete হলো।")

        # ৫. manual_data.json আপডেট করে save করা (পুরনো expired events ছাড়া)
        manual["manual_events"] = valid_manual_events
        # id_mapping থেকে যে id গুলো আর live নেই সেগুলো সরানো
        id_mapping = manual.get("id_mapping", {})
        manual["id_mapping"] = {k: v for k, v in id_mapping.items() if k in live_ids}
        self._save_manual_data(manual)

        return events

    def scrape_all_data(self) -> list:
        """মূল scraping ফাংশন — সব data fetch করে processed list return করে"""
        api_url = self._get_api_url_from_firebase()
        if not api_url:
            print("❌ API URL পাওয়া যায়নি!")
            return []

        print(f"🔗 API URL Found: {api_url}")
        base_api = api_url.rstrip('/')

        # ১. Events list fetch করা
        events = self._fetch_and_parse(f"{base_api}/events.json")
        if not isinstance(events, list) or not events:
            print("❌ Events data পাওয়া যায়নি!")
            return []

        print(f"📋 মোট {len(events)} টি event পাওয়া গেছে।")

        # ২. Manual data লোড করা (id_mapping সহ)
        manual = self._load_manual_data()
        id_mapping = manual.get("id_mapping", {})

        # ৩. প্রতিটি event এর channel data fetch করা
        for event in events:
            if "formats" in event:
                del event["formats"]

            eid = str(event.get("id", ""))
            if not eid:
                continue

            # id_mapping থেকে আলাদা channel id আছে কিনা দেখা (IPL/PSL fix)
            fetch_id = id_mapping.get(eid, eid)

            channels = self._fetch_and_parse(f"{base_api}/channels/{fetch_id}.json")

            if not isinstance(channels, list):
                channels = []

            # Channel clean করা
            event["channels_data"] = [self._clean_channel(ch) for ch in channels]

            if fetch_id != eid:
                print(f"🗺️ Event {eid} → channel id {fetch_id} থেকে fetch হলো ({len(channels)} টি channel)")

        # ৪. Manual data apply করা (replace/append/delete)
        events = self._apply_manual_data(events, manual)

        print(f"✅ চূড়ান্তভাবে {len(events)} টি event প্রস্তুত।")
        return events


# 🔐 Encryption ফাংশন — আগের মতোই AES-256-CBC (পরিবর্তন নেই)
def save_with_encryption(data: list):
    if not data:
        print("⚠️ কোন ডাটা পাওয়া যায়নি, ফাইল সেভ করা হলো না।")
        return

    # Key ৩২ বাইট নিশ্চিত করা
    key = AES_SECRET.encode('utf-8').ljust(32)[:32]

    # CBC মোড এবং র‍্যান্ডম IV তৈরি
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # ডাটা প্যাডিং এবং এনক্রিপ্ট
    json_data = json.dumps(data).encode('utf-8')
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))

    # IV + Ciphertext একসাথে করে Base64 করা
    final_blob = base64.b64encode(iv + ciphertext).decode('utf-8')

    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_blob}, f, indent=4)

    print("✅ সফলভাবে এনক্রিপ্ট করে Sportzx.json তৈরি হয়েছে!")


if __name__ == "__main__":
    scraper = SportzxScraper()
    final_data = scraper.scrape_all_data()
    save_with_encryption(final_data)
