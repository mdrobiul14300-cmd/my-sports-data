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
AES_SECRET = os.getenv("AES_SECRET")  # আপনার নিজের ৩২ ক্যারেক্টারের সিক্রেট কী

# লিঙ্ক রিপ্লেসমেন্ট রুলস
REPLACE_STREAM = "https://video.twimg.com/amplify_video/1919602814160125952/pl/t5p2RHLI21i-hXga.m3u8?variant_version=1&tag=14"
NEW_STREAM = "https://fallback-video.ivan-flux.workers.dev/video/index.m3u8"


class SportzxClient:
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
        u32 = lambda x: x & 0xFFFFFFFF
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

    def _decrypt_data(self, b64_data: str):
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

    def _fetch_and_decrypt(self, url: str):
        """URL থেকে ডেটা ফেচ করে ডিক্রিপ্ট করে"""
        try:
            r = self.session.get(url, timeout=self.timeout)
            decrypted = self._decrypt_data(r.json().get("data", ""))
            return json.loads(decrypted) if decrypted else {}
        except:
            return {}

    def _get_api_url(self):
        """Firebase থেকে ডাইনামিক API URL সংগ্রহ করা"""
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

    def _apply_rules(self, data):
        """ডকুমেন্ট ১ এর সব কারেকশন রুল প্রয়োগ করা"""
        # 🛠️ ফাইনাল ম্যাপিং টেবিল (৭টি সলিড কারেকশন রুল)
        correction_map = {
            'J': 'a',
            '$': '5',
            'l': '2',
            'Q': 'b',
            'W': 'f',
            ')': '2',
            'Z': 'a'
        }

        for event in data:
            if "formats" in event:
                del event["formats"]
            if "title" in event:
                event["title"] = event["title"].replace("Sportzx", "SPORTIFy").replace("SportzX", "SPORTIFy")

            for channel in event.get("channels_data", []):
                title = channel.get("title", "")
                # ব্র্যান্ড নাম রিপ্লেস (ডকুমেন্ট ১ + ডকুমেন্ট ২ উভয়ের রুল)
                title = re.sub(r'S.?portz[xX]', 'SPORTIFy', title)
                title = re.sub(r'S.?P[xX]', 'SPY', title)
                channel["title"] = title

                # --- 🎯 API Key (Token) ডিকোডিং ও মেরামতের ফাইনাল লজিক ---
                api_val = channel.get("api", "")
                if api_val:
                    # ১. যদি Base64 থাকে তবে ডিকোড করা
                    try:
                        if len(api_val) > 20:
                            decoded = base64.b64decode(api_val).decode('utf-8')
                            if ":" in decoded:
                                api_val = decoded
                    except:
                        pass

                    # ২. সমস্ত ভুল ক্যারেক্টার সঠিক হেক্স কোডে রূপান্তর করা
                    for wrong, right in correction_map.items():
                        api_val = api_val.replace(wrong, right)

                    channel["api"] = api_val

                # স্ট্রিম লিংক রিপ্লেস
                link = channel.get("link", "")
                if link == REPLACE_STREAM:
                    link = NEW_STREAM
                channel["link"] = link

        return data

    def get_json_data(self):
        """সম্পূর্ণ ডেটা ফেচ, manual_data মার্জ, এবং রুল প্রয়োগ"""
        api_url = self._get_api_url()
        if not api_url:
            print("❌ API URL পাওয়া যায়নি!")
            return []

        print(f"🔗 API URL Found: {api_url}")
        base_api = api_url.rstrip('/')

        raw_events = self._fetch_and_decrypt(f"{base_api}/events.json")
        if not isinstance(raw_events, list):
            return []

        # --- Manual Data ম্যানেজমেন্ট (ডকুমেন্ট ১ থেকে) ---
        manual_file = "manual_data.json"
        manual = {}
        id_mapping = {}
        if os.path.exists(manual_file):
            try:
                with open(manual_file, "r") as f:
                    manual = json.load(f)
                    id_mapping = manual.get("id_mapping", {})
            except:
                pass

        # চ্যানেল ডেটা ফেচ (ID Mapping সহ)
        for event in raw_events:
            eid = str(event.get("id"))
            fetch_id = id_mapping.get(eid, eid)
            if fetch_id:
                event["channels_data"] = self._fetch_and_decrypt(f"{base_api}/channels/{fetch_id}.json")

        # Manual Events মার্জ করা
        if manual:
            try:
                manual_events = manual.get("manual_events", [])
                now_utc = datetime.utcnow()
                cleaned_manual = []

                for m_ev in manual_events:
                    end_time_str = m_ev.get("eventInfo", {}).get("endTime", "")
                    try:
                        end_time_dt = datetime.strptime(end_time_str, "%Y/%m/%d %H:%M:%S +0000")
                        if now_utc < end_time_dt:
                            cleaned_manual.append(m_ev)
                    except:
                        cleaned_manual.append(m_ev)

                live_ids = [str(ev.get("id")) for ev in raw_events]
                for m_ev in cleaned_manual:
                    m_id = str(m_ev.get("id"))
                    if m_id in live_ids:
                        for i, ev in enumerate(raw_events):
                            if str(ev.get("id")) == m_id:
                                raw_events[i] = m_ev
                    else:
                        raw_events.append(m_ev)

                # Delete List প্রয়োগ
                delete_ids = [str(d) for d in manual.get("delete", [])]
                raw_events = [ev for ev in raw_events if str(ev.get("id")) not in delete_ids]

                # manual_data.json আপডেট করা
                manual["manual_events"] = cleaned_manual
                manual["id_mapping"] = {k: v for k, v in id_mapping.items() if k in live_ids}
                with open(manual_file, "w") as f:
                    json.dump(manual, f, indent=4)

            except:
                pass

        return self._apply_rules(raw_events)


# 🔐 PHP-Compatible AES-256-CBC এনক্রিপশন (ডকুমেন্ট ২ এর মতোই)
def save_with_encryption(data):
    if not data:
        print("⚠️ কোন ডাটা পাওয়া যায়নি, ফাইল সেভ করা হলো না।")
        return

    # IST টাইমস্ট্যাম্প (ডকুমেন্ট ১ থেকে)
    ist_now = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%I:%M:%S %p %d-%m-%Y")

    # মেটাডেটা র‍্যাপার (ডকুমেন্ট ১ থেকে)
    wrapped_data = {
        "AUTHOR": "iVan_FLUx",
        "TELEGRAM": "https://t.me/iVan_flux",
        "Last update time": ist_now,
        "events": data
    }

    # কি (Key) ৩২ বাইট নিশ্চিত করা
    key = AES_SECRET.encode('utf-8').ljust(32)[:32]

    # PHP-Compatible AES-256-CBC এনক্রিপশন (IV + Ciphertext)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    json_data = json.dumps(wrapped_data).encode('utf-8')
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))

    # IV + Ciphertext একসাথে করে Base64 করা (PHP-এ সহজে ডিক্রিপ্ট করা যাবে)
    final_blob = base64.b64encode(iv + ciphertext).decode('utf-8')

    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump({"data": final_blob}, f, indent=4)

    print("✅ সফলভাবে এনক্রিপ্ট করে Sportzx.json তৈরি করা হয়েছে (PHP Compatible)!")


if __name__ == "__main__":
    client = SportzxClient()
    data = client.get_json_data()
    save_with_encryption(data)
