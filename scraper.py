import requests
import json
import base64
import os
from Crypto.Cipher import AES

# 🔐 Settings from GitHub Secrets (Settings > Secrets > Actions)
APP_PASSWORD = os.getenv("APP_PASSWORD", "oAR80SGuX3EEjUGFRwLFKBTiris=")
MY_APP_SECRET = os.getenv("MY_APP_SECRET", "12345678901234567890123456789012") # 32 bit key
APP_NAME = "SPORTSPU" # Apnar App Er Name

# Faki link bad deyar jonno
BAD_LINKS = [
    "https://video.twimg.com/amplify_video/1919602814160125952/pl/t5p2RHLI21i-hXga.m3u8",
    "http://dummy-link.m3u8"
]

class SportzxClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Dalvik/2.1.0 (Linux; Android 13)"})

    def _generate_key_iv(self, s):
        CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+!@#$%&="
        u32 = lambda x: x & 0xFFFFFFFF
        data = s.encode("utf-8")
        n = len(data)
        u = 0x811c9dc5
        for b in data: u = u32((u ^ b) * 0x1000193)
        key = bytearray(16)
        for i in range(16):
            u = u32(u * 0x1f + (i ^ data[i % n]))
            key[i] = CHARSET[u % len(CHARSET)]
        return bytes(key), bytes(key) # Using same for IV as per app logic

    def decrypt(self, b64_data):
        try:
            ct = base64.b64decode(b64_data)
            key, iv = self._generate_key_iv(APP_PASSWORD)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            return pt[:-pt[-1]].decode("utf-8")
        except: return ""

    def get_api_url(self):
        # Firebase theke dynamic API URL neya (Jate server change holeo kaj kore)
        try:
            headers = {"x-goog-api-key": os.getenv("FIREBASE_API_KEY", "AIzaSyBa5qiq95T97xe4uSYlKo0Wosmye_UEf6w")}
            r = self.session.post("https://firebaseinstallations.googleapis.com/v1/projects/446339309956/installations", 
                                  json={"fid": "eOaLWBo8S7S1oN-vb23mkf", "appId": "1:446339309956:android:b26582b5d2ad841861bdd1"}, headers=headers)
            token = r.json()["authToken"]["token"]
            r2 = self.session.post("https://firebaseremoteconfig.googleapis.com/v1/projects/446339309956/namespaces/firebase:fetch",
                                   json={"appId": "1:446339309956:android:b26582b5d2ad841861bdd1", "packageName": "com.sportzx.live"},
                                   headers={**headers, "X-Goog-Firebase-Installations-Auth": token})
            return r2.json().get("entries", {}).get("api_url")
        except: return None

    def fetch_data(self, url):
        try:
            r = self.session.get(url)
            dec = self.decrypt(r.json().get("data", ""))
            return json.loads(dec) if dec else []
        except: return []

def encrypt_for_github(data, secret):
    # Apnar nijer secret diye data encrypt kora
    key = secret.encode()[:32]
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

if __name__ == "__main__":
    client = SportzxClient()
    api_base = client.get_api_url()
    
    if api_base:
        all_data = []
        events = client.fetch_data(f"{api_base.rstrip('/')}/events.json")
        
        for ev in events:
            eid = ev.get("id")
            if not eid: continue
            
            channels = client.fetch_data(f"{api_base.rstrip('/')}/channels/{eid}.json")
            valid_channels = []
            
            for ch in channels:
                link = ch.get("link", "").split("|")[0].strip()
                # 🛑 Faki link filter kora
                if any(bad in link for bad in BAD_LINKS) or not link:
                    continue
                
                # 🏷️ Branding Change
                title = ch.get("title", "").replace("Sportzx", APP_NAME).replace("SportzX", APP_NAME)
                ch["title"] = title
                valid_channels.append(ch)
            
            if valid_channels:
                ev["channels_data"] = valid_channels
                all_data.append(ev)

        # 🔐 Nijer Secret diye Encrypt kore save kora
        encrypted_blob = encrypt_for_github(all_data, MY_APP_SECRET)
        with open("data.json", "w") as f:
            json.dump({"status": "success", "data": encrypted_blob}, f)
        print("Done! Data updated and encrypted.")
