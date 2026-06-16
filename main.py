import os
import json
import base64
import re
import requests
import urllib.request
import ssl
import urllib3  # SSL ওয়ার্নিং ডিসেবল করার জন্য
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ❌ পাইথনের ইনসিকিউর রিকোয়েস্ট ওয়ার্নিংগুলো বন্ধ করা হচ্ছে
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 🔐 GitHub Secrets থেকে সমস্ত সেনসিティブ কনফিগারেশন নেওয়া হচ্ছে ---
DEFAULT_IVANZ_BASE = os.environ.get("DEFAULT_IVANZ_BASE")

# 🌐 হোস্টিং সার্ভার ১ এর কনফিগারেশন (আপনার পুরোনো সার্ভার)
PHP_TARGET_URL_1 = os.environ.get("PHP_TARGET_URL")
SECRET_KEY_1 = os.environ.get("PHP_SECRET_KEY")

# 🌐 হোস্টিং সার্ভার ২ এর কনফিগারেশন (নতুন হোস্টসেবা / sportzpulse.xyz সার্ভার)
PHP_TARGET_URL_2 = os.environ.get("PHP_TARGET_URL_2")
SECRET_KEY_2 = os.environ.get("PHP_SECRET_KEY_2")

# Firebase ক্রেডেনশিয়ালস
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID")
FIREBASE_APP_ID = os.environ.get("FIREBASE_APP_ID")

# নতুন যোগ করা সিক্রেটস
EVENTS_PATH = os.environ.get("EVENTS_PATH", "events.txt")

try:
    IVANZ_ALPHA = json.loads(os.environ.get("IVANZ_ALPHA", "[]"))
    IVANZ_MAPPED = json.loads(os.environ.get("IVANZ_MAPPED", "[]"))
    
    # KEYS-এর স্ট্রিং ডেটাকে Byte-string এ রূপান্তর করা হচ্ছে
    raw_keys = json.loads(os.environ.get("KEYS", "[]"))
    KEYS = []
    for k in raw_keys:
        KEYS.append({
            "key": k["key"].encode('utf-8'),
            "iv": k["iv"].encode('utf-8')
        })
except Exception as e:
    print(f"❌ Error parsing structural secrets: {e}")
    IVANZ_ALPHA, IVANZ_MAPPED, KEYS = [], [], []

# ------------------------------------------------------------------

# f11454d ডিক্রিপশন টেবিল তৈরি
f11454d = [chr(i) for i in range(128)]
if IVANZ_ALPHA and IVANZ_MAPPED:
    for i in range(min(len(IVANZ_ALPHA), len(IVANZ_MAPPED))):
        f11454d[ord(IVANZ_MAPPED[i])] = IVANZ_ALPHA[i]

IVANZ_BASE = DEFAULT_IVANZ_BASE


def get_dynamic_url_from_firebase():
    if not all([FIREBASE_API_KEY, FIREBASE_PROJECT_ID, FIREBASE_APP_ID]):
        print("⚠️ Warning: Firebase GitHub Secrets are missing! Using default URL.")
        return DEFAULT_IVANZ_BASE
        
    url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/namespaces/firebase:fetch?key={FIREBASE_API_KEY}"

    payload = {
        "appId": FIREBASE_APP_ID,
        "appInstanceId": "random_instance_id_1234567890",
        "countryCode": "BD",
        "languageCode": "bn-BD",
        "platformVersion": "33",
        "timeZone": "Asia/Dhaka",
        "packageName": "com.playz.tv",
        "sdkVersion": "23.0.1"
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; Build/TP1A.220624.014)"
    }

    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=15, verify=False)
        if response.status_code == 200:
            config_data = response.json()
            entries = config_data.get("entries", {})
            api_url = entries.get("api_url")
            if api_url:
                return api_url
    except:
        pass
    return DEFAULT_IVANZ_BASE

def custom_substitute_ivanz(data):
    return "".join([f11454d[ord(c)] if ord(c) < 128 else c for c in data])

def decrypt_aes_cbc(data_bytes, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data_bytes)
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except: return None

def unpack_json(data):
    if isinstance(data, list):
        for i in range(len(data)): data[i] = unpack_json(data[i])
    elif isinstance(data, dict):
        for k in list(data.keys()):
            v = data[k]
            if isinstance(v, str):
                v_s = v.strip()
                if v_s.startswith('{') or v_s.startswith('['):
                    try: data[k] = unpack_json(json.loads(v_s))
                    except: pass
            else: data[k] = unpack_json(v)
    return data

def try_decrypt(data_str):
    try:
        clean1 = re.sub(r'[^A-Za-z0-9+/=]', '', data_str)
        while len(clean1) % 4 != 0: clean1 += '='
        binary1 = base64.b64decode(clean1)
        for k in KEYS:
            dec = decrypt_aes_cbc(binary1, k['key'], k['iv'])
            if dec: return dec
        try:
            intermediate = binary1.decode('utf-8', errors='replace').strip()
            clean2 = re.sub(r'[^A-Za-z0-9+/=]', '', intermediate)
            while len(clean2) % 4 != 0: clean2 += '='
            binary2 = base64.b64decode(clean2)
            for k in KEYS:
                dec = decrypt_aes_cbc(binary2, k['key'], k['iv'])
                if dec: return dec
        except: pass
    except: pass
    return None

def decrypt_ivanz_data(raw_data, embed=True):
    if not raw_data: return None
    decrypted_str = None
    try:
        substituted = custom_substitute_ivanz(raw_data)
        decrypted_str = try_decrypt(substituted)
        if not decrypted_str: decrypted_str = try_decrypt(raw_data)
    except: pass
    if not decrypted_str: return None
    try:
        clean_decrypted = decrypted_str.replace('\0', '').strip()
        last_brace = max(clean_decrypted.rfind('}'), clean_decrypted.rfind(']'))
        if last_brace != -1: clean_decrypted = clean_decrypted[:last_brace+1]
        parsed = json.loads(clean_decrypted)
        unpacked = unpack_json(parsed)
        if embed: unpacked = embed_links(unpacked)
        return unpacked
    except: return None

def embed_links(data):
    targets = []
    def find_txt(obj):
        if isinstance(obj, list):
            for i in obj: find_txt(i)
        elif isinstance(obj, dict):
            for k, v in list(obj.items()):
                if k in ('api', 'links', 'Multiple URL') and isinstance(v, str) and v.endswith('.txt'):
                    targets.append({'parent': obj, 'key': k, 'path': v})
                else: find_txt(v)
    find_txt(data)
    if not targets: return data

    def process_item(item):
        url = IVANZ_BASE + item['path']
        raw = fetch_url(url)
        if raw:
            dec = decrypt_ivanz_data(raw, embed=False)
            if dec: return item, dec
        return item, [{"name": "Server", "link": "Offline"}]

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_item, t) for t in targets]
        for f in as_completed(futures):
            item, res = f.result()
            item['parent'][item['key']] = res
    return data

def fetch_url(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Dalvik/2.1.0'})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
            return response.read().decode('utf-8').strip()
    except: return None


def main():
    global IVANZ_BASE
    print("🚀 Starting Ultra-Secure Data Processing Engine...")
    
    # আবশ্যিক স্ট্রাকচার ভ্যালিডেশন
    if not KEYS or not IVANZ_ALPHA or not IVANZ_MAPPED:
        print("❌ Error: Core decryption parameters (KEYS/ALPHA/MAPPED) are missing or corrupted!")
        return
        
    if not all([PHP_TARGET_URL_1, SECRET_KEY_1, DEFAULT_IVANZ_BASE]):
        print("❌ Error: Essential hosting environment variables for Server 1 are missing!")
        return
        
    IVANZ_BASE = get_dynamic_url_from_firebase()
    if not IVANZ_BASE:
        print("❌ Error: Base URL initialization failed.")
        return
        
    raw_events = fetch_url(IVANZ_BASE + EVENTS_PATH)
    
    if raw_events:
        final_data = decrypt_ivanz_data(raw_events, embed=True)
        if not final_data:
            print("❌ Decryption failed.")
            return

        # 🔄 সার্ভার লিস্ট তৈরি (লুপের মাধ্যমে ডেটা পুশ করার জন্য)
        hosting_targets = []
        
        # প্রথম সার্ভার অ্যাড করা হচ্ছে
        hosting_targets.append(("সার্ভার ১ (Old)", PHP_TARGET_URL_1, SECRET_KEY_1))
        
        # দ্বিতীয় সার্ভার কন্ডিশনালি অ্যাড করা হচ্ছে (যদি সেটিংস থাকে)
        if PHP_TARGET_URL_2 and SECRET_KEY_2:
            hosting_targets.append(("সার্ভার ২ (New)", PHP_TARGET_URL_2, SECRET_KEY_2))
        else:
            print("⚠️ Warning: Server 2 config variables (PHP_TARGET_URL_2 / SECRET_KEY_2) are missing. Skipping Server 2.")

        # 📡 লুপ চালিয়ে সব হোস্টিং সার্ভারে ডেটা পাঠানো হচ্ছে
        json_payload = json.dumps(final_data, ensure_ascii=False)
        
        for server_name, target_url, secret_key in hosting_targets:
            print(f"📡 Sending data to {server_name} via PHP...")
            headers = {
                "Content-Type": "application/json",
                "X-Auth-Token": secret_key
            }
            try:
                # 🟢 verify=False যোগ করা হয়েছে SSL/TLS এরর বাইপাস করার জন্য
                response = requests.post(target_url, data=json_payload, headers=headers, timeout=60, verify=False)
                print(f"🔹 {server_name} Response Code: {response.status_code}")
                print(f"🔹 {server_name} Message: {response.text}")
            except Exception as e:
                print(f"❌ Failed to transmit data to {server_name}: {e}")
    else:
        print("❌ Could not fetch root data from source server.")

if __name__ == "__main__":
    main()
