import requests
import json
import base64
import os
from Crypto.Cipher import AES

# এটি আপনার নিজস্ব এনক্রিপশন কী (১৬ বা ৩২ অক্ষরের হতে হবে)
# গিটহাব সিক্রেটে এটি সেভ করে রাখবেন
AES_SECRET = os.getenv("MY_APP_SECRET", "1234567890123456").encode() 

def encrypt_data(data):
    # AES CBC মোডে এনক্রিপ্ট করা (আপনার অ্যাপ যেন ডিক্রিপ্ট করতে পারে)
    key = AES_SECRET[:16]
    iv = AES_SECRET[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # প্যাডিং করা (১৬ ব্লকের জন্য)
    raw_data = json.dumps(data).encode()
    pad_len = 16 - (len(raw_data) % 16)
    raw_data += bytes([pad_len] * pad_len)
    
    encrypted = cipher.encrypt(raw_data)
    return base64.b64encode(encrypted).decode()

def run_sync():
    # এখানে আপনার সেই ২য় কোডের Fetching লজিক থাকবে (চ্যানেল এবং ইভেন্ট কালেকশন)
    # স্যাম্পল ডেটা হিসেবে দেখাচ্ছি
    my_data = {
        "status": "success",
        "matches": [
            {"title": "SmackDown", "link": "https://example.com/live.m3u8|KID:KEY"},
            {"title": "F1 Bahrain", "link": "https://example.com/f1.mpd|KID:KEY"}
        ]
    }
    
    # এনক্রিপ্ট করা
    encrypted_blob = encrypt_data(my_data)
    
    # ফাইলে সেভ করা
    output = {"data": encrypted_blob}
    with open("my_secure_data.json", "w") as f:
        json.dump(output, f)
    print("Data Encrypted and Saved!")

if __name__ == "__main__":
    run_sync()
