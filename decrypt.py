import json
import base64
import os
from Crypto.Cipher import AES

# আপনার ৩২ ক্যারেক্টারের সিক্রেট কী (যা এনক্রিপ্ট করার সময় ব্যবহার করেছেন)
AES_SECRET = os.getenv("AES_SECRET") or "12345678912345671234567891234567"

def decrypt_sportzx_json():
    try:
        # ১. ফাইলটি ওপেন করা
        if not os.path.exists("Sportzx.json"):
            print("❌ Sportzx.json ফাইলটি পাওয়া যায়নি!")
            return

        with open("Sportzx.json", "r", encoding="utf-8") as f:
            file_data = json.load(f)
            encrypted_blob_b64 = file_data.get("data", "")

        # ২. Base64 থেকে ডিকোড করা
        encrypted_blob = base64.b64decode(encrypted_blob_b64)

        # ৩. Key-কে ৩২ বাইটে সেট করা (পাইথন এনক্রিপশন লজিক অনুযায়ী)
        key = AES_SECRET.encode().ljust(32)[:32]

        # ৪. EAX মোডে Nonce, Tag এবং Ciphertext আলাদা করা
        # পাইথনে EAX মোড ব্যবহারের সময় Nonce থাকে ১৬ বাইট এবং Tag থাকে ১৬ বাইট
        nonce = encrypted_blob[:16]
        tag = encrypted_blob[16:32]
        ciphertext = encrypted_blob[32:]

        # ৫. ডিক্রিপশন শুরু
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        
        # ডিক্রিপ্ট এবং ভেরিফাই করা (ট্যাগ ভুল হলে এটি এরর দেবে)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        # ৬. ডাটা প্রিন্ট করা
        final_json = json.loads(decrypted_data.decode('utf-8'))
        print("✅ ডিক্রিপশন সফল হয়েছে!")
        print(json.dumps(final_json, indent=4))
        
        return final_json

    except ValueError:
        print("❌ ডিক্রিপশন ব্যর্থ হয়েছে! কী (Key) ভুল অথবা ডাটা নষ্ট হয়ে গেছে।")
    except Exception as e:
        print(f"❌ একটি ভুল হয়েছে: {e}")

if __name__ == "__main__":
    decrypt_sportzx_json()
