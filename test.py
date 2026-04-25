# 🔍 DEBUG: কোন id তে channel data আছে দেখার জন্য
for test_id in ['364', '365', '366', '367', '368', '369', '370', '371']:
    r = self.session.get(f"{base_api}/channels/{test_id}.json", timeout=10)
    try:
        data = r.json()
        decrypted = self._decrypt_source_data(data.get("data", ""))
        parsed = json.loads(decrypted) if decrypted else []
        print(f"ID {test_id}: {len(parsed)} channels")
    except:
        print(f"ID {test_id}: ❌ empty/error")
# 🔍 DEBUG END
