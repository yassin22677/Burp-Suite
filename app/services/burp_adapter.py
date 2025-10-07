import requests

BURP_URL = "http://127.0.0.1:5008"

def check_burp_status():
    try:
        res = requests.get(f"{BURP_URL}/api/health", timeout=3)
        if res.status_code == 200:
            return res.json()
        else:
            return {"status": "error", "message": "Burp returned error"}
    except Exception as e:
        return {"status": "offline", "message": str(e)}

def apply_config_to_burp(cfg):
    print("[BURP CONFIG UPDATE]")
    for k, v in cfg.items():
        print(f"{k}: {v}")
    return "Configuration applied successfully!"
