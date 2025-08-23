import requests
import json
from typing import List, Dict, Any
from datetime import datetime, timezone
from openai import OpenAI, NotFoundError, RateLimitError

# ---- Configuration ----
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"
MITRE_ATTACK_API = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SIGMA_RULES_REPO = "https://url-to-your-sigma-rules-repo"
OSINT_FEEDS = [
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    # Add more feeds as needed
]

# ---- LLM Wrapper ----
client = OpenAI(api_key=OPENAI_API_KEY)

# Select your preferred model from your available models:
# For chat: try 'gpt-4o', 'gpt-4o-2024-05-13', 'gpt-5', 'gpt-5-mini', 'gpt-5-nano', 'gpt-3.5-turbo', etc.
PREFERRED_MODELS = [
    "gpt-4o", "gpt-4o-2024-05-13", "gpt-5", "gpt-5-mini", "gpt-5-nano", 
    "gpt-3.5-turbo", "gpt-3.5-turbo-0125", "gpt-3.5-turbo-16k"
]

def get_best_model():
    available = [m.id for m in client.models.list().data]
    for m in PREFERRED_MODELS:
        if m in available:
            return m
    # fallback to first available chat model
    for m in available:
        if "turbo" in m or "gpt-4o" in m or "gpt-5" in m or "gpt-3.5" in m:
            return m
    raise RuntimeError("No suitable chat model available!")

CHAT_MODEL = get_best_model()

def query_llm(prompt: str) -> str:
    try:
        response = client.chat.completions.create(
            model=CHAT_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst LLM."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except NotFoundError as e:
        print(f"[Error] The specified OpenAI model '{CHAT_MODEL}' was not found or you do not have access.")
        models = client.models.list()
        print("You have access to the following models:", [m.id for m in models.data])
        raise
    except RateLimitError as e:
        print(f"[RateLimitError] {e}")
        print("You have exceeded your OpenAI API quota. Please check your usage and billing at https://platform.openai.com/usage")
        raise SystemExit(1)

# ---- Threat Intel Ingestion ----
def fetch_mitre_attack() -> Dict[str, Any]:
    r = requests.get(MITRE_ATTACK_API, timeout=20)
    r.raise_for_status()
    return r.json()

def fetch_sigma_rules() -> List[Dict[str, Any]]:
    # Simplified: In reality, you'd clone the repo and parse YAMLs
    return []  # Placeholder

def fetch_osint_feeds() -> List[str]:
    indicators = []
    for url in OSINT_FEEDS:
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            indicators += r.text.splitlines()
        except requests.exceptions.RequestException as e:
            print(f"[Warning] Could not fetch {url}: {e}")
            # Optionally: log or add fallback here
    return indicators

# ---- Alert Example ----
def fetch_recent_alerts() -> List[Dict[str, Any]]:
    # Replace with integration to SIEM, EDR, or log source
    return [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "Suspicious PowerShell activity",
            "src_ip": "192.168.1.44",
            "user": "alice",
            "cmd": "powershell.exe -enc ...",
            "raw": "...",
        }
    ]

# ---- Contextualization Engine ----
def contextualize_alert(alert: Dict[str, Any],
                       mitre_attack: Dict[str, Any],
                       sigma_rules: List[Dict[str, Any]],
                       osint_indicators: List[str]) -> str:
    context = {
        "alert": alert,
        "mitre_attack": mitre_attack,
        "sigma_rules": sigma_rules,
        "osint_indicators": osint_indicators,
    }
    prompt = (
        f"Given the following security alert and threat intel, generate a context-aware analysis.\n\n"
        f"Alert: {json.dumps(alert, indent=2)}\n\n"
        f"OSINT indicators (top 5): {osint_indicators[:5]}\n\n"
        f"MITRE ATT&CK data (summary): {mitre_attack.get('description', '')[:500]}...\n"
        f"Sigma rule count: {len(sigma_rules)}\n\n"
        f"Suggest likely ATT&CK techniques, possible threat actors, and mitigation steps. "
        f"Highlight any novel patterns or adaptation needs."
    )
    return query_llm(prompt)

# ---- Adaptation/Updating Mechanism ----
def retrain_or_update():
    # Placeholder: Could trigger fine-tuning, pull latest rules/intel, etc.
    print("Retraining/updating threat models and intelligence feeds...")

# ---- Main Loop ----
def main():
    print(f"Using OpenAI chat model: {CHAT_MODEL}")
    # Periodically update threat intelligence
    mitre_attack = fetch_mitre_attack()
    sigma_rules = fetch_sigma_rules()
    osint_indicators = fetch_osint_feeds()

    alerts = fetch_recent_alerts()
    for alert in alerts:
        insight = contextualize_alert(alert, mitre_attack, sigma_rules, osint_indicators)
        print(f"\n[Context-Aware Insight for Alert]\n{insight}\n{'-'*60}")

    # Schedule retraining/updating as needed
    retrain_or_update()

if __name__ == "__main__":
    main()