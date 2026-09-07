import streamlit as st
import re
import base64
import requests
import whois
from ipwhois import IPWhois
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from urllib.parse import urlparse
from google import genai

st.set_page_config(page_title="ThreatLens", page_icon="🔍", layout="wide")

# --- ARCHITECTURE: CORE MODELS & REGISTRY ---
@dataclass
class ProviderResult:
    provider_name: str
    status: str  # "clean", "suspicious", "malicious", "unknown", "error"
    malicious_count: int = 0
    total_scans: int = 0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    key_findings: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

PROVIDER_REGISTRY: Dict[str, List[Callable]] = {"ip": [], "domain": [], "url": []}

def register_provider(supported_types: List[str]):
    def decorator(func):
        for t in supported_types:
            if t in PROVIDER_REGISTRY:
                PROVIDER_REGISTRY[t].append(func)
        return func
    return decorator

# --- INPUT VALIDATION & AUTO-DETECTION ---
def sanitize_input(text: str) -> str:
    text = text.strip()
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = text.replace("hxxp", "http").replace("hXXp", "http")
    return text

def detect_target_type(target: str) -> str:
    target = sanitize_input(target)
    
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$"
    if re.match(ipv4_pattern, target) or re.match(ipv6_pattern, target):
        return "ip"
    
    if target.startswith("http://") or target.startswith("https://") or "/" in target:
        return "url"
        
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, target):
        return "domain"
        
    return "unknown"

# --- PLUGINS: INTELLIGENCE PROVIDERS ---

@register_provider(["ip", "domain", "url"])
def virustotal_provider(target: str, target_type: str, api_keys: dict) -> ProviderResult:
    api_key = api_keys.get("vt")
    if not api_key:
        return ProviderResult("VirusTotal", "error", error_message="API Key missing in secrets.toml.")
        
    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    
    try:
        if target_type == "ip":
            url = f"{base_url}/ip_addresses/{target}"
        elif target_type == "domain":
            url = f"{base_url}/domains/{target}"
        elif target_type == "url":
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"{base_url}/urls/{url_id}"
        else:
            return ProviderResult("VirusTotal", "error", error_message="Unsupported target type.")

        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 401:
            return ProviderResult("VirusTotal", "error", error_message="Invalid API Key.")
        elif response.status_code != 200:
            return ProviderResult("VirusTotal", "error", error_message=f"API Error {response.status_code}")
            
        data = response.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        
        status = "clean"
        if malicious > 0:
            status = "malicious" if malicious > 2 else "suspicious"
            
        findings = []
        if malicious > 0:
            findings.append(f"Flagged by {malicious} out of {total} security vendors.")
        else:
            findings.append("No security vendors flagged this target.")
            
        return ProviderResult("VirusTotal", status, malicious, total, data, findings)
        
    except Exception as e:
        return ProviderResult("VirusTotal", "error", error_message=str(e))


@register_provider(["ip", "domain", "url"])
def whois_provider(target: str, target_type: str, api_keys: dict) -> ProviderResult:
    try:
        findings = []
        raw_data = {}
        status = "clean"
        
        if target_type == "url":
            parsed = urlparse(target if "://" in target else f"http://{target}")
            target = parsed.netloc.split(":")[0]
            target_type = detect_target_type(target) 
            
        if target_type == "ip":
            obj = IPWhois(target)
            res = obj.lookup_rdap()
            raw_data = res
            asn = res.get("asn_description", "Unknown")
            findings.append(f"ASN/ISP: {asn}")
            
        else:
            res = whois.whois(target)
            raw_data = dict(res)
            
            creation_date = res.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                age = (datetime.now() - creation_date).days
                findings.append(f"Domain Age: {age} days")
                if age < 30:
                    status = "suspicious"
                    findings.append("⚠️ Domain is extremely new (less than 30 days old).")
            
            org = res.get('org') or res.get('registrar')
            if org:
                findings.append(f"Registrar/Org: {org}")

        return ProviderResult("WHOIS / RDAP", status, 0, 1, raw_data, findings)
        
    except Exception as e:
        return ProviderResult("WHOIS / RDAP", "error", error_message=f"Lookup failed: {str(e)}")


@register_provider(["ip", "domain", "url"])
def gemini_osint_provider(target: str, target_type: str, api_keys: dict) -> ProviderResult:
    api_key = api_keys.get("gemini")
    if not api_key:
        return ProviderResult("Gemini AI OSINT", "error", error_message="Gemini API Key missing in secrets.toml.")
    
    try:
        client = genai.Client(api_key=api_key)
        prompt = f"Act as a cybersecurity threat analyst. Provide a brief, factual 2-sentence OSINT background on this {target_type}: '{target}'. State its typical use cases, known reputation, and if it is a known benign entity (like Google DNS) or associated with threats."
        
        response = client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt,
        )
        
        return ProviderResult("Gemini AI OSINT", "unknown", 0, 1, {"ai_response": response.text}, [response.text])
    except Exception as e:
        return ProviderResult("Gemini AI OSINT", "error", error_message=f"Gemini Analysis Failed: {str(e)}")


# --- UI & FORMATTING ENGINE ---
def render_beginner_view(results: List[ProviderResult]):
    st.subheader("Executive Summary")
    is_malicious = any(r.status == "malicious" for r in results)
    is_suspicious = any(r.status == "suspicious" for r in results)
    
    if is_malicious:
        st.error("🔴 **DANGER: This target is Malicious.** We highly advise against visiting this link or interacting with this IP/Domain. Close it immediately.")
    elif is_suspicious:
        st.warning("🟡 **CAUTION: This target is Suspicious.** It has some red flags. Proceed with extreme caution.")
    else:
        st.success("🟢 **CLEAN: No immediate threats detected.** Our engines did not find known malicious activity.")
        
    st.write("### Key Findings:")
    for r in results:
        if r.error_message:
            continue
        for f in r.key_findings:
            st.markdown(f"- **{r.provider_name}:** {f}")

def render_intermediate_view(results: List[ProviderResult]):
    st.subheader("Security Breakdown")
    cols = st.columns(len(results))
    
    for idx, r in enumerate(results):
        with cols[idx]:
            st.markdown(f"### {r.provider_name}")
            if r.error_message:
                st.error(f"Error: {r.error_message}")
                continue
                
            if r.total_scans > 1:
                st.metric("Engines Flagged", f"{r.malicious_count} / {r.total_scans}")
            
            for f in r.key_findings:
                st.markdown(f"- {f}")

def render_expert_view(results: List[ProviderResult]):
    st.subheader("Raw Threat Intelligence")
    tabs = st.tabs([r.provider_name for r in results])
    
    for tab, r in zip(tabs, results):
        with tab:
            if r.error_message:
                st.error(f"Error: {r.error_message}")
            else:
                st.markdown(f"**Calculated Status:** `{r.status.upper()}`")
                st.json(r.raw_data)

# --- STREAMLIT APP RUNNER ---
def main():
    st.title("🔍 ThreatLens")
    st.markdown("Advanced Threat Intelligence Aggregator with Zero-Touch Extensibility.")
    
    # Retrieve secrets natively
    keys = {
        "vt": st.secrets.get("VT_API_KEY", ""),
        "gemini": st.secrets.get("GEMINI_API_KEY", "")
    }
    
    with st.sidebar:
        st.header("⚙️ System Status")
        st.success("✅ Secrets Loaded") if keys["vt"] and keys["gemini"] else st.warning("⚠️ Missing API Keys in secrets.toml")
        
        st.markdown("---")
        st.markdown("**Active Provider Plugins:**")
        for p_type, providers in PROVIDER_REGISTRY.items():
            st.markdown(f"- **{p_type.upper()}:** {len(providers)} registered")
            
    col1, col2 = st.columns([3, 1])
    with col1:
        raw_input = st.text_input("Target (IP / Domain / URL):", placeholder="e.g., example.com, 8.8.8.8, hxxps://badsite[.]com")
    
    detected_type = detect_target_type(raw_input) if raw_input else "unknown"
    
    with col2:
        type_options = ["Auto-detect", "ip", "domain", "url"]
        default_idx = 0 if detected_type == "unknown" else type_options.index(detected_type)
        target_type = st.selectbox("Override Type", type_options, index=default_idx)
    
    if target_type == "Auto-detect":
        target_type = detected_type

    if raw_input:
        if target_type == "unknown":
            st.warning("⚠️ Could not automatically detect format. Please select type manually.")
        else:
            st.info(f"Analyzed as: **{target_type.upper()}**")
        
    knowledge_level = st.radio("Display Level:", ["Beginner", "Intermediate", "Expert"], horizontal=True)
    
    if st.button("Scan Target", type="primary", use_container_width=True):
        if not raw_input or target_type == "unknown":
            st.warning("Please enter a valid target to scan.")
            return
            
        target = sanitize_input(raw_input)
        providers = PROVIDER_REGISTRY.get(target_type, [])
        
        with st.spinner(f"Gathering Threat Intelligence using {len(providers)} providers..."):
            results = []
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_provider = {
                    executor.submit(p, target, target_type, keys): p for p in providers
                }
                for future in concurrent.futures.as_completed(future_to_provider):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        st.error(f"Provider execution failed: {str(e)}")

            st.markdown("---")
            if knowledge_level == "Beginner":
                render_beginner_view(results)
            elif knowledge_level == "Intermediate":
                render_intermediate_view(results)
            else:
                render_expert_view(results)

if __name__ == "__main__":
    main()
