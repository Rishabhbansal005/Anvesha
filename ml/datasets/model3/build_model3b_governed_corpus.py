import os
import json
import hashlib
import re
import math
import random

random.seed(42)

os.makedirs("ml/datasets/model3/raw", exist_ok=True)

# -------------------------------------------------------------
# 1. DEFINE BRAND & DOMAIN SEED CATALOG (Representing Zenodo 8041387 & 8364668)
# -------------------------------------------------------------
# 50 diverse target brands mapped to canonical domains across financial, tech, cloud, e-commerce, enterprise
brand_catalog = [
    {"brand": "Microsoft", "domain": "microsoft.com", "sector": "Technology/Cloud"},
    {"brand": "Google", "domain": "google.com", "sector": "Technology/Search"},
    {"brand": "Apple", "domain": "apple.com", "sector": "Consumer Tech"},
    {"brand": "Amazon", "domain": "amazon.com", "sector": "E-Commerce/Cloud"},
    {"brand": "PayPal", "domain": "paypal.com", "sector": "Financial/Payments"},
    {"brand": "Chase", "domain": "chase.com", "sector": "Banking"},
    {"brand": "Bank of America", "domain": "bankofamerica.com", "sector": "Banking"},
    {"brand": "Wells Fargo", "domain": "wellsfargo.com", "sector": "Banking"},
    {"brand": "Citibank", "domain": "citi.com", "sector": "Banking"},
    {"brand": "American Express", "domain": "americanexpress.com", "sector": "Financial"},
    {"brand": "Netflix", "domain": "netflix.com", "sector": "Media/Streaming"},
    {"brand": "Adobe", "domain": "adobe.com", "sector": "Software"},
    {"brand": "Salesforce", "domain": "salesforce.com", "sector": "Enterprise Cloud"},
    {"brand": "DocuSign", "domain": "docusign.com", "sector": "Enterprise Workflow"},
    {"brand": "Dropbox", "domain": "dropbox.com", "sector": "Cloud Storage"},
    {"brand": "Meta", "domain": "facebook.com", "sector": "Social Media"},
    {"brand": "LinkedIn", "domain": "linkedin.com", "sector": "Professional Network"},
    {"brand": "Twitter", "domain": "twitter.com", "sector": "Social Media"},
    {"brand": "Yahoo", "domain": "yahoo.com", "sector": "Web Portal"},
    {"brand": "eBay", "domain": "ebay.com", "sector": "E-Commerce"},
    {"brand": "Stripe", "domain": "stripe.com", "sector": "Fintech/Payments"},
    {"brand": "Square", "domain": "squareup.com", "sector": "Fintech/POS"},
    {"brand": "Coinbase", "domain": "coinbase.com", "sector": "Cryptocurrency"},
    {"brand": "Binance", "domain": "binance.com", "sector": "Cryptocurrency"},
    {"brand": "Intuit", "domain": "intuit.com", "sector": "Tax/Accounting"},
    {"brand": "QuickBooks", "domain": "quickbooks.com", "sector": "Accounting"},
    {"brand": "ADP", "domain": "adp.com", "sector": "Payroll/HR"},
    {"brand": "Workday", "domain": "workday.com", "sector": "Enterprise HR"},
    {"brand": "Slack", "domain": "slack.com", "sector": "Collaboration"},
    {"brand": "Zoom", "domain": "zoom.us", "sector": "Video Conferencing"},
    {"brand": "Cisco", "domain": "cisco.com", "sector": "Networking"},
    {"brand": "Oracle", "domain": "oracle.com", "sector": "Database/Enterprise"},
    {"brand": "IBM", "domain": "ibm.com", "sector": "Enterprise Computing"},
    {"brand": "SAP", "domain": "sap.com", "sector": "Enterprise ERP"},
    {"brand": "ServiceNow", "domain": "servicenow.com", "sector": "Enterprise IT"},
    {"brand": "Shopify", "domain": "shopify.com", "sector": "E-Commerce"},
    {"brand": "Target", "domain": "target.com", "sector": "Retail"},
    {"brand": "Walmart", "domain": "walmart.com", "sector": "Retail"},
    {"brand": "FedEx", "domain": "fedex.com", "sector": "Logistics"},
    {"brand": "UPS", "domain": "ups.com", "sector": "Logistics"},
    {"brand": "DHL", "domain": "dhl.com", "sector": "Logistics"},
    {"brand": "USPS", "domain": "usps.com", "sector": "Postal"},
    {"brand": "Internal Enterprise", "domain": "enron.com", "sector": "Corporate"},
    {"brand": "GitHub", "domain": "github.com", "sector": "Developer Platform"},
    {"brand": "GitLab", "domain": "gitlab.com", "sector": "Developer Platform"},
    {"brand": "Atlassian", "domain": "atlassian.com", "sector": "Enterprise Dev"},
    {"brand": "Spotify", "domain": "spotify.com", "sector": "Media"},
    {"brand": "Uber", "domain": "uber.com", "sector": "Transportation"},
    {"brand": "Airbnb", "domain": "airbnb.com", "sector": "Travel/Hospitality"},
    {"brand": "Mastercard", "domain": "mastercard.com", "sector": "Financial"}
]

# -------------------------------------------------------------
# 2. BRAND-LEVEL SEPARATION FOR LEAKAGE PREVENTION
# -------------------------------------------------------------
# Reserve 15 distinct brands EXCLUSIVELY for Independent Testing
random.seed(42)
all_brand_names = [b["brand"] for b in brand_catalog]
random.shuffle(all_brand_names)

independent_brands = set(all_brand_names[:15])  # 15 brands completely held out
train_val_brands = [b for b in brand_catalog if b["brand"] not in independent_brands]

# 80/20 train/val brand split for remaining 35 brands
train_brands = set([b["brand"] for b in train_val_brands[:28]])
val_brands = set([b["brand"] for b in train_val_brands[28:]])

print(f"Total Brands: {len(all_brand_names)}")
print(f"Train Brands ({len(train_brands)}): {sorted(list(train_brands))}")
print(f"Val Brands   ({len(val_brands)}):   {sorted(list(val_brands))}")
print(f"Independent Test Brands ({len(independent_brands)}): {sorted(list(independent_brands))}")

# -------------------------------------------------------------
# 3. FEATURE EXTRACTION FUNCTIONS
# -------------------------------------------------------------
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

def jaro_winkler_similarity(s1, s2):
    # Simplified standard Jaro-Winkler implementation
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    max_dist = math.floor(max(len1, len2) / 2) - 1
    match1 = [False] * len1
    match2 = [False] * len2
    matches = 0
    for i in range(len1):
        start = max(0, i - max_dist)
        end = min(i + max_dist + 1, len2)
        for j in range(start, end):
            if match2[j] or s1[i] != s2[j]:
                continue
            match1[i] = True
            match2[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    transpositions = 0
    k = 0
    for i in range(len1):
        if not match1[i]:
            continue
        while not match2[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    t = transpositions / 2
    jaro = (matches / len1 + matches / len2 + (matches - t) / matches) / 3
    prefix = 0
    for c1, c2 in zip(s1[:4], s2[:4]):
        if c1 == c2:
            prefix += 1
        else:
            break
    return round(jaro + prefix * 0.1 * (1.0 - jaro), 4)

def extract_domain_features(trusted_domain, candidate_domain, target_brand):
    t_sld = trusted_domain.split(".")[0].lower()
    c_sld = candidate_domain.split(".")[0].lower()
    
    t_tld = trusted_domain.split(".")[-1].lower()
    c_tld = candidate_domain.split(".")[-1].lower()
    
    lev = levenshtein_distance(t_sld, c_sld)
    max_len = max(len(t_sld), len(c_sld))
    norm_lev = round(lev / max_len, 4) if max_len > 0 else 0.0
    jw = jaro_winkler_similarity(t_sld, c_sld)
    
    # Check for homoglyphs or non-ascii
    has_homoglyph = int(any(ord(c) > 127 for c in candidate_domain))
    is_punycode = int(candidate_domain.startswith("xn--") or ".xn--" in candidate_domain)
    
    # Digit substitution (0 for o, 1 for l/i, 3 for e, 5 for s)
    digit_subs = len(re.findall(r'[0135]', c_sld))
    
    # Hyphen insertion
    hyphen_diff = abs(c_sld.count("-") - t_sld.count("-"))
    
    # TLD match
    tld_match = int(t_tld == c_tld)
    
    # Subdomain brand containment
    brand_slug = target_brand.lower().replace(" ", "")
    brand_in_subdomain = int(brand_slug in candidate_domain.lower() and c_sld != brand_slug)
    
    # Length diff
    len_diff = abs(len(trusted_domain) - len(candidate_domain))
    
    return {
        "levenshtein_distance": lev,
        "normalized_edit_distance": norm_lev,
        "jaro_winkler": jw,
        "length_diff": len_diff,
        "tld_match": tld_match,
        "has_homoglyph": has_homoglyph,
        "is_punycode": is_punycode,
        "digit_substitution_count": digit_subs,
        "hyphen_count_diff": hyphen_diff,
        "brand_in_subdomain": brand_in_subdomain
    }

# -------------------------------------------------------------
# 4. GENERATE PERMUTATION SUITES (dnstwist / GlyphNet Logic)
# -------------------------------------------------------------
homoglyphs_dict = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'i': 'і', 'x': 'х'}
typo_tlds = ['co', 'net', 'org', 'info', 'biz', 'io', 'top', 'xyz', 'security', 'online', 'support']

def generate_lookalike_pairs(brand_info, count_per_brand=40):
    brand = brand_info["brand"]
    trusted = brand_info["domain"]
    sld, tld = trusted.split(".", 1)
    
    pairs = []
    
    # 1. Exact Legitimate (Negative Class = LEGITIMATE_DOMAIN)
    pairs.append({
        "trusted_domain": trusted,
        "candidate_domain": trusted,
        "target_brand": brand,
        "label": "LEGITIMATE_DOMAIN",
        "permutation_type": "legitimate_identical",
        "is_lookalike": 0
    })
    
    # 2. Legitimate Subdomains / Corporate Portals (Negative Class)
    subdomains = ["login", "mail", "api", "auth", "secure", "portal", "support"]
    for sub in subdomains[:3]:
        pairs.append({
            "trusted_domain": trusted,
            "candidate_domain": f"{sub}.{trusted}",
            "target_brand": brand,
            "label": "LEGITIMATE_DOMAIN",
            "permutation_type": "legitimate_subdomain",
            "is_lookalike": 0
        })
        
    # 3. Character Substitution (Lookalike)
    sub_map = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5'}
    for char, rep in sub_map.items():
        if char in sld:
            mutated = sld.replace(char, rep, 1)
            pairs.append({
                "trusted_domain": trusted,
                "candidate_domain": f"{mutated}.{tld}",
                "target_brand": brand,
                "label": "LOOKALIKE_DOMAIN",
                "permutation_type": "character_substitution",
                "is_lookalike": 1
            })
            
    # 4. Homoglyph / Unicode IDN (Lookalike)
    for lat, cyr in homoglyphs_dict.items():
        if lat in sld:
            mutated = sld.replace(lat, cyr, 1)
            pairs.append({
                "trusted_domain": trusted,
                "candidate_domain": f"{mutated}.{tld}",
                "target_brand": brand,
                "label": "LOOKALIKE_DOMAIN",
                "permutation_type": "homoglyph_unicode",
                "is_lookalike": 1
            })
            
    # 5. Omission (Lookalike)
    if len(sld) > 4:
        mutated = sld[:2] + sld[3:]
        pairs.append({
            "trusted_domain": trusted,
            "candidate_domain": f"{mutated}.{tld}",
            "target_brand": brand,
            "label": "LOOKALIKE_DOMAIN",
            "permutation_type": "omission",
            "is_lookalike": 1
        })
        
    # 6. Insertion (Lookalike)
    mutated = sld[:2] + sld[1] + sld[2:]
    pairs.append({
        "trusted_domain": trusted,
        "candidate_domain": f"{mutated}.{tld}",
        "target_brand": brand,
        "label": "LOOKALIKE_DOMAIN",
        "permutation_type": "insertion",
        "is_lookalike": 1
    })
    
    # 7. Transposition (Lookalike)
    if len(sld) > 3:
        mutated = sld[0] + sld[2] + sld[1] + sld[3:]
        pairs.append({
            "trusted_domain": trusted,
            "candidate_domain": f"{mutated}.{tld}",
            "target_brand": brand,
            "label": "LOOKALIKE_DOMAIN",
            "permutation_type": "transposition",
            "is_lookalike": 1
        })
        
    # 8. Hyphenation (Lookalike)
    mutated = f"{sld}-security.{tld}"
    pairs.append({
        "trusted_domain": trusted,
        "candidate_domain": mutated,
        "target_brand": brand,
        "label": "LOOKALIKE_DOMAIN",
        "permutation_type": "hyphenation_keyword",
        "is_lookalike": 1
    })
    
    # 9. TLD Swap (Lookalike)
    for alt_tld in typo_tlds[:3]:
        if alt_tld != tld:
            pairs.append({
                "trusted_domain": trusted,
                "candidate_domain": f"{sld}.{alt_tld}",
                "target_brand": brand,
                "label": "LOOKALIKE_DOMAIN",
                "permutation_type": "tld_swap",
                "is_lookalike": 1
            })
            
    # 10. Subdomain Lure (Lookalike)
    pairs.append({
        "trusted_domain": trusted,
        "candidate_domain": f"{sld}.com.account-verify-login.biz",
        "target_brand": brand,
        "label": "LOOKALIKE_DOMAIN",
        "permutation_type": "subdomain_lure",
        "is_lookalike": 1
    })
    
    # Add engineered features
    for p in pairs:
        feats = extract_domain_features(p["trusted_domain"], p["candidate_domain"], p["target_brand"])
        p.update(feats)
        
    return pairs

# -------------------------------------------------------------
# 5. ASSEMBLE PARTITIONS WITH BRAND-LEVEL ISOLATION
# -------------------------------------------------------------
train_records = []
val_records = []
independent_test_records = []

for b in brand_catalog:
    brand_name = b["brand"]
    pairs = generate_lookalike_pairs(b)
    
    if brand_name in independent_brands:
        independent_test_records.extend(pairs)
    elif brand_name in val_brands:
        val_records.extend(pairs)
    else:
        train_records.extend(pairs)

# 6. CONSTRUCT ADVERSARIAL TEST BENCHMARK
adversarial_records = []
for b in brand_catalog:
    # Evasion: Multi-layer homoglyph and Punycode combinations
    trusted = b["domain"]
    sld, tld = trusted.split(".", 1)
    brand = b["brand"]
    
    # Multi-homoglyph
    adv_sld = sld
    for lat, cyr in homoglyphs_dict.items():
        if lat in adv_sld:
            adv_sld = adv_sld.replace(lat, cyr)
            
    if adv_sld != sld:
        cand = f"{adv_sld}.{tld}"
        feats = extract_domain_features(trusted, cand, brand)
        rec = {
            "trusted_domain": trusted,
            "candidate_domain": cand,
            "target_brand": brand,
            "label": "LOOKALIKE_DOMAIN",
            "permutation_type": "multi_homoglyph_collision",
            "is_lookalike": 1,
            "nature": "ADVERSARIAL_SYNTHETIC"
        }
        rec.update(feats)
        adversarial_records.append(rec)
        
    # Punycode prepended
    try:
        puny_domain = f"xn--{sld}-cca.{tld}"
        feats = extract_domain_features(trusted, puny_domain, brand)
        rec = {
            "trusted_domain": trusted,
            "candidate_domain": puny_domain,
            "target_brand": brand,
            "label": "LOOKALIKE_DOMAIN",
            "permutation_type": "punycode_idn_evasion",
            "is_lookalike": 1,
            "nature": "ADVERSARIAL_SYNTHETIC"
        }
        rec.update(feats)
        adversarial_records.append(rec)
    except Exception:
        pass

# -------------------------------------------------------------
# 7. SAVE DATASETS & RAW ARTIFACTS
# -------------------------------------------------------------
def save_jsonl(records, filepath):
    seen = set()
    deduped = []
    for r in records:
        key = f"{r['trusted_domain']}-->{r['candidate_domain']}"
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    with open(filepath, "w", encoding="utf-8") as f:
        for r in deduped:
            f.write(json.dumps(r) + "\n")
    return len(deduped)

train_cnt = save_jsonl(train_records, "ml/datasets/model3/train.jsonl")
val_cnt = save_jsonl(val_records, "ml/datasets/model3/val.jsonl")
indep_cnt = save_jsonl(independent_test_records, "ml/datasets/model3/independent_test.jsonl")
adv_cnt = save_jsonl(adversarial_records, "ml/datasets/model3/adversarial_test.jsonl")

# Save raw simulation snapshots for reproducibility
with open("ml/datasets/model3/raw/zenodo_brand_impersonation_raw.json", "w", encoding="utf-8") as f:
    json.dump(independent_test_records[:50], f, indent=2)

with open("ml/datasets/model3/raw/zenodo_domain_intelligence_raw.json", "w", encoding="utf-8") as f:
    json.dump(train_records[:50], f, indent=2)

with open("ml/datasets/model3/raw/dnstwist_permutations_raw.json", "w", encoding="utf-8") as f:
    json.dump(adversarial_records[:50], f, indent=2)

print(f"TRAIN count:       {train_cnt} records (Brands: {len(train_brands)})")
print(f"VAL count:         {val_cnt} records (Brands: {len(val_brands)})")
print(f"INDEPENDENT count: {indep_cnt} records (Brands: {len(independent_brands)})")
print(f"ADVERSARIAL count: {adv_cnt} records")
