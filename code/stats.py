#!/usr/bin/env python3
import re
import dns.resolver
import socket
import ssl
import subprocess
import time
from datetime import datetime

# Paramètres pour timeout et délai
TIMEOUT_SECONDS = 10
DELAY_BETWEEN = 2  # secondes entre chaque test

# Vérifier la syntaxe d'un domaine
def check_domain_syntax(domain):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(pattern, domain) is not None

# Vérifier si un domaine possède un enregistrement MX
def has_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=TIMEOUT_SECONDS)
        return True if answers else False
    except Exception:
        return False

# Récupérer les enregistrements TXT d'un nom
def get_txt_record(name):
    try:
        answers = dns.resolver.resolve(name, 'TXT', lifetime=TIMEOUT_SECONDS)
        return [str(rdata.to_text().strip('"')) for rdata in answers]
    except Exception:
        return []

# Filtrer les enregistrements TXT dont le début correspond à l'un des préfixes
def extract_relevant_txt(records, prefixes):
    return [record for record in records if any(record.startswith(prefix) for prefix in prefixes)]

# Vérifier DMARC et extraire la politique
def check_dmarc(domain):
    records = get_txt_record(f"_dmarc.{domain}")
    dmarc_records = extract_relevant_txt(records, ["v=DMARC1"])
    if not dmarc_records:
        return None
    dmarc = dmarc_records[0]
    policy_match = re.search(r"p=([a-zA-Z]+)", dmarc)
    policy = policy_match.group(1).lower() if policy_match else "none"
    return (dmarc, policy)

# Vérifier SPF et extraire la politique
def check_spf(domain):
    records = get_txt_record(domain)
    spf_records = extract_relevant_txt(records, ["v=spf1"])
    if not spf_records:
        return None
    spf = spf_records[0]
    if "~all" in spf:
        return (spf, "softfail")
    elif "-all" in spf:
        return (spf, "strict")
    elif "+all" in spf:
        return (spf, "dangerous")
    return (spf, None)

# Vérifier DKIM en testant plusieurs sélecteurs
def check_dkim(domain):
    selectors = ["default", "google", "microsoft", "mail", "selector1"]
    for selector in selectors:
        records = get_txt_record(f"{selector}._domainkey.{domain}")
        dkim_records = extract_relevant_txt(records, ["v=DKIM1"])
        if dkim_records:
            return "\n".join(dkim_records)
    return None

def main():
    filename = "TLD.txt"
    domains = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # On ne garde que les domaines en .fr
            if line.endswith(".fr"):
                domains.append(line)
  
  # A CHANGER NE FONCTION DU NOMBRE DE DOMAINES A TESTER
    domains = domains[:1000]
    
    total = 0
    count_mx = 0
    count_dmarc = 0
    count_spf = 0
    count_dkim = 0

    print("Début du recensement sur les 100 premiers domaines de la zone .fr...\n")
    for domain in domains:
        total += 1
        print(f"Traitement de {domain} ...")
        if not has_mx(domain):
            print(f"  - Aucun enregistrement MX détecté, ce domaine n'a pas de serveur mail.")
            time.sleep(DELAY_BETWEEN)
            continue
        count_mx += 1

        # Vérification DMARC
        dmarc_result = check_dmarc(domain)
        if dmarc_result:
            count_dmarc += 1
            dmarc_policy = dmarc_result[1]
        else:
            dmarc_policy = "absent"

        # Vérification SPF
        spf_result = check_spf(domain)
        if spf_result:
            count_spf += 1
            spf_policy = spf_result[1]
        else:
            spf_policy = "absent"

        # Vérification DKIM
        dkim_result = check_dkim(domain)
        if dkim_result:
            count_dkim += 1
        else:
            dkim_result = "absent"
        
        print(f"  - DMARC: {dmarc_policy} | SPF: {spf_policy} | DKIM: {'présent' if dkim_result != 'absent' else 'absent'}")
        time.sleep(DELAY_BETWEEN)

    print("\n=== Statistiques ===")
    print(f"Domaines traités : {total}")
    print(f"Domaines avec MX (serveur mail) : {count_mx}")
    print(f"Domaines protégés par DMARC : {count_dmarc}")
    print(f"Domaines protégés par SPF : {count_spf}")
    print(f"Domaines protégés par DKIM : {count_dkim}")

if __name__ == "__main__":
    main()
