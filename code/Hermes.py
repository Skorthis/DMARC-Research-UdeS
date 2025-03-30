#!/usr/bin/env python3
import re
import dns.resolver
import socket
import ssl
import subprocess
import argparse
import time
import readline  # Pour l'édition avec les flèches dans CLI
from datetime import datetime
from fpdf import FPDF  # Pour générer le PDF


# Librairies pour l'affichage amélioré
try:
    from rich.console import Console
    from rich.table import Table
    from rich.status import Status
except ImportError:
    Console = None

try:
    import pyfiglet
except ImportError:
    pyfiglet = None

console = Console() if Console else None

# Affichage de l'ASCII Art avec le nom mythologique "Hermes"
def print_banner():
    tool_name = "Hermes"
    try:
        ascii_art = pyfiglet.figlet_format(tool_name, font="doom")
    except Exception:
        ascii_art = f"*** {tool_name} ***"
    if console:
        console.print(f"[bold cyan]{ascii_art}[/bold cyan]")
    else:
        print(ascii_art)

# Vérifier la syntaxe d'un domaine
def check_domain_syntax(domain):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return re.match(pattern, domain) is not None

# Récupérer les enregistrements TXT
def get_txt_record(name):
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        return [str(rdata.to_text().strip('"')) for rdata in answers]
    except Exception:
        return []

# Filtrer les enregistrements qui commencent par l'un des préfixes donnés
def extract_relevant_txt(records, prefixes):
    return [record for record in records if any(record.startswith(prefix) for prefix in prefixes)]

# Vérifier DMARC et extraire la politique
def check_dmarc(domain):
    records = get_txt_record(f"_dmarc.{domain}")
    dmarc_records = extract_relevant_txt(records, ["v=DMARC1"])
    if not dmarc_records:
        return "Manquant", None
    dmarc = dmarc_records[0]
    policy_match = re.search(r"p=([a-zA-Z]+)", dmarc)
    policy = policy_match.group(1).lower() if policy_match else "none"
    return dmarc, policy

# Vérifier SPF et extraire la politique
def check_spf(domain):
    records = get_txt_record(domain)
    spf_records = extract_relevant_txt(records, ["v=spf1"])
    if not spf_records:
        return "Manquant", None
    spf = spf_records[0]
    if "~all" in spf:
        return spf, "softfail"
    elif "-all" in spf:
        return spf, "strict"
    elif "+all" in spf:
        return spf, "dangerous"
    return spf, None

# Vérifier DKIM en testant plusieurs sélecteurs
def check_dkim(domain):
    selectors = ["default", "google", "microsoft", "mail", "selector1"]
    for selector in selectors:
        records = get_txt_record(f"{selector}._domainkey.{domain}")
        dkim_records = extract_relevant_txt(records, ["v=DKIM1"])
        if dkim_records:
            return "\n".join(dkim_records)
    return "Manquant"

# Récupérer le WHOIS complet via la commande système
def get_full_whois_info(domain):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20)
        output = result.stdout.strip() or result.stderr.strip()
        return output if output else "Non disponible"
    except Exception:
        return "Non disponible"

# Extraction des informations WHOIS avec des expressions régulières plus souples
def get_whois_info(domain):
    full_whois = get_full_whois_info(domain)
    if full_whois == "Non disponible":
        return full_whois

    # Dictionnaire des patterns avec des expressions régulières plus souples. Après recherches sur internet
    patterns = {
        "Domain Name": r"Domain Name\s*:\s*(.+)",
        "Registrar": r"Registrar\s*:\s*(.+)",
        "Creation Date": r"(?:Creation Date|Created On)\s*:\s*(.+)",
        "Expiry Date": r"(?:Registry Expiry Date|Expiration Date|Expires On)\s*:\s*(.+)",
        "DNSSEC": r"DNSSEC\s*:\s*(.+)",
        "Registrant Organization": r"Registrant Organization\s*:\s*(.+)"
    }

    info = {}
    for label, pattern in patterns.items():
        match = re.search(pattern, full_whois, re.IGNORECASE)
        if match:
            info[label] = match.group(1).strip()

    if info:
        return "\n".join([f"{k}: {v}" for k, v in info.items()])
    else:
        return "Données WHOIS insuffisantes."

# Récupérer les informations du certificat SSL/TLS en testant plusieurs ports
def get_ssl_certificate_info(domain):
    context = ssl.create_default_context()
    ports = [443, 465, 587]
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(cert.get("issuer", []))
                    return f"🔒 Émis par : {issuer.get('commonName', 'Inconnu')}\n📅 Expire le : {cert.get('notAfter', 'Inconnu')}"
        except Exception:
            continue
    return "Non trouvé"

# Calculer le score en fonction des résultats
def calculate_score(results):
    score = 0
    if "v=DMARC1" in results["dmarc"]:
        score += 20 if results["dmarc_policy"] != "none" else 10
    if "v=spf1" in results["spf"]:
        score += 20 if results["spf_policy"] == "strict" else 10
    if "v=DKIM1" in results["dkim"]:
        score += 20
    if "🔒 Émis par" in results["ssl_cert"]:
        score += 20
    if ("Registrar:" in results["whois"]) or ("Registrar" in results["whois"]):
        score += 10
    return score

# Afficher les résultats dans la console
def print_results(domain, results, score):
    if console:
        table = Table(title=f"🔍 Analyse complète de {domain}")
        table.add_column("Test", style="cyan", no_wrap=True)
        table.add_column("Résultat", style="magenta")
        table.add_row("DMARC", results["dmarc"])
        table.add_row("SPF", results["spf"])
        table.add_row("DKIM", results["dkim"])
        table.add_row("WHOIS", results["whois"])
        table.add_row("Certificat SSL", results["ssl_cert"])
        table.add_row("Score global", f"{score} / 100")
        console.print(table)
    else:
        print(f"\n=== Analyse complète de {domain} ===")
        for key, value in results.items():
            print(f"{key} : {value}")
        print(f"\nScore global : {score} / 100")





# Générer un rapport PDF détaillé
def generate_pdf(domain, results, score, pdf_filename):
    pdf = FPDF()
    pdf.add_page()
    
    # Titre
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, f"Rapport d'analyse de sécurité pour {domain}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)
    
    # Résumé de la configuration
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Résumé de la configuration :", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    pdf.multi_cell(0, 8, f"DMARC:\n{results['dmarc']}\n")
    pdf.multi_cell(0, 8, f"SPF:\n{results['spf']}\n")
    pdf.multi_cell(0, 8, f"DKIM:\n{results['dkim']}\n")
    pdf.multi_cell(0, 8, f"WHOIS (résumé):\n{results['whois']}\n")
    pdf.multi_cell(0, 8, f"Certificat SSL:\n{results['ssl_cert']}\n")
    pdf.cell(0, 10, f"Score global: {score} / 100", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Informations complémentaires :", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    info_text = (
        "DMARC (Domain-based Message Authentication, Reporting, and Conformance) permet de vérifier que les courriels proviennent bien du domaine déclaré et d'indiquer aux récepteurs la manière de traiter les messages non authentifiés.\n\n"
        "SPF (Sender Policy Framework) définit la liste des serveurs autorisés à envoyer des courriels pour un domaine.\n\n"
        "DKIM (DomainKeys Identified Mail) ajoute une signature numérique aux courriels afin d'assurer leur intégrité et leur authenticité.\n\n"
        "Les certificats SSL/TLS garantissent la sécurité des communications via HTTPS.\n\n"
        "Les informations WHOIS permettent de vérifier la propriété et la gestion d'un domaine."
    )
    pdf.multi_cell(0, 8, info_text)
    
    pdf.ln(5)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Remédiations proposées :", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    remediation_text = ""
    if results["dmarc_policy"] == "none":
        remediation_text += ("- DMARC est en mode 'p=none'. Envisagez de passer à 'p=quarantine' ou 'p=reject'.\nGuide DMARC: https://dmarcian.com/dmarc-record-wizard/\n\n")
    if results["spf_policy"] in ["softfail", "dangerous"]:
        remediation_text += ("- SPF utilise une politique laxiste ('~all' ou '+all'). Pour une sécurité optimale, utilisez '-all'.\nGuide SPF: https://www.spfwizard.net/\n\n")
    if "v=DKIM1" not in results["dkim"]:
        remediation_text += ("- DKIM est manquant. Activez DKIM pour signer vos courriels.\nGuide DKIM: https://www.mailgun.com/blog/email-security/what-is-dkim/\n\n")
    if "🔒 Émis par" not in results["ssl_cert"]:
        remediation_text += ("- Aucun certificat SSL/TLS valide détecté. Installez un certificat SSL/TLS.\nGuide SSL: https://letsencrypt.org/getting-started/\n\n")
    if ("Registrar:" not in results["whois"]) and ("Registrar" not in results["whois"]):
        remediation_text += ("- Les informations WHOIS sont insuffisantes. Vérifiez et mettez à jour vos données WHOIS.\nGuide WHOIS: https://www.icann.org/resources/pages/whois-2012-02-25-en\n\n")
    pdf.multi_cell(0, 8, remediation_text)
    
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Rapport WHOIS complet :", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 10)
    full_whois = get_full_whois_info(domain)
    try:
        full_whois_clean = full_whois.encode("latin-1", errors="replace").decode("latin-1")
    except Exception:
        full_whois_clean = "Erreur lors de l'encodage du rapport WHOIS."
    pdf.multi_cell(0, 6, full_whois_clean)
    
    try:
        pdf.output(pdf_filename)
        if console:
            console.print(f"[bold green]Rapport PDF généré avec succès : {pdf_filename}[/bold green]")
        else:
            print(f"\nRapport PDF généré avec succès : {pdf_filename}")
    except Exception as e:
        if console:
            console.print(f"[bold red]Erreur lors de la génération du PDF : {str(e)}[/bold red]")
        else:
            print(f"\nErreur lors de la génération du PDF : {str(e)}")

# Demander un domaine valide (avec readline pour l'historique)
def get_valid_domain():
    while True:
        domain = input("Entrez le nom de domaine à vérifier : ").strip().lower()
        if check_domain_syntax(domain):
            return domain
        print("\n❌ Erreur : Nom de domaine invalide. Veuillez réessayer.")




# _-_-_-_-_-_-_-_-_-_- MAIN -_-_-_-_--__-_-_-_-_-_-_--_-_-_-_-_-_-_-_-


# Fonction principale
def main():
    print_banner()
    print("Bienvenue dans Hermes, un outil d’analyse de la sécurité des courriels.\n")
    
    parser = argparse.ArgumentParser(
        description="Outil de diagnostic de configuration de courriel (DMARC, SPF, DKIM, WHOIS, certificat SSL)"
    )
    parser.add_argument("domain", nargs="?", help="Nom de domaine à analyser")
    args = parser.parse_args()

    domain = args.domain.strip().lower() if args.domain else get_valid_domain()
    results = {}

    if console:
        with console.status("[bold green]Analyse en cours...[/bold green]", spinner="dots"):
            time.sleep(1.5)
            dmarc_str, dmarc_policy = check_dmarc(domain)
            results["dmarc"] = dmarc_str
            results["dmarc_policy"] = dmarc_policy if dmarc_policy else "none"
            spf_str, spf_policy = check_spf(domain)
            results["spf"] = spf_str
            results["spf_policy"] = spf_policy if spf_policy else "indéfini"
            results["dkim"] = check_dkim(domain)
            results["whois"] = get_whois_info(domain)
            results["ssl_cert"] = get_ssl_certificate_info(domain)
            time.sleep(1)
    else:
        print("Analyse en cours...")
        time.sleep(1.5)
        dmarc_str, dmarc_policy = check_dmarc(domain)
        results["dmarc"] = dmarc_str
        results["dmarc_policy"] = dmarc_policy if dmarc_policy else "none"
        spf_str, spf_policy = check_spf(domain)
        results["spf"] = spf_str
        results["spf_policy"] = spf_policy if spf_policy else "indéfini"
        results["dkim"] = check_dkim(domain)
        results["whois"] = get_whois_info(domain)
        results["ssl_cert"] = get_ssl_certificate_info(domain)
        time.sleep(1)

    score = calculate_score(results)
    print_results(domain, results, score)

    print("\n=== 🔧 Suggestions de Remédiation ===")
    if results["dmarc_policy"] == "none":
        print(" - ⚠ DMARC est en mode 'p=none'. Envisagez de passer à 'p=quarantine' ou 'p=reject'. [Guide DMARC](https://dmarcian.com/dmarc-record-wizard/)")
    if results["spf_policy"] in ["softfail", "dangerous"]:
        print(" - ⚠ SPF utilise une politique laxiste ('~all' ou '+all'). Pour une sécurité optimale, optez pour '-all'. [Guide SPF](https://www.spfwizard.net/)")
    if "v=DKIM1" not in results["dkim"]:
        print(" - ⚠ DKIM est manquant. Configurez DKIM pour signer vos courriels. [Guide DKIM](https://www.mailgun.com/blog/email-security/what-is-dkim/)")
    if "🔒 Émis par" not in results["ssl_cert"]:
        print(" - ⚠ Aucun certificat SSL/TLS valide détecté. Installez un certificat SSL/TLS. [Guide SSL](https://letsencrypt.org/getting-started/)")
    if ("Registrar:" not in results["whois"]) and ("Registrar" not in results["whois"]):
        print(" - ⚠ Les informations WHOIS semblent insuffisantes. Vérifiez vos données WHOIS. [Guide WHOIS](https://www.icann.org/resources/pages/whois-2012-02-25-en)")

    user_choice = input("\nVoulez-vous générer un rapport PDF détaillé ? (O/N) : ").strip().lower()
    if user_choice in ["o", "oui"]:
        pdf_filename = f"rapport_{domain.replace('.', '_')}.pdf"
        generate_pdf(domain, results, score, pdf_filename)


if __name__ == "__main__":
    main()
