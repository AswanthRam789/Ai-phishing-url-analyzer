import os
import re
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()


class PhishingAssessment(BaseModel):
    phishing_intent_detected: bool = Field(
        description="True if the URL or page content shows phishing or credential harvesting."
    )
    risk_level: str = Field(
        description="Overall threat severity: Low, Medium, High, or Critical."
    )
    confidence_score: int = Field(
        description="Confidence percentage from 0 to 100."
    )
    impersonated_brand: str = Field(
        description="Name of the impersonated brand if applicable, otherwise None."
    )
    red_flags: list[str] = Field(
        description="List of technical or social engineering red flags observed."
    )
    analyst_summary: str = Field(
        description="Concise 2-sentence SOC analyst explanation of the verdict."
    )


class PhishingDetector:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key or api_key == "your_actual_api_key_here":
            raise ValueError("GEMINI_API_KEY is missing or invalid in your .env file.")
        self.client = genai.Client(api_key=api_key)

    def calculate_heuristic_score(self, lexical: dict, whois_info: dict, page_data: dict) -> tuple[int, list[str]]:
        score = 0
        triggers = []

        if lexical.get("is_ip_address"):
            score += 35
            triggers.append("Raw IP address used instead of a domain name (+35)")
        if lexical.get("has_at_symbol"):
            score += 20
            triggers.append("Contains '@' symbol used to obscure destination (+20)")
        if not lexical.get("uses_https"):
            score += 15
            triggers.append("Insecure HTTP connection without TLS/HTTPS (+15)")
        if lexical.get("subdomain_count", 0) > 2:
            score += 15
            triggers.append(f"Excessive subdomains ({lexical['subdomain_count']}) detected (+15)")
        if lexical.get("hyphen_count", 0) > 3:
            score += 10
            triggers.append("Multiple hyphens in URL typical of typosquatting (+10)")

        age = whois_info.get("domain_age_days")
        if age is not None:
            if age < 30:
                score += 30
                triggers.append(f"Newly registered domain ({age} days old) (+30)")
            elif age < 90:
                score += 15
                triggers.append(f"Relatively young domain ({age} days old) (+15)")

        if page_data.get("has_password_field") and (not lexical.get("uses_https") or (age is not None and age < 90)):
            score += 25
            triggers.append("Login form detected on unencrypted or newly registered domain (+25)")

        return min(score, 100), triggers

    def _offline_fallback_analysis(self, lexical: dict, whois_info: dict, page_data: dict) -> PhishingAssessment:
        heuristic_score, red_flags = self.calculate_heuristic_score(lexical, whois_info, page_data)
        nlp_score = 0

        combined_text = (
            f"{lexical.get('normalized_url', '')} "
            f"{page_data.get('title', '')} "
            f"{page_data.get('text_snippet', '')}"
        ).lower()
        registered_domain = lexical.get("registered_domain", "").lower()

        brands = ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "hdfc", "icici", "sbi", "bank"]
        impersonated = "None"
        for brand in brands:
            if brand in combined_text and brand not in registered_domain:
                impersonated = brand.capitalize()
                nlp_score += 35
                red_flags.append(f"Brand impersonation: '{impersonated}' referenced on unrelated domain '{registered_domain}'")
                break

        urgency_phrases = ["urgent", "suspended", "verify", "unusual login", "24 hours", "action required", "limited"]
        matched = [kw for kw in urgency_phrases if re.search(rf"\b{re.escape(kw)}\b", combined_text)]
        if matched:
            nlp_score += min(len(matched) * 12, 40)
            red_flags.append(f"Social engineering urgency cues: {', '.join(matched)}")

        total_risk = min(int((heuristic_score * 0.6) + (nlp_score * 0.7)), 100)
        risk_level = "Critical" if total_risk >= 75 else "High" if total_risk >= 50 else "Medium" if total_risk >= 25 else "Low"
        is_phishing = total_risk >= 50

        return PhishingAssessment(
            phishing_intent_detected=is_phishing,
            risk_level=risk_level,
            confidence_score=max(total_risk, 15) if is_phishing else (100 - total_risk),
            impersonated_brand=impersonated,
            red_flags=red_flags if red_flags else ["No suspicious indicators detected."],
            analyst_summary=f"[Local Fallback Engine] Assessed {risk_level.lower()} phishing risk ({total_risk}/100) based on lexical, WHOIS, and keyword telemetry.",
        )

    def analyze_with_ai(self, lexical: dict, whois_info: dict, page_data: dict) -> PhishingAssessment:
        prompt = f"""
        You are a Senior Cybersecurity SOC Analyst specializing in phishing triage.
        Evaluate the following URL, OSINT data, and scraped webpage content for phishing intent.

        Target URL: {lexical.get('normalized_url')}
        Final Redirected URL: {page_data.get('final_url')}
        Registered Domain: {lexical.get('registered_domain')}
        Domain Age (Days): {whois_info.get('domain_age_days')}
        Registrar: {whois_info.get('registrar')}
        Has Password Field: {page_data.get('has_password_field')}
        Form Actions: {page_data.get('form_actions')}
        Page Title: {page_data.get('title')}
        Visible Text: "{page_data.get('text_snippet')}"
        """

        models_to_try = [
            "gemini-3.8-flash",
            "gemini-3.5-flash-lite",
            "gemini-3.6-flash",
            "gemini-3.1-flash-lite",
        ]

        for model_name in models_to_try:
            try:
                response = self.client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=PhishingAssessment,
                        temperature=0.1,
                    ),
                )
                return PhishingAssessment.model_validate_json(response.text)
            except Exception as e:
                print(f"[!] {model_name} unavailable ({type(e).__name__}), trying next model...")

        print("[!] Cloud API models temporarily overloaded. Using local heuristic/NLP fallback...")
        return self._offline_fallback_analysis(lexical, whois_info, page_data)


if __name__ == "__main__":
    detector = PhishingDetector()
    mock_lexical = {
        "normalized_url": "http://paypal-security-alert-login.xyz/verify",
        "registered_domain": "paypal-security-alert-login.xyz",
        "uses_https": False,
        "is_ip_address": False,
        "has_at_symbol": False,
        "subdomain_count": 0,
        "hyphen_count": 3,
    }
    mock_whois = {"domain_age_days": 4, "registrar": "NameCheap, Inc."}
    mock_page = {
        "final_url": "http://paypal-security-alert-login.xyz/verify",
        "title": "PayPal Security Center - Urgent Action Required",
        "has_password_field": True,
        "form_actions": ["http://evil-harvester.ru/steal.php"],
        "text_snippet": "Your PayPal account has been temporarily limited due to unusual login activity. Verify your password within 24 hours.",
    }

    score, rules = detector.calculate_heuristic_score(mock_lexical, mock_whois, mock_page)
    print(f"Heuristic Score: {score}/100")
    print("Triggered Rules:", rules)

    print("\nRunning Gemini AI Triage...")
    ai_result = detector.analyze_with_ai(mock_lexical, mock_whois, mock_page)
    print(ai_result.model_dump_json(indent=2))