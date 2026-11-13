import requests
from bs4 import BeautifulSoup


def scrape_url_content(url: str, timeout: int = 8) -> dict:
    """Safely fetches and parses HTML content from a target URL."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        # Pass raw bytes (response.content) so BeautifulSoup handles character encodings cleanly
        soup = BeautifulSoup(response.content, "html.parser")

        # Remove non-visible script and style tags
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        title = soup.title.get_text(strip=True) if soup.title else "No Title Found"
        
        # Extract clean visible text (capped at 2,500 chars for LLM token efficiency)
        visible_text = " ".join(soup.stripped_strings)[:2500]

        # Security check: Look for password fields and form targets
        password_inputs = soup.find_all("input", {"type": "password"})
        forms = soup.find_all("form")
        form_actions = [form.get("action", "") for form in forms if form.get("action")]

        return {
            "reachable": True,
            "status_code": response.status_code,
            "final_url": response.url,  # Captures if the URL redirected elsewhere
            "title": title,
            "has_password_field": len(password_inputs) > 0,
            "form_actions": form_actions,
            "text_snippet": visible_text,
            "error": None
        }

    except requests.exceptions.RequestException as e:
        return {
            "reachable": False,
            "status_code": None,
            "final_url": url,
            "title": "",
            "has_password_field": False,
            "form_actions": [],
            "text_snippet": "",
            "error": str(e)
        }


# Standalone test block
if __name__ == "__main__":
    print("--- Testing Scraper on Example.com ---")
    result = scrape_url_content("https://example.com")
    for k, v in result.items():
        if k != "text_snippet":
            print(f"{k}: {v}")
    print(f"text_snippet: {result['text_snippet'][:150]}...")