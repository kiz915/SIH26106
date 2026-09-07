import re

def clean_text(text: str) -> str:
    """
    Strip HTML tags, normalize whitespace, strip leading/trailing spaces.
    
    Args:
        text (str): Input text string.
        
    Returns:
        str: Cleaned text.
    """
    if not text:
        return ""
    
    # Remove HTML tags using a lightweight regex
    clean_html = re.sub(r'<[^>]+>', ' ', text)
    
    # Normalize whitespace (replace multiple spaces/newlines with a single space)
    normalized_space = re.sub(r'\s+', ' ', clean_html)
    
    return normalized_space.strip()


def extract_urls_from_text(text: str) -> list[str]:
    """
    Extract all http/https URLs from text using regex.
    
    Args:
        text (str): Input text string.
        
    Returns:
        list[str]: A list of extracted URLs.
    """
    if not text:
        return []
    
    # Simple regex for http/https URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return re.findall(url_pattern, text)


def assemble_email_text(subject: str, body: str) -> str:
    """
    Concatenate subject and body into a single text string, then clean it.
    
    Args:
        subject (str): The email subject.
        body (str): The email body.
        
    Returns:
        str: Cleaned concatenated text.
    """
    raw_text = f"Subject: {subject or ''}\n\n{body or ''}"
    return clean_text(raw_text)
