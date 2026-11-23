"""LLM adapters: callable(prompt:str) -> str. The LLM only ever PROPOSES plans."""
import os

def gemini_llm():
    """Returns a Gemini callable if GOOGLE_API_KEY is set, else None. (pip install google-genai)"""
    key = os.getenv("GOOGLE_API_KEY")
    if not key:
        return None
    from google import genai
    client = genai.Client(api_key=key)
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    def call(prompt: str) -> str:
        return client.models.generate_content(model=model, contents=prompt).text
    return call
