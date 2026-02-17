import google.generativeai as genai


class GeminiClient:
    def __init__(self, api_key=None, model_name=None):
        genai.configure(api_key=api_key)
        self.model_name = model_name or "gemini-2.5-flash"
        self.model = genai.GenerativeModel(self.model_name)

    def get_model(self):
        return self.model

    def generate_content(self, prompt):
        """Generate content for a prompt using Gemini."""
        return self.get_model().generate_content(prompt)

    def get_text(self, response):
        """Extract text from a Gemini response across SDK versions."""
        if hasattr(response, "text"):
            return response.text
        return response.candidates[0].content.parts[0].text
