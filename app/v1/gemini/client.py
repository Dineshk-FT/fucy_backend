import os
import google.generativeai as genai

class GeminiClient:
    """Wrapper for Gemini API"""
    
    def __init__(self, api_key=None, model="gemini-2.5-flash-lite"):
        if api_key:
            genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)
    
    def generate(self, prompt):
        """Generate text from prompt"""
        response = self.model.generate_content(prompt)
        return response.text
    
    def generate_with_config(self, prompt, temperature=0.7, max_tokens=2048):
        """Generate with custom config"""
        response = self.model.generate_content(
            prompt,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            }
        )
        return response.text