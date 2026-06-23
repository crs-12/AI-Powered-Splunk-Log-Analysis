import os

from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

model = genai.GenerativeModel(
     "models/gemini-2.5-flash"
)


def generate_ai_analysis(alert):

    prompt = f"""
You are a SOC Analyst.

Analyze the following security event.

Source IP: {alert['Source_IP']}
Username: {alert['Username']}
Severity: {alert['Severity']}
Risk Score: {alert['Risk_Score']}
Attack Type: {alert['Attack_Type']}
MITRE: {alert['MITRE_ID']}

Provide:

1. Executive Summary

2. Findings

3. Recommendations

Keep it concise.
"""

    try:

        response = model.generate_content(prompt)

        return response.text

    except Exception as e:

        return f"AI Analysis Error: {str(e)}"