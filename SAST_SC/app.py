import os
import re
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import openai

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Get OpenAI API key securely
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("No OpenAI API key found. Please add it to your .env file.")

# Configure OpenAI client
client = openai.OpenAI(api_key=api_key)

def preprocess_solidity_code(code):
    """
    Optimize Solidity code by removing comments before sending to LLM.
    """
    # Remove single-line comments
    code = re.sub(r'//.*', '', code)
    
    # Remove multi-line comments
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    
    # Remove empty lines that might have been created by comment removal
    code = re.sub(r'\n\s*\n', '\n', code)
    
    return code.strip()

def analyze_solidity_with_gpt4(code):
    """
    Send Solidity code to GPT-4o for vulnerability analysis.
    """
    prompt = f"""
    Analyze the following Solidity smart contract for security vulnerabilities and potential issues.
    Focus on common vulnerabilities such as:
    
    1. Reentrancy attacks
    2. Integer overflow/underflow
    3. Unchecked external calls
    4. Front-running vulnerabilities
    5. Access control issues
    6. Gas limitations
    7. Denial of Service (DoS) vulnerabilities
    8. Logic errors
    9. Timestamp dependence
    10. Other known smart contract vulnerabilities
    
    For each vulnerability found, provide:
    1. The vulnerability type
    2. Affected code location (line or function)
    3. Severity level (Critical, High, Medium, Low)
    4. A brief explanation of the issue
    5. Recommendation for fixing it
    
    Here is the Solidity code:
    ```
    {code}
    ```
    
    Return your analysis in a structured JSON format with a 'vulnerabilities' array.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,  # Lower temperature for more consistent results
            max_tokens=4000
        )
        
        return {
            "success": True,
            "analysis": response.choices[0].message.content
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.route('/')
def index():
    """Render the main page of the application."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    API endpoint to analyze Solidity code for vulnerabilities.
    """
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"success": False, "error": "No code provided"}), 400
    
    # Get the Solidity code from the request
    code = data['code']
    
    # Preprocess the code (remove comments, etc.)
    preprocessed_code = preprocess_solidity_code(code)
    
    # Analyze the code using GPT-4o
    analysis_result = analyze_solidity_with_gpt4(preprocessed_code)
    
    return jsonify(analysis_result)

if __name__ == '__main__':
    # Run the Flask application on port 5003
    app.run(debug=True, host='0.0.0.0', port=5003)
