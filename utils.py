# utils.py
import json

def parse_response(response):
    try:
        return json.loads(response.choices[0].message.content)
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        return None
