import os
from groq import Groq

task = os.environ.get("AGENT_TASK", "Summarize what Constle is in one sentence.")
if not task:
    print("Error: AGENT_TASK not set")
    exit(1)


client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
response = client.chat.completions.create(
    model="llama-3.1-8b-instant",
    messages=[{"role": "user", "content": task}],
    max_tokens=512
)
print(response.choices[0].message.content)
import time
time.sleep(30)  # מחכה 30 שניות