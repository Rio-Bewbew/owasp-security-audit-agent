from agent.graph import build_graph

vulnerable_code = """
import os
import hashlib

password = "admin123"
api_key = "sk-secret123"

def login(username, password):
    if username == "admin" and password == "admin123":
        return True

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

DEBUG = True
os.system("ls " + user_input)
"""

graph = build_graph()
result = graph.invoke({
    "code": vulnerable_code,
    "filename": "test_app.py",
    "findings": [],
    "summary": ""
})

print(f"\nFindings: {len(result['findings'])} vulnerability ditemukan")
for f in result['findings']:
    print(f"  [{f.severity}] {f.title} - Baris {f.line_number}")

print(f"\nSummary:\n{result['summary']}")
