from langchain_groq import ChatGroq
from dotenv import load_dotenv

load_dotenv()

llm = ChatGroq(model="llama-3.1-8b-instant")
response = llm.invoke("Halo! Balas dengan: 'Koneksi Groq berhasil!'")
print(response.content)