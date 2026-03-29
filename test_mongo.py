from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=5000)
try:
    client.admin.command('ping')
    print("Connected successfully")
except Exception as e:
    print(f"Connection failed: {e}")