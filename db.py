from pymongo import MongoClient

# clientMongo = MongoClient('mongodb+srv://abhishekuttur88:r3qYxiOosZLIGhFZ@cluster0.iqdidy8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
clientMongo = MongoClient(
    "mongodb+srv://sureshpatil:W0cJnrfCr6ImA8Ca@cluster0.iwg05za.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
    maxPoolSize=100,  # Increase connection pool size
    socketTimeoutMS=5000,
)
# clientMongo = MongoClient('mongodb://localhost:27017')

db = clientMongo["MY_DB"]
