const express = require ('express');
const cors = require('cors');
const app = express();
const dotenv = require("dotenv");
dotenv.config();
const port = process.env.port || 5000;

const { MongoClient, ServerApiVersion } = require('mongodb');


// middleware
app.use(cors());
app.use(express.json());


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.dgti16b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    
	
   app.get("/", (req, res) =>{
	res.send("MCMS Server Running");
});
    await client.db("admin").command({ ping: 1 });
    console.log("You successfully connected to MongoDB!");
  } catch(err) {
    
	console.log("MongoDB connection error:",err);
  }
}
run().catch(console.dir);

app.listen(port, () =>{
	console.log(`Server running on port ${port}`);
});