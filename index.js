// MCMS Server - index.js
const express = require("express");
const cors = require("cors");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
dotenv.config();
const port = process.env.PORT || 5000;

// Initialize Stripe
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// Middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Debug middleware to log all requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
  console.log("Request body:", req.body);
  console.log(
    "Request headers:",
    req.headers.authorization ? "Token present" : "No token"
  );
  next();
});

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.dgti16b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT verification middleware
const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).json({ error: "Access token is required" });
  }

  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.JWT_TOKEN, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.decoded = decoded;
    next();
  });
};

async function run() {
  try {
    await client.connect();

    // Database Collections
    const userCollection = client.db("MCMS").collection("users");
    const campCollection = client.db("MCMS").collection("camps");
    const registrationCollection = client
      .db("MCMS")
      .collection("registrations");
    const paymentCollection = client.db("MCMS").collection("payments");
    const feedbackCollection = client.db("MCMS").collection("feedbacks");

    // ========== AUTHENTICATION ROUTES ==========

    // POST /register
    app.post("/register", async (req, res) => {
      const { name, email, password, role } = req.body;
      if (!name || !email || !password) {
        return res
          .status(400)
          .json({ error: "Name, email, and password are required" });
      }
      if (password.length < 6) {
        return res
          .status(400)
          .json({ error: "Password must be at least 6 characters long" });
      }
      try {
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ error: "User already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: role || "user",
          createdAt: new Date(),
        };
        const result = await userCollection.insertOne(newUser);
        const token = jwt.sign(
          { email, userId: result.insertedId, role: newUser.role },
          process.env.JWT_TOKEN,
          { expiresIn: "7d" }
        );
        res.status(201).json({
          message: "User registered successfully",
          token,
          user: { id: result.insertedId, email, name, role: newUser.role },
        });
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // POST /login
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      if (!email || !password) {
        return res
          .status(400)
          .json({ error: "Email and password are required" });
      }
      try {
        const user = await userCollection.findOne({ email });
        if (!user)
          return res.status(401).json({ error: "Invalid credentials" });
        const match = await bcrypt.compare(password, user.password);
        if (!match)
          return res.status(401).json({ error: "Invalid credentials" });
        const token = jwt.sign(
          { email: user.email, userId: user._id, role: user.role },
          process.env.JWT_TOKEN,
          { expiresIn: "7d" }
        );
        res.json({
          token,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
          },
        });
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // POST /jwt (Firebase Users)
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      if (!email) return res.status(400).json({ error: "Email required" });
      try {
        let user = await userCollection.findOne({ email });
        if (!user) {
          const newUser = {
            email,
            role: "participant",
            createdAt: new Date(),
            authProvider: "firebase",
          };
          const result = await userCollection.insertOne(newUser);
          user = { ...newUser, _id: result.insertedId };
        }
        const token = jwt.sign(
          { email: user.email, userId: user._id, role: user.role },
          process.env.JWT_TOKEN,
          { expiresIn: "7d" }
        );
        res.json({
          token,
          user: {
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
          },
        });
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // GET /verify-token
    app.get("/verify-token", verifyJWT, (req, res) => {
      res.json({
        valid: true,
        user: {
          email: req.decoded.email,
          userId: req.decoded.userId,
          role: req.decoded.role,
        },
      });
    });

    // GET /users/:email
    app.get("/users/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      try {
        const user = await userCollection.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({
          id: user._id,
          name: user.name || "",
          email: user.email,
          role: user.role || "participant",
          photoURL: user.photoURL || "",
        });
      } catch (error) {
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // GET /profile (protected route)
    app.get("/profile", verifyJWT, async (req, res) => {
      try {
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({
          id: user._id,
          name: user.name,
          displayName: user.displayName || user.name,
          email: user.email,
          role: user.role,
          phone: user.phone || "",
          organization: user.organization || "",
          specialization: user.specialization || "",
          experience: user.experience || "",
          location: user.location || "",
          bio: user.bio || "",
          photoURL: user.photoURL || "",
          createdAt: user.createdAt,
        });
      } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // PUT /profile - Update user profile (protected route)
    app.put("/profile", verifyJWT, async (req, res) => {
      try {
        const {
          displayName,
          phone,
          organization,
          specialization,
          experience,
          location,
          bio,
        } = req.body;

        console.log("Profile update request:", req.body);
        console.log("User from token:", req.decoded);

        // Validate required fields
        if (!displayName || displayName.trim().length < 2) {
          return res.status(400).json({
            error: "Display name is required and must be at least 2 characters",
          });
        }

        const updateData = {
          displayName: displayName.trim(),
          phone: phone || "",
          organization: organization || "",
          specialization: specialization || "",
          experience: experience || "",
          location: location || "",
          bio: bio || "",
          updatedAt: new Date(),
        };

        // Update user profile
        const result = await userCollection.updateOne(
          { email: req.decoded.email },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        // Fetch updated user data
        const updatedUser = await userCollection.findOne({
          email: req.decoded.email,
        });

        console.log("Profile updated successfully:", result);

        res.json({
          message: "Profile updated successfully",
          user: {
            id: updatedUser._id,
            name: updatedUser.name,
            displayName: updatedUser.displayName,
            email: updatedUser.email,
            role: updatedUser.role,
            phone: updatedUser.phone,
            organization: updatedUser.organization,
            specialization: updatedUser.specialization,
            experience: updatedUser.experience,
            location: updatedUser.location,
            bio: updatedUser.bio,
            photoURL: updatedUser.photoURL || "",
            createdAt: updatedUser.createdAt,
            updatedAt: updatedUser.updatedAt,
          },
        });
      } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // Root route
    app.get("/", (req, res) => {
      res.send("MCMS Server Running");
    });

    // ========== CAMP MANAGEMENT ROUTES ==========
    // GET /camps - Get all camps
    app.get("/camps", async (req, res) => {
      try {
        const camps = await campCollection.find({}).toArray();
        res.json(camps);
      } catch (error) {
        console.error("Error fetching camps:", error);
        res.status(500).json({ error: "Failed to fetch camps" });
      }
    });

    // GET /camps/:id - Get a specific camp by ID
    app.get("/camps/:id", async (req, res) => {
      try {
        const { id } = req.params;
        console.log("Fetching camp with ID:", id);

        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        const camp = await campCollection.findOne({ _id: new ObjectId(id) });

        if (!camp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        console.log("Camp found:", camp);
        res.json(camp);
      } catch (error) {
        console.error("Error fetching camp details:", error);
        res.status(500).json({ error: "Failed to fetch camp details" });
      }
    });

    // POST /camps - Add a new camp (requires authentication)
    app.post("/camps", verifyJWT, async (req, res) => {
      const campData = req.body;
      console.log("Incoming campData:", campData);
      console.log("User from token:", req.decoded);

      if (!campData.campName || !campData.campFees) {
        console.error("Missing campName or campFees:", campData);
        return res
          .status(400)
          .json({ error: "Camp name and fees are required" });
      }

      try {
        // Add organizer information
        campData.organizerEmail = req.decoded.email;
        campData.organizerId = req.decoded.userId;
        campData.createdAt = new Date();

        console.log("Final campData before insertion:", campData);

        const result = await campCollection.insertOne(campData);
        console.log("Camp inserted, result:", result);

        res.status(201).json({
          message: "Camp created successfully",
          camp: { ...campData, _id: result.insertedId },
        });
      } catch (error) {
        console.error("Error inserting camp:", error);
        res
          .status(500)
          .json({ error: "Failed to create camp", details: error.message });
      }
    });

    // ========== REGISTRATION ROUTES ==========

    // PUT /camps/:id - Update a camp (requires authentication)
    app.put("/camps/:id", verifyJWT, async (req, res) => {
      console.log("PUT /camps/:id called with ID:", req.params.id);
      console.log("Request body:", req.body);
      console.log("User from token:", req.decoded);

      try {
        const campId = req.params.id;

        // Validate ObjectId
        if (!ObjectId.isValid(campId)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        const {
          campName,
          image,
          campFees,
          dateTime,
          location,
          healthcareProfessional,
          targetAudience,
          description,
          specializedServices,
        } = req.body;

        // Validation
        if (
          !campName ||
          !campFees ||
          !dateTime ||
          !location ||
          !healthcareProfessional ||
          !targetAudience ||
          !description ||
          !specializedServices
        ) {
          return res
            .status(400)
            .json({ error: "All required fields must be provided" });
        }

        // Check if camp exists and belongs to organizer
        const existingCamp = await campCollection.findOne({
          _id: new ObjectId(campId),
        });
        console.log("Existing camp found:", existingCamp);

        if (!existingCamp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        console.log(
          "Checking ownership: existingCamp.organizerEmail =",
          existingCamp.organizerEmail,
          "vs req.decoded.email =",
          req.decoded.email
        );

        if (existingCamp.organizerEmail !== req.decoded.email) {
          return res
            .status(403)
            .json({ error: "You can only update your own camps" });
        }

        // Prepare update data
        const updateData = {
          campName,
          image,
          campFees: parseInt(campFees),
          dateTime,
          location,
          healthcareProfessional,
          targetAudience,
          description,
          specializedServices: Array.isArray(specializedServices)
            ? specializedServices
            : specializedServices.split(",").map((s) => s.trim()),
          updatedAt: new Date(),
        };

        console.log("Update data prepared:", updateData);

        const result = await campCollection.updateOne(
          { _id: new ObjectId(campId) },
          { $set: updateData }
        );

        console.log("Update result:", result);

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Camp not found" });
        }

        res.json({
          message: "Camp updated successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error("Error updating camp:", error);
        res
          .status(500)
          .json({ error: "Failed to update camp", details: error.message });
      }
    });

    // DELETE /camps/:id - Delete a camp (requires authentication)
    app.delete("/camps/:id", verifyJWT, async (req, res) => {
      console.log("DELETE /camps/:id called with ID:", req.params.id);
      console.log("User from token:", req.decoded);

      try {
        const campId = req.params.id;

        // Validate ObjectId
        if (!ObjectId.isValid(campId)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        // Check if camp exists and belongs to organizer
        const existingCamp = await campCollection.findOne({
          _id: new ObjectId(campId),
        });
        if (!existingCamp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        if (existingCamp.organizerEmail !== req.decoded.email) {
          return res
            .status(403)
            .json({ error: "You can only delete your own camps" });
        }

        const result = await campCollection.deleteOne({
          _id: new ObjectId(campId),
        });
        console.log("Delete result:", result);

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Camp not found" });
        }

        res.json({
          message: "Camp deleted successfully",
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error("Error deleting camp:", error);
        res
          .status(500)
          .json({ error: "Failed to delete camp", details: error.message });
      }
    });

    // POST /registrations - Register for a camp
    app.post("/registrations", verifyJWT, async (req, res) => {
      try {
        const {
          campId,
          name,
          email,
          phone,
          age,
          gender,
          emergencyContact,
          medicalHistory,
          paymentMethod,
        } = req.body;

        console.log("Registration request:", req.body);
        console.log("User from token:", req.decoded);

        // Check user role - only participants can register for camps
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // Determine user role (same logic as frontend)
        const userRole =
          user.role ||
          (user.displayName === "Organizer" ? "organizer" : "participant");

        if (userRole === "organizer") {
          return res.status(403).json({
            error: "Organizers cannot register for camps",
            message:
              "Only participants are allowed to register for medical camps",
          });
        }

        // Validate required fields
        if (
          !campId ||
          !name ||
          !email ||
          !phone ||
          !age ||
          !gender ||
          !emergencyContact
        ) {
          return res
            .status(400)
            .json({ error: "All required fields must be provided" });
        }

        // Validate camp exists
        if (!ObjectId.isValid(campId)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        const camp = await campCollection.findOne({
          _id: new ObjectId(campId),
        });
        if (!camp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        // Check if user is already registered for this camp
        const existingRegistration = await registrationCollection.findOne({
          campId: new ObjectId(campId),
          userEmail: req.decoded.email,
        });

        if (existingRegistration) {
          return res
            .status(409)
            .json({ error: "You are already registered for this camp" });
        }

        // Create registration
        const registrationData = {
          campId: new ObjectId(campId),
          campName: camp.campName || camp.name,
          userEmail: req.decoded.email,
          userId: req.decoded.userId,
          name,
          email,
          phone,
          age: parseInt(age),
          gender,
          emergencyContact,
          medicalHistory: medicalHistory || "",
          paymentMethod,
          registrationDate: new Date(),
          status: "confirmed",
          paymentStatus: paymentMethod === "cash" ? "pending" : "paid",
        };

        const result = await registrationCollection.insertOne(registrationData);

        // Update participant count in camp
        await campCollection.updateOne(
          { _id: new ObjectId(campId) },
          { $inc: { participantCount: 1 } }
        );

        console.log("Registration created:", result);

        res.status(201).json({
          message: "Registration successful",
          registrationId: result.insertedId,
          success: true,
        });
      } catch (error) {
        console.error("Error creating registration:", error);
        res.status(500).json({ error: "Failed to process registration" });
      }
    });

    // GET /registrations/participant - Get user's registrations
    app.get("/registrations/participant", verifyJWT, async (req, res) => {
      try {
        const registrations = await registrationCollection
          .find({ userEmail: req.decoded.email })
          .toArray();

        res.json(registrations);
      } catch (error) {
        console.error("Error fetching participant registrations:", error);
        res.status(500).json({ error: "Failed to fetch registrations" });
      }
    });

    // ========== STRIPE PAYMENT ENDPOINTS ==========

    // POST /api/create-payment-intent - Create payment intent for camp registration
    app.post("/api/create-payment-intent", verifyJWT, async (req, res) => {
      try {
        const {
          amount,
          currency = "usd",
          campName,
          registrationData,
        } = req.body;

        // Validate request
        if (!amount || amount <= 0) {
          return res.status(400).json({ error: "Valid amount is required" });
        }

        if (!campName || !registrationData) {
          return res
            .status(400)
            .json({ error: "Camp and registration data are required" });
        }

        // Create payment intent
        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(amount), // Amount in cents
          currency: currency,
          metadata: {
            campName: campName,
            participantName: registrationData.name,
            participantEmail: registrationData.email,
            organizerEmail: req.decoded.email,
          },
        });

        console.log("Payment intent created:", paymentIntent.id);

        res.json({
          client_secret: paymentIntent.client_secret,
          payment_intent_id: paymentIntent.id,
        });
      } catch (error) {
        console.error("Error creating payment intent:", error);
        res.status(500).json({
          error: "Failed to create payment intent",
          message: error.message,
        });
      }
    });

    // GET /registrations/organizer - Get registrations for organizer's camps
    app.get("/registrations/organizer", verifyJWT, async (req, res) => {
      try {
        // Get all camps by this organizer
        const organizerCamps = await campCollection
          .find({ organizerEmail: req.decoded.email })
          .toArray();

        const campIds = organizerCamps.map((camp) => camp._id);

        // Get all registrations for these camps
        const registrations = await registrationCollection
          .find({ campId: { $in: campIds } })
          .toArray();

        res.json(registrations);
      } catch (error) {
        console.error("Error fetching organizer registrations:", error);
        res.status(500).json({ error: "Failed to fetch registrations" });
      }
    });

    // POST /api/confirm-payment - Confirm payment and complete registration
    app.post("/api/confirm-payment", verifyJWT, async (req, res) => {
      try {
        const { payment_intent_id, campId, registrationData } = req.body;

        // Check user role - only participants can register for camps
        const user = await userCollection.findOne({ email: req.decoded.email });
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // Determine user role (same logic as frontend)
        const userRole =
          user.role ||
          (user.displayName === "Organizer" ? "organizer" : "participant");

        if (userRole === "organizer") {
          return res.status(403).json({
            error: "Organizers cannot register for camps",
            message:
              "Only participants are allowed to register for medical camps",
          });
        }

        // Verify payment with Stripe
        const paymentIntent = await stripe.paymentIntents.retrieve(
          payment_intent_id
        );

        if (paymentIntent.status !== "succeeded") {
          return res.status(400).json({
            error: "Payment has not been completed successfully",
          });
        }

        // Validate camp exists
        if (!ObjectId.isValid(campId)) {
          return res.status(400).json({ error: "Invalid camp ID format" });
        }

        const camp = await campCollection.findOne({
          _id: new ObjectId(campId),
        });
        if (!camp) {
          return res.status(404).json({ error: "Camp not found" });
        }

        // Check for duplicate registration
        const existingRegistration = await registrationCollection.findOne({
          campId: new ObjectId(campId),
          userEmail: req.decoded.email,
        });

        if (existingRegistration) {
          return res
            .status(409)
            .json({ error: "You are already registered for this camp" });
        }

        // Create registration with payment info
        const registrationDoc = {
          campId: new ObjectId(campId),
          campName: camp.campName || camp.name,
          userEmail: req.decoded.email,
          userId: req.decoded.userId,
          name: registrationData.name,
          email: registrationData.email,
          phone: registrationData.phone,
          age: parseInt(registrationData.age),
          gender: registrationData.gender,
          emergencyContact: registrationData.emergencyContact,
          medicalHistory: registrationData.medicalHistory || "",
          paymentMethod: "card",
          registrationDate: new Date(),
          status: "confirmed",
          paymentStatus: "paid",
          paymentIntentId: payment_intent_id,
          amountPaid: paymentIntent.amount / 100, // Convert back to dollars
        };

        const result = await registrationCollection.insertOne(registrationDoc);

        // Update participant count
        await campCollection.updateOne(
          { _id: new ObjectId(campId) },
          { $inc: { participantCount: 1 } }
        );

        console.log("Registration completed with payment:", result.insertedId);

        res.status(201).json({
          success: true,
          message: "Registration and payment completed successfully",
          registrationId: result.insertedId,
          paymentIntentId: payment_intent_id,
        });
      } catch (error) {
        console.error("Error confirming payment:", error);
        res.status(500).json({
          error: "Failed to confirm payment and registration",
          message: error.message,
        });
      }
    });

    // GET /api/payment-methods - Get user's saved payment methods (optional)
    app.get("/api/payment-methods", verifyJWT, async (req, res) => {
      try {
        // This is optional - you can implement if you want to save customer payment methods
        res.json({ payment_methods: [] });
      } catch (error) {
        console.error("Error fetching payment methods:", error);
        res.status(500).json({ error: "Failed to fetch payment methods" });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB connected successfully!");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
