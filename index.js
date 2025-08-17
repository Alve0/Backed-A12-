import express from "express";
import dotenv from "dotenv";
const app = express();
import cors from "cors";
dotenv.config();
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";

const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware

app.use(cors());
app.use(express.json());
app.get("/", (req, res) => res.send("Server running"));
// MongoDB connection
const uri = `mongodb+srv://${process.env.Name}:${process.env.Password}@cluster0.6w1zkna.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// const uri = "mongodb://localhost:27017";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const userCollection = client.db("quanticoinz").collection("users");
    const taskCollection = client.db("quanticoinz").collection("tasks");
    const purchaseCollection = client.db("quanticoinz").collection("purchases");
    const submissionCollection = client
      .db("quanticoinz")
      .collection("submissions");
    const withdrawalCollection = client
      .db("quanticoinz")
      .collection("withdrawals");
    const notificationCollection = client
      .db("quanticoinz")
      .collection("notifications");

    // Create index for notificationCollection
    // await notificationCollection.createIndex({ toEmail: 1, time: -1 });

    // Middleware to verify Firebase token
    const verifyFBToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res
          .status(401)
          .send({ message: "Unauthorized access: No authorization header" });
      }
      const token = authHeader.split(" ")[1];
      if (!token) {
        return res
          .status(401)
          .send({ message: "Unauthorized access: No token provided" });
      }

      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
      } catch (error) {
        console.error("Firebase token verification error:", error);
        return res
          .status(403)
          .send({ message: "Forbidden access", error: error.message });
      }
    };

    // Middleware to verify worker role
    const verifyWorker = async (req, res, next) => {
      try {
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        if (user.role !== "worker") {
          return res
            .status(403)
            .send({ message: "Forbidden: User is not a worker" });
        }
        next();
      } catch (error) {
        console.error("Worker verification error:", error);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: error.message });
      }
    };

    // Middleware to verify admin role
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        if (user.role !== "admin") {
          return res
            .status(403)
            .send({ message: "Forbidden: User is not an admin" });
        }
        next();
      } catch (error) {
        console.error("Admin verification error:", error);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: error.message });
      }
    };

    // Create or update user
    app.post("/users", async (req, res) => {
      try {
        const data = req.body;
        const email = data.email;

        if (!email) {
          return res.status(400).send({ message: "Email is required." });
        }

        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          const result = await userCollection.updateOne(
            { email },
            { $set: { last_login: data.last_login } }
          );
          return res.send({
            message: "User login updated.",
            modifiedCount: result.modifiedCount,
          });
        } else {
          const newUser = {
            ...data,
            role: data.role || "buyer",
            created_at: new Date().toLocaleString(),
          };
          const result = await userCollection.insertOne(newUser);
          return res.send({
            message: "User created.",
            insertedId: result.insertedId,
          });
        }
      } catch (err) {
        console.error("Create/Update user error:", err);
        return res.status(500).send({
          message: "Internal Server Error user is not created successfully",
          error: err.message,
        });
      }
    });

    // GET TOP WORKER
    app.get("/users/top-workers", async (req, res) => {
      try {
        const topWorkers = await userCollection
          .find({ role: "worker" })
          .sort({ coin: -1 })
          .limit(6)
          .toArray();

        res.send(topWorkers); // Removed duplicate res.send
      } catch (error) {
        console.error("Error fetching top workers:", error);
        res.status(500).send({
          message: "Failed to fetch top workers",
          error: error.message,
        });
      }
    });

    // Get coin for user profile
    app.get("/users/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({
            message: "Unauthorized access 1",
          });
        }

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        res.send({
          coin: user.coin,
          role: user.role,
        });
      } catch (err) {
        console.error("Fetch user coin error:", err);
        res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get user data for navigation
    app.get("/userData/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({
            message: "Unauthorized access 2",
            email,
            email_decoded: req.decoded.email,
          });
        }
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        return res.status(200).send(user);
      } catch (err) {
        console.error("Fetch user data error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Create a new task
    app.post("/tasks", verifyFBToken, async (req, res) => {
      try {
        const taskData = req.body;
        const email = req.decoded.email;

        // Validate required fields
        const requiredFields = [
          "task_title",
          "task_detail",
          "required_workers",
          "payable_amount",
          "total_amount",
          "completion_date",
          "submission_info",
          "task_image",
          "user_email",
        ];
        for (const field of requiredFields) {
          if (!taskData[field]) {
            return res
              .status(400)
              .send({ message: `Missing required field: ${field}` });
          }
        }

        // Verify user exists and has enough coins
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        if (user.email !== taskData.user_email) {
          return res
            .status(401)
            .send({ message: "Unauthorized: Email mismatch" });
        }
        if (taskData.total_amount > user.coin) {
          return res.status(400).send({
            message: "Insufficient coins",
            required_coins: taskData.total_amount,
            available_coins: user.coin,
          });
        }

        // Validate role (only buyers can create tasks)
        if (user.role !== "buyer") {
          return res
            .status(403)
            .send({ message: "Only buyers can create tasks" });
        }

        // Create task
        const newTask = {
          ...taskData,
          created_at: new Date(),
          status: "pending",
          assigned_workers: [],
        };
        const taskResult = await taskCollection.insertOne(newTask);

        // Deduct coins
        const updateResult = await userCollection.updateOne(
          { email },
          { $inc: { coin: -taskData.total_amount } }
        );

        if (updateResult.modifiedCount === 0) {
          // Rollback task insertion if coin deduction fails
          await taskCollection.deleteOne({ _id: taskResult.insertedId });
          return res.status(500).send({ message: "Failed to deduct coins" });
        }

        return res.status(201).send({
          message: "Task created successfully",
          insertedId: taskResult.insertedId,
        });
      } catch (err) {
        console.error("Create task error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get all tasks for a user
    app.get("/tasks/user/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({ message: "Unauthorized access 3" });
        }
        const tasks = await taskCollection
          .find({ user_email: email })
          .toArray();
        return res.status(200).send(tasks);
      } catch (err) {
        console.error("Fetch tasks error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get all tasks for workers
    app.get("/tasks/worker", verifyFBToken, async (req, res) => {
      try {
        const tasks = await taskCollection
          .find({ required_workers: { $gt: 0 }, status: "pending" })
          .toArray();
        return res.status(200).send(tasks);
      } catch (err) {
        console.error("Fetch worker tasks error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Update a task
    app.put("/tasks/:id", verifyFBToken, async (req, res) => {
      try {
        const taskId = req.params.id;
        const { task_title, task_detail, submission_info, user_email } =
          req.body;

        if (!ObjectId.isValid(taskId)) {
          return res.status(400).send({ message: "Invalid task ID" });
        }

        if (req.decoded.email !== user_email) {
          return res.status(401).send({ message: "Unauthorized access 4" });
        }

        // Validate required fields
        if (!task_title || !task_detail || !submission_info) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        const updatedTask = {
          $set: {
            task_title,
            task_detail,
            submission_info,
            updated_at: new Date(),
          },
        };

        const result = await taskCollection.updateOne(
          { _id: new ObjectId(taskId), user_email },
          updatedTask
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .send({ message: "Task not found or unauthorized" });
        }

        return res.status(200).send({ message: "Task updated successfully" });
      } catch (err) {
        console.error("Update task error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Delete a task
    app.delete("/tasks/:id", verifyFBToken, async (req, res) => {
      try {
        const taskId = req.params.id;
        const { user_email, status, total_amount } = req.body;

        if (!ObjectId.isValid(taskId)) {
          return res.status(400).send({ message: "Invalid task ID" });
        }

        if (req.decoded.email !== user_email) {
          return res.status(401).send({ message: "Unauthorized access 5" });
        }

        const task = await taskCollection.findOne({
          _id: new ObjectId(taskId),
          user_email,
        });
        if (!task) {
          return res.status(404).send({ message: "Task not found" });
        }

        // Delete the task
        const deleteResult = await taskCollection.deleteOne({
          _id: new ObjectId(taskId),
          user_email,
        });

        if (deleteResult.deletedCount === 0) {
          return res.status(500).send({ message: "Failed to delete task" });
        }

        // Refund coins if task is pending
        if (status === "pending") {
          const updateResult = await userCollection.updateOne(
            { email: user_email },
            { $inc: { coin: total_amount } }
          );
          if (updateResult.modifiedCount === 0) {
            return res.status(500).send({ message: "Failed to refund coins" });
          }
        }

        return res.status(200).send({ message: "Task deleted successfully" });
      } catch (err) {
        console.error("Delete task error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Create a purchase record and update coins
    app.post("/purchases", verifyFBToken, async (req, res) => {
      try {
        const { coins, price, user_email } = req.body;

        if (req.decoded.email !== user_email) {
          return res.status(401).send({ message: "Unauthorized access 6" });
        }

        // Validate input
        if (!coins || !price || !user_email) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        // Validate coin and price options
        const validOptions = [
          { coins: 10, price: 1 },
          { coins: 150, price: 10 },
          { coins: 500, price: 20 },
          { coins: 1000, price: 35 },
        ];
        if (
          !validOptions.some(
            (opt) => opt.coins === coins && opt.price === price
          )
        ) {
          return res
            .status(400)
            .send({ message: "Invalid coin or price option" });
        }

        // Verify user exists
        const user = await userCollection.findOne({ email: user_email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // Save purchase details
        const purchaseData = {
          user_email,
          coins: parseInt(coins),
          price,
          created_at: new Date(),
        };
        await purchaseCollection.insertOne(purchaseData);

        // Update user's coin balance
        const updateResult = await userCollection.updateOne(
          { email: user_email },
          { $inc: { coin: parseInt(coins) } }
        );

        if (updateResult.modifiedCount === 0) {
          return res
            .status(500)
            .send({ message: "Failed to update user coins" });
        }

        return res
          .status(200)
          .send({ message: "Coins purchased successfully" });
      } catch (err) {
        console.error("Purchase error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get all purchases for a user
    app.get("/purchases/user/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({ message: "Unauthorized access 7" });
        }
        const purchases = await purchaseCollection
          .find({ user_email: email })
          .toArray();
        return res.status(200).send(purchases);
      } catch (err) {
        console.error("Fetch purchases error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get task by ID
    app.get("/tasks/:id", verifyFBToken, verifyWorker, async (req, res) => {
      try {
        const taskId = req.params.id;
        if (!ObjectId.isValid(taskId)) {
          return res.status(400).send({ message: "Invalid task ID" });
        }
        const task = await taskCollection.findOne({
          _id: new ObjectId(taskId),
          required_workers: { $gt: 0 },
          status: "pending",
        });
        if (!task) {
          return res
            .status(404)
            .send({ message: "Task not found or not available" });
        }
        return res.status(200).send(task);
      } catch (err) {
        console.error("Fetch task error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Submit a task
    app.post("/submissions", verifyFBToken, verifyWorker, async (req, res) => {
      try {
        const submissionData = req.body;

        // Validate required fields
        const requiredFields = [
          "task_id",
          "task_title",
          "payable_amount",
          "worker_email",
          "worker_name",
          "buyer_name",
          "buyer_email",
          "submission_details",
          "submission_date",
          "status",
        ];
        for (const field of requiredFields) {
          if (!submissionData[field]) {
            return res
              .status(400)
              .send({ message: `Missing required field: ${field}` });
          }
        }

        if (!ObjectId.isValid(submissionData.task_id)) {
          return res.status(400).send({ message: "Invalid task ID" });
        }

        const taskId = new ObjectId(submissionData.task_id);

        const task = await taskCollection.findOne({
          _id: taskId,
          status: "pending",
          required_workers: { $gt: 0 },
        });

        if (!task) {
          return res.status(404).send({
            message: "Task not found or not available for submission",
          });
        }

        // Check for duplicate submissions
        const existingSubmission = await submissionCollection.findOne({
          task_id: taskId,
          worker_email: submissionData.worker_email,
        });

        if (existingSubmission) {
          return res
            .status(400)
            .send({ message: "You have already submitted this task." });
        }

        // Ensure only authorized user can submit
        if (submissionData.worker_email !== req.decoded.email) {
          return res
            .status(401)
            .send({ message: "Unauthorized: Worker email mismatch" });
        }

        // Include worker UID in submission
        const user = await admin
          .auth()
          .getUserByEmail(submissionData.worker_email);
        submissionData.worker_uid = user.uid;

        // Insert submission
        const submission = {
          ...submissionData,
          task_id: taskId,
          created_at: new Date(),
        };

        await submissionCollection.insertOne(submission);

        // Update submission count and task status if needed
        const submissionCount = await submissionCollection.countDocuments({
          task_id: taskId,
        });

        let statusUpdate = {};
        if (submissionCount >= task.required_workers) {
          statusUpdate.status = "submitted";
        }

        const taskUpdate = {
          $set: {
            ...statusUpdate,
            updated_at: new Date(),
          },
          $inc: {
            submission_count: 1,
            required_workers: -1,
          },
          $push: {
            assigned_workers: submissionData.worker_email,
          },
        };

        await taskCollection.updateOne({ _id: taskId }, taskUpdate);

        // Insert notification for buyer
        const notification = {
          message: `New submission by ${submissionData.worker_name} for task ${submissionData.task_title}`,
          toEmail: submissionData.buyer_email,
          actionRoute: "/dashboard/taskreview",
          time: new Date(),
        };

        await notificationCollection.insertOne(notification);

        return res.status(201).send({
          message: "Submission created successfully",
          inserted: true,
        });
      } catch (err) {
        console.error("Submission error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Get buyer stats: total tasks, pending workers, total payment
    app.get("/buyers/stats/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.decoded.email !== email) {
          return res.status(401).send({ message: "Unauthorized access 8" });
        }

        const tasks = await taskCollection
          .find({ user_email: email })
          .toArray();

        const totalTasks = tasks.length;
        const pendingWorkers = tasks
          .filter((t) => t.status === "pending")
          .reduce((sum, t) => sum + (t.required_workers || 0), 0);
        const totalPaid = tasks.reduce(
          (sum, t) => sum + (t.total_amount || 0),
          0
        );

        return res.status(200).send({
          totalTasks,
          pendingWorkers,
          totalPaid,
        });
      } catch (err) {
        console.error("Buyer stats error:", err);
        return res.status(500).send({
          message: "Internal Server Error",
          error: err.message,
        });
      }
    });

    // Get submissions for review
    app.get("/submissions/review/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({ message: "Unauthorized access 9" });
        }
        const submissions = await submissionCollection
          .find({ buyer_email: email, status: "pending" })
          .toArray();
        res.send(submissions);
      } catch (err) {
        console.error("Fetch submissions for review error:", err);
        res.status(500).send({
          message: "Internal Server Error",
          error: err.message,
        });
      }
    });

    // Approve a submission
    app.patch("/submissions/approve/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid submission ID" });
        }

        const submission = await submissionCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!submission) {
          return res.status(404).send({ message: "Submission not found" });
        }

        // Ensure only the task's buyer can approve
        if (submission.buyer_email !== req.decoded.email) {
          return res
            .status(401)
            .send({ message: "Unauthorized: Only the task buyer can approve" });
        }

        // Update submission status
        await submissionCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "approved", approved_at: new Date() } }
        );

        // Increase worker coin
        const updateResult = await userCollection.updateOne(
          { email: submission.worker_email },
          { $inc: { coin: submission.payable_amount } }
        );

        if (updateResult.modifiedCount === 0) {
          return res
            .status(500)
            .send({ message: "Failed to update worker coins" });
        }

        // Insert notification for worker
        const notification = {
          message: `You have earned ${submission.payable_amount} coins from ${submission.buyer_name} for completing ${submission.task_title}`,
          toEmail: submission.worker_email,
          actionRoute: "/dashboard/worker-home",
          time: new Date(),
        };

        await notificationCollection.insertOne(notification);

        res.send({ message: "Submission approved" });
      } catch (err) {
        console.error("Submission approval error:", err);
        res.status(500).send({
          message: "Internal Server Error",
          error: err.message,
        });
      }
    });

    // Reject a submission
    app.patch("/submissions/reject/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid submission ID" });
        }

        const submission = await submissionCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!submission) {
          return res.status(404).send({ message: "Submission not found" });
        }

        // Ensure only the task's buyer can reject
        if (submission.buyer_email !== req.decoded.email) {
          return res
            .status(401)
            .send({ message: "Unauthorized: Only the task buyer can reject" });
        }

        // Update submission status
        await submissionCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "rejected", rejected_at: new Date() } }
        );

        // Increase required_workers in task
        const updateResult = await taskCollection.updateOne(
          { _id: new ObjectId(submission.task_id) },
          { $inc: { required_workers: 1 } }
        );

        if (updateResult.modifiedCount === 0) {
          return res
            .status(500)
            .send({ message: "Failed to update task required workers" });
        }

        // Insert notification for worker
        const notification = {
          message: `Your submission for ${submission.task_title} was rejected by ${submission.buyer_name}`,
          toEmail: submission.worker_email,
          actionRoute: "/dashboard/tasklist",
          time: new Date(),
        };

        await notificationCollection.insertOne(notification);

        res.send({ message: "Submission rejected" });
      } catch (err) {
        console.error("Submission rejection error:", err);
        res.status(500).send({
          message: "Internal Server Error",
          error: err.message,
        });
      }
    });

    // Get worker stats
    app.get(
      "/worker-stats/:email",
      verifyFBToken,
      verifyWorker,
      async (req, res) => {
        try {
          const email = req.params.email;
          if (req.decoded.email !== email) {
            return res.status(401).send({ message: "Unauthorized access 10" });
          }

          const [totalSubmissions, pendingSubmissions, earningsResult] =
            await Promise.all([
              submissionCollection.countDocuments({ worker_email: email }),
              submissionCollection.countDocuments({
                worker_email: email,
                status: "pending",
              }),
              submissionCollection
                .aggregate([
                  {
                    $match: {
                      worker_email: email,
                      status: "approved",
                    },
                  },
                  {
                    $group: {
                      _id: null,
                      totalEarning: { $sum: "$payable_amount" },
                    },
                  },
                ])
                .toArray(),
            ]);

          const totalEarning = earningsResult[0]?.totalEarning || 0;

          res.send({
            totalSubmissions,
            pendingSubmissions,
            totalEarning,
          });
        } catch (error) {
          console.error("Worker stats error:", error);
          res
            .status(500)
            .send({ message: "Internal Server Error", error: error.message });
        }
      }
    );

    // Get user approved submissions with pagination
    app.get(
      "/submissions/approved/:email",
      verifyFBToken,
      verifyWorker,
      async (req, res) => {
        try {
          const email = req.params.email;
          if (req.decoded.email !== email) {
            return res.status(401).send({ message: "Unauthorized access 11" });
          }

          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;
          const skip = (page - 1) * limit;

          const [submissions, totalSubmissions] = await Promise.all([
            submissionCollection
              .find({ worker_email: email, status: "approved" })
              .project({
                task_title: 1,
                payable_amount: 1,
                buyer_name: 1,
                status: 1,
                _id: 0,
              })
              .skip(skip)
              .limit(limit)
              .toArray(),
            submissionCollection.countDocuments({
              worker_email: email,
              status: "approved",
            }),
          ]);

          const totalPages = Math.ceil(totalSubmissions / limit);

          res.status(200).send({
            submissions,
            totalPages,
            currentPage: page,
            totalSubmissions,
          });
        } catch (error) {
          console.error("Fetch approved submissions error:", error);
          res.status(500).send({
            message: "Internal Server Error",
            error: error.message,
          });
        }
      }
    );

    // Withdraw coin
    app.post("/withdrawals", verifyFBToken, verifyWorker, async (req, res) => {
      try {
        const {
          withdrawal_coin,
          withdrawal_amount,
          payment_system,
          account_number,
          worker_email,
          worker_name,
        } = req.body;

        // Validate required fields
        if (
          !withdrawal_coin ||
          !withdrawal_amount ||
          !payment_system ||
          !account_number ||
          !worker_email ||
          !worker_name
        ) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        // Validate payment system
        const validPaymentSystems = [
          "Bkash",
          "Rocket",
          "Nagad",
          "Payoneer",
          "Bank",
        ];
        if (!validPaymentSystems.includes(payment_system)) {
          return res.status(400).send({ message: "Invalid payment system" });
        }

        // Validate account number (basic check)
        if (account_number.length < 4) {
          return res.status(400).send({ message: "Invalid account number" });
        }

        // Validate amount conversion (1 dollar = 20 coins)
        const expectedAmount = (withdrawal_coin / 20).toFixed(2);
        if (parseFloat(withdrawal_amount).toFixed(2) !== expectedAmount) {
          return res.status(400).send({ message: "Invalid withdrawal amount" });
        }

        // Check coin balance
        const user = await userCollection.findOne({ email: worker_email });
        if (!user || user.coin < withdrawal_coin) {
          return res.status(400).send({ message: "Insufficient coin balance" });
        }

        // Deduct coins
        const updateResult = await userCollection.updateOne(
          { email: worker_email },
          { $inc: { coin: -withdrawal_coin } }
        );

        if (updateResult.modifiedCount === 0) {
          return res.status(500).send({ message: "Failed to deduct coins" });
        }

        // Save withdrawal record
        const withdrawalData = {
          worker_email,
          worker_name,
          withdrawal_coin: parseInt(withdrawal_coin),
          withdrawal_amount: parseFloat(withdrawal_amount),
          payment_system,
          account_number,
          withdraw_date: new Date(),
          status: "pending",
        };

        const result = await withdrawalCollection.insertOne(withdrawalData);

        return res.status(201).send({
          message: "Withdrawal request submitted",
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error("Withdrawal error:", err);
        return res
          .status(500)
          .send({ message: "Internal Server Error", error: err.message });
      }
    });

    // Admin section

    app.get("/admin/summary", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        const purchases = await purchaseCollection.find().toArray();
        const withdrawals = await withdrawalCollection.find().toArray();

        const totalWorkers = users.filter(
          (user) => user.role === "worker"
        ).length;
        const totalBuyers = users.filter(
          (user) => user.role === "buyer"
        ).length;
        const totalCoins = users.reduce(
          (sum, user) => sum + (user.coin || 0),
          0
        );

        // Total payments from purchases
        const totalPurchaseAmount = purchases.reduce(
          (sum, p) => sum + (p.price || 0),
          0
        );

        // Total withdrawn amount in dollars
        const totalWithdrawnAmount = withdrawals.reduce(
          (sum, w) => sum + (w.withdrawal_amount || 0),
          0
        );

        res.send({
          totalWorkers,
          totalBuyers,
          totalCoins,
          totalPurchaseAmount,
          totalWithdrawnAmount,
        });
      } catch (err) {
        console.error("Error fetching admin summary:", err);
        res
          .status(500)
          .send({ message: "Error fetching summary", error: err.message });
      }
    });

    // Withdraw request
    app.get(
      "/admin/withdrawals/pending",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const withdrawals = await withdrawalCollection
            .find({ status: "pending" })
            .toArray();
          res.send(withdrawals);
        } catch (err) {
          console.error("Error fetching pending withdrawals:", err);
          res.status(500).send({
            message: "Error fetching pending withdrawals",
            error: err.message,
          });
        }
      }
    );

    // Approve a withdrawal request
    app.patch(
      "/admin/withdrawals/approve/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const withdrawalId = req.params.id;
          if (!ObjectId.isValid(withdrawalId)) {
            return res.status(400).send({ message: "Invalid withdrawal ID" });
          }

          const withdrawal = await withdrawalCollection.findOne({
            _id: new ObjectId(withdrawalId),
            status: "pending",
          });

          if (!withdrawal) {
            return res
              .status(404)
              .send({ message: "Withdrawal not found or not pending" });
          }

          // Update withdrawal status to approved
          const updateResult = await withdrawalCollection.updateOne(
            { _id: new ObjectId(withdrawalId) },
            { $set: { status: "approved", approved_at: new Date() } }
          );

          if (updateResult.modifiedCount === 0) {
            return res
              .status(500)
              .send({ message: "Failed to approve withdrawal" });
          }

          // Insert notification for worker
          const notification = {
            message: `Your withdrawal of $${withdrawal.withdrawal_amount} via ${withdrawal.payment_system} has been approved`,
            toEmail: withdrawal.worker_email,
            actionRoute: "/dashboard/withdrawform",
            time: new Date(),
          };

          await notificationCollection.insertOne(notification);

          res.send({ message: "Withdrawal approved successfully" });
        } catch (err) {
          console.error("Error approving withdrawal:", err);
          res.status(500).send({
            message: "Internal Server Error",
            error: err.message,
          });
        }
      }
    );

    // Get all users
    app.get("/admin/users", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        const formattedUsers = users.map((user) => ({
          ...user,
          display_name: user.name || user.email.split("@")[0],
          photo_url: user.photoURL,
        }));
        res.send(formattedUsers);
      } catch (err) {
        console.error("Error fetching users:", err);
        res.status(500).send({
          message: "Error fetching users",
          error: err.message,
        });
      }
    });

    // Delete a user
    app.delete(
      "/admin/users/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const userId = req.params.id;
          if (!ObjectId.isValid(userId)) {
            return res.status(400).send({ message: "Invalid user ID" });
          }

          const user = await userCollection.findOne({
            _id: new ObjectId(userId),
          });
          if (!user) {
            return res.status(404).send({ message: "User not found" });
          }

          if (user.email === req.decoded.email) {
            return res
              .status(403)
              .send({ message: "Cannot delete your own account" });
          }

          // Check for pending tasks or withdrawals
          const pendingTasks = await taskCollection.countDocuments({
            user_email: user.email,
            status: "pending",
          });
          const pendingWithdrawals = await withdrawalCollection.countDocuments({
            worker_email: user.email,
            status: "pending",
          });

          if (pendingTasks > 0 || pendingWithdrawals > 0) {
            return res.status(400).send({
              message: "Cannot delete user with pending tasks or withdrawals",
            });
          }

          const deleteResult = await userCollection.deleteOne({
            _id: new ObjectId(userId),
          });

          if (deleteResult.deletedCount === 0) {
            return res.status(500).send({ message: "Failed to delete user" });
          }

          res.send({ message: "User deleted successfully" });
        } catch (err) {
          console.error("Error deleting user:", err);
          res.status(500).send({
            message: "Internal Server Error",
            error: err.message,
          });
        }
      }
    );

    // Update user role
    app.patch(
      "/admin/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const userId = req.params.id;
          const { role } = req.body;

          if (!ObjectId.isValid(userId)) {
            return res.status(400).send({ message: "Invalid user ID" });
          }

          // Validate role
          const validRoles = ["admin", "buyer", "worker"];
          if (!validRoles.includes(role)) {
            return res.status(400).send({ message: "Invalid role" });
          }

          const user = await userCollection.findOne({
            _id: new ObjectId(userId),
          });
          if (!user) {
            return res.status(404).send({ message: "User not found" });
          }

          // Prevent admin from changing their own role
          if (user.email === req.decoded.email) {
            return res
              .status(403)
              .send({ message: "Cannot change your own role" });
          }

          const updateResult = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { role, updated_at: new Date() } }
          );

          if (updateResult.modifiedCount === 0) {
            return res
              .status(500)
              .send({ message: "Failed to update user role" });
          }

          res.send({ message: "User role updated successfully" });
        } catch (err) {
          console.error("Error updating user role:", err);
          res.status(500).send({
            message: "Internal Server Error",
            error: err.message,
          });
        }
      }
    );

    // Get all tasks
    app.get("/admin/tasks", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const tasks = await taskCollection.find().toArray();
        res.send(tasks);
      } catch (err) {
        console.error("Error fetching tasks:", err);
        res.status(500).send({
          message: "Error fetching tasks",
          error: err.message,
        });
      }
    });

    // Delete a task (admin override)
    app.delete(
      "/admin/tasks/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const taskId = req.params.id;
          if (!ObjectId.isValid(taskId)) {
            return res.status(400).send({ message: "Invalid task ID" });
          }

          const task = await taskCollection.findOne({
            _id: new ObjectId(taskId),
          });
          if (!task) {
            return res.status(404).send({ message: "Task not found" });
          }

          // Refund coins if task is pending
          if (task.status === "pending") {
            const updateResult = await userCollection.updateOne(
              { email: task.user_email },
              { $inc: { coin: task.total_amount } }
            );
            if (updateResult.modifiedCount === 0) {
              return res
                .status(500)
                .send({ message: "Failed to refund coins" });
            }
          }

          // Delete the task
          const deleteResult = await taskCollection.deleteOne({
            _id: new ObjectId(taskId),
          });

          if (deleteResult.deletedCount === 0) {
            return res.status(500).send({ message: "Failed to delete task" });
          }

          res.send({ message: "Task deleted successfully" });
        } catch (err) {
          console.error("Error deleting task:", err);
          res.status(500).send({
            message: "Internal Server Error",
            error: err.message,
          });
        }
      }
    );

    // Get notifications for a user
    app.get("/notifications/:email", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded.email !== email) {
          return res.status(401).send({ message: "Unauthorized access" });
        }

        const notifications = await notificationCollection
          .find({ toEmail: email })
          .sort({ time: -1 })
          .toArray();

        res.send(notifications);
      } catch (err) {
        console.error("Error fetching notifications:", err);
        res.status(500).send({
          message: "Error fetching notifications",
          error: err.message,
        });
      }
    });
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}

run().catch(console.dir);

app.listen(5000, () => console.log("Server running on port 5000"));
