require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5001;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// --- NODEMAILER CONFIG ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "noreply@merchantinsights.com",
    pass: process.env.EMAIL_PASSWORD || "test-password",
  },
});

// --- CORS CONFIG ---
// --- CORS CONFIG - Allow all origins ---
app.use(
  cors({
    origin: "*", // Allow from anywhere
    credentials: false,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cache-Control"],
    optionsSuccessStatus: 200,
  })
);

app.use(express.json());

const SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;

async function getTenant() {
  // Always use the same tenant for all users (single Shopify store)
  let tenant = await prisma.tenant.findUnique({
    where: { shopDomain: SHOP_DOMAIN },
  });
  if (!tenant) {
    tenant = await prisma.tenant.create({
      data: { shopDomain: SHOP_DOMAIN, accessToken: ACCESS_TOKEN },
    });
  }
  return tenant;
}

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// --- AUTH ROUTES ---
// Step 1: Login - Send OTP only for new users
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    let user = await prisma.user.findUnique({ where: { email } });
    const isNewUser = !user;

    if (!user) {
      // Create new user - requires OTP verification
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await prisma.user.create({
        data: { email, password: hashedPassword, isVerified: false },
      });
    } else {
      // Verify password for existing user
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid password" });
      }
    }

    // If user is already verified, return token directly
    if (user.isVerified) {
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "7d",
      });
      return res.json({
        token,
        user: { id: user.id, email: user.email },
        requiresOTP: false,
      });
    }

    // For new users, send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await prisma.user.update({
      where: { id: user.id },
      data: { otp, otpExpiry },
    });

    // Log OTP to console for development/demo
    console.log(`\n📧 OTP for ${email}: ${otp} (expires in 10 minutes)\n`);

    // Send OTP via email (if configured)
    if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Your Merchant Insights OTP Code",
          html: `
            <h2>Welcome to Merchant Insights</h2>
            <p>Your OTP code is: <strong style="font-size: 24px; color: #059669;">${otp}</strong></p>
            <p>This code will expire in 10 minutes.</p>
            <p>Do not share this code with anyone.</p>
          `,
        });
        console.log(`✅ Email sent to ${email}`);
      } catch (emailError) {
        console.error(`❌ Failed to send email: ${emailError.message}`);
      }
    } else {
      console.log(
        `⚠️  Email not configured. OTP: ${otp} (check console above)`
      );
    }

    res.json({
      message: "OTP sent to your email. Please check your inbox.",
      email: email,
      userId: user.id,
      requiresOTP: true,
    });
  } catch (error) {
    console.error("Auth error:", error);
    res.status(500).json({ error: "Authentication failed" });
  }
});

// Step 2: Verify OTP and get token
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { userId, otp } = req.body;
    if (!userId || !otp) {
      return res.status(400).json({ error: "User ID and OTP required" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if OTP is valid and not expired
    if (user.otp !== otp) {
      return res.status(401).json({ error: "Invalid OTP" });
    }

    if (!user.otpExpiry || new Date() > user.otpExpiry) {
      return res.status(401).json({ error: "OTP expired" });
    }

    // Mark user as verified and clear OTP
    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, otp: null, otpExpiry: null },
    });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({ error: "OTP verification failed" });
  }
});

// Verify token
app.get("/api/auth/verify", authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/sync", authenticateToken, async (req, res) => {
  try {
    console.log("📦 Starting Shopify sync...");
    const tenant = await getTenant();
    console.log(`✓ Tenant found: ${tenant.shopDomain}`);

    const headers = { "X-Shopify-Access-Token": ACCESS_TOKEN };
    const baseURL = `https://${SHOP_DOMAIN}/admin/api/2023-10`;

    console.log(`🔄 Fetching orders from ${baseURL}/orders.json`);
    const ordersRes = await axios.get(`${baseURL}/orders.json?status=any`, {
      headers,
    });
    console.log(`✓ Found ${ordersRes.data.orders?.length || 0} orders`);

    for (const o of ordersRes.data.orders) {
      const name = o.customer
        ? `${o.customer.first_name} ${o.customer.last_name}`
        : "Guest";
      await prisma.order.createMany({
        data: {
          shopifyId: String(o.id),
          totalPrice: parseFloat(o.total_price),
          currency: o.currency,
          customerName: name,
          createdAt: new Date(o.created_at),
          tenantId: tenant.id,
        },
        skipDuplicates: true,
      });
    }

    console.log(`🔄 Fetching customers from ${baseURL}/customers.json`);
    const customersRes = await axios.get(`${baseURL}/customers.json`, {
      headers,
    });
    console.log(
      `✓ Found ${customersRes.data.customers?.length || 0} customers`
    );

    for (const c of customersRes.data.customers) {
      await prisma.customer.createMany({
        data: {
          shopifyId: String(c.id),
          firstName: c.first_name,
          email: c.email,
          tenantId: tenant.id,
        },
        skipDuplicates: true,
      });
    }

    console.log("✅ Sync completed successfully!");
    res.json({
      message: "Synced!",
      ordersCount: ordersRes.data.orders?.length || 0,
      customersCount: customersRes.data.customers?.length || 0,
    });
  } catch (error) {
    console.error("❌ Sync Error:", error.response?.data || error.message);
    res.status(500).json({ error: "Sync failed", details: error.message });
  }
});

app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const tenant = await getTenant();
    const { startDate, endDate } = req.query;

    // Build date filter
    const dateFilter = {};
    if (startDate) {
      dateFilter.gte = new Date(startDate);
    }
    if (endDate) {
      dateFilter.lte = new Date(endDate);
    }

    // 1. Fetch Orders with optional date filter
    const allOrders = await prisma.order.findMany({
      where: {
        tenantId: tenant.id,
        ...(Object.keys(dateFilter).length > 0 && { createdAt: dateFilter }),
      },
      orderBy: { createdAt: "desc" },
    });

    // 2. Stats
    const totalRevenue = allOrders.reduce((sum, o) => sum + o.totalPrice, 0);
    const totalOrders = allOrders.length;
    const totalCustomers = await prisma.customer.count({
      where: { tenantId: tenant.id },
    });

    // 3. List (Top 50)
    const recentList = allOrders.slice(0, 50).map((o) => ({
      id: o.id,
      shopifyId: o.shopifyId,
      name: o.customerName || "Guest",
      date: new Date(o.createdAt).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
        hour12: true,
      }),
      amount: o.totalPrice.toFixed(2),
      status: "paid",
    }));

    // 4. Graph (Group by "Dec 6" format)
    const trendMap = {};
    const today = new Date();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      const dateKey = d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });
      trendMap[dateKey] = 0;
    }

    allOrders.forEach((order) => {
      const orderDate = new Date(order.createdAt);
      const diffTime = Math.abs(today - orderDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      if (diffDays <= 7) {
        const dateKey = orderDate.toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
        });
        if (trendMap[dateKey] !== undefined) {
          trendMap[dateKey] += order.totalPrice;
        }
      }
    });

    const trendData = Object.keys(trendMap).map((date) => ({
      name: date,
      value: trendMap[date],
    }));

    res.json({
      stats: {
        revenue: totalRevenue.toFixed(2),
        orders: String(totalOrders),
        customers: String(totalCustomers),
      },
      orders: recentList,
      trend: trendData,
    });
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    res.status(500).json({ error: "Could not fetch data" });
  }
});

// --- TOP 5 CUSTOMERS BY SPEND ---
app.get("/api/top-customers", authenticateToken, async (req, res) => {
  try {
    const tenant = await getTenant();
    const { startDate, endDate } = req.query;

    // Build date filter
    const dateFilter = {};
    if (startDate) {
      dateFilter.gte = new Date(startDate);
    }
    if (endDate) {
      dateFilter.lte = new Date(endDate);
    }

    // Get all orders with optional date filter
    const allOrders = await prisma.order.findMany({
      where: {
        tenantId: tenant.id,
        ...(Object.keys(dateFilter).length > 0 && { createdAt: dateFilter }),
      },
    });

    // Group by customer name and sum their spending
    const customerSpend = {};
    allOrders.forEach((order) => {
      const customerName = order.customerName || "Guest";
      if (!customerSpend[customerName]) {
        customerSpend[customerName] = 0;
      }
      customerSpend[customerName] += order.totalPrice;
    });

    // Sort and get top 5
    const topCustomers = Object.entries(customerSpend)
      .map(([name, totalSpent]) => ({
        name,
        totalSpent: parseFloat(totalSpent.toFixed(2)),
        percentage: 0, // Will calculate based on total
      }))
      .sort((a, b) => b.totalSpent - a.totalSpent)
      .slice(0, 5);

    // Calculate percentage of total revenue
    const totalRevenue = topCustomers.reduce((sum, c) => sum + c.totalSpent, 0);
    topCustomers.forEach((customer) => {
      customer.percentage = parseFloat(
        ((customer.totalSpent / totalRevenue) * 100).toFixed(2)
      );
    });

    res.json(topCustomers);
  } catch (error) {
    console.error("Error fetching top customers:", error);
    res.status(500).json({ error: "Could not fetch top customers" });
  }
});

app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);
