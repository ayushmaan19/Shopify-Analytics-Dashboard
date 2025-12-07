require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Brevo = require("@getbrevo/brevo");

const app = express();
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});
const PORT = process.env.PORT || 5001;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// --- BREVO CONFIG ---
const brevoClient = new Brevo.TransactionalEmailsApi();
brevoClient.setApiKey(
  Brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY || ""
);

// Async email helper function using Brevo
const sendEmailAsync = async (to, subject, html) => {
  try {
    if (!process.env.BREVO_API_KEY) {
      console.error("❌ BREVO_API_KEY not configured");
      return;
    }

    console.log(`📧 Sending email to ${to}...`);

    const sendSmtpEmail = new Brevo.SendSmtpEmail();
    sendSmtpEmail.subject = subject;
    sendSmtpEmail.htmlContent = html;
    sendSmtpEmail.sender = {
      name: "Merchant Insights",
      email: process.env.BREVO_SENDER_EMAIL || "noreply@merchant-insights.com",
    };
    sendSmtpEmail.to = [{ email: to }];

    await brevoClient.sendTransacEmail(sendSmtpEmail);
    console.log(`✅ Email sent successfully to ${to}`);
  } catch (emailError) {
    console.error(`❌ Failed to send email to ${to}:`, emailError.message);
  }
};

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
const SHOP_TIMEZONE = process.env.SHOP_TIMEZONE || "Asia/Kolkata";

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
// Password validation helper
const validatePassword = (password) => {
  const minLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return {
    isValid:
      minLength && hasUppercase && hasLowercase && hasNumber && hasSpecial,
    message: !minLength
      ? "Password must be at least 8 characters"
      : !hasUppercase
      ? "Password must contain at least one uppercase letter"
      : !hasLowercase
      ? "Password must contain at least one lowercase letter"
      : !hasNumber
      ? "Password must contain at least one number"
      : !hasSpecial
      ? "Password must contain at least one special character"
      : "",
  };
};

// Login - Send OTP for new users
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, isRegistration } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      // Validate password for new users
      const passwordCheck = validatePassword(password);
      if (!passwordCheck.isValid) {
        return res.status(400).json({ error: passwordCheck.message });
      }

      // Create new user - requires OTP verification
      const hashedPassword = await bcrypt.hash(password, 10);
      user = await prisma.user.create({
        data: { email, password: hashedPassword, isVerified: false },
      });
    } else {
      // If user exists and this is a registration attempt, return error
      if (isRegistration) {
        return res
          .status(400)
          .json({ error: "Account already exists. Please login instead." });
      }

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

    // Send OTP via email asynchronously (don't wait for completion)
    sendEmailAsync(
      email,
      "Your Merchant Insights OTP Code",
      `
        <h2>Welcome to Merchant Insights</h2>
        <p>Your OTP code is: <strong style="font-size: 24px; color: #059669;">${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>Do not share this code with anyone.</p>
      `
    );

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

// Verify OTP and get token
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

// Forgot Password - Send OTP to reset
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await prisma.user.update({
      where: { id: user.id },
      data: { otp, otpExpiry },
    });

    // Log OTP to console for development/demo
    console.log(
      `\n📧 Password Reset OTP for ${email}: ${otp} (expires in 10 minutes)\n`
    );

    // Send OTP via email asynchronously (don't wait for completion)
    sendEmailAsync(
      email,
      "Password Reset - Merchant Insights",
      `
        <h2>Password Reset Request</h2>
        <p>Your OTP code is: <strong style="font-size: 24px; color: #059669;">${otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
      `
    );

    res.json({
      message: "OTP sent to your email for password reset.",
      email: email,
      userId: user.id,
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ error: "Password reset request failed" });
  }
});

// Reset Password with OTP
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { userId, otp, newPassword } = req.body;
    if (!userId || !otp || !newPassword) {
      return res
        .status(400)
        .json({ error: "User ID, OTP, and new password required" });
    }

    // Validate new password
    const passwordCheck = validatePassword(newPassword);
    if (!passwordCheck.isValid) {
      return res.status(400).json({ error: passwordCheck.message });
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

    // Hash new password and update
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        otp: null,
        otpExpiry: null,
        isVerified: true,
      },
    });

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: { id: user.id, email: user.email },
      message: "Password reset successful",
    });
  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({ error: "Password reset failed" });
  }
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

    // Batch insert orders for better performance
    const orderData = ordersRes.data.orders.map((o) => {
      const name = o.customer
        ? `${o.customer.first_name} ${o.customer.last_name}`
        : "Guest";
      return {
        shopifyId: String(o.id),
        totalPrice: parseFloat(o.total_price),
        currency: o.currency,
        customerName: name,
        createdAt: new Date(o.created_at),
        tenantId: tenant.id,
      };
    });

    await prisma.order.createMany({
      data: orderData,
      skipDuplicates: true,
    });

    console.log(`🔄 Fetching customers from ${baseURL}/customers.json`);
    const customersRes = await axios.get(`${baseURL}/customers.json`, {
      headers,
    });
    console.log(
      `✓ Found ${customersRes.data.customers?.length || 0} customers`
    );

    // Batch insert customers for better performance
    const customerData = customersRes.data.customers.map((c) => ({
      shopifyId: String(c.id),
      firstName: c.first_name,
      email: c.email,
      tenantId: tenant.id,
    }));

    await prisma.customer.createMany({
      data: customerData,
      skipDuplicates: true,
    });

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

    const dateTimeFormatter = new Intl.DateTimeFormat("en-US", {
      timeZone: SHOP_TIMEZONE,
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "numeric",
      hour12: true,
    });

    const dateFormatter = new Intl.DateTimeFormat("en-US", {
      timeZone: SHOP_TIMEZONE,
      month: "short",
      day: "numeric",
    });

    const toTimezoneDate = (date) =>
      new Date(
        date.toLocaleString("en-US", {
          timeZone: SHOP_TIMEZONE,
        })
      );

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
      date: dateTimeFormatter.format(new Date(o.createdAt)),
      amount: o.totalPrice.toFixed(2),
      status: "paid",
    }));

    // 4. Graph (Group by "Dec 6" format)
    const trendMap = {};
    const today = toTimezoneDate(new Date());

    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const dateKey = dateFormatter.format(d);
      trendMap[dateKey] = 0;
    }

    allOrders.forEach((order) => {
      const orderDate = toTimezoneDate(new Date(order.createdAt));

      const diffTime = Math.abs(today - orderDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

      if (diffDays <= 7) {
        const dateKey = dateFormatter.format(orderDate);
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
