# 🛍️ Shopify Analytics Dashboard

A modern, real-time Shopify merchant analytics platform with JWT authentication, OTP email verification, and advanced data visualization. Built with React, Node.js, PostgreSQL, and TailwindCSS.

## ✨ Features

### 🔐 Authentication & Security
- **JWT-based Authentication**: Secure token-based login system
- **OTP Email Verification**: Two-factor authentication via Gmail for new users
- **Password Hashing**: bcryptjs for secure password storage
- **Protected API Routes**: All sensitive endpoints require Bearer token

### 📊 Data Analytics
- **Real-time Dashboard**: Live order metrics and trends
- **Sales Trend Chart**: Interactive area chart with daily revenue visualization
- **Top 5 Customers**: Spending breakdown by customer with percentages
- **Order Management**: Search, filter, and view detailed order information
- **Date Range Filtering**: Custom filters for orders and analytics

### 🔄 Data Synchronization
- **Auto-Sync Toggle**: Automatic Shopify data synchronization
- **Manual Sync**: One-click data refresh from Shopify API
- **Last Synced Timestamp**: Track when data was last updated
- **Multi-tenant Support**: Isolated data per Shopify store

### 🎨 User Experience
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Modern UI**: TailwindCSS with gradient effects and animations
- **Xeno Branding**: Custom logo with gradient text
- **Toast Notifications**: Real-time feedback for user actions
- **Loading States**: Skeleton loaders for better UX

## 🏗️ Architecture

### Tech Stack
```
Frontend:
- React 19 with Hooks
- Vite (build tool)
- TailwindCSS (styling)
- Recharts (data visualization)
- Axios (HTTP client)
- React Hot Toast (notifications)

Backend:
- Node.js with Express.js
- Prisma ORM
- PostgreSQL (Neon)
- JWT (jsonwebtoken)
- bcryptjs (password hashing)
- Nodemailer (email sending)

Database:
- PostgreSQL with Neon
- Multi-tenant isolation
- Automated migrations
```

### System Design
```
┌─────────────────┐
│   React App     │
│   (Port 5174)   │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────────────┐
│  Express API Server     │
│  (Port 5001)            │
│  - Auth Endpoints       │
│  - Data APIs            │
└────────┬────────────────┘
         │
    ┌────┴────┬──────────┐
    ▼         ▼          ▼
┌────────┐ ┌──────┐ ┌──────────┐
│ Neon   │ │Gmail │ │ Shopify  │
│ Postgres│ │SMTP  │ │   API    │
└────────┘ └──────┘ └──────────┘
```

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ and npm
- PostgreSQL database (Neon recommended)
- Shopify Admin API credentials
- Gmail account with App Password

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ayushmaan19/Shopify-Analytics-Dashboard.git
cd Shopify-Analytics-Dashboard
```

2. **Setup Backend**
```bash
cd backend
cp .env.example .env
# Edit .env with your credentials
npm install
npm start
```

3. **Setup Frontend**
```bash
cd frontend
npm install
npm run dev
```

4. **Access the application**
- Frontend: http://localhost:5174
- Backend API: http://localhost:5001

## 📋 Environment Variables

### Backend (.env)
```
DATABASE_URL=postgresql://...
SHOPIFY_SHOP_DOMAIN=your-store.myshopify.com
SHOPIFY_ACCESS_TOKEN=shpat_...
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=xxxx xxxx xxxx xxxx
JWT_SECRET=your-secret-key
PORT=5001
NODE_ENV=development
```

### Frontend (.env)
```
VITE_API_BASE_URL=http://localhost:5001
VITE_SHOPIFY_DOMAIN=your-store.myshopify.com
```

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/login` - Login with email/password (generates OTP)
- `POST /api/auth/verify-otp` - Verify OTP and get JWT token
- `GET /api/auth/verify` - Verify token validity

### Data
- `GET /api/orders` - Get orders with stats and trends (requires auth)
- `POST /api/sync` - Sync data from Shopify (requires auth)
- `GET /api/top-customers` - Get top 5 customers by spending (requires auth)

## 📊 Database Schema

```
User
├── id (UUID, primary key)
├── email (unique)
├── password (hashed)
├── otp (temporary)
├── otpExpiry
├── isVerified (boolean)
└── createdAt

Tenant (Multi-tenant isolation)
├── id
├── shopDomain
├── accessToken
└── relationships to Orders, Customers, Products

Order
├── id
├── shopifyId
├── totalPrice
├── currency
├── customerName
├── tenantId (foreign key)
└── createdAt

Customer
├── id
├── shopifyId
├── firstName
├── email
└── tenantId

Product
├── id
├── shopifyId
├── title
└── tenantId
```

## 🔐 Authentication Flow

### New User Registration
```
1. User enters email + password
2. Backend creates user (isVerified: false)
3. 6-digit OTP generated and sent to email
4. User enters OTP in verification screen
5. User marked as verified (isVerified: true)
6. JWT token returned for session
```

### Returning User Login
```
1. User enters email + password
2. Backend checks isVerified flag
3. If verified: Return JWT token directly (no OTP needed)
4. If not verified: Send OTP (first-time only)
```

## 🚢 Deployment

### Deploy Backend (Render/Railway/Heroku)
```bash
# Set environment variables in platform dashboard
# Ensure PostgreSQL is accessible from the cloud

npm run build  # (if applicable)
npm start
```

### Deploy Frontend (Vercel/Netlify/GitHub Pages)
```bash
npm run build
# Deploy dist/ folder to CDN
```

### Environment Setup for Production
1. Use strong JWT_SECRET
2. Enable HTTPS everywhere
3. Set secure CORS origins
4. Use production email service
5. Enable database backups
6. Setup monitoring and logging

## 📈 Performance Considerations

- Frontend bundle: 171KB gzipped
- Database queries optimized with Prisma
- Implement code splitting for large bundles
- Add caching layer (Redis) for frequently accessed data
- Enable CDN for static assets

## 🔄 Data Flow

```
User Login → OTP Email → Token Generation → API Requests
                    ↓
         Sync Shopify Data
                    ↓
         Store in PostgreSQL
                    ↓
         Fetch & Display in Dashboard
```

## 🛠️ Development

### Available Scripts

**Backend:**
```bash
npm start      # Production mode
npm run dev    # Development with nodemon
```

**Frontend:**
```bash
npm run dev    # Development server
npm run build  # Production build
npm run lint   # Run ESLint
npm run preview # Preview production build
```

## 🐛 Known Issues & Future Improvements

### Current Limitations
- OTP expires in 10 minutes
- Max 5 customers displayed
- No pagination for orders
- Bundle size warning (557KB)

### Planned Enhancements
- Token refresh mechanism
- Pagination for orders
- More analytics metrics
- Multi-store support
- Real-time WebSocket updates
- Mobile app
- Advanced filtering options
- Export to CSV/PDF

## 📝 Notes & Assumptions

### Design Decisions
1. **Single Page Application**: React for dynamic UI without page reloads
2. **JWT Tokens**: Stateless authentication for scalability
3. **PostgreSQL**: Relational database for structured data
4. **Prisma ORM**: Type-safe database operations
5. **TailwindCSS**: Utility-first CSS for rapid development

### Security Assumptions
- HTTPS enabled in production
- Secrets not committed to version control
- API rate limiting implemented at platform level
- CORS configured for specific origins
- Password hashing with bcryptjs (salt rounds: 10)

## 🤝 Contributing

This is a submission project. For features/bugs, please create issues or submit PRs.

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Made by

**Ayushmaan Kumar Yadav**
- GitHub: [@ayushmaan19](https://github.com/ayushmaan19)
- Email: ayushmaan1092003@gmail.com

---

**Last Updated**: December 6, 2025
**Status**: Production Ready ✅
