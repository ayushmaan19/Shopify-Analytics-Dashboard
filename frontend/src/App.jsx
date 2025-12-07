import React, { useState, useEffect, useCallback } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Package, User, Search, X, Loader2, RefreshCcw, TrendingUp, Users, ShoppingBag, Zap, Hash, AlertCircle } from 'lucide-react';
import toast, { Toaster } from 'react-hot-toast';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5001";
const SHOPIFY_DOMAIN = import.meta.env.VITE_SHOPIFY_DOMAIN || "xeno-test-storeV1.myshopify.com";

const LoginPage = ({ onLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [userId, setUserId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('login'); // 'login', 'register', 'forgot-password'
  const [step, setStep] = useState('login'); // 'login', 'otp', 'reset-password'
  const [otpTimer, setOtpTimer] = useState(600); // 10 minutes
  const [showPasswordHints, setShowPasswordHints] = useState(false);
  const [showNewPasswordHints, setShowNewPasswordHints] = useState(false);

  const validatePassword = (pwd) => {
    const minLength = pwd.length >= 8;
    const hasUppercase = /[A-Z]/.test(pwd);
    const hasLowercase = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(pwd);
    
    return {
      isValid: minLength && hasUppercase && hasLowercase && hasNumber && hasSpecial,
      minLength,
      hasUppercase,
      hasLowercase,
      hasNumber,
      hasSpecial
    };
  };

  const passwordValidation = validatePassword(password);
  const newPasswordValidation = validatePassword(newPassword);

  useEffect(() => {
    if (step === 'otp' && otpTimer > 0) {
      const interval = setInterval(() => setOtpTimer(t => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [step, otpTimer]);

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to send OTP');
      }

      setUserId(data.userId);
      setStep('otp');
      setOtpTimer(600);
      toast.success('OTP sent to your email!');
    } catch (err) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (!newPasswordValidation.isValid) {
      setError('Password does not meet requirements');
      setLoading(false);
      setShowNewPasswordHints(true);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, otp, newPassword }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Password reset failed');
      }

      toast.success('Password reset successfully!');
      setMode('login');
      setStep('login');
      setEmail('');
      setPassword('');
      setNewPassword('');
      setOtp('');
      setError('');
    } catch (err) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (mode === 'register' && !passwordValidation.isValid) {
      setError('Password does not meet requirements');
      setLoading(false);
      setShowPasswordHints(true);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, isRegistration: mode === 'register' }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (mode === 'register' && data.error && data.error.includes('already exists')) {
          setError('Account already exists. Please login instead.');
          toast.error('Account already exists. Please login instead.');
        } else {
          setError(data.error || 'Login failed');
          toast.error(data.error || 'Login failed');
        }
        setLoading(false);
        return;
      }

      if (mode === 'register' && !data.requiresOTP && data.token) {
        setError('Account already exists. Please use login instead.');
        toast.error('Account already exists. Please use login instead.');
        setLoading(false);
        return;
      }

      if (!data.requiresOTP && data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        onLogin(data.user);
        toast.success('Logged in successfully!');
      } else {
        setUserId(data.userId);
        setStep('otp');
        setOtpTimer(600);
        toast.success('OTP sent to your email!');
      }
    } catch (err) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (mode === 'forgot-password') {
        setStep('reset-password');
        setLoading(false);
        return;
      }

      const response = await fetch(`${API_BASE_URL}/api/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, otp }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'OTP verification failed');
      }

      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user);
      toast.success('Account verified!');
    } catch (err) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setLoading(true);
    setError('');

    try {
      const endpoint = mode === 'forgot-password' 
        ? `${API_BASE_URL}/api/auth/forgot-password`
        : `${API_BASE_URL}/api/auth/login`;
      
      const body = mode === 'forgot-password'
        ? { email }
        : { email, password };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to resend OTP');
      }

      setOtpTimer(600);
      setOtp('');
      toast.success('OTP resent to your email!');
    } catch (err) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (step === 'reset-password') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-md">
          <div className="mb-8 text-center">
            <h1 className="text-3xl font-extrabold text-slate-900 mb-2">Reset Password</h1>
            <p className="text-slate-500">Enter your new password</p>
          </div>

          <form onSubmit={handleResetPassword} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                onFocus={() => setShowNewPasswordHints(true)}
                placeholder="••••••••"
                className="w-full px-4 py-2 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-emerald-500"
                required
              />
              {showNewPasswordHints && newPassword && (
                <div className="mt-2 p-3 bg-slate-50 rounded-lg space-y-1 text-xs">
                  <p className="font-semibold text-slate-700 mb-1">Password must contain:</p>
                  <div className="flex items-center gap-2">
                    <span className={newPasswordValidation.minLength ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={newPasswordValidation.minLength ? 'text-emerald-600' : 'text-slate-500'}>At least 8 characters</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={newPasswordValidation.hasUppercase ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={newPasswordValidation.hasUppercase ? 'text-emerald-600' : 'text-slate-500'}>One uppercase letter (A-Z)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={newPasswordValidation.hasLowercase ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={newPasswordValidation.hasLowercase ? 'text-emerald-600' : 'text-slate-500'}>One lowercase letter (a-z)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={newPasswordValidation.hasNumber ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={newPasswordValidation.hasNumber ? 'text-emerald-600' : 'text-slate-500'}>One number (0-9)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={newPasswordValidation.hasSpecial ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={newPasswordValidation.hasSpecial ? 'text-emerald-600' : 'text-slate-500'}>One special character (!@#$%...)</span>
                  </div>
                </div>
              )}
            </div>

            {error && <p className="text-red-500 text-sm font-semibold">{error}</p>}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-bold rounded-xl transition-all disabled:opacity-50"
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>

          <div className="mt-4 text-center">
            <button
              onClick={() => {
                setStep('login');
                setMode('login');
                setError('');
                setNewPassword('');
              }}
              className="text-sm text-slate-500 hover:text-slate-700 font-semibold underline"
            >
              Back to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (step === 'otp') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-md">
          <div className="mb-8 text-center">
            <h1 className="text-3xl font-extrabold text-slate-900 mb-2">Verify OTP</h1>
            <p className="text-slate-500">Enter the 6-digit code sent to your email</p>
            <p className="text-sm text-slate-400 mt-2">{email}</p>
          </div>

          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">OTP Code</label>
              <input
                type="text"
                maxLength="6"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="w-full px-4 py-3 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-emerald-500 text-center text-2xl font-bold tracking-widest"
                required
              />
            </div>

            {error && <p className="text-red-500 text-sm font-semibold">{error}</p>}

            <button
              type="submit"
              disabled={loading || otp.length !== 6}
              className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-bold rounded-xl transition-all disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify OTP'}
            </button>
          </form>

          <div className="mt-6 text-center space-y-2">
            <p className="text-sm text-slate-500">
              OTP expires in: <span className="font-semibold text-emerald-600">{Math.floor(otpTimer / 60)}:{String(otpTimer % 60).padStart(2, '0')}</span>
            </p>
            <button
              onClick={handleResendOtp}
              disabled={loading}
              className="text-sm text-emerald-600 hover:text-emerald-700 font-semibold underline disabled:opacity-50"
            >
              Didn't receive OTP? Resend
            </button>
            <button
              onClick={() => {
                setStep('login');
                setError('');
                setOtp('');
              }}
              className="text-sm text-slate-500 hover:text-slate-700 font-semibold underline block mx-auto"
            >
              Back to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4">
      {/* Xeno Logo - Top Left */}
      <div className="absolute top-8 left-8">
        <div className="flex items-center gap-2">
          <div className="w-10 h-10 bg-gradient-to-br from-emerald-400 to-teal-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-lg">X</span>
          </div>
          <span className="text-2xl font-black bg-gradient-to-r from-emerald-400 via-teal-500 to-emerald-600 bg-clip-text text-transparent">Xeno</span>
        </div>
      </div>

      <div className="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="text-4xl font-extrabold text-slate-900 mb-2">Merchant Insights</h1>
          <p className="text-slate-500">
            {mode === 'register' ? 'Create your account' : mode === 'forgot-password' ? 'Reset your password' : 'Sign in to your account'}
          </p>
        </div>

        <form onSubmit={mode === 'forgot-password' ? handleForgotPassword : handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-semibold text-slate-700 mb-2">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              className="w-full px-4 py-2 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-emerald-500"
              required
            />
          </div>

          {mode !== 'forgot-password' && (
            <div>
              <label className="block text-sm font-semibold text-slate-700 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onFocus={() => mode === 'register' && setShowPasswordHints(true)}
                placeholder="••••••••"
                className="w-full px-4 py-2 border-2 border-slate-200 rounded-xl focus:outline-none focus:border-emerald-500"
                required
              />
              {mode === 'register' && showPasswordHints && password && (
                <div className="mt-2 p-3 bg-slate-50 rounded-lg space-y-1 text-xs">
                  <p className="font-semibold text-slate-700 mb-1">Password must contain:</p>
                  <div className="flex items-center gap-2">
                    <span className={passwordValidation.minLength ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={passwordValidation.minLength ? 'text-emerald-600' : 'text-slate-500'}>At least 8 characters</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={passwordValidation.hasUppercase ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={passwordValidation.hasUppercase ? 'text-emerald-600' : 'text-slate-500'}>One uppercase letter (A-Z)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={passwordValidation.hasLowercase ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={passwordValidation.hasLowercase ? 'text-emerald-600' : 'text-slate-500'}>One lowercase letter (a-z)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={passwordValidation.hasNumber ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={passwordValidation.hasNumber ? 'text-emerald-600' : 'text-slate-500'}>One number (0-9)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={passwordValidation.hasSpecial ? 'text-emerald-600' : 'text-slate-400'}>●</span>
                    <span className={passwordValidation.hasSpecial ? 'text-emerald-600' : 'text-slate-500'}>One special character (!@#$%...)</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {error && <p className="text-red-500 text-sm font-semibold">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white font-bold rounded-xl transition-all disabled:opacity-50"
          >
            {loading 
              ? (mode === 'register' ? 'Creating Account...' : mode === 'forgot-password' ? 'Sending OTP...' : 'Signing in...') 
              : (mode === 'register' ? 'Create Account' : mode === 'forgot-password' ? 'Send OTP' : 'Sign In')}
          </button>
        </form>

        {mode === 'login' && (
          <div className="text-center mt-3">
            <button
              onClick={() => {
                setMode('forgot-password');
                setError('');
                setPassword('');
              }}
              className="text-sm text-slate-600 hover:text-slate-800 font-semibold"
            >
              Forgot password?
            </button>
          </div>
        )}

        <div className="text-center mt-4">
          <button
            onClick={() => {
              if (mode === 'forgot-password') {
                setMode('login');
              } else {
                setMode(mode === 'login' ? 'register' : 'login');
              }
              setError('');
              setShowPasswordHints(false);
            }}
            className="text-sm text-emerald-600 hover:text-emerald-700 font-semibold"
          >
            {mode === 'login' ? "Don't have an account? Register" : mode === 'forgot-password' ? 'Back to Login' : 'Already have an account? Login'}
          </button>
        </div>

        {mode === 'register' && (
          <p className="text-center text-slate-500 text-xs mt-2">
            Password must be 8+ characters with uppercase, lowercase, number & special character
          </p>
        )}
      </div>
    </div>
  );
};

const OrderModal = ({ order, onClose }) => {
  if (!order) return null;
  
  const handleViewInShopify = () => {
    const shopifyOrderUrl = `https://${SHOPIFY_DOMAIN}/admin/orders/${order.shopifyId}`;
    window.open(shopifyOrderUrl, '_blank');
  };
  
  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-white rounded-3xl w-full max-w-lg p-6 relative shadow-2xl border border-slate-100">
        <button onClick={onClose} className="absolute right-5 top-5 p-2 bg-slate-50 hover:bg-slate-100 rounded-full text-slate-400 hover:text-slate-600 transition-colors">
          <X size={20} />
        </button>
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-3 bg-emerald-50 rounded-2xl">
              <Package className="text-emerald-600" size={24} />
            </div>
            <div>
              <h3 className="text-xl font-bold text-slate-800">Order Details</h3>
              <p className="text-sm text-slate-500">{order.date}</p>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Customer</p>
            <p className="font-bold text-slate-800">{order.name}</p>
          </div>
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Amount</p>
            <p className="font-bold text-emerald-600 text-lg">INR {order.amount}</p>
          </div>
        </div>
        <div className="space-y-3">
           <p className="text-xs font-bold text-slate-400 uppercase tracking-wider ml-1">Technical Data</p>
           <div className="flex items-center justify-between p-3 border border-slate-100 rounded-xl hover:bg-slate-50 transition-colors">
              <div className="flex items-center gap-3">
                 <div className="p-2 bg-blue-50 text-blue-600 rounded-lg">
                    <Hash size={18} />
                 </div>
                 <div>
                    <p className="text-xs text-slate-500 font-bold">Shopify Order ID</p>
                    <p className="text-sm font-medium text-slate-800">#{order.shopifyId || order.id || "N/A"}</p>
                 </div>
              </div>
              <div className="px-2 py-1 bg-slate-100 text-slate-500 text-xs rounded-md font-medium">Sync: Active</div>
           </div>
        </div>
        <div className="mt-8 pt-6 border-t border-slate-100 flex gap-3">
          <button onClick={onClose} className="flex-1 py-3 rounded-xl font-bold text-slate-600 hover:bg-slate-50 transition-colors">Close</button>
          <button onClick={handleViewInShopify} className="flex-1 py-3 rounded-xl bg-slate-900 text-white font-bold hover:bg-slate-800 shadow-lg shadow-slate-200 transition-all">View in Shopify</button>
        </div>
      </div>
    </div>
  );
};

function App() {
  const [user, setUser] = useState(null);
  const [topCustomers, setTopCustomers] = useState([]);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  
  const [stats, setStats] = useState({ revenue: '0', orders: '0', customers: '0' });
  const [recentOrders, setRecentOrders] = useState([]);
  const [chartData, setChartData] = useState([]); 
  const [isOrdersLoading, setIsOrdersLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const [isOrderSearchOpen, setIsOrderSearchOpen] = useState(false);
  const [orderSearchTerm, setOrderSearchTerm] = useState('');
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [lastSyncTime, setLastSyncTime] = useState(null);

  const [isAutoSync, setIsAutoSync] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const getHeaders = () => {
    const token = localStorage.getItem('token');
    return {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` })
    };
  };

  const fetchTopCustomers = useCallback(async () => {
    try {
      const queryParams = new URLSearchParams();
      if (startDate) queryParams.append('startDate', startDate);
      if (endDate) queryParams.append('endDate', endDate);
      
      const response = await fetch(`${API_BASE_URL}/api/top-customers?${queryParams}`, {
        headers: getHeaders()
      });
      if (!response.ok) throw new Error('Failed to fetch top customers');
      
      const data = await response.json();
      setTopCustomers(data);
      console.log("Top customers updated:", data);
    } catch (error) {
      console.error("Failed to fetch top customers:", error);
    }
  }, [startDate, endDate]);

  const fetchOrders = useCallback(async (isBackground = false) => {
    if (!isBackground) setIsOrdersLoading(true);
    setHasError(false);
    
    try {
      const queryParams = new URLSearchParams();
      if (startDate) queryParams.append('startDate', startDate);
      if (endDate) queryParams.append('endDate', endDate);
      
      console.log(`[${new Date().toLocaleTimeString()}] Fetching from: ${API_BASE_URL}/api/orders${isBackground ? ' (Background)' : ''}`);
      console.log("Headers:", getHeaders());
      
      const response = await fetch(`${API_BASE_URL}/api/orders?${queryParams}`, {
        headers: getHeaders()
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error("Fetch error response:", errorData);
        throw new Error(errorData.error || `Server Error: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Data received:", data);

      if (data.stats) {
        setStats(data.stats);
        console.log("Stats updated:", data.stats);
      }
      if (data.orders) {
        setRecentOrders(data.orders);
        console.log("Orders updated:", data.orders.length);
      }
      if (data.trend) {
        setChartData(data.trend);
        console.log("Chart data updated:", data.trend);
      }

      if (!isBackground) {
        toast.success("Dashboard Synced");
        setLastSyncTime(new Date());
        console.log("Manual sync completed");
        await fetchTopCustomers(); // Fetch top customers when syncing
      } else {
        console.log(`[Auto-sync] Completed at ${new Date().toLocaleTimeString()}`);
      }
      
    } catch (error) {
      console.error("Fetch Failed:", error);
      setHasError(true);
      if (!isBackground) toast.error("Sync Failed");
    } finally {
      if (!isBackground) setIsOrdersLoading(false);
    }
  }, [startDate, endDate, fetchTopCustomers]);

  const handleSync = useCallback(async () => {
    setIsOrdersLoading(true);
    setHasError(false);
    
    try {
      console.log(`[${new Date().toLocaleTimeString()}] Starting Shopify sync...`);
      
      const syncResponse = await fetch(`${API_BASE_URL}/api/sync`, {
        method: 'POST',
        headers: getHeaders()
      });
      
      const syncData = await syncResponse.json();
      
      if (!syncResponse.ok) {
        console.error("Sync error response:", syncData);
        throw new Error(syncData.details || syncData.error || `Sync failed: ${syncResponse.status}`);
      }
      
      console.log("Sync response:", syncData);
      
      await fetchOrders(false);
      
      setLastSyncTime(new Date());
      toast.success("Synced from Shopify!");
    } catch (error) {
      console.error("Sync Error:", error);
      setHasError(true);
      toast.error("Sync Failed: " + error.message);
    } finally {
      setIsOrdersLoading(false);
    }
  }, [fetchOrders]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    toast.success('Logged out');
  };

  useEffect(() => {
    if (user) {
      console.log("🔄 Initial load: Starting auto-sync...");
      handleSync();
    }
  }, [user, handleSync]);

  useEffect(() => {
    let interval;
    if (isAutoSync) {
      console.log("🔄 Auto-Sync ENABLED - Syncing every 30 seconds");
      interval = setInterval(async () => {
        try {
          const syncResponse = await fetch(`${API_BASE_URL}/api/sync`, {
            method: 'POST',
            headers: getHeaders()
          });
          
          if (syncResponse.ok) {
            await new Promise(r => setTimeout(r, 500));
            fetchOrders(true);
          }
        } catch (error) {
          console.error("Auto-sync error:", error);
        }
      }, 500); // 0.5 second
    } else {
      console.log("⏸ Auto-Sync DISABLED");
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isAutoSync, fetchOrders]);

  useEffect(() => {
    if (user) {
      fetchOrders(false);
    }
  }, [startDate, endDate, fetchOrders, user]);

  const filteredOrders = recentOrders.filter((order) =>
    (order.date && order.date.toLowerCase().includes(orderSearchTerm.toLowerCase())) ||
    (order.name && order.name.toLowerCase().includes(orderSearchTerm.toLowerCase()))
  );

  if (!user) {
    return <LoginPage onLogin={(userData) => setUser(userData)} />;
  }

  return (
    <div className="min-h-screen bg-slate-50 p-6 font-sans text-slate-900">
      <Toaster position="top-right" />
      {selectedOrder && <OrderModal order={selectedOrder} onClose={() => setSelectedOrder(null)} />}

      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* HEADER */}
        <header className="flex flex-col md:flex-row md:items-start justify-between gap-6">
          <div>
            <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Merchant Insights</h1>
            <p className="text-slate-500 mt-1">Real-time performance monitor</p>
            <button 
              onClick={handleLogout}
              className="mt-3 px-4 py-1.5 rounded-full text-xs font-semibold text-slate-600 bg-slate-200 hover:bg-slate-300 transition-all"
            >
              Logout
            </button>
          </div>
          <div className="flex flex-col items-end gap-3">
            {/* TOP ROW: DATE FILTERS */}
            <div className="flex items-center gap-3 w-full md:w-auto">
              {/* DATE FILTERS */}
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="px-3 py-1.5 border border-slate-200 rounded-lg text-xs font-semibold focus:outline-none focus:border-emerald-500"
              />
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="px-3 py-1.5 border border-slate-200 rounded-lg text-xs font-semibold focus:outline-none focus:border-emerald-500"
              />
              <button 
                onClick={() => {
                  setStartDate("");
                  setEndDate("");
                }}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-600 bg-slate-100 hover:bg-slate-200 transition-all"
              >
                Clear
              </button>
            </div>
            
            {/* BOTTOM ROW: AUTO SYNC + SYNC NOW */}
            <div className="flex items-center gap-3 w-full md:w-auto">
              {/* AUTO SYNC TOGGLE BUTTON */}
              <button 
                onClick={() => setIsAutoSync(!isAutoSync)}
                className={`px-3 py-1.5 border rounded-full text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer relative ${
                  isAutoSync 
                  ? "bg-emerald-50 border-emerald-200 text-emerald-700 shadow-md shadow-emerald-200" 
                  : "bg-white border-slate-200 text-slate-500 hover:border-slate-300"
                }`}
              >
                {isAutoSync && <div className="absolute inset-0 rounded-full animate-pulse bg-emerald-100 opacity-50"></div>}
                <div className="relative flex items-center gap-2">
                  <Zap size={14} className={isAutoSync ? "fill-current animate-bounce" : "text-slate-400"} /> 
                  <span>Auto-Sync: {isAutoSync ? 'ON' : 'OFF'}</span>
                </div>
              </button>
              
              <button 
                onClick={() => handleSync()}
                className={`px-4 py-2 rounded-full text-sm font-semibold flex items-center gap-2 transition-all shadow-lg ${
                  hasError 
                  ? "bg-red-500 hover:bg-red-600 text-white shadow-red-200"
                  : "bg-slate-900 hover:bg-slate-800 text-white shadow-slate-200"
                }`}
              >
                {isOrdersLoading ? <Loader2 size={16} className="animate-spin" /> : hasError ? <AlertCircle size={16} /> : <RefreshCcw size={16} />}
                {isOrdersLoading ? "Syncing..." : hasError ? "Retry Sync" : "Sync Now"}
              </button>
            </div>
            {lastSyncTime && (
              <p className="text-xs text-slate-500">
                Last synced: {lastSyncTime.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </p>
            )}
          </div>
        </header>

        {/* STATS CARDS */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm relative overflow-hidden group hover:border-blue-100 transition-all">
            <div className="absolute top-0 right-0 w-32 h-32 bg-blue-50 rounded-full -mr-16 -mt-16 transition-transform group-hover:scale-110"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-2 text-slate-500">
                <TrendingUp size={18} className="text-blue-500" />
                <span className="text-sm font-semibold">Total Revenue</span>
              </div>
              <div className="text-4xl font-bold text-slate-900">₹{parseFloat(stats.revenue).toLocaleString()}</div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm relative overflow-hidden group hover:border-emerald-100 transition-all">
             <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-50 rounded-full -mr-16 -mt-16 transition-transform group-hover:scale-110"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-2 text-slate-500">
                <ShoppingBag size={18} className="text-emerald-500" />
                <span className="text-sm font-semibold">Total Orders</span>
              </div>
              <div className="text-4xl font-bold text-slate-900">{stats.orders}</div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-3xl border border-slate-100 shadow-sm relative overflow-hidden group hover:border-purple-100 transition-all">
             <div className="absolute top-0 right-0 w-32 h-32 bg-purple-50 rounded-full -mr-16 -mt-16 transition-transform group-hover:scale-110"></div>
            <div className="relative">
              <div className="flex items-center gap-2 mb-2 text-slate-500">
                <Users size={18} className="text-purple-500" />
                <span className="text-sm font-semibold">Active Customers</span>
              </div>
              <div className="text-4xl font-bold text-slate-900">{stats.customers}</div>
            </div>
          </div>
        </div>

        {/* MAIN GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* SALES CHART */}
          <div className="lg:col-span-2 bg-white rounded-3xl shadow-sm border border-slate-100 p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-slate-800">Sales Trend</h2>
              {isAutoSync ? (
                <span className="px-3 py-1 bg-emerald-50 text-emerald-700 text-xs font-bold rounded-md flex items-center gap-2">
                  <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                  Live
                </span>
              ) : (
                <span className="px-3 py-1 bg-indigo-50 text-indigo-600 text-xs font-bold rounded-md">Live Data</span>
              )}
            </div>
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.1}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 12}} dy={10} />
                  <YAxis axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 12}} />
                  <Tooltip 
                    contentStyle={{borderRadius: '12px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'}}
                    cursor={{stroke: '#6366f1', strokeWidth: 1, strokeDasharray: '4 4'}}
                  />
                  <Area type="monotone" dataKey="value" stroke="#6366f1" strokeWidth={3} fillOpacity={1} fill="url(#colorValue)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* RIGHT COLUMN */}
          <div className="space-y-6 flex flex-col">
            
            {/* TOP 5 CUSTOMERS */}
            <div className="bg-white rounded-3xl shadow-sm border border-slate-100 p-6">
              <h3 className="font-bold text-slate-800 mb-4">Top 5 Customers</h3>
              <div className="space-y-3">
                {topCustomers.length > 0 ? (
                  topCustomers.map((customer, idx) => (
                    <div key={idx} className="flex items-center justify-between p-3 bg-slate-50 rounded-2xl border border-slate-100 hover:border-emerald-200 transition-colors">
                      <div className="flex-1">
                        <p className="font-bold text-slate-800 text-sm">{idx + 1}. {customer.name}</p>
                        <p className="text-xs text-slate-500 mt-1">₹{customer.totalSpent.toLocaleString()}</p>
                      </div>
                      <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-full">{customer.percentage}%</span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-400 text-center py-4">No customer data</p>
                )}
              </div>
            </div>
            
            {/* SYSTEM STATUS (Preserved) */}
            <div className="bg-white rounded-3xl shadow-sm border border-slate-100 p-6">
              <h3 className="font-bold text-slate-800 mb-4">System Status</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                    <div className="text-sm">
                      <p className="font-semibold text-slate-700">Database Sync</p>
                      <p className="text-xs text-slate-400">PostgreSQL</p>
                    </div>
                  </div>
                  <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-full">Active</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                    <div className="text-sm">
                      <p className="font-semibold text-slate-700">Shopify API</p>
                      <p className="text-xs text-slate-400">Admin Scope</p>
                    </div>
                  </div>
                  <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-full">Active</span>
                </div>
              </div>
            </div>

            {/* RECENT ORDERS LIST */}
            <div className="bg-white rounded-3xl shadow-sm border border-slate-100 p-6 flex flex-col flex-1">
              
              <div className="flex items-center justify-between mb-4 h-10">
                <div className={`flex items-center gap-2 ${isOrderSearchOpen ? 'hidden xl:flex' : 'flex'}`}>
                  <Package className="text-slate-800" size={20} />
                  <h2 className={`font-bold text-slate-800 ${isOrderSearchOpen ? 'hidden' : 'block'}`}>Recent Orders</h2>
                </div>
                
                <div className={`flex items-center bg-white border-2 border-slate-200 rounded-full transition-all duration-300 ml-auto ${
                    isOrderSearchOpen ? 'w-48 px-3 py-2 shadow-md border-emerald-500' : 'w-10 h-10 justify-center border-transparent hover:bg-slate-50'
                  }`}>
                  {isOrderSearchOpen && (
                    <input
                      type="text"
                      placeholder="Search..."
                      value={orderSearchTerm}
                      onChange={(e) => setOrderSearchTerm(e.target.value)}
                      autoFocus
                      className="w-full bg-transparent outline-none text-sm text-slate-600 placeholder-slate-400 mr-2 font-medium"
                    />
                  )}
                  <button 
                    onClick={() => {
                      if (isOrderSearchOpen) setOrderSearchTerm('');
                      setIsOrderSearchOpen(!isOrderSearchOpen);
                    }} 
                    className={`flex-shrink-0 focus:outline-none transition-colors ${isOrderSearchOpen ? 'text-emerald-600' : 'text-slate-500 hover:text-slate-800'}`}
                  >
                    {isOrderSearchOpen ? <X size={14} /> : <Search size={16} />}
                  </button>
                </div>
              </div>

              <div className="flex flex-col gap-3 flex-1 overflow-y-auto max-h-[300px] pr-1 custom-scrollbar">
                {isOrdersLoading && recentOrders.length === 0 ? (
                  [1, 2, 3].map((i) => (
                    <div key={i} className="flex items-center justify-between p-3 border border-slate-100 rounded-2xl animate-pulse">
                      <div className="flex gap-3 items-center">
                        <div className="h-8 w-8 bg-slate-200 rounded-full"></div>
                        <div className="h-3 w-20 bg-slate-200 rounded"></div>
                      </div>
                      <div className="h-3 w-12 bg-slate-200 rounded"></div>
                    </div>
                  ))
                ) : filteredOrders.length > 0 ? (
                  filteredOrders.map((order) => (
                    <div 
                      key={order.id} 
                      onClick={() => setSelectedOrder(order)}
                      className="flex items-center justify-between bg-slate-50 rounded-2xl p-3 hover:bg-slate-100 transition-colors cursor-pointer border border-transparent hover:border-slate-200 group"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full border border-slate-200 flex items-center justify-center bg-white text-slate-400 group-hover:border-emerald-200 group-hover:text-emerald-500 transition-colors">
                          <User size={14} />
                        </div>
                        <div>
                          <p className="font-bold text-slate-800 text-xs">{order.name}</p>
                          <p className="text-slate-400 text-[10px] font-medium">{order.date}</p>
                        </div>
                      </div>
                      <div className="font-bold text-emerald-700 text-xs">INR {order.amount}</div>
                    </div>
                  ))
                ) : (
                  <div className="flex flex-col items-center justify-center py-8 text-slate-400 text-center">
                    {hasError ? (
                       <>
                        <AlertCircle size={24} className="text-red-400 mb-2"/>
                        <p className="text-xs text-red-500 font-bold">Connection Failed</p>
                       </>
                    ) : (
                       <>
                        <Package size={24} className="opacity-20 mb-2"/>
                        <p className="text-xs">No orders found.</p>
                       </>
                    )}
                  </div>
                )}
              </div>
            </div>

          </div>
        </div>

        {/* FOOTER */}
        <footer className="mt-12 pt-8 border-t border-slate-200 text-center text-slate-500 text-sm">
          <p>
            Made by{' '}
            <a
              href="https://github.com/ayushmaan19"
              target="_blank"
              rel="noopener noreferrer"
              className="text-emerald-600 hover:text-emerald-700 font-semibold underline transition-colors"
            >
              Ayushmaan Kumar Yadav
            </a>
          </p>
        </footer>
      </div>
    </div>
  );
}

export default App;