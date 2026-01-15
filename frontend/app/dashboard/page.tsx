'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

interface User {
  id: string;
  email: string;
  username: string;
  roles: string[];
  permissions: string[];
}

interface Device {
  fingerprint: string;
  trusted: boolean;
  trustScore: number;
  lastSeen: string | number;
  userAgent: string;
  isCurrent: boolean;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const loadUserData = async () => {
      try {
        const meResponse = await fetch(`${API_URL}/auth/me`, {
          credentials: 'include',
        });

        if (!meResponse.ok) {
          router.push('/login');
          return;
        }

        const meData = await meResponse.json();
        setUser(meData.data.user);
        setIsAuthenticated(true);
      } catch (err) {
        console.error('Failed to fetch user:', err);
        router.push('/login');
        return;
      }

      // Fetch devices
      try {
        const response = await fetch(`${API_URL}/api/devices`, {
          credentials: 'include',
        });

        if (response.ok) {
          const data = await response.json();
          setDevices(data.data.devices || []);
        }
      } catch (err) {
        console.error('Failed to fetch devices:', err);
      }

      setLoading(false);
    };

    loadUserData();
  }, [router]);

  const handleLogout = async () => {
    try {
      await fetch(`${API_URL}/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      });
    } catch (err) {
      console.error('Logout error:', err);
    }

    router.push('/');
  };

  const formatDate = (timestamp: string | number | Date) => {
    return new Date(timestamp).toLocaleString();
  };

  const trustedCount = devices.filter(device => device.trusted).length;
  const averageTrustScore = devices.length
    ? Math.round(devices.reduce((sum, device) => sum + device.trustScore, 0) / devices.length)
    : 0;
  const currentDevice = devices.find(device => device.isCurrent);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-6">
              <h1 className="text-xl font-bold text-gray-900">Zero-Trust Dashboard</h1>
              <div className="hidden md:flex items-center gap-4 text-sm text-gray-600">
                <Link href="/dashboard" className="hover:text-gray-900">Dashboard</Link>
                <Link href="/products" className="hover:text-gray-900">Products</Link>
                <Link href="/orders" className="hover:text-gray-900">Orders</Link>
                <Link href="/inventory" className="hover:text-gray-900">Inventory</Link>
              </div>
            </div>
            <div className="flex items-center">
              <button
                onClick={handleLogout}
                className="ml-4 px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-red-600 hover:bg-red-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {error && (
          <div className="mb-4 rounded-lg bg-red-50 p-4">
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}

        {/* User Info Card */}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">User Information</h2>
          {user && (
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm font-medium text-gray-500">Username:</span>
                <span className="text-sm text-gray-900">{user.username}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm font-medium text-gray-500">Email:</span>
                <span className="text-sm text-gray-900">{user.email}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm font-medium text-gray-500">User ID:</span>
                <span className="text-sm text-gray-900 font-mono">{user.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm font-medium text-gray-500">Roles:</span>
                <span className="text-sm text-gray-900">{user.roles.join(', ')}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm font-medium text-gray-500">Permissions:</span>
                <span className="text-sm text-gray-900">
                  {user.permissions?.length ? user.permissions.join(', ') : 'none'}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Devices Card */}
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Trusted Devices ({devices.length})
          </h2>

          {devices.length === 0 ? (
            <p className="text-sm text-gray-500">No devices found</p>
          ) : (
            <div className="space-y-4">
              {devices.map(device => (
                <div
                  key={device.fingerprint}
                  className={`border rounded-lg p-4 ${
                    device.isCurrent ? 'border-indigo-500 bg-indigo-50' : 'border-gray-200'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center">
                        <span className="text-sm font-medium text-gray-900">
                          {device.userAgent.substring(0, 50)}...
                        </span>
                        {device.isCurrent && (
                          <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
                            Current Device
                          </span>
                        )}
                      </div>
                      <div className="mt-2 space-y-1">
                        <div className="flex items-center text-xs text-gray-500">
                          <span className="font-medium mr-2">Trust Score:</span>
                          <div className="flex-1 bg-gray-200 rounded-full h-2 max-w-xs">
                            <div
                              className={`h-2 rounded-full ${
                                device.trustScore >= 70
                                  ? 'bg-green-500'
                                  : device.trustScore >= 40
                                    ? 'bg-yellow-500'
                                    : 'bg-red-500'
                              }`}
                              style={{ width: `${device.trustScore}%` }}
                            ></div>
                          </div>
                          <span className="ml-2">{device.trustScore}/100</span>
                        </div>
                        <p className="text-xs text-gray-500">
                          Last seen: {formatDate(device.lastSeen)}
                        </p>
                        <p className="text-xs text-gray-400 font-mono">
                          Device Fingerprint: {device.fingerprint}
                        </p>
                      </div>
                    </div>
                    <div>
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          device.trusted
                            ? 'bg-green-100 text-green-800'
                            : 'bg-gray-100 text-gray-800'
                        }`}
                      >
                        {device.trusted ? 'Trusted' : 'Untrusted'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Features */}
        <div className="mt-6 bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Security Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">JWT Authentication</h3>
              <p className="text-xs text-gray-500">Token-based auth with refresh tokens</p>
            </div>
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">MFA Support</h3>
              <p className="text-xs text-gray-500">TOTP-based two-factor authentication</p>
              <p className="mt-2 text-xs text-gray-600">
                User roles: {user?.roles?.join(', ') || 'unknown'}.
              </p>
            </div>
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">Device Fingerprinting</h3>
              <p className="text-xs text-gray-500">SHA-256 based device identification</p>
            </div>
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">Risk Assessment</h3>
              <p className="text-xs text-gray-500">Real-time trust scoring and monitoring</p>
            </div>
          </div>
        </div>

        {/* Raw Data */}
        <div className="mt-6 bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Raw Data</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">Devices</h3>
              <p className="text-xs text-gray-500 break-all">
                {devices.map(device => device.fingerprint).join(', ')}
              </p>
            </div>

            <div className="border border-gray-200 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-900 mb-2">User</h3>
              <p className="text-xs text-gray-500 break-all">{JSON.stringify(user, null, 2)}</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
