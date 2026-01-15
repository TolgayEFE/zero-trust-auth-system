'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

interface Order {
  id: string;
  orderNumber: string;
  status: string;
  totalAmount: number;
  createdAt: string;
}

export default function OrdersPage() {
  const router = useRouter();
  const [orders, setOrders] = useState<Order[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const loadData = async () => {
      try {
        const meResponse = await fetch(`${API_URL}/auth/me`, {
          credentials: 'include',
        });

        if (!meResponse.ok) {
          router.push('/login');
          return;
        }
      } catch {
        router.push('/login');
        return;
      }

      try {
        const response = await fetch(`${API_URL}/graphql`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            query: `
              query OrdersPage {
                orders { id orderNumber status totalAmount createdAt }
              }
            `,
          }),
        });

        const data = await response.json();
        if (data?.data?.orders) {
          setOrders(data.data.orders);
        } else if (data?.errors?.length) {
          setError(data.errors[0]?.message || 'Failed to load orders');
        }
      } catch (err) {
        console.error('Failed to fetch orders:', err);
        setError('Failed to load orders');
      }

      setLoading(false);
    };

    loadData();
  }, [router]);

  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-6">
              <h1 className="text-xl font-bold text-gray-900">Orders Service</h1>
              <div className="hidden md:flex items-center gap-4 text-sm text-gray-600">
                <Link href="/dashboard" className="hover:text-gray-900">Dashboard</Link>
                <Link href="/products" className="hover:text-gray-900">Products</Link>
                <Link href="/orders" className="hover:text-gray-900">Orders</Link>
                <Link href="/inventory" className="hover:text-gray-900">Inventory</Link>
              </div>
            </div>
            <div className="flex items-center">
              <button
                onClick={() => router.push('/dashboard')}
                className="ml-4 px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-gray-900 hover:bg-gray-800"
              >
                Back to Dashboard
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

        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Orders List</h2>
          {loading ? (
            <p className="text-sm text-gray-500">Loading orders...</p>
          ) : orders.length === 0 ? (
            <p className="text-sm text-gray-500">No orders returned by gateway.</p>
          ) : (
            <div className="space-y-3">
              {orders.map(order => (
                <div key={order.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium text-gray-900">
                      Order {order.orderNumber}
                    </h3>
                    <span className="text-xs text-gray-500">
                      ${order.totalAmount.toFixed(2)}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-gray-500">Status: {order.status}</p>
                  <p className="mt-1 text-xs text-gray-500">
                    Created: {formatDate(order.createdAt)}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
