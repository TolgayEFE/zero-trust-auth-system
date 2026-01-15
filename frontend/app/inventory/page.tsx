'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

interface InventoryItem {
  id: string;
  productId: string;
  warehouse: string;
  quantity: number;
  reservedQuantity: number;
  availableQuantity: number;
}

export default function InventoryPage() {
  const router = useRouter();
  const [items, setItems] = useState<InventoryItem[]>([]);
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
              query InventoryPage {
                allInventory { id productId warehouse quantity reservedQuantity availableQuantity }
              }
            `,
          }),
        });

        const data = await response.json();
        if (data?.data?.allInventory) {
          setItems(data.data.allInventory);
        } else if (data?.errors?.length) {
          setError(data.errors[0]?.message || 'Failed to load inventory');
        }
      } catch (err) {
        console.error('Failed to fetch inventory:', err);
        setError('Failed to load inventory');
      }

      setLoading(false);
    };

    loadData();
  }, [router]);

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-6">
              <h1 className="text-xl font-bold text-gray-900">Inventory Service</h1>
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
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Inventory Snapshot</h2>
          {loading ? (
            <p className="text-sm text-gray-500">Loading inventory...</p>
          ) : items.length === 0 ? (
            <p className="text-sm text-gray-500">No inventory returned by gateway.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {items.map(item => (
                <div key={item.id} className="border border-gray-200 rounded-lg p-4">
                  <h3 className="text-sm font-medium text-gray-900">
                    Product {item.productId}
                  </h3>
                  <p className="mt-2 text-xs text-gray-500">Warehouse: {item.warehouse}</p>
                  <p className="mt-1 text-xs text-gray-500">
                    Available: {item.availableQuantity}
                  </p>
                  <p className="mt-1 text-xs text-gray-500">Reserved: {item.reservedQuantity}</p>
                  <p className="mt-1 text-xs text-gray-500">Total: {item.quantity}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
