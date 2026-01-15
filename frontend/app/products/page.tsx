'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

interface Product {
  id: string;
  name: string;
  description: string;
  price: number;
  category: string;
  stock: number;
}

interface User {
  id: string;
  email: string;
  username: string;
  roles: string[];
  permissions: string[];
}

export default function ProductsPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [products, setProducts] = useState<Product[]>([]);
  const [form, setForm] = useState({
    name: '',
    description: '',
    price: '',
    category: '',
    stock: '',
  });
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const loadData = async () => {
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
            query ProductsPage {
              products { id name description price category stock }
            }
          `,
        }),
      });

      const data = await response.json();
      if (data?.data?.products) {
        setProducts(data.data.products);
      } else if (data?.errors?.length) {
        setError(data.errors[0]?.message || 'Failed to load products');
      }
    } catch (err) {
      console.error('Failed to fetch products:', err);
      setError('Failed to load products');
    }

    setLoading(false);
  };
  useEffect(() => {
    loadData();
  }, [router]);

  const canCreateProduct = Boolean(
    user?.roles?.includes('admin') ||
    user?.permissions?.includes('write:products') ||
    user?.permissions?.includes('write:all')
  );
  const canDeleteProduct = Boolean(
    user?.roles?.includes('admin') ||
    user?.permissions?.includes('delete:products') ||
    user?.permissions?.includes('delete:all')
  );

  const handleInputChange =
    (field: keyof typeof form) => (event: React.ChangeEvent<HTMLInputElement>) => {
      setForm(prev => ({ ...prev, [field]: event.target.value }));
    };

  const handleCreateProduct = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setMessage('');

    if (!canCreateProduct) {
      setError('You do not have permission to create products.');
      return;
    }

    setSubmitting(true);

    try {
      const response = await fetch(`${API_URL}/graphql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          query: `
            mutation CreateProduct($input: CreateProductInput!) {
              createProduct(input: $input) {
                id
                name
                description
                price
                category
                stock
              }
            }
          `,
          variables: {
            input: {
              name: form.name.trim(),
              description: form.description.trim(),
              price: Number(form.price),
              category: form.category.trim(),
              stock: Number(form.stock),
            },
          },
        }),
      });

      const data = await response.json();

      if (data?.errors?.length) {
        setError(data.errors[0]?.message || 'Failed to create product');
      } else if (data?.data?.createProduct) {
        setProducts(prev => [data.data.createProduct, ...prev]);
        setMessage('Product created successfully.');
        setForm({ name: '', description: '', price: '', category: '', stock: '' });
        loadData();
      }
    } catch (err) {
      console.error('Failed to create product:', err);
      setError('Failed to create product');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteProduct = async (productId: string) => {
    setError('');
    setMessage('');

    if (!canDeleteProduct) {
      setError('You do not have permission to delete products.');
      return;
    }

    setSubmitting(true);

    try {
      const response = await fetch(`${API_URL}/graphql`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          query: `
            mutation DeleteProduct($id: ID!) {
              deleteProduct(id: $id)
            }
          `,
          variables: { id: productId },
        }),
      });

      const data = await response.json();

      if (data?.errors?.length) {
        setError(data.errors[0]?.message || 'Failed to delete product');
      } else if (data?.data?.deleteProduct) {
        setProducts(prev => prev.filter(product => product.id !== productId));
        setMessage('Product deleted successfully.');
      } else {
        setError('Failed to delete product');
      }
    } catch (err) {
      console.error('Failed to delete product:', err);
      setError('Failed to delete product');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center gap-6">
              <h1 className="text-xl font-bold text-gray-900">Products Service</h1>
              <div className="hidden md:flex items-center gap-4 text-sm text-gray-600">
                <Link href="/dashboard" className="hover:text-gray-900">
                  Dashboard
                </Link>
                <Link href="/products" className="hover:text-gray-900">
                  Products
                </Link>
                <Link href="/orders" className="hover:text-gray-900">
                  Orders
                </Link>
                <Link href="/inventory" className="hover:text-gray-900">
                  Inventory
                </Link>
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
        {message && (
          <div className="mb-4 rounded-lg bg-green-50 p-4">
            <p className="text-sm text-green-800">{message}</p>
          </div>
        )}

        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Create Product</h2>
          {!canCreateProduct && (
            <p className="text-sm text-gray-500 mb-4">
              This action requires `write:products` or `write:all` permission.
            </p>
          )}
          <form onSubmit={handleCreateProduct} className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-700">Name</label>
              <input
                value={form.name}
                onChange={handleInputChange('name')}
                disabled={!canCreateProduct || submitting}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-700">Category</label>
              <input
                value={form.category}
                onChange={handleInputChange('category')}
                disabled={!canCreateProduct || submitting}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div className="flex flex-col gap-1 md:col-span-2">
              <label className="text-xs font-medium text-gray-700">Description</label>
              <input
                value={form.description}
                onChange={handleInputChange('description')}
                disabled={!canCreateProduct || submitting}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-700">Price</label>
              <input
                type="number"
                min="0"
                step="0.01"
                value={form.price}
                onChange={handleInputChange('price')}
                disabled={!canCreateProduct || submitting}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-gray-700">Stock</label>
              <input
                type="number"
                min="0"
                value={form.stock}
                onChange={handleInputChange('stock')}
                disabled={!canCreateProduct || submitting}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm"
                required
              />
            </div>
            <div className="md:col-span-2 flex justify-end">
              <button
                type="submit"
                disabled={!canCreateProduct || submitting}
                className="px-4 py-2 text-sm font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Creating...' : 'Create Product'}
              </button>
            </div>
            <p className="text-sm text-yellow-900 bg-yellow-100 p-2 rounded-lg mb-4 md:w-max w-full border border-yellow-400">
              Disabled on frontend because user does not have `write:products` or `write:all`
              permission.
            </p>
          </form>
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Products List</h2>
          <p className="text-sm text-yellow-900 bg-yellow-100 p-2 rounded-lg mb-4 md:w-max w-full border border-yellow-400">
            I let delete products button open for user test purposes!
          </p>

          {loading ? (
            <p className="text-sm text-gray-500">Loading products...</p>
          ) : products.length === 0 ? (
            <p className="text-sm text-gray-500">No products returned by gateway.</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {products.map(product => (
                <div key={product.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium text-gray-900">{product.name}</h3>
                    <span className="text-xs text-gray-500">${product.price.toFixed(2)}</span>
                  </div>
                  <p className="mt-2 text-xs text-gray-500">Category: {product.category}</p>
                  <p className="mt-1 text-xs text-gray-500">Stock: {product.stock}</p>
                  <div className="mt-3 flex justify-end">
                    <button
                      type="button"
                      onClick={() => handleDeleteProduct(product.id)}
                      //disabled={!canDeleteProduct || submitting}
                      className="px-3 py-1.5 text-xs font-medium rounded-lg text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
