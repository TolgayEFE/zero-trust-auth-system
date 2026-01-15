import express from 'express';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { buildSubgraphSchema } from '@apollo/subgraph';
import { gql } from 'graphql-tag';
import cors from 'cors';

const PORT = process.env.PORT || 4003;

// Sample orders data
const orders = [
  {
    id: '1',
    orderNumber: 'ORD-2024-001',
    userId: '1',
    items: [
      { productId: '1', quantity: 2, price: 29.99 },
      { productId: '3', quantity: 1, price: 49.99 },
    ],
    status: 'DELIVERED',
    totalAmount: 109.97,
    createdAt: '2024-01-15T10:30:00Z',
    updatedAt: '2024-01-20T14:45:00Z',
  },
  {
    id: '2',
    orderNumber: 'ORD-2024-002',
    userId: '2',
    items: [
      { productId: '2', quantity: 1, price: 49.99 },
      { productId: '4', quantity: 3, price: 19.99 },
    ],
    status: 'SHIPPED',
    totalAmount: 109.96,
    createdAt: '2024-01-18T09:15:00Z',
    updatedAt: '2024-01-22T16:20:00Z',
  },
  {
    id: '3',
    orderNumber: 'ORD-2024-003',
    userId: '1',
    items: [
      { productId: '5', quantity: 1, price: 199.99 },
    ],
    status: 'PROCESSING',
    totalAmount: 199.99,
    createdAt: '2024-01-25T11:00:00Z',
    updatedAt: '2024-01-25T11:00:00Z',
  },
  {
    id: '4',
    orderNumber: 'ORD-2024-004',
    userId: '3',
    items: [
      { productId: '1', quantity: 1, price: 29.99 },
      { productId: '2', quantity: 1, price: 49.99 },
    ],
    status: 'CONFIRMED',
    totalAmount: 79.98,
    createdAt: '2024-01-26T14:30:00Z',
    updatedAt: '2024-01-26T15:00:00Z',
  },
  {
    id: '5',
    orderNumber: 'ORD-2024-005',
    userId: '2',
    items: [
      { productId: '3', quantity: 2, price: 49.99 },
    ],
    status: 'PENDING',
    totalAmount: 99.98,
    createdAt: '2024-01-27T08:45:00Z',
    updatedAt: '2024-01-27T08:45:00Z',
  },
];

// GraphQL schema (Federation)
const typeDefs = gql`
  extend schema
    @link(url: "https://specs.apollo.dev/federation/v2.0", import: ["@key", "@shareable", "@external"])

  type Order @key(fields: "id") {
    id: ID!
    orderNumber: String!
    userId: ID!
    user: User
    items: [OrderItem!]!
    status: OrderStatus!
    totalAmount: Float!
    createdAt: String!
    updatedAt: String!
  }

  type OrderItem {
    productId: ID!
    product: Product
    quantity: Int!
    price: Float!
  }

  enum OrderStatus {
    PENDING
    CONFIRMED
    PROCESSING
    SHIPPED
    DELIVERED
    CANCELLED
  }

  type User @key(fields: "id", resolvable: false) {
    id: ID!
  }

  type Product @key(fields: "id", resolvable: false) {
    id: ID!
  }

  type Query {
    orders: [Order!]!
    order(id: ID!): Order
    myOrders: [Order!]!
    ordersByStatus(status: OrderStatus!): [Order!]!
    ordersByUser(userId: ID!): [Order!]!
  }

  input CreateOrderInput {
    items: [OrderItemInput!]!
  }

  input OrderItemInput {
    productId: ID!
    quantity: Int!
    price: Float!
  }

  type Mutation {
    createOrder(input: CreateOrderInput!): Order!
    updateOrderStatus(id: ID!, status: OrderStatus!): Order
    cancelOrder(id: ID!): Order
  }
`;

// Resolvers
const resolvers = {
  Query: {
    orders: (_parent: any, _args: any, context: any) => {
      console.log('Fetching all orders', {
        userId: context.userId,
        roles: context.roles,
      });
      return orders;
    },
    order: (_parent: any, { id }: { id: string }) => {
      return orders.find((o) => o.id === id);
    },
    myOrders: (_parent: any, _args: any, context: any) => {
      const userId = context.userId;
      if (!userId) {
        throw new Error('Authentication required');
      }
      return orders.filter((o) => o.userId === userId);
    },
    ordersByStatus: (_parent: any, { status }: { status: string }) => {
      return orders.filter((o) => o.status === status);
    },
    ordersByUser: (_parent: any, { userId }: { userId: string }) => {
      return orders.filter((o) => o.userId === userId);
    },
  },
  Mutation: {
    createOrder: (
      _parent: any,
      { input }: { input: any },
      context: any
    ) => {
      const userId = context.userId;
      if (!userId) {
        throw new Error('Authentication required');
      }

      const newOrder = {
        id: String(orders.length + 1),
        orderNumber: `ORD-2024-${String(orders.length + 1).padStart(3, '0')}`,
        userId,
        items: input.items,
        status: 'PENDING',
        totalAmount: input.items.reduce(
          (sum: number, item: any) => sum + item.price * item.quantity,
          0
        ),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      orders.push(newOrder);
      console.log('Order created:', newOrder);
      return newOrder;
    },
    updateOrderStatus: (
      _parent: any,
      { id, status }: { id: string; status: string }
    ) => {
      const order = orders.find((o) => o.id === id);
      if (!order) {
        throw new Error('Order not found');
      }

      order.status = status as any;
      order.updatedAt = new Date().toISOString();
      console.log('Order status updated:', order);
      return order;
    },
    cancelOrder: (_parent: any, { id }: { id: string }) => {
      const order = orders.find((o) => o.id === id);
      if (!order) {
        throw new Error('Order not found');
      }

      order.status = 'CANCELLED';
      order.updatedAt = new Date().toISOString();
      console.log('Order cancelled:', order);
      return order;
    },
  },
  Order: {
    __resolveReference(reference: { id: string }) {
      return orders.find((o) => o.id === reference.id);
    },
    user(order: any) {
      return { __typename: 'User', id: order.userId };
    },
  },
  OrderItem: {
    product(item: any) {
      return { __typename: 'Product', id: item.productId };
    },
  },
};

const app = express();

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'orders-service' });
});

async function startServer() {
  const server = new ApolloServer({
    schema: buildSubgraphSchema([{ typeDefs, resolvers }]),
  });

  await server.start();

  app.use(
    '/graphql',
    cors<cors.CorsRequest>(),
    express.json(),
    expressMiddleware(server, {
      context: async ({ req }) => {
        // Read security context from gateway headers
        return {
          userId: req.headers['x-user-id'],
          roles: req.headers['x-user-roles']?.toString().split(',') || [],
          permissions: req.headers['x-user-permissions']?.toString().split(',') || [],
          email: req.headers['x-user-email'],
          trustLevel: req.headers['x-trust-level'],
          riskScore: req.headers['x-risk-score'],
          authenticated: req.headers['x-authenticated'] === 'true',
          requestId: req.headers['x-request-id'],
        };
      },
    })
  );

  app.listen(PORT, () => {
    console.log(`Orders Service ready at http://localhost:${PORT}/graphql`);
    console.log(`Health check at http://localhost:${PORT}/health`);
  });
}

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
