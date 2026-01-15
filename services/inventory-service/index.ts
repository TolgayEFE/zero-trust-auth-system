import express from 'express';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { buildSubgraphSchema } from '@apollo/subgraph';
import { gql } from 'graphql-tag';
import cors from 'cors';

const PORT = process.env.PORT || 4004;

// Sample inventory data
const inventory = [
  {
    id: '1',
    productId: '1',
    warehouse: 'US-WEST',
    quantity: 150,
    reservedQuantity: 10,
    lowStockThreshold: 20,
    lastRestocked: '2024-01-20T10:00:00Z',
  },
  {
    id: '2',
    productId: '2',
    warehouse: 'US-EAST',
    quantity: 75,
    reservedQuantity: 5,
    lowStockThreshold: 15,
    lastRestocked: '2024-01-18T14:30:00Z',
  },
  {
    id: '3',
    productId: '3',
    warehouse: 'US-WEST',
    quantity: 200,
    reservedQuantity: 15,
    lowStockThreshold: 30,
    lastRestocked: '2024-01-22T09:15:00Z',
  },
  {
    id: '4',
    productId: '4',
    warehouse: 'US-CENTRAL',
    quantity: 300,
    reservedQuantity: 25,
    lowStockThreshold: 50,
    lastRestocked: '2024-01-25T11:45:00Z',
  },
  {
    id: '5',
    productId: '5',
    warehouse: 'US-EAST',
    quantity: 45,
    reservedQuantity: 3,
    lowStockThreshold: 10,
    lastRestocked: '2024-01-26T16:20:00Z',
  },
  {
    id: '6',
    productId: '1',
    warehouse: 'US-EAST',
    quantity: 120,
    reservedQuantity: 8,
    lowStockThreshold: 20,
    lastRestocked: '2024-01-21T13:00:00Z',
  },
  {
    id: '7',
    productId: '2',
    warehouse: 'US-WEST',
    quantity: 90,
    reservedQuantity: 6,
    lowStockThreshold: 15,
    lastRestocked: '2024-01-19T10:30:00Z',
  },
];

// GraphQL schema (Federation)
const typeDefs = gql`
  extend schema
    @link(url: "https://specs.apollo.dev/federation/v2.0", import: ["@key", "@shareable", "@external"])

  type Product @key(fields: "id") {
    id: ID! @external
    inventory: [Inventory!]!
    totalAvailableQuantity: Int!
    isInStock: Boolean!
  }

  type Inventory {
    id: ID!
    productId: ID!
    warehouse: String!
    quantity: Int!
    reservedQuantity: Int!
    availableQuantity: Int!
    lowStockThreshold: Int!
    isLowStock: Boolean!
    lastRestocked: String
  }

  type Query {
    inventory(productId: ID!): [Inventory!]!
    inventoryByWarehouse(warehouse: String!): [Inventory!]!
    lowStockProducts: [Inventory!]!
    allInventory: [Inventory!]!
  }

  input UpdateInventoryInput {
    productId: ID!
    warehouse: String!
    quantity: Int!
  }

  input ReserveInventoryInput {
    productId: ID!
    warehouse: String!
    quantity: Int!
  }

  input RestockInput {
    productId: ID!
    warehouse: String!
    quantity: Int!
  }

  type Mutation {
    updateInventory(input: UpdateInventoryInput!): Inventory!
    reserveInventory(input: ReserveInventoryInput!): Inventory!
    releaseInventory(input: ReserveInventoryInput!): Inventory!
    restockProduct(input: RestockInput!): Inventory!
  }
`;

// Resolvers
const resolvers = {
  Query: {
    inventory: (_parent: any, { productId }: { productId: string }) => {
      return inventory.filter((i) => i.productId === productId);
    },
    inventoryByWarehouse: (_parent: any, { warehouse }: { warehouse: string }) => {
      return inventory.filter((i) => i.warehouse === warehouse);
    },
    lowStockProducts: () => {
      return inventory.filter(
        (i) => i.quantity - i.reservedQuantity <= i.lowStockThreshold
      );
    },
    allInventory: () => {
      return inventory;
    },
  },
  Mutation: {
    updateInventory: (
      _parent: any,
      { input }: { input: any }
    ) => {
      const item = inventory.find(
        (i) => i.productId === input.productId && i.warehouse === input.warehouse
      );

      if (!item) {
        throw new Error('Inventory item not found');
      }

      item.quantity = input.quantity;
      console.log('Inventory updated:', item);
      return item;
    },
    reserveInventory: (
      _parent: any,
      { input }: { input: any }
    ) => {
      const item = inventory.find(
        (i) => i.productId === input.productId && i.warehouse === input.warehouse
      );

      if (!item) {
        throw new Error('Inventory item not found');
      }

      const availableQuantity = item.quantity - item.reservedQuantity;
      if (availableQuantity < input.quantity) {
        throw new Error('Insufficient inventory');
      }

      item.reservedQuantity += input.quantity;
      console.log('Inventory reserved:', item);
      return item;
    },
    releaseInventory: (
      _parent: any,
      { input }: { input: any }
    ) => {
      const item = inventory.find(
        (i) => i.productId === input.productId && i.warehouse === input.warehouse
      );

      if (!item) {
        throw new Error('Inventory item not found');
      }

      item.reservedQuantity = Math.max(0, item.reservedQuantity - input.quantity);
      console.log('Inventory released:', item);
      return item;
    },
    restockProduct: (
      _parent: any,
      { input }: { input: any }
    ) => {
      const item = inventory.find(
        (i) => i.productId === input.productId && i.warehouse === input.warehouse
      );

      if (!item) {
        throw new Error('Inventory item not found');
      }

      item.quantity += input.quantity;
      item.lastRestocked = new Date().toISOString();
      console.log('Product restocked:', item);
      return item;
    },
  },
  Product: {
    __resolveReference(reference: { id: string }) {
      return { id: reference.id };
    },
    inventory(product: any) {
      return inventory.filter((i) => i.productId === product.id);
    },
    totalAvailableQuantity(product: any) {
      return inventory
        .filter((i) => i.productId === product.id)
        .reduce((sum, i) => sum + (i.quantity - i.reservedQuantity), 0);
    },
    isInStock(product: any) {
      const total = inventory
        .filter((i) => i.productId === product.id)
        .reduce((sum, i) => sum + (i.quantity - i.reservedQuantity), 0);
      return total > 0;
    },
  },
  Inventory: {
    availableQuantity(item: any) {
      return item.quantity - item.reservedQuantity;
    },
    isLowStock(item: any) {
      return (item.quantity - item.reservedQuantity) <= item.lowStockThreshold;
    },
  },
};

const app = express();

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'inventory-service' });
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
    console.log(`Inventory Service ready at http://localhost:${PORT}/graphql`);
    console.log(`Health check at http://localhost:${PORT}/health`);
  });
}

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
