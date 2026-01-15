import express from 'express';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { buildSubgraphSchema } from '@apollo/subgraph';
import { gql } from 'graphql-tag';
import { json } from 'body-parser';

const PORT = process.env.PORT || 4002;

// Sample product data
const products = [
  {
    id: '1',
    name: 'Laptop Pro',
    description: 'High-performance laptop for professionals',
    price: 1299.99,
    category: 'electronics',
    stock: 50,
    createdBy: '1',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    name: 'Wireless Mouse',
    description: 'Ergonomic wireless mouse',
    price: 49.99,
    category: 'accessories',
    stock: 200,
    createdBy: '1',
    createdAt: '2024-01-02T00:00:00Z',
  },
  {
    id: '3',
    name: 'USB-C Hub',
    description: 'Multi-port USB-C hub with HDMI',
    price: 79.99,
    category: 'accessories',
    stock: 100,
    createdBy: '2',
    createdAt: '2024-01-03T00:00:00Z',
  },
];

// GraphQL schema (Federation)
const typeDefs = gql`
  extend schema @link(url: "https://specs.apollo.dev/federation/v2.0", import: ["@key", "@external", "@requires"])

  type Query {
    products: [Product!]!
    product(id: ID!): Product
    productsByCategory(category: String!): [Product!]!
  }

  type Mutation {
    createProduct(input: CreateProductInput!): Product!
    updateProduct(id: ID!, input: UpdateProductInput!): Product
    deleteProduct(id: ID!): Boolean!
    updateStock(id: ID!, quantity: Int!): Product
  }

  type Product @key(fields: "id") {
    id: ID!
    name: String!
    description: String!
    price: Float!
    category: String!
    stock: Int!
    createdBy: ID!
    createdAt: String!
  }

  input CreateProductInput {
    name: String!
    description: String!
    price: Float!
    category: String!
    stock: Int!
  }

  input UpdateProductInput {
    name: String
    description: String
    price: Float
    category: String
    stock: Int
  }
`;

// Resolvers
const resolvers = {
  Query: {
    products: (_: unknown, __: unknown, context: { userId?: string }) => {
      console.log(`[Products Service] Fetching all products, requested by: ${context.userId || 'anonymous'}`);
      return products;
    },
    product: (_: unknown, { id }: { id: string }) => {
      console.log(`[Products Service] Fetching product: ${id}`);
      return products.find(p => p.id === id) || null;
    },
    productsByCategory: (_: unknown, { category }: { category: string }) => {
      console.log(`[Products Service] Fetching products in category: ${category}`);
      return products.filter(p => p.category === category);
    },
  },
  Mutation: {
    createProduct: (
      _: unknown,
      { input }: { input: { name: string; description: string; price: number; category: string; stock: number } },
      context: { userId?: string }
    ) => {
      const newProduct = {
        id: String(products.length + 1),
        ...input,
        createdBy: context.userId || 'unknown',
        createdAt: new Date().toISOString(),
      };
      products.push(newProduct);
      console.log(`[Products Service] Created product: ${newProduct.id}`);
      return newProduct;
    },
    updateProduct: (
      _: unknown,
      { id, input }: { id: string; input: Partial<{ name: string; description: string; price: number; category: string; stock: number }> }
    ) => {
      const productIndex = products.findIndex(p => p.id === id);
      if (productIndex === -1) return null;
      products[productIndex] = { ...products[productIndex]!, ...input };
      console.log(`[Products Service] Updated product: ${id}`);
      return products[productIndex];
    },
    deleteProduct: (_: unknown, { id }: { id: string }) => {
      const productIndex = products.findIndex(p => p.id === id);
      if (productIndex === -1) return false;
      products.splice(productIndex, 1);
      console.log(`[Products Service] Deleted product: ${id}`);
      return true;
    },
    updateStock: (_: unknown, { id, quantity }: { id: string; quantity: number }) => {
      const product = products.find(p => p.id === id);
      if (!product) return null;
      product.stock += quantity;
      console.log(`[Products Service] Updated stock for product ${id}: ${product.stock}`);
      return product;
    },
  },
  Product: {
    __resolveReference: (product: { id: string }) => {
      return products.find(p => p.id === product.id);
    },
  },
};

async function startServer() {
  const app = express();

  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'products-service' });
  });

  // Build schema
  const schema = buildSubgraphSchema({ typeDefs, resolvers });

  const server = new ApolloServer({
    schema,
  });

  await server.start();

  app.use(
    '/graphql',
    json(),
    expressMiddleware(server, {
      context: async ({ req }) => {
        // Read user context from gateway headers
        const userId = req.headers['x-user-id'] as string;
        const userRoles = (req.headers['x-user-roles'] as string)?.split(',') || [];
        const trustLevel = req.headers['x-trust-level'] as string;
        const requestId = req.headers['x-request-id'] as string;

        console.log(
          `[Products Service] Request ${requestId} from user ${userId || 'anonymous'}, trust: ${trustLevel || 'none'}`
        );

        return {
          userId,
          userRoles,
          trustLevel,
          requestId,
        };
      },
    })
  );

  app.listen(PORT, () => {
    console.log(`Products Service ready at http://localhost:${PORT}/graphql`);
    console.log(`Health check at http://localhost:${PORT}/health`);
  });
}

startServer().catch(err => {
  console.error('Failed to start Products Service:', err);
  process.exit(1);
});
