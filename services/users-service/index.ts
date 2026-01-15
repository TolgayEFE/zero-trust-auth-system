import express from 'express';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { buildSubgraphSchema } from '@apollo/subgraph';
import { gql } from 'graphql-tag';
import { json } from 'body-parser';

const PORT = process.env.PORT || 4001;

// Sample user data
const users = [
  {
    id: '1',
    email: 'alice@example.com',
    username: 'alice',
    name: 'Alice Johnson',
    role: 'admin',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    email: 'bob@example.com',
    username: 'bob',
    name: 'Bob Smith',
    role: 'user',
    createdAt: '2024-01-02T00:00:00Z',
  },
  {
    id: '3',
    email: 'charlie@example.com',
    username: 'charlie',
    name: 'Charlie Brown',
    role: 'user',
    createdAt: '2024-01-03T00:00:00Z',
  },
];

// GraphQL schema (Federation)
const typeDefs = gql`
  extend schema @link(url: "https://specs.apollo.dev/federation/v2.0", import: ["@key", "@shareable"])

  type Query {
    users: [User!]!
    user(id: ID!): User
    me: User
  }

  type Mutation {
    createUser(input: CreateUserInput!): User!
    updateUser(id: ID!, input: UpdateUserInput!): User
    deleteUser(id: ID!): Boolean!
  }

  type User @key(fields: "id") {
    id: ID!
    email: String!
    username: String!
    name: String!
    role: String!
    createdAt: String!
  }

  input CreateUserInput {
    email: String!
    username: String!
    name: String!
    role: String
  }

  input UpdateUserInput {
    email: String
    username: String
    name: String
    role: String
  }
`;

// Resolvers
const resolvers = {
  Query: {
    users: (_: unknown, __: unknown, context: { userId?: string }) => {
      console.log(`[Users Service] Fetching all users, requested by: ${context.userId || 'anonymous'}`);
      return users;
    },
    user: (_: unknown, { id }: { id: string }) => {
      console.log(`[Users Service] Fetching user: ${id}`);
      return users.find(u => u.id === id) || null;
    },
    me: (_: unknown, __: unknown, context: { userId?: string }) => {
      if (!context.userId) return null;
      return users.find(u => u.id === context.userId) || null;
    },
  },
  Mutation: {
    createUser: (_: unknown, { input }: { input: { email: string; username: string; name: string; role?: string } }) => {
      const newUser = {
        id: String(users.length + 1),
        ...input,
        role: input.role || 'user',
        createdAt: new Date().toISOString(),
      };
      users.push(newUser);
      console.log(`[Users Service] Created user: ${newUser.id}`);
      return newUser;
    },
    updateUser: (_: unknown, { id, input }: { id: string; input: Partial<{ email: string; username: string; name: string; role: string }> }) => {
      const userIndex = users.findIndex(u => u.id === id);
      if (userIndex === -1) return null;
      users[userIndex] = { ...users[userIndex]!, ...input };
      console.log(`[Users Service] Updated user: ${id}`);
      return users[userIndex];
    },
    deleteUser: (_: unknown, { id }: { id: string }) => {
      const userIndex = users.findIndex(u => u.id === id);
      if (userIndex === -1) return false;
      users.splice(userIndex, 1);
      console.log(`[Users Service] Deleted user: ${id}`);
      return true;
    },
  },
  User: {
    __resolveReference: (user: { id: string }) => {
      return users.find(u => u.id === user.id);
    },
  },
};

async function startServer() {
  const app = express();

  // Health check
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'users-service' });
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
          `[Users Service] Request ${requestId} from user ${userId || 'anonymous'}, trust: ${trustLevel || 'none'}`
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
    console.log(`Users Service ready at http://localhost:${PORT}/graphql`);
    console.log(`Health check at http://localhost:${PORT}/health`);
  });
}

startServer().catch(err => {
  console.error('Failed to start Users Service:', err);
  process.exit(1);
});
