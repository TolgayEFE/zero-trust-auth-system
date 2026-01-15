import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } from '@apollo/gateway';
import { Application } from 'express';
import { json } from 'body-parser';
import { GraphQLContext, ZeroTrustRequest } from '../types';
import { config, features } from '../config';
import { logger } from '../utils/logger';
import { generateUUID } from '../utils/crypto';

/**
 * Custom data source that adds security context to downstream requests
 */
class AuthenticatedDataSource extends RemoteGraphQLDataSource {
  override willSendRequest(options: any): void {
    const { request, context } = options;
    const graphqlContext = context as GraphQLContext;

    // Add request ID
    if (request.http?.headers) {
      request.http.headers.set(
        'X-Request-ID',
        graphqlContext.securityContext?.requestId || generateUUID()
      );

      // Add user context if authenticated
      if (graphqlContext.securityContext?.user) {
        request.http.headers.set('X-User-ID', graphqlContext.securityContext.user.id);
        request.http.headers.set('X-User-Roles', graphqlContext.securityContext.user.roles.join(','));
        request.http.headers.set(
          'X-User-Permissions',
          graphqlContext.securityContext.user.permissions.join(',')
        );
        request.http.headers.set('X-User-Email', graphqlContext.securityContext.user.email);
      }

      // Add trust level and risk score
      if (graphqlContext.securityContext) {
        const trustLevel = graphqlContext.securityContext.trustLevel || 'none';
        request.http.headers.set('X-Trust-Level', trustLevel);
        request.http.headers.set('X-Risk-Score', graphqlContext.securityContext.riskScore.toString());
        request.http.headers.set(
          'X-Authenticated',
          graphqlContext.securityContext.authenticated.toString()
        );
      }

      // Add gateway identifier
      request.http.headers.set('X-Gateway', 'zero-trust-gateway');
      request.http.headers.set('X-Gateway-Version', process.env.npm_package_version || '1.0.0');
    }
  }
}

/**
 * Initialize Apollo GraphQL Gateway
 */
export const initializeGraphQLGateway = async (app: Application): Promise<void> => {
  if (!features.graphqlFederation) {
    logger.info('GraphQL Federation is disabled');
    return;
  }

  try {
    // Build subgraph list from service configuration
    const subgraphs = Object.entries(config.services)
      .filter(([, url]) => typeof url === 'string' && url)
      .map(([name, url]) => ({
        name,
        url: url as string,
      }));

    if (subgraphs.length === 0) {
      logger.warn('No subgraphs configured for GraphQL Federation');
      return;
    }

    logger.info({ subgraphs }, 'Configuring GraphQL Federation with subgraphs');

    // Create Apollo Gateway
    const gateway = new ApolloGateway({
      supergraphSdl: new IntrospectAndCompose({
        subgraphs,
        pollIntervalInMs: 10000, // Poll for schema changes
      }),
      buildService({ url }) {
        return new AuthenticatedDataSource({ url });
      },
    });

    // Create Apollo Server
    const server = new ApolloServer<GraphQLContext>({
      gateway,
      introspection: config.graphql.introspectionEnabled,
      plugins: [
        {
          async requestDidStart() {
            const startTime = Date.now();

            return {
              async didResolveOperation(requestContext) {
                logger.debug(
                  {
                    operationName: requestContext.operationName,
                    query: requestContext.request.query?.substring(0, 200),
                  },
                  'GraphQL operation resolved'
                );
              },

              async willSendResponse(requestContext) {
                const duration = Date.now() - startTime;
                logger.info(
                  {
                    operationName: requestContext.operationName,
                    durationMs: duration,
                    errors: requestContext.errors?.length || 0,
                  },
                  'GraphQL request completed'
                );
              },

              async didEncounterErrors(requestContext) {
                logger.error(
                  {
                    operationName: requestContext.operationName,
                    errors: requestContext.errors,
                  },
                  'GraphQL errors encountered'
                );
              },
            };
          },
        },
      ],
    });

    // Start the Apollo Server
    await server.start();

    // Mount middleware
    app.use(
      config.graphql.path,
      json(),
      expressMiddleware(server, {
        context: async ({ req }): Promise<GraphQLContext> => {
          const zeroTrustReq = req as ZeroTrustRequest;

          return {
            securityContext: zeroTrustReq.securityContext || {
              requestId: zeroTrustReq.requestId || generateUUID(),
              timestamp: Date.now(),
              clientIp: 'unknown',
              userAgent: 'unknown',
              authenticated: false,
              authorized: false,
              riskScore: 100,
              trustLevel: 'none',
              policies: [],
            },
          };
        },
      })
    );

    logger.info(
      {
        path: config.graphql.path,
        introspection: config.graphql.introspectionEnabled,
        playground: config.graphql.playgroundEnabled,
      },
      'Apollo GraphQL Gateway initialized'
    );
  } catch (error) {
    logger.error({ error }, 'Failed to initialize GraphQL Gateway');

    // In dev, return a simple error endpoint
    if (config.server.env === 'development') {
      app.use(config.graphql.path, (_req, res) => {
        res.status(503).json({
          errors: [
            {
              message: 'GraphQL Gateway is not available. Ensure subgraph services are running.',
            },
          ],
        });
      });

      logger.warn('GraphQL Gateway running in degraded mode');
    } else {
      throw error;
    }
  }
};
