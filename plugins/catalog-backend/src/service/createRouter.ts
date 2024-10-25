/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { errorHandler } from '@backstage/backend-common';
import {
  ANNOTATION_LOCATION,
  ANNOTATION_ORIGIN_LOCATION,
  Entity,
  parseLocationRef,
  stringifyEntityRef,
} from '@backstage/catalog-model';
import { Config } from '@backstage/config';
import { InputError, NotFoundError, serializeError } from '@backstage/errors';
import express from 'express';
import yn from 'yn';
import { z } from 'zod';
import { EntitiesCatalog } from '../catalog/types';
import { LocationAnalyzer } from '../ingestion';
import { CatalogProcessingOrchestrator } from '../processing/types';
import { validateEntityEnvelope } from '../processing/util';
import {
  basicEntityFilter,
  entitiesBatchRequest,
  parseEntityFilterParams,
  parseEntityTransformParams,
  parseQueryEntitiesParams,
} from './request';
import { parseEntityFacetParams } from './request/parseEntityFacetParams';
import { parseEntityOrderParams } from './request/parseEntityOrderParams';
import { LocationService, RefreshService } from './types';
import {
  disallowReadonlyMode,
  encodeCursor,
  locationInput,
  validateRequestBody,
} from './util';
import { createOpenApiRouter } from '../schema/openapi.generated';
import { PluginTaskScheduler } from '@backstage/backend-tasks';
import { parseEntityPaginationParams } from './request/parseEntityPaginationParams';
import {
  AuthService,
  HttpAuthService,
  LoggerService,
} from '@backstage/backend-plugin-api';

import { DefaultAuditLogger } from '@janus-idp/backstage-plugin-audit-log-node';

/**
 * Options used by {@link createRouter}.
 *
 * @public
 */
export interface RouterOptions {
  entitiesCatalog?: EntitiesCatalog;
  locationAnalyzer?: LocationAnalyzer;
  locationService: LocationService;
  orchestrator?: CatalogProcessingOrchestrator;
  refreshService?: RefreshService;
  scheduler?: PluginTaskScheduler;
  logger: LoggerService;
  config: Config;
  permissionIntegrationRouter?: express.Router;
  auth: AuthService;
  httpAuth: HttpAuthService;
}

/**
 * Creates a catalog router.
 *
 * @public
 */
export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const router = await createOpenApiRouter({
    validatorOptions: {
      // We want the spec to be up to date with the expected value, but the return type needs
      //  to be controlled by the router implementation not the request validator.
      ignorePaths: /^\/validate-entity\/?$/,
    },
  });
  const {
    entitiesCatalog,
    locationAnalyzer,
    locationService,
    orchestrator,
    refreshService,
    config,
    logger,
    permissionIntegrationRouter,
    auth,
    httpAuth,
  } = options;

  const auditLogger = new DefaultAuditLogger({
    logger,
    authService: auth,
    httpAuthService: httpAuth,
  });
  const readonlyEnabled =
    config.getOptionalBoolean('catalog.readonly') || false;
  if (readonlyEnabled) {
    logger.info('Catalog is running in readonly mode');
  }

  if (refreshService) {
    // TODO: Potentially find a way to track the ancestor that gets refreshed to refresh this entity (as well as the child of that ancestor?)
    router.post('/refresh', async (req, res) => {
      const { authorizationToken, ...restBody } = req.body;
      const actorId = await auditLogger.getActorId(req);
      try {
        await auditLogger.auditLog({
          eventName: 'CatalogEntityRefresh',
          actorId,
          status: 'succeeded',
          stage: 'initiation',
          metadata: {
            entityRef: restBody.entityRef,
          },
          request: req,
          message: `Refresh attempt for ${restBody.entityRef} initiated by ${actorId}`,
        });

        const credentials = authorizationToken
          ? await auth.authenticate(authorizationToken)
          : await httpAuth.credentials(req);

        await refreshService.refresh({
          ...restBody,
          credentials,
        });
        await auditLogger.auditLog({
          eventName: 'CatalogEntityRefresh',
          actorId,
          status: 'succeeded',
          stage: 'completion',
          metadata: {
            entityRef: restBody.entityRef,
          },
          response: {
            status: 200,
          },
          request: req,
          message: `Refresh attempt for ${restBody.entityRef} triggered by ${actorId}`,
        });
        res.status(200).end();
      } catch (err) {
        await auditLogger.auditLog({
          eventName: 'CatalogEntityRefresh',
          actorId,
          status: 'failed',
          stage: 'completion',
          level: 'error',
          errors: [
            {
              name: err.name,
              message: err.message,
              stack: err.stack,
            },
          ],
          metadata: {
            entityRef: restBody.entityRef,
          },
          request: req,
          message: `Refresh attempt for ${restBody.entityRef} by ${actorId} failed`,
        });
        throw err;
      }
    });
  }

  if (permissionIntegrationRouter) {
    router.use(permissionIntegrationRouter);
  }

  if (entitiesCatalog) {
    router
      .get('/entities', async (req, res) => {
        const actorId = await auditLogger.getActorId(
          req as unknown as express.Request,
        );
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetch',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req as unknown as express.Request,
            message: `Entity fetch attempt initiated by ${actorId}`,
          });
          const { entities, pageInfo } = await entitiesCatalog.entities({
            filter: parseEntityFilterParams(req.query),
            fields: parseEntityTransformParams(req.query),
            order: parseEntityOrderParams(req.query),
            pagination: parseEntityPaginationParams(req.query),
            credentials: await httpAuth.credentials(req),
          });

          // Add a Link header to the next page
          if (pageInfo.hasNextPage) {
            const url = new URL(`http://ignored${req.url}`);
            url.searchParams.delete('offset');
            url.searchParams.set('after', pageInfo.endCursor);
            res.setHeader('link', `<${url.pathname}${url.search}>; rel="next"`);
          }

          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetch',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req as unknown as express.Request,
            // Let's not log out the entities since this can make the log very big due to it not being paged?
            response: {
              status: 200,
            },
            message: `Entity fetch attempt by ${actorId} succeeded`,
          });

          // TODO(freben): encode the pageInfo in the response
          res.json(entities);
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetch',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req as unknown as express.Request,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Entity fetch attempt by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/entities/by-query', async (req, res) => {
        const actorId = await auditLogger.getActorId(
          req as unknown as express.Request,
        );
        try {
          await auditLogger.auditLog({
            eventName: 'QueriedCatalogEntityFetch',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req as unknown as express.Request,
            message: `Queried entity fetch attempt initiated by ${actorId}`,
          });
          const { items, pageInfo, totalItems } =
            await entitiesCatalog.queryEntities({
              limit: req.query.limit,
              ...parseQueryEntitiesParams(req.query),
              credentials: await httpAuth.credentials(req),
            });

          res.json({
            items,
            totalItems,
            pageInfo: {
              ...(pageInfo.nextCursor && {
                nextCursor: encodeCursor(pageInfo.nextCursor),
              }),
              ...(pageInfo.prevCursor && {
                prevCursor: encodeCursor(pageInfo.prevCursor),
              }),
            },
          });
          await auditLogger.auditLog({
            eventName: 'QueriedCatalogEntityFetch',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req as unknown as express.Request,
            metadata: {
              totalEntities: totalItems,
              pageInfo: {
                ...(pageInfo.nextCursor && {
                  nextCursor: encodeCursor(pageInfo.nextCursor),
                }),
                ...(pageInfo.prevCursor && {
                  prevCursor: encodeCursor(pageInfo.prevCursor),
                }),
              },
            },
            // Let's not log out the entities since this can make the log very big
            response: {
              status: 200,
            },
            message: `Queried entity fetch attempt by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'QueriedCatalogEntityFetch',
            actorId,
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req as unknown as express.Request,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Queried entity fetch attempt by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/entities/by-uid/:uid', async (req, res) => {
        const { uid } = req.params;
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByUid',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req,
            metadata: {
              uid: uid,
            },
            message: `Fetch attempt for entity with uid ${uid} initiated by ${actorId}`,
          });
          const { entities } = await entitiesCatalog.entities({
            filter: basicEntityFilter({ 'metadata.uid': uid }),
            credentials: await httpAuth.credentials(req),
          });
          if (!entities.length) {
            throw new NotFoundError(`No entity with uid ${uid}`);
          }
          res.status(200).json(entities[0]);
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByUid',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req,
            metadata: {
              uid: uid,
              entityRef: stringifyEntityRef(entities[0]),
            },
            response: {
              status: 200,
            },
            message: `Fetch attempt for entity with uid ${uid} by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByUid',
            actorId,
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req,
            metadata: {
              uid: uid,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Fetch attempt for entity with uid ${uid} by ${actorId} failed`,
          });
          throw err;
        }
      })
      .delete('/entities/by-uid/:uid', async (req, res) => {
        const { uid } = req.params;
        const actorId = await auditLogger.getActorId(req);
        let entityRef: string | undefined;
        try {
          // Get the entityRef of the UID so users can more easily identity the entity
          const { entities } = await entitiesCatalog.entities({
            filter: basicEntityFilter({ 'metadata.uid': uid }),
            credentials: await httpAuth.credentials(req),
          });
          if (entities.length) {
            entityRef = stringifyEntityRef(entities[0]);
          }
          await auditLogger.auditLog({
            eventName: 'CatalogEntityDeletion',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req,
            metadata: {
              uid: uid,
              entityRef: entityRef,
            },
            message: `Deletion attempt for entity with uid ${uid} initiated by ${actorId}`,
          });
          await entitiesCatalog.removeEntityByUid(uid, {
            credentials: await httpAuth.credentials(req),
          });
          await auditLogger.auditLog({
            eventName: 'CatalogEntityDeletion',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req,
            metadata: {
              uid: uid,
              entityRef: entityRef,
            },
            response: {
              status: 204,
            },
            message: `Deletion attempt for entity with uid ${uid} by ${actorId} succeeded`,
          });
          res.status(204).end();
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityDeletion',
            actorId,
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Deletion attempt for entity with uid ${uid} by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/entities/by-name/:kind/:namespace/:name', async (req, res) => {
        const { kind, namespace, name } = req.params;
        const entityRef = stringifyEntityRef({ kind, namespace, name });
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByName',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req,
            metadata: {
              entityRef: entityRef,
            },
            message: `Fetch attempt for entity with entityRef ${entityRef} initiated by ${actorId}`,
          });
          const { entities } = await entitiesCatalog.entities({
            filter: basicEntityFilter({
              kind: kind,
              'metadata.namespace': namespace,
              'metadata.name': name,
            }),
            credentials: await httpAuth.credentials(req),
          });
          if (!entities.length) {
            throw new NotFoundError(
              `No entity named '${name}' found, with kind '${kind}' in namespace '${namespace}'`,
            );
          }
          res.status(200).json(entities[0]);
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByName',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req,
            metadata: {
              entityRef: entityRef,
            },
            response: {
              status: 200,
            },
            message: `Fetch attempt for entity with entityRef ${entityRef} by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFetchByName',
            actorId,
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req,
            metadata: {
              entityRef: entityRef,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Fetch attempt for entity with entityRef ${entityRef} by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get(
        '/entities/by-name/:kind/:namespace/:name/ancestry',
        async (req, res) => {
          const { kind, namespace, name } = req.params;
          const entityRef = stringifyEntityRef({ kind, namespace, name });
          const actorId = await auditLogger.getActorId(req);
          try {
            await auditLogger.auditLog({
              eventName: 'CatalogEntityAncestryFetch',
              actorId,
              status: 'succeeded',
              stage: 'initiation',
              request: req,
              metadata: {
                entityRef: entityRef,
              },
              message: `Fetch attempt for entity ancestor of entity ${entityRef} initiated by ${actorId}`,
            });
            const response = await entitiesCatalog.entityAncestry(entityRef, {
              credentials: await httpAuth.credentials(req),
            });
            res.status(200).json(response);
            await auditLogger.auditLog({
              eventName: 'CatalogEntityAncestryFetch',
              actorId,
              status: 'succeeded',
              stage: 'completion',
              request: req,
              metadata: {
                rootEntityRef: response.rootEntityRef,
                ancestry: response.items.map(ancestryLink => {
                  return {
                    entityRef: stringifyEntityRef(ancestryLink.entity),
                    parentEntityRefs: ancestryLink.parentEntityRefs,
                  };
                }),
              },
              response: {
                status: 200,
              },
              message: `Fetch attempt for entity ancestor of entity ${entityRef} by ${actorId} succeeded`,
            });
          } catch (err) {
            await auditLogger.auditLog({
              eventName: 'CatalogEntityAncestryFetch',
              actorId,
              status: 'failed',
              stage: 'completion',
              level: 'error',
              request: req,
              metadata: {
                entityRef: entityRef,
              },
              errors: [
                {
                  name: err.name,
                  message: err.message,
                  stack: err.stack,
                },
              ],
              message: `Fetch attempt for entity ancestor of entity ${entityRef} by ${actorId} failed`,
            });
            throw err;
          }
        },
      )
      .post('/entities/by-refs', async (req, res) => {
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityBatchFetch',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req,
            message: `Batch entity fetch attempt initiated by ${actorId}`,
          });
          const request = entitiesBatchRequest(req);
          const response = await entitiesCatalog.entitiesBatch({
            entityRefs: request.entityRefs,
            filter: parseEntityFilterParams(req.query),
            fields: parseEntityTransformParams(req.query, request.fields),
            credentials: await httpAuth.credentials(req),
          });
          res.status(200).json(response);
          await auditLogger.auditLog({
            eventName: 'CatalogEntityBatchFetch',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req,
            metadata: {
              ...request,
            },
            response: {
              status: 200,
            },
            message: `Batch entity fetch attempt by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityBatchFetch',
            actorId,
            status: 'failed',
            stage: 'completion',
            level: 'error',
            request: req,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Batch entity fetch attempt by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/entity-facets', async (req, res) => {
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFacetFetch',
            actorId,
            status: 'succeeded',
            stage: 'initiation',
            request: req,
            message: `Entity facet fetch attempt initiated by ${actorId}`,
          });
          const response = await entitiesCatalog.facets({
            filter: parseEntityFilterParams(req.query),
            facets: parseEntityFacetParams(req.query),
            credentials: await httpAuth.credentials(req),
          });
          res.status(200).json(response);
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFacetFetch',
            actorId,
            status: 'succeeded',
            stage: 'completion',
            request: req,
            response: { status: 200 },
            message: `Entity facet fetch attempt by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogEntityFacetFetch',
            actorId,
            status: 'failed',
            stage: 'completion',
            request: req,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Entity facet fetch attempt by ${actorId} failed`,
          });
          throw err;
        }
      });
  }

  if (locationService) {
    router
      .post('/locations', async (req, res) => {
        const credentials = await httpAuth.credentials(req);
        const actorId = await auditLogger.getActorId(req);
        const location = await validateRequestBody(req, locationInput);
        const dryRun = yn(req.query.dryRun, { default: false });

        try {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationCreation',
            status: 'succeeded',
            stage: 'initiation',
            actorId,
            metadata: {
              location: location,
              isDryRun: dryRun,
            },
            request: req,
            message: `Creation attempt of location entity for ${location.target} initiated by ${actorId}`,
          });

          // when in dryRun addLocation is effectively a read operation so we don't
          // need to disallow readonly
          if (!dryRun) {
            disallowReadonlyMode(readonlyEnabled);
          }

          const output = await locationService.createLocation(
            location,
            dryRun,
            {
              credentials,
            },
          );
          await auditLogger.auditLog({
            eventName: 'CatalogLocationCreation',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            metadata: {
              location: output.location,
              isDryRun: dryRun,
            },
            request: req,
            response: {
              status: 201,
            },
            message: `Creation of location entity for ${location.target} initiated by ${actorId} succeeded`,
          });
          res.status(201).json(output);
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationCreation',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            actorId,
            metadata: {
              location: location,
              isDryRun: dryRun,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            request: req,
            message: `Creation of location entity for ${location.target} initiated by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/locations', async (req, res) => {
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetch',
            status: 'succeeded',
            stage: 'initiation',
            actorId,
            request: req,
            message: `Fetch attempt of locations initiated by ${actorId}`,
          });
          const locations = await locationService.listLocations({
            credentials: await httpAuth.credentials(req),
          });
          res.status(200).json(locations.map(l => ({ data: l })));
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetch',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            request: req,
            response: {
              status: 200,
            },
            message: `Fetch attempt of locations by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetch',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            actorId,
            request: req,
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            message: `Fetch attempt of locations by ${actorId} failed`,
          });
          throw err;
        }
      })

      .get('/locations/:id', async (req, res) => {
        const { id } = req.params;
        const actorId = await auditLogger.getActorId(req);
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchById',
            status: 'succeeded',
            stage: 'initiation',
            actorId,
            metadata: {
              id: id,
            },
            request: req,
            message: `Fetch attempt of location with id: ${id} initiated by ${actorId}`,
          });
          const output = await locationService.getLocation(id, {
            credentials: await httpAuth.credentials(req),
          });
          res.status(200).json(output);
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchById',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            metadata: {
              id: id,
            },
            response: {
              status: 200,
              body: output,
            },
            request: req,
            message: `Fetch attempt of location with id: ${id} by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchById',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            actorId,
            metadata: {
              id: id,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            request: req,
            message: `Fetch attempt of location with id: ${id} by ${actorId} failed`,
          });
          throw err;
        }
      })
      .delete('/locations/:id', async (req, res) => {
        const actorId = await auditLogger.getActorId(req);
        const { id } = req.params;
        try {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationDeletion',
            status: 'succeeded',
            stage: 'initiation',
            actorId,
            metadata: {
              id: id,
            },
            request: req,
            message: `Deletion attempt of location with id: ${id} initiated by ${actorId}`,
          });
          disallowReadonlyMode(readonlyEnabled);
          // Grabbing the information of the location begin deleted
          const location = await locationService.getLocation(id, {
            credentials: await httpAuth.credentials(req),
          });
          await locationService.deleteLocation(id, {
            credentials: await httpAuth.credentials(req),
          });
          await auditLogger.auditLog({
            eventName: 'CatalogLocationDeletion',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            metadata: {
              location,
            },
            response: {
              status: 204,
            },
            request: req,
            message: `Deletion attempt of location with id: ${id} by ${actorId} succeeded`,
          });
          res.status(204).end();
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationDeletion',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            actorId,
            metadata: {
              id: id,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            request: req,
            message: `Deletion attempt of location with id: ${id} by ${actorId} failed`,
          });
          throw err;
        }
      })
      .get('/locations/by-entity/:kind/:namespace/:name', async (req, res) => {
        const { kind, namespace, name } = req.params;
        const actorId = await auditLogger.getActorId(req);
        const locationRef = `${kind}:${namespace}/${name}`;

        try {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchByEntityRef',
            status: 'succeeded',
            stage: 'initiation',
            actorId,
            metadata: {
              locationRef: locationRef,
            },
            request: req,
            message: `Fetch attempt for location ${locationRef} initiated by ${actorId}`,
          });

          const output = await locationService.getLocationByEntity(
            { kind, namespace, name },
            { credentials: await httpAuth.credentials(req) },
          );
          res.status(200).json(output);
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchByEntityRef',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            metadata: {
              locationRef: locationRef,
            },
            response: {
              status: 200,
              body: output,
            },
            request: req,
            message: `Fetch attempt for location ${locationRef} by ${actorId} succeeded`,
          });
        } catch (err) {
          await auditLogger.auditLog({
            eventName: 'CatalogLocationFetchByEntityRef',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            actorId,
            metadata: {
              locationRef: locationRef,
            },
            errors: [
              {
                name: err.name,
                message: err.message,
                stack: err.stack,
              },
            ],
            request: req,
            message: `Fetch attempt for location ${locationRef} by ${actorId} failed`,
          });
          throw err;
        }
      });
  }

  if (locationAnalyzer) {
    router.post('/analyze-location', async (req, res) => {
      const actorId = await auditLogger.getActorId(req);

      try {
        await auditLogger.auditLog({
          eventName: 'CatalogLocationAnalyze',
          status: 'succeeded',
          stage: 'initiation',
          actorId,
          request: req,
          message: `Analyze location for location initiated by ${actorId}`,
        });
        const body = await validateRequestBody(
          req,
          z.object({
            location: locationInput,
            catalogFilename: z.string().optional(),
          }),
        );
        const schema = z.object({
          location: locationInput,
          catalogFilename: z.string().optional(),
        });
        const parsedBody = schema.parse(body);
        try {
          const output = await locationAnalyzer.analyzeLocation(parsedBody);
          res.status(200).json(output);
          await auditLogger.auditLog({
            eventName: 'CatalogLocationAnalyze',
            status: 'succeeded',
            stage: 'completion',
            actorId,
            request: req,
            response: {
              status: 200,
              body: output,
            },
            message: `Analyze location for location by ${actorId} succeeded`,
          });
        } catch (err) {
          if (
            // Catch errors from parse-url library.
            err.name === 'Error' &&
            'subject_url' in err
          ) {
            throw new InputError('The given location.target is not a URL');
          }
          throw err;
        }
      } catch (err) {
        await auditLogger.auditLog({
          eventName: 'CatalogLocationAnalyze',
          status: 'failed',
          stage: 'completion',
          level: 'error',
          actorId,
          errors: [
            {
              name: err.name,
              message: err.message,
              stack: err.stack,
            },
          ],
          request: req,
          message: `Analyze location for location by ${actorId} failed`,
        });
        throw err;
      }
    });
  }

  if (orchestrator) {
    router.post('/validate-entity', async (req, res) => {
      const actorId = await auditLogger.getActorId(req);

      try {
        await auditLogger.auditLog({
          eventName: 'CatalogEntityValidate',
          status: 'succeeded',
          stage: 'initiation',
          actorId,
          request: req,
          message: `Entity validation for entity initiated by ${actorId}`,
        });
        const bodySchema = z.object({
          entity: z.unknown(),
          location: z.string(),
        });

        let body: z.infer<typeof bodySchema>;
        let entity: Entity;
        let location: { type: string; target: string };
        try {
          body = await validateRequestBody(req, bodySchema);
          entity = validateEntityEnvelope(body.entity);
          location = parseLocationRef(body.location);
          if (location.type !== 'url')
            throw new TypeError(
              `Invalid location ref ${body.location}, only 'url:<target>' is supported, e.g. url:https://host/path`,
            );
        } catch (err) {
          return res.status(400).json({
            errors: [serializeError(err)],
          });
        }

        const processingResult = await orchestrator.process({
          entity: {
            ...entity,
            metadata: {
              ...entity.metadata,
              annotations: {
                [ANNOTATION_LOCATION]: body.location,
                [ANNOTATION_ORIGIN_LOCATION]: body.location,
                ...entity.metadata.annotations,
              },
            },
          },
        });

        if (!processingResult.ok) {
          const errors = processingResult.errors.map(e => serializeError(e));
          await auditLogger.auditLog({
            eventName: 'CatalogEntityValidate',
            status: 'failed',
            stage: 'completion',
            level: 'error',
            errors: errors,
            response: {
              status: 400,
            },
            actorId,
            request: req,
            message: `Entity validation for entity initiated by ${actorId} failed`,
          });
          return res.status(400).json({
            errors,
          });
        }
        await auditLogger.auditLog({
          eventName: 'CatalogEntityValidate',
          status: 'succeeded',
          stage: 'completion',
          actorId,
          response: {
            status: 200,
          },
          request: req,
          message: `Entity validation for entity by ${actorId} succeeded`,
        });
        return res.status(200).end();
      } catch (err) {
        await auditLogger.auditLog({
          eventName: 'CatalogEntityValidate',
          status: 'failed',
          stage: 'completion',
          level: 'error',
          errors: [
            {
              name: err.name,
              message: err.message,
              stack: err.stack,
            },
          ],
          actorId,
          request: req,
          message: `Entity validation for entity initiated by ${actorId} failed`,
        });
        throw err;
      }
    });
  }

  router.use(errorHandler());
  return router;
}
