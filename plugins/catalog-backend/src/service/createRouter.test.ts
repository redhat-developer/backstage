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

import { ConfigReader } from '@backstage/config';
import { NotFoundError } from '@backstage/errors';
import type { Location } from '@backstage/catalog-client';
import {
  ANNOTATION_LOCATION,
  ANNOTATION_ORIGIN_LOCATION,
  Entity,
  stringifyEntityRef,
} from '@backstage/catalog-model';
import express from 'express';
import request from 'supertest';
import { Cursor, EntitiesCatalog } from '../catalog/types';
import { LocationInput, LocationService, RefreshService } from './types';
import { basicEntityFilter } from './request';
import { createRouter } from './createRouter';
import { AuthorizeResult } from '@backstage/plugin-permission-common';
import {
  createPermissionIntegrationRouter,
  createPermissionRule,
} from '@backstage/plugin-permission-node';
import { RESOURCE_TYPE_CATALOG_ENTITY } from '@backstage/plugin-catalog-common/alpha';
import { CatalogProcessingOrchestrator } from '../processing/types';
import { z } from 'zod';
import { decodeCursor, encodeCursor } from './util';
import { wrapInOpenApiTestServer } from '@backstage/backend-openapi-utils';
import { Server } from 'http';
import { mockCredentials, mockServices } from '@backstage/backend-test-utils';
import { LocationAnalyzer } from '@backstage/plugin-catalog-node';

const localhostNames = ['localhost', '127.0.0.1', '::1', '::ffff:127.0.0.1'];
const localhostIps = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];

const commonAuditLogMeta = {
  actor: {
    ip: expect.stringMatching(new RegExp(localhostIps.join('|'))),
    actorId: 'user:default/mock',
    hostname: expect.stringMatching(new RegExp(localhostNames.join('|'))),
  },
  request: {
    body: {},
    method: 'GET',
    params: {},
    query: {},
  },
  isAuditLog: true,
  meta: {},
  status: 'succeeded',
};

describe('createRouter readonly disabled', () => {
  let entitiesCatalog: jest.Mocked<EntitiesCatalog>;
  let locationService: jest.Mocked<LocationService>;
  let orchestrator: jest.Mocked<CatalogProcessingOrchestrator>;
  let app: express.Express | Server;
  let refreshService: RefreshService;
  let locationAnalyzer: jest.Mocked<LocationAnalyzer>;
  const logger = mockServices.logger.mock();
  let loggerSpy: jest.SpyInstance;
  let loggerErrorSpy: jest.SpyInstance;

  beforeAll(async () => {
    entitiesCatalog = {
      entities: jest.fn(),
      entitiesBatch: jest.fn(),
      removeEntityByUid: jest.fn(),
      entityAncestry: jest.fn(),
      facets: jest.fn(),
      queryEntities: jest.fn(),
    };
    locationService = {
      getLocation: jest.fn(),
      createLocation: jest.fn(),
      listLocations: jest.fn(),
      deleteLocation: jest.fn(),
      getLocationByEntity: jest.fn(),
    };

    locationAnalyzer = {
      analyzeLocation: jest.fn(),
    };
    refreshService = { refresh: jest.fn() };
    orchestrator = { process: jest.fn() };

    const router = await createRouter({
      entitiesCatalog,
      locationService,
      orchestrator,
      logger,
      refreshService,
      config: new ConfigReader(undefined),
      permissionIntegrationRouter: express.Router(),
      auth: mockServices.auth(),
      httpAuth: mockServices.httpAuth(),
      locationAnalyzer,
    });
    app = wrapInOpenApiTestServer(express().use(router));
  });

  beforeEach(() => {
    loggerSpy = jest.spyOn(logger, 'info');
    loggerErrorSpy = jest.spyOn(logger, 'error');
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('POST /refresh', () => {
    it('refreshes an entity using the refresh service', async () => {
      const response = await request(app)
        .post('/refresh')
        .set('Content-Type', 'application/json')
        .send({ entityRef: 'Component/default:foo' });
      expect(response.status).toBe(200);
      expect(refreshService.refresh).toHaveBeenCalledWith({
        entityRef: 'Component/default:foo',
        credentials: mockCredentials.user(),
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityRefresh',
        request: {
          ...commonAuditLogMeta.request,
          body: { entityRef: 'Component/default:foo' },
          url: '/refresh',
          method: 'POST',
        },
        meta: {
          entityRef: 'Component/default:foo',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Refresh attempt for Component/default:foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Refresh attempt for Component/default:foo triggered by user:default/mock`,
        auditLogCompletionMeta,
      );
    });

    it('should support passing the token in the request body for backwards compatibility', async () => {
      const requestBody = {
        entityRef: 'Component/default:foo',
        authorizationToken: mockCredentials.user.token('user:default/other'),
      };
      const response = await request(app)
        .post('/refresh')
        .set('Content-Type', 'application/json')
        .send(requestBody);
      expect(response.status).toBe(200);
      expect(refreshService.refresh).toHaveBeenCalledWith({
        entityRef: 'Component/default:foo',
        credentials: mockCredentials.user('user:default/other'),
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityRefresh',
        request: {
          ...commonAuditLogMeta.request,
          body: requestBody,
          url: '/refresh',
          method: 'POST',
        },
        meta: {
          entityRef: 'Component/default:foo',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Refresh attempt for Component/default:foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Refresh attempt for Component/default:foo triggered by user:default/mock`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /entities', () => {
    it('happy path: lists entities', async () => {
      const entities: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.entities.mockResolvedValueOnce({
        entities: [entities[0]],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities');

      expect(response.status).toEqual(200);
      expect(response.body).toEqual(entities);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: '/entities',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('parses single and multiple request parameters and passes them down', async () => {
      entitiesCatalog.entities.mockResolvedValueOnce({
        entities: [],
        pageInfo: { hasNextPage: false },
      });
      const response = await request(app).get(
        '/entities?filter=a=1,a=2,b=3&filter=c=4',
      );

      expect(response.status).toEqual(200);
      expect(entitiesCatalog.entities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entities).toHaveBeenCalledWith({
        filter: {
          anyOf: [
            {
              allOf: [
                { key: 'a', values: ['1', '2'] },
                { key: 'b', values: ['3'] },
              ],
            },
            { allOf: [{ key: 'c', values: ['4'] }] },
          ],
        },
        credentials: mockCredentials.user(),
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: '/entities?filter=a=1,a=2,b=3&filter=c=4',
          query: {
            filter: ['a=1,a=2,b=3', 'c=4'],
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /entities/by-query', () => {
    it('happy path: lists entities', async () => {
      const items: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: mockCursor() },
      });

      const response = await request(app).get('/entities/by-query');
      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        items,
        totalItems: 100,
        pageInfo: {
          nextCursor: expect.any(String),
        },
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: '/entities/by-query',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          totalEntities: 100,
          pageInfo: {
            nextCursor: expect.any(String),
          },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('parses initial request', async () => {
      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items: [],
        pageInfo: {},
        totalItems: 0,
      });
      const response = await request(app).get(
        '/entities/by-query?filter=a=1,a=2,b=3&filter=c=4&orderField=metadata.name,asc&orderField=metadata.uid,desc',
      );

      expect(response.status).toEqual(200);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledWith({
        filter: {
          anyOf: [
            {
              allOf: [
                { key: 'a', values: ['1', '2'] },
                { key: 'b', values: ['3'] },
              ],
            },
            { allOf: [{ key: 'c', values: ['4'] }] },
          ],
        },
        orderFields: [
          { field: 'metadata.name', order: 'asc' },
          { field: 'metadata.uid', order: 'desc' },
        ],
        fullTextFilter: {
          fields: undefined,
          term: '',
        },
        credentials: mockCredentials.user(),
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: '/entities/by-query?filter=a=1,a=2,b=3&filter=c=4&orderField=metadata.name,asc&orderField=metadata.uid,desc',
          query: {
            filter: ['a=1,a=2,b=3', 'c=4'],
            orderField: ['metadata.name,asc', 'metadata.uid,desc'],
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          pageInfo: {},
          totalEntities: 0,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('parses encoded params request', async () => {
      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items: [],
        pageInfo: {},
        totalItems: 0,
      });
      const response = await request(app).get(
        `/entities/by-query?filter=${encodeURIComponent(
          'a=1,a=2,b=3',
        )}&filter=c=4&orderField=${encodeURIComponent(
          'metadata.name,asc',
        )}&orderField=metadata.uid,desc`,
      );

      expect(response.status).toEqual(200);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledWith({
        filter: {
          anyOf: [
            {
              allOf: [
                { key: 'a', values: ['1', '2'] },
                { key: 'b', values: ['3'] },
              ],
            },
            { allOf: [{ key: 'c', values: ['4'] }] },
          ],
        },
        orderFields: [
          { field: 'metadata.name', order: 'asc' },
          { field: 'metadata.uid', order: 'desc' },
        ],
        fullTextFilter: {
          fields: undefined,
          term: '',
        },
        credentials: mockCredentials.user(),
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-query?filter=${encodeURIComponent(
            'a=1,a=2,b=3',
          )}&filter=c=4&orderField=${encodeURIComponent(
            'metadata.name,asc',
          )}&orderField=metadata.uid,desc`,
          query: {
            filter: ['a=1,a=2,b=3', 'c=4'],
            orderField: ['metadata.name,asc', 'metadata.uid,desc'],
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          pageInfo: {},
          totalEntities: 0,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('parses cursor request', async () => {
      const items: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: mockCursor() },
      });

      const cursor = mockCursor({ totalItems: 100, isPrevious: false });

      const response = await request(app).get(
        `/entities/by-query?cursor=${encodeCursor(cursor)}`,
      );
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledWith({
        cursor,
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: expect.any(String) },
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-query?cursor=${encodeCursor(cursor)}`,
          query: {
            cursor: `${encodeCursor(cursor)}`,
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          totalEntities: 100,
          pageInfo: {
            nextCursor: expect.any(String),
          },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('parses cursor request with fullTextFilter', async () => {
      const items: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items,
        totalItems: 100,
        pageInfo: {
          nextCursor: mockCursor({ fullTextFilter: { term: 'mySearch' } }),
        },
      });

      const cursor = mockCursor({
        totalItems: 100,
        isPrevious: false,
        fullTextFilter: { term: 'mySearch' },
      });

      const response = await request(app).get(
        `/entities/by-query?cursor=${encodeCursor(cursor)}`,
      );
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.queryEntities).toHaveBeenCalledWith({
        cursor,
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: expect.any(String) },
      });
      const decodedCursor = decodeCursor(response.body.pageInfo.nextCursor);
      expect(decodedCursor).toMatchObject({
        isPrevious: false,
        fullTextFilter: {
          term: 'mySearch',
        },
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-query?cursor=${encodeCursor(cursor)}`,
          query: {
            cursor: `${encodeCursor(cursor)}`,
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          totalEntities: 100,
          pageInfo: {
            nextCursor: expect.any(String),
          },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('should throw in case of malformed cursor', async () => {
      const items: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: mockCursor() },
      });

      const encodedBadCursor = `${Buffer.from(
        JSON.stringify({ bad: 'cursor' }),
        'utf8',
      ).toString('base64')}`;

      let response = await request(app).get(
        `/entities/by-query?cursor=${encodedBadCursor}`,
      );
      expect(response.status).toEqual(400);
      expect(response.body.error.message).toMatch(/Malformed cursor/);

      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'QueriedCatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-query?cursor=${encodedBadCursor}`,
          query: {
            cursor: `${encodedBadCursor}`,
          },
        },
        stage: 'initiation',
      };
      const auditLogErrorMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'InputError',
            message: expect.stringContaining('Malformed cursor'),
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Queried entity fetch attempt by user:default/mock failed`,
        auditLogErrorMeta,
      );

      response = await request(app).get(`/entities/by-query?cursor=badcursor`);
      expect(response.status).toEqual(400);
      expect(response.body.error.message).toMatch(/Malformed cursor/);
      const auditLogInitMeta2 = {
        ...auditLogInitMeta,
        request: {
          ...auditLogInitMeta.request,
          url: `/entities/by-query?cursor=badcursor`,
          query: {
            cursor: `badcursor`,
          },
        },
      };
      const auditLogErrorMeta2 = {
        ...auditLogInitMeta2,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'InputError',
            message: expect.stringContaining('Malformed cursor'),
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta2,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        2,
        `Queried entity fetch attempt by user:default/mock failed`,
        auditLogErrorMeta2,
      );
    });

    it('should throw in case of invalid limit', async () => {
      // TODO(frkong): this error is thrown by the openapi-router so it does not hit the audit logging code for the endpoint
      const items: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.queryEntities.mockResolvedValueOnce({
        items,
        totalItems: 100,
        pageInfo: { nextCursor: mockCursor() },
      });

      const response = await request(app).get(`/entities/by-query?limit=asdf`);
      expect(response.status).toEqual(400);
      expect(response.body.error.message).toMatch(
        /request\/query\/limit must be integer/,
      );
    });
  });

  describe('GET /entities/by-uid/:uid', () => {
    it('can fetch entity by uid', async () => {
      const entity: Entity = {
        apiVersion: 'a',
        kind: 'b',
        metadata: {
          name: 'c',
        },
      };
      entitiesCatalog.entities.mockResolvedValue({
        entities: [entity],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities/by-uid/zzz');

      expect(entitiesCatalog.entities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entities).toHaveBeenCalledWith({
        filter: basicEntityFilter({ 'metadata.uid': 'zzz' }),
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual(expect.objectContaining(entity));
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetchByUid',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-uid/zzz`,
          params: {
            uid: 'zzz',
          },
        },
        meta: {
          uid: 'zzz',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          uid: 'zzz',
          entityRef: 'b:default/c',
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with uid zzz initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt for entity with uid zzz by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('responds with a 404 for missing entities', async () => {
      entitiesCatalog.entities.mockResolvedValue({
        entities: [],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities/by-uid/zzz');

      expect(entitiesCatalog.entities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entities).toHaveBeenCalledWith({
        filter: basicEntityFilter({ 'metadata.uid': 'zzz' }),
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(404);
      expect(response.text).toMatch(/uid/);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetchByUid',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-uid/zzz`,
          params: {
            uid: 'zzz',
          },
        },
        meta: {
          uid: 'zzz',
        },
        stage: 'initiation',
      };
      const auditLogFailureMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'NotFoundError',
            message: 'No entity with uid zzz',
            stack: expect.any(String),
          },
        ],
        meta: {
          uid: 'zzz',
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with uid zzz initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with uid zzz by user:default/mock failed`,
        auditLogFailureMeta,
      );
    });
  });

  describe('GET /entities/by-name/:kind/:namespace/:name', () => {
    it('can fetch entity by name', async () => {
      const entity: Entity = {
        apiVersion: 'a',
        kind: 'k',
        metadata: {
          name: 'n',
          namespace: 'ns',
        },
      };
      entitiesCatalog.entities.mockResolvedValue({
        entities: [entity],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities/by-name/k/ns/n');

      expect(entitiesCatalog.entities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entities).toHaveBeenCalledWith({
        filter: basicEntityFilter({
          kind: 'k',
          'metadata.namespace': 'ns',
          'metadata.name': 'n',
        }),
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual(expect.objectContaining(entity));
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetchByName',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-name/k/ns/n`,
          params: {
            kind: 'k',
            namespace: 'ns',
            name: 'n',
          },
        },
        meta: {
          entityRef: 'k:ns/n',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with entityRef k:ns/n initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt for entity with entityRef k:ns/n by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('responds with a 404 for missing entities', async () => {
      entitiesCatalog.entities.mockResolvedValue({
        entities: [],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities/by-name/b/d/c');

      expect(entitiesCatalog.entities).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entities).toHaveBeenCalledWith({
        filter: basicEntityFilter({
          kind: 'b',
          'metadata.namespace': 'd',
          'metadata.name': 'c',
        }),
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(404);
      expect(response.text).toMatch(/name/);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetchByName',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-name/b/d/c`,
          params: {
            kind: 'b',
            namespace: 'd',
            name: 'c',
          },
        },
        meta: {
          entityRef: 'b:d/c',
        },
        stage: 'initiation',
      };
      const auditLogFailureMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'NotFoundError',
            message:
              "No entity named 'c' found, with kind 'b' in namespace 'd'",
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with entityRef b:d/c initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for entity with entityRef b:d/c by user:default/mock failed`,
        auditLogFailureMeta,
      );
    });
  });

  describe('DELETE /entities/by-uid/:uid', () => {
    it('can remove', async () => {
      entitiesCatalog.removeEntityByUid.mockResolvedValue(undefined);
      entitiesCatalog.entities.mockResolvedValue({
        entities: [
          {
            apiVersion: 'v1',
            kind: 'k',
            metadata: {
              name: 'n',
              namespace: 'ns',
            },
          },
        ],
        pageInfo: { hasNextPage: false },
      });
      const response = await request(app).delete('/entities/by-uid/apa');
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledWith('apa', {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(204);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityDeletion',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-uid/apa`,
          method: 'DELETE',
          params: {
            uid: 'apa',
          },
        },
        meta: {
          uid: 'apa',
          entityRef: 'k:ns/n',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 204 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt for entity with uid apa initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Deletion attempt for entity with uid apa by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('responds with a 404 for missing entities', async () => {
      entitiesCatalog.removeEntityByUid.mockRejectedValue(
        new NotFoundError('nope'),
      );
      entitiesCatalog.entities.mockResolvedValue({
        entities: [],
        pageInfo: { hasNextPage: false },
      });
      const response = await request(app).delete('/entities/by-uid/apa');
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledWith('apa', {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(404);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityDeletion',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-uid/apa`,
          method: 'DELETE',
          params: {
            uid: 'apa',
          },
        },
        meta: {
          uid: 'apa',
        },
        stage: 'initiation',
      };
      const auditLogFailureMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        meta: {},
        errors: [
          {
            name: 'NotFoundError',
            message: 'nope',
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt for entity with uid apa initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt for entity with uid apa by user:default/mock failed`,
        auditLogFailureMeta,
      );
    });
  });

  describe('POST /entities/by-refs', () => {
    it.each([
      '',
      'not json',
      '[',
      '[]',
      '{}',
      '{"unknown":7}',
      '{"entityRefs":7}',
      '{"entityRefs":[7]}',
      '{"entityRefs":[7],"fields":7}',
      '{"entityRefs":[7],"fields":[7]}',
    ])('properly rejects malformed request body, %p', async p => {
      // TODO(frkong): These are rejected by the openapi router as well so no audit logging
      await expect(
        request(app)
          .post('/entities/by-refs')
          .set('Content-Type', 'application/json')
          .send(p),
      ).resolves.toMatchObject({ status: 400 });
    });

    it('can fetch entities by refs', async () => {
      const entity: Entity = {
        apiVersion: 'a',
        kind: 'component',
        metadata: {
          name: 'a',
        },
      };
      const entityRef = stringifyEntityRef(entity);
      entitiesCatalog.entitiesBatch.mockResolvedValue({ items: [entity] });
      const response = await request(app)
        .post('/entities/by-refs?filter=kind=Component')
        .set('Content-Type', 'application/json')
        .send(
          JSON.stringify({
            entityRefs: [entityRef],
            fields: ['metadata.name'],
          }),
        );
      expect(entitiesCatalog.entitiesBatch).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.entitiesBatch).toHaveBeenCalledWith({
        entityRefs: [entityRef],
        fields: expect.any(Function),
        credentials: mockCredentials.user(),
        filter: {
          anyOf: [
            {
              allOf: [{ key: 'kind', values: ['Component'] }],
            },
          ],
        },
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual({ items: [entity] });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityBatchFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-refs?filter=kind=Component`,
          method: 'POST',
          query: {
            filter: ['kind=Component'],
          },
          body: {
            entityRefs: [entityRef],
            fields: ['metadata.name'],
          },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
        meta: {
          entityRefs: [entityRef],
          fields: ['metadata.name'],
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Batch entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Batch entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /locations', () => {
    it('happy path: lists locations', async () => {
      const locations: Location[] = [
        { id: 'foo', type: 'url', target: 'example.com' },
      ];
      locationService.listLocations.mockResolvedValueOnce(locations);

      const response = await request(app).get('/locations');
      expect(locationService.listLocations).toHaveBeenCalledTimes(1);
      expect(locationService.listLocations).toHaveBeenCalledWith({
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(200);
      expect(response.body).toEqual([
        { data: { id: 'foo', target: 'example.com', type: 'url' } },
      ]);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations`,
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt of locations initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt of locations by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /locations/:id', () => {
    it('happy path: gets location by id', async () => {
      const location: Location = {
        id: 'foo',
        type: 'url',
        target: 'example.com',
      };
      locationService.getLocation.mockResolvedValueOnce(location);

      const response = await request(app).get('/locations/foo');
      expect(locationService.getLocation).toHaveBeenCalledTimes(1);
      expect(locationService.getLocation).toHaveBeenCalledWith('foo', {
        credentials: mockCredentials.user(),
      });

      expect(response.status).toEqual(200);
      expect(response.body).toEqual(location);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetchById',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations/foo`,
          params: { id: 'foo' },
        },
        meta: {
          id: 'foo',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 200,
          body: location,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt of location with id: foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt of location with id: foo by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('POST /locations', () => {
    it('rejects malformed locations', async () => {
      const spec = {
        typez: 'b',
        target: 'c',
      } as unknown as LocationInput;

      const response = await request(app).post('/locations').send(spec);

      expect(locationService.createLocation).not.toHaveBeenCalled();
      expect(response.status).toEqual(400);
    });

    it('passes the body down', async () => {
      const spec: LocationInput = {
        type: 'b',
        target: 'c',
      };

      locationService.createLocation.mockResolvedValue({
        location: { id: 'a', ...spec },
        entities: [],
      });

      const response = await request(app).post('/locations').send(spec);

      expect(locationService.createLocation).toHaveBeenCalledTimes(1);
      expect(locationService.createLocation).toHaveBeenCalledWith(spec, false, {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(201);
      expect(response.body).toEqual(
        expect.objectContaining({
          location: { id: 'a', ...spec },
        }),
      );
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationCreation',
        request: {
          ...commonAuditLogMeta.request,
          method: 'POST',
          url: `/locations`,
          body: spec,
        },
        meta: {
          isDryRun: false,
          location: { ...spec },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 201,
        },
        meta: {
          isDryRun: false,
          location: { id: 'a', ...spec },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Creation attempt of location entity for c initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Creation of location entity for c initiated by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });

    it('supports dry run', async () => {
      const spec: LocationInput = {
        type: 'b',
        target: 'c',
      };

      locationService.createLocation.mockResolvedValue({
        location: { id: 'a', ...spec },
        entities: [],
      });

      const response = await request(app)
        .post('/locations?dryRun=true')
        .send(spec);

      expect(locationService.createLocation).toHaveBeenCalledTimes(1);
      expect(locationService.createLocation).toHaveBeenCalledWith(spec, true, {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(201);
      expect(response.body).toEqual(
        expect.objectContaining({
          location: { id: 'a', ...spec },
        }),
      );
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationCreation',
        request: {
          ...commonAuditLogMeta.request,
          method: 'POST',
          url: `/locations?dryRun=true`,
          query: { dryRun: 'true' },
          body: spec,
        },
        meta: {
          isDryRun: true,
          location: { ...spec },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 201,
        },
        meta: {
          isDryRun: true,
          location: { id: 'a', ...spec },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Creation attempt of location entity for c initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Creation of location entity for c initiated by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('DELETE /locations', () => {
    it('deletes the location', async () => {
      locationService.deleteLocation.mockResolvedValueOnce(undefined);
      locationService.getLocation.mockResolvedValueOnce({
        id: 'joo',
        target: 'test',
        type: 'url',
      });
      const response = await request(app).delete('/locations/foo');
      expect(locationService.deleteLocation).toHaveBeenCalledTimes(1);
      expect(locationService.deleteLocation).toHaveBeenCalledWith('foo', {
        credentials: mockCredentials.user(),
      });

      expect(response.status).toEqual(204);

      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationDeletion',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations/foo`,
          method: 'DELETE',
          params: {
            id: 'foo',
          },
        },
        meta: {
          id: 'foo',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        meta: {
          location: {
            id: 'joo',
            target: 'test',
            type: 'url',
          },
        },
        response: {
          status: 204,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt of location with id: foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Deletion attempt of location with id: foo by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /locations/by-entity/:kind/:namespace/:name', () => {
    it('happy path: gets location by entity ref', async () => {
      const location: Location = {
        id: 'foo',
        type: 'url',
        target: 'example.com',
      };
      locationService.getLocationByEntity.mockResolvedValueOnce(location);

      const response = await request(app).get('/locations/by-entity/c/ns/n');
      expect(locationService.getLocationByEntity).toHaveBeenCalledTimes(1);
      expect(locationService.getLocationByEntity).toHaveBeenCalledWith(
        { kind: 'c', namespace: 'ns', name: 'n' },
        {
          credentials: mockCredentials.user(),
        },
      );

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        id: 'foo',
        target: 'example.com',
        type: 'url',
      });

      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetchByEntityRef',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations/by-entity/c/ns/n`,
          params: {
            kind: 'c',
            namespace: 'ns',
            name: 'n',
          },
        },
        meta: {
          locationRef: 'c:ns/n',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 200,
          body: location,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for location c:ns/n initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt for location c:ns/n by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('POST /validate-entity', () => {
    describe('valid entity', () => {
      it('returns 200', async () => {
        const entity: Entity = {
          apiVersion: 'a',
          kind: 'b',
          metadata: { name: 'n' },
        };

        orchestrator.process.mockResolvedValueOnce({
          ok: true,
          state: {},
          completedEntity: entity,
          deferredEntities: [],
          refreshKeys: [],
          relations: [],
          errors: [],
        });

        const response = await request(app)
          .post('/validate-entity')
          .send({ entity, location: 'url:validate-entity' });

        expect(response.status).toEqual(200);
        expect(orchestrator.process).toHaveBeenCalledTimes(1);
        expect(orchestrator.process).toHaveBeenCalledWith({
          entity: {
            apiVersion: 'a',
            kind: 'b',
            metadata: {
              name: 'n',
              annotations: {
                [ANNOTATION_LOCATION]: 'url:validate-entity',
                [ANNOTATION_ORIGIN_LOCATION]: 'url:validate-entity',
              },
            },
          },
        });

        const auditLogInitMeta = {
          ...commonAuditLogMeta,
          eventName: 'CatalogEntityValidate',
          request: {
            ...commonAuditLogMeta.request,
            url: `/validate-entity`,
            method: 'POST',
            body: {
              entity,
              location: 'url:validate-entity',
            },
          },
          stage: 'initiation',
        };
        const auditLogCompletionMeta = {
          ...auditLogInitMeta,
          stage: 'completion',
          response: {
            status: 200,
          },
        };
        expect(loggerSpy).toHaveBeenCalledTimes(2);
        expect(loggerSpy).toHaveBeenNthCalledWith(
          1,
          `Entity validation for entity initiated by user:default/mock`,
          auditLogInitMeta,
        );
        expect(loggerSpy).toHaveBeenNthCalledWith(
          2,
          `Entity validation for entity by user:default/mock succeeded`,
          auditLogCompletionMeta,
        );
      });
    });

    describe('invalid entity', () => {
      it('returns 400', async () => {
        const entity: Entity = {
          apiVersion: 'a',
          kind: 'b',
          metadata: { name: 'invalid*name' },
        };

        orchestrator.process.mockResolvedValueOnce({
          ok: false,
          errors: [new Error('Invalid entity name')],
        });

        const response = await request(app)
          .post('/validate-entity')
          .send({ entity, location: 'url:validate-entity' });

        expect(response.status).toEqual(400);
        expect(response.body.errors.length).toEqual(1);
        expect(response.body.errors[0].message).toEqual('Invalid entity name');
        expect(orchestrator.process).toHaveBeenCalledTimes(1);
        expect(orchestrator.process).toHaveBeenCalledWith({
          entity: {
            apiVersion: 'a',
            kind: 'b',
            metadata: {
              name: 'invalid*name',
              annotations: {
                [ANNOTATION_LOCATION]: 'url:validate-entity',
                [ANNOTATION_ORIGIN_LOCATION]: 'url:validate-entity',
              },
            },
          },
        });
        const auditLogInitMeta = {
          ...commonAuditLogMeta,
          eventName: 'CatalogEntityValidate',
          request: {
            ...commonAuditLogMeta.request,
            url: `/validate-entity`,
            method: 'POST',
            body: {
              entity,
              location: 'url:validate-entity',
            },
          },
          stage: 'initiation',
        };
        const auditLogFailureMeta = {
          ...auditLogInitMeta,
          stage: 'completion',
          response: {
            status: 400,
          },
          status: 'failed',
          errors: [
            {
              name: 'Error',
              message: 'Invalid entity name',
            },
          ],
        };
        expect(loggerSpy).toHaveBeenCalledTimes(1);
        expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
        expect(loggerSpy).toHaveBeenNthCalledWith(
          1,
          `Entity validation for entity initiated by user:default/mock`,
          auditLogInitMeta,
        );
        expect(loggerErrorSpy).toHaveBeenNthCalledWith(
          1,
          `Entity validation for entity initiated by user:default/mock failed`,
          auditLogFailureMeta,
        );
      });
    });

    describe('no location', () => {
      it('returns 400', async () => {
        const entity: Entity = {
          apiVersion: 'a',
          kind: 'b',
          metadata: { name: 'n' },
        };

        const response = await request(app)
          .post('/validate-entity')
          .send({ entity, location: null });

        expect(response.status).toEqual(400);
        expect(response.body.errors.length).toEqual(1);
        expect(response.body.errors[0].message).toContain('Malformed request:');
        expect(orchestrator.process).toHaveBeenCalledTimes(0);
      });
    });

    describe('no entity', () => {
      it('returns 400', async () => {
        const response = await request(app)
          .post('/validate-entity')
          .send({ entity: null, location: 'url:entity' });

        expect(response.status).toEqual(400);
        expect(response.body.errors.length).toEqual(1);
        expect(response.body.errors[0].message).toContain(
          '<root> must be object - type: object',
        );
      });
    });
  });

  describe('POST /analyze-location', () => {
    it('handles invalid URLs', async () => {
      const parseUrlError = new Error();
      (parseUrlError as any).subject_url = 'not a url';
      locationAnalyzer.analyzeLocation.mockRejectedValue(parseUrlError);
      const response = await request(app)
        .post('/analyze-location')
        .send({ location: { type: 'url', target: 'not a url' } });
      expect(response.status).toEqual(400);
      expect(response.body.error.message).toMatch(
        /The given location.target is not a URL/,
      );
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationAnalyze',
        request: {
          ...commonAuditLogMeta.request,
          url: `/analyze-location`,
          method: 'POST',
          body: { location: { type: 'url', target: 'not a url' } },
        },
        stage: 'initiation',
      };
      const auditLogFailureMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'InputError',
            message: 'The given location.target is not a URL',
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Analyze location for location initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Analyze location for location by user:default/mock failed`,
        auditLogFailureMeta,
      );
    });
  });
});

describe('createRouter readonly enabled', () => {
  let entitiesCatalog: jest.Mocked<EntitiesCatalog>;
  let app: express.Express;
  let locationService: jest.Mocked<LocationService>;
  const logger = mockServices.logger.mock();
  let loggerSpy: jest.SpyInstance;
  let loggerErrorSpy: jest.SpyInstance;

  beforeAll(async () => {
    entitiesCatalog = {
      entities: jest.fn(),
      entitiesBatch: jest.fn(),
      removeEntityByUid: jest.fn(),
      entityAncestry: jest.fn(),
      facets: jest.fn(),
      queryEntities: jest.fn(),
    };
    locationService = {
      getLocation: jest.fn(),
      createLocation: jest.fn(),
      listLocations: jest.fn(),
      deleteLocation: jest.fn(),
      getLocationByEntity: jest.fn(),
    };
    const router = await createRouter({
      entitiesCatalog,
      locationService,
      logger,
      config: new ConfigReader({
        catalog: {
          readonly: true,
        },
      }),
      permissionIntegrationRouter: express.Router(),
      auth: mockServices.auth(),
      httpAuth: mockServices.httpAuth(),
    });
    app = express().use(router);
  });

  beforeEach(() => {
    loggerSpy = jest.spyOn(logger, 'info');
    loggerErrorSpy = jest.spyOn(logger, 'error');
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('GET /entities', () => {
    it('happy path: lists entities', async () => {
      const entities: Entity[] = [
        { apiVersion: 'a', kind: 'b', metadata: { name: 'n' } },
      ];

      entitiesCatalog.entities.mockResolvedValueOnce({
        entities: [entities[0]],
        pageInfo: { hasNextPage: false },
      });

      const response = await request(app).get('/entities');

      expect(response.status).toEqual(200);
      expect(response.body).toEqual(entities);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities`,
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };

      expect(loggerSpy).toHaveBeenCalledTimes(3);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Catalog is running in readonly mode`,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Entity fetch attempt initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        3,
        `Entity fetch attempt by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('DELETE /entities/by-uid/:uid', () => {
    // this delete is allowed as there is no other way to remove entities
    it('is allowed', async () => {
      entitiesCatalog.entities.mockResolvedValue({
        entities: [
          {
            apiVersion: 'v1',
            kind: 'k',
            metadata: {
              name: 'n',
              namespace: 'ns',
            },
          },
        ],
        pageInfo: { hasNextPage: false },
      });
      const response = await request(app).delete('/entities/by-uid/apa');
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledTimes(1);
      expect(entitiesCatalog.removeEntityByUid).toHaveBeenCalledWith('apa', {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(204);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogEntityDeletion',
        request: {
          ...commonAuditLogMeta.request,
          url: `/entities/by-uid/apa`,
          method: 'DELETE',
          params: {
            uid: 'apa',
          },
        },
        meta: {
          uid: 'apa',
          entityRef: 'k:ns/n',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 204 },
      };

      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt for entity with uid apa initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Deletion attempt for entity with uid apa by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /locations', () => {
    it('happy path: lists locations', async () => {
      const locations: Location[] = [
        { id: 'foo', type: 'url', target: 'example.com' },
      ];
      locationService.listLocations.mockResolvedValueOnce(locations);

      const response = await request(app).get('/locations');
      expect(locationService.listLocations).toHaveBeenCalledTimes(1);
      expect(locationService.listLocations).toHaveBeenCalledWith({
        credentials: mockCredentials.user(),
      });

      expect(response.status).toEqual(200);
      expect(response.body).toEqual([
        { data: { id: 'foo', target: 'example.com', type: 'url' } },
      ]);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetch',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations`,
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: { status: 200 },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt of locations initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt of locations by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('GET /locations/:id', () => {
    it('happy path: gets location by id', async () => {
      const location: Location = {
        id: 'foo',
        type: 'url',
        target: 'example.com',
      };
      locationService.getLocation.mockResolvedValueOnce(location);

      const response = await request(app).get('/locations/foo');
      expect(locationService.getLocation).toHaveBeenCalledTimes(1);
      expect(locationService.getLocation).toHaveBeenCalledWith('foo', {
        credentials: mockCredentials.user(),
      });

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        id: 'foo',
        target: 'example.com',
        type: 'url',
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetchById',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations/foo`,
          params: { id: 'foo' },
        },
        meta: {
          id: 'foo',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 200,
          body: location,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt of location with id: foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt of location with id: foo by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('POST /locations', () => {
    it('is not allowed', async () => {
      const spec: LocationInput = {
        type: 'b',
        target: 'c',
      };

      const response = await request(app).post('/locations').send(spec);

      expect(locationService.createLocation).not.toHaveBeenCalled();
      expect(response.status).toEqual(403);
      expect(response.text).toMatch(/not allowed in readonly/);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationCreation',
        request: {
          ...commonAuditLogMeta.request,
          method: 'POST',
          url: `/locations`,
          body: spec,
        },
        meta: {
          isDryRun: false,
          location: { ...spec },
        },
        stage: 'initiation',
      };
      const auditLogErrorMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'NotAllowedError',
            message: 'This operation not allowed in readonly mode',
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Creation attempt of location entity for c initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Creation of location entity for c initiated by user:default/mock failed`,
        auditLogErrorMeta,
      );
    });

    it('supports dry run', async () => {
      const spec: LocationInput = {
        type: 'b',
        target: 'c',
      };

      locationService.createLocation.mockResolvedValue({
        location: { id: 'a', ...spec },
        entities: [],
      });

      const response = await request(app)
        .post('/locations?dryRun=true')

        .send(spec);

      expect(locationService.createLocation).toHaveBeenCalledTimes(1);
      expect(locationService.createLocation).toHaveBeenCalledWith(spec, true, {
        credentials: mockCredentials.user(),
      });
      expect(response.status).toEqual(201);
      expect(response.body).toEqual(
        expect.objectContaining({
          location: { id: 'a', ...spec },
        }),
      );
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationCreation',
        request: {
          ...commonAuditLogMeta.request,
          method: 'POST',
          url: `/locations?dryRun=true`,
          query: { dryRun: 'true' },
          body: spec,
        },
        meta: {
          isDryRun: true,
          location: { ...spec },
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 201,
        },
        meta: {
          isDryRun: true,
          location: { id: 'a', ...spec },
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Creation attempt of location entity for c initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Creation of location entity for c initiated by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });

  describe('DELETE /locations', () => {
    it('is not allowed', async () => {
      const response = await request(app).delete('/locations/foo');
      expect(locationService.deleteLocation).not.toHaveBeenCalled();
      expect(response.status).toEqual(403);
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationDeletion',
        request: {
          ...commonAuditLogMeta.request,
          method: 'DELETE',
          url: `/locations/foo`,
          params: {
            id: 'foo',
          },
        },
        meta: {
          id: 'foo',
        },
        stage: 'initiation',
      };
      const auditLogErrorMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        status: 'failed',
        errors: [
          {
            name: 'NotAllowedError',
            message: 'This operation not allowed in readonly mode',
            stack: expect.any(String),
          },
        ],
      };
      expect(loggerSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt of location with id: foo initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerErrorSpy).toHaveBeenNthCalledWith(
        1,
        `Deletion attempt of location with id: foo by user:default/mock failed`,
        auditLogErrorMeta,
      );
    });
  });

  describe('GET /locations/by-entity/:kind/:namespace/:name', () => {
    it('happy path: gets location by entity ref', async () => {
      const location: Location = {
        id: 'foo',
        type: 'url',
        target: 'example.com',
      };
      locationService.getLocationByEntity.mockResolvedValueOnce(location);

      const response = await request(app).get('/locations/by-entity/c/ns/n');
      expect(locationService.getLocationByEntity).toHaveBeenCalledTimes(1);
      expect(locationService.getLocationByEntity).toHaveBeenCalledWith(
        { kind: 'c', namespace: 'ns', name: 'n' },
        {
          credentials: mockCredentials.user(),
        },
      );

      expect(response.status).toEqual(200);
      expect(response.body).toEqual({
        id: 'foo',
        target: 'example.com',
        type: 'url',
      });
      const auditLogInitMeta = {
        ...commonAuditLogMeta,
        eventName: 'CatalogLocationFetchByEntityRef',
        request: {
          ...commonAuditLogMeta.request,
          url: `/locations/by-entity/c/ns/n`,
          params: {
            kind: 'c',
            namespace: 'ns',
            name: 'n',
          },
        },
        meta: {
          locationRef: 'c:ns/n',
        },
        stage: 'initiation',
      };
      const auditLogCompletionMeta = {
        ...auditLogInitMeta,
        stage: 'completion',
        response: {
          status: 200,
          body: location,
        },
      };
      expect(loggerSpy).toHaveBeenCalledTimes(2);
      expect(loggerSpy).toHaveBeenNthCalledWith(
        1,
        `Fetch attempt for location c:ns/n initiated by user:default/mock`,
        auditLogInitMeta,
      );
      expect(loggerSpy).toHaveBeenNthCalledWith(
        2,
        `Fetch attempt for location c:ns/n by user:default/mock succeeded`,
        auditLogCompletionMeta,
      );
    });
  });
});

describe('NextRouter permissioning', () => {
  let entitiesCatalog: jest.Mocked<EntitiesCatalog>;
  let locationService: jest.Mocked<LocationService>;
  let app: express.Express;
  let refreshService: RefreshService;

  const fakeRule = createPermissionRule({
    name: 'FAKE_RULE',
    description: 'fake rule',
    resourceType: RESOURCE_TYPE_CATALOG_ENTITY,
    paramsSchema: z.object({
      foo: z.string(),
    }),
    apply: () => true,
    toQuery: () => ({ key: '', values: [] }),
  });

  beforeAll(async () => {
    entitiesCatalog = {
      entities: jest.fn(),
      entitiesBatch: jest.fn(),
      removeEntityByUid: jest.fn(),
      entityAncestry: jest.fn(),
      facets: jest.fn(),
      queryEntities: jest.fn(),
    };
    locationService = {
      getLocation: jest.fn(),
      createLocation: jest.fn(),
      listLocations: jest.fn(),
      deleteLocation: jest.fn(),
      getLocationByEntity: jest.fn(),
    };
    refreshService = { refresh: jest.fn() };
    const router = await createRouter({
      entitiesCatalog,
      locationService,
      logger: mockServices.logger.mock(),
      refreshService,
      config: new ConfigReader(undefined),
      permissionIntegrationRouter: createPermissionIntegrationRouter({
        resourceType: RESOURCE_TYPE_CATALOG_ENTITY,
        rules: [fakeRule],
        getResources: jest.fn((resourceRefs: string[]) =>
          Promise.resolve(
            resourceRefs.map(resourceRef => ({ id: resourceRef })),
          ),
        ),
      }),
      auth: mockServices.auth(),
      httpAuth: mockServices.httpAuth(),
    });
    app = express().use(router);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('accepts and evaluates conditions at the apply-conditions endpoint', async () => {
    const spideySense: Entity = {
      apiVersion: 'a',
      kind: 'component',
      metadata: {
        name: 'spidey-sense',
      },
    };
    entitiesCatalog.entities.mockResolvedValueOnce({
      entities: [spideySense],
      pageInfo: { hasNextPage: false },
    });

    const requestBody = {
      items: [
        {
          id: '123',
          resourceType: 'catalog-entity',
          resourceRef: 'component:default/spidey-sense',
          conditions: {
            rule: 'FAKE_RULE',
            resourceType: 'catalog-entity',
            params: {
              foo: 'user:default/spiderman',
            },
          },
        },
      ],
    };
    const response = await request(app)
      .post('/.well-known/backstage/permissions/apply-conditions')
      .send(requestBody);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      items: [{ id: '123', result: AuthorizeResult.ALLOW }],
    });
  });
});

function mockCursor(partialCursor?: Partial<Cursor>): Cursor {
  return {
    orderFields: [],
    orderFieldValues: [],
    isPrevious: false,
    ...partialCursor,
  };
}
