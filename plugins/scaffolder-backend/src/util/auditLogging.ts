/*
 * Copyright 2024 The Backstage Authors
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

import {
  AuthService,
  HttpAuthService,
  LoggerService,
} from '@backstage/backend-plugin-api';
import { ErrorLike } from '@backstage/errors';
import { JsonObject, JsonValue } from '@backstage/types';
import { cloneDeep } from 'lodash';
import { Request } from 'express';

export type ActorDetails = {
  actorId: string | null;
  ip?: string;
  hostname?: string;
  userAgent?: string;
};

export type AuditRequest = {
  body: any;
  url: string;
  method: string;
  params?: any;
  query?: any;
};

export type AuditResponse = {
  status: number;
  body?: any;
};
export type AuditLogSuccessStatus = { status: 'succeeded' };
export type AuditLogFailureStatus = {
  status: 'failed';
  errors: ErrorLike[];
};
export type AuditLogUnknownFailureStatus = {
  status: 'failed';
  errors: unknown[];
};

export type AuditLogStatus = AuditLogSuccessStatus | AuditLogFailureStatus;

/**
 * Common fields of an audit log. Note: timestamp and pluginId are automatically added at log creation.
 *
 * @public
 */
export type AuditLogDetails = {
  actor: ActorDetails;
  eventName: string;
  stage: string;
  request?: AuditRequest;
  response?: AuditResponse;
  meta: JsonValue;
  isAuditLog: true;
} & AuditLogStatus;

export type AuditLogDetailsOptions = {
  eventName: string;
  stage: string;
  metadata?: JsonValue;
  response?: AuditResponse;
  actorId?: string;
  request?: Request;
} & (AuditLogSuccessStatus | AuditLogUnknownFailureStatus);

export type AuditLogOptions = {
  eventName: string;
  message: string;
  stage: string;
  level?: 'info' | 'debug' | 'warn' | 'error';
  actorId?: string;
  metadata?: JsonValue;
  response?: AuditResponse;
  request?: Request;
} & (AuditLogSuccessStatus | AuditLogUnknownFailureStatus);

export type AuditLoggerOptions = {
  logger: LoggerService;
  authService: AuthService;
  httpAuthService: HttpAuthService;
};

export interface AuditLogger {
  /**
   * Processes an express request and obtains the actorId from it. Returns undefined if actorId is not obtainable.
   *
   * @public
   */
  getActorId(request?: Request): Promise<string | undefined>;

  /**
   * Generates the audit log details to place in the metadata argument of the logger
   *
   * Secrets in the metadata field and request body, params and query field should be redacted by the user before passing in the request object
   * @public
   */
  createAuditLogDetails(
    options: AuditLogDetailsOptions,
  ): Promise<AuditLogDetails>;

  /**
   * Generates an Audit Log and logs it at the level passed by the user.
   * Supports `info`, `debug`, `warn` or `error` level. Defaults to `info` if no level is passed.
   *
   * Secrets in the metadata field and request body, params and query field should be redacted by the user before passing in the request object
   * @public
   */
  auditLog(options: AuditLogOptions): Promise<void>;
}

export class DefaultAuditLogger implements AuditLogger {
  private readonly logger: LoggerService;
  private readonly authService: AuthService;
  private readonly httpAuthService: HttpAuthService;

  constructor(options: AuditLoggerOptions) {
    this.logger = options.logger;
    this.authService = options.authService;
    this.httpAuthService = options.httpAuthService;
  }

  async getActorId(request?: Request): Promise<string | undefined> {
    if (!(request && this.httpAuthService && this.authService)) {
      return undefined;
    }
    try {
      const credentials = await this.httpAuthService.credentials(request);
      const userEntityRef = this.authService.isPrincipal(credentials, 'user')
        ? credentials.principal.userEntityRef
        : undefined;

      const serviceEntityRef = this.authService.isPrincipal(
        credentials,
        'service',
      )
        ? credentials.principal.subject
        : undefined;

      return userEntityRef ?? serviceEntityRef;
    } catch {
      return undefined;
    }
  }
  async createAuditLogDetails(
    options: AuditLogDetailsOptions,
  ): Promise<AuditLogDetails> {
    const { eventName, stage, metadata, request, response, status } = options;

    const actorId = options.actorId || (await this.getActorId(request)) || null;

    // Secrets in the body field should be redacted by the user before passing in the request object
    const auditRequest = request
      ? {
          method: request.method,
          url: request.originalUrl,
          params: cloneDeep(request.params),
          query: cloneDeep(request.query),
          body: cloneDeep(request.body),
        }
      : undefined;

    const actor: ActorDetails = { actorId };
    if (request) {
      actor.ip = request.ip;
      actor.hostname = request.hostname;
      actor.userAgent = request.get('user-agent');
    }

    const auditLogCommonDetails = {
      actor: cloneDeep(actor),
      meta: cloneDeep(metadata) || {},
      request: auditRequest,
      isAuditLog: true as const,
      response: cloneDeep(response),
      eventName,
      stage,
    };

    if (status === 'failed') {
      const errs = cloneDeep(options.errors) as ErrorLike[];
      return {
        ...auditLogCommonDetails,
        status,
        errors: errs.map(err => {
          return {
            name: err.name,
            message: err.message,
            stack: err.stack,
          };
        }),
      };
    }

    return {
      ...auditLogCommonDetails,
      status,
    };
  }
  async auditLog(options: AuditLogOptions): Promise<void> {
    let auditLogDetails: AuditLogDetails;
    const logLevel = options.level || 'info';
    const auditLogCommonDetails = {
      eventName: options.eventName,
      stage: options.stage,
      actorId: options.actorId,
      request: options.request,
      response: options.response,
      metadata: options.metadata,
    };
    if (options.status === 'failed') {
      auditLogDetails = await this.createAuditLogDetails({
        ...auditLogCommonDetails,
        status: options.status,
        errors: options.errors,
      });
    } else {
      auditLogDetails = await this.createAuditLogDetails({
        ...auditLogCommonDetails,
        status: options.status,
      });
    }

    switch (logLevel) {
      case 'info':
        this.logger.info(options.message, auditLogDetails as JsonObject);
        return;
      case 'debug':
        this.logger.debug(options.message, auditLogDetails as JsonObject);
        return;
      case 'warn':
        this.logger.warn(options.message, auditLogDetails as JsonObject);
        return;
      case 'error':
        this.logger.error(options.message, auditLogDetails as JsonObject);
        return;
      default:
        throw new Error(`Log level of ${logLevel} is not supported`);
    }
  }
}
