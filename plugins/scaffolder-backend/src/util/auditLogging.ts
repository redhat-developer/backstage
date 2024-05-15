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
import { JsonValue } from '@backstage/types';

import { Request } from 'express';

export type ActorDetails = {
  actorId: string;
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

export type AuditLogStatus =
  | {
      status: 'failed';
      errors: ErrorLike[];
    }
  | { status: 'succeeded' };

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

export type AuditActorOptions =
  | {
      actor_id: string;
      request?: Request;
    }
  | {
      actor_id?: string;
      request: Request;
    };

export type AuditLogDetailsOptions = {
  eventName: string;
  stage: string;
  metadata?: JsonValue;
  response?: AuditResponse;
} & AuditActorOptions &
  ({ status: 'succeeded' } | { status: 'failed'; errors: unknown[] });

export type AuditLogOptions = {
  eventName: string;
  message: string;
  stage: string;
  metadata?: JsonValue;
  response?: AuditResponse;
} & AuditActorOptions;

export type AuditErrorLogOptions = AuditLogOptions & { errors: unknown[] };

export type AuditLoggerOptions = {
  logger: LoggerService;
  authService: AuthService;
  httpAuthService: HttpAuthService;
};

export interface AuditLogger {
  /**
   *
   * Processes an express request and obtains the actorId from it. Returns undefined if actorId is not obtainable.
   */
  getActorId(request?: Request): Promise<string | undefined>;

  /**
   *
   * Generates an AuditLogDetails object containing non-message details of the audit log
   * Secrets in the request body field should be redacted by the user before passing in the request object
   */
  createAuditLogDetails(
    options: AuditLogDetailsOptions,
  ): Promise<AuditLogDetails>;

  /**
   *
   * Generates an Audit Log and logs it at the info level
   */
  auditLog(options: AuditLogOptions): Promise<void>;

  /**
   *
   * Generates an Audit Log for an error and logs it at the error level
   */
  auditErrorLog(options: AuditErrorLogOptions): Promise<void>;
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
  async createAuditLogDetails(options: AuditLogDetailsOptions) {
    const { eventName, stage, metadata, actor_id, request, response, status } =
      options;

    const actorId = actor_id || (await this.getActorId(request));
    if (!actorId) {
      throw new Error('No actor id was provided for audit log');
    }

    // Secrets in the body field should be redacted by the user before passing in the request object
    const auditRequest = request
      ? {
          method: request.method,
          url: request.originalUrl,
          params: request.params,
          query: request.query,
          body: request.body,
        }
      : undefined;

    const auditLogCommonDetails = {
      actor: {
        actorId,
        ip: request?.ip,
        hostname: request?.hostname,
        userAgent: request?.get('user-agent'),
      },
      meta: metadata || {},
      request: auditRequest,
      isAuditLog: true as const,
      response,
      eventName,
      stage,
    };

    if (status === 'failed') {
      const errs = options.errors as ErrorLike[];
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
    if (!options.request && !options.actor_id) {
      throw new Error('No actor id was provided for audit log');
    }
    // Typescript is being dumb here and seems to think it's possible for request and actor_id to both be undefined here
    const auditLogDetails = await this.createAuditLogDetails({
      eventName: options.eventName,
      status: 'succeeded',
      stage: options.stage,
      actor_id: options.actor_id!,
      request: options.request,
      response: options.response!,
      metadata: options.metadata,
    });

    this.logger.info(options.message, auditLogDetails);
  }

  async auditErrorLog(options: AuditErrorLogOptions): Promise<void> {
    if (!options.request && !options.actor_id) {
      throw new Error('No actor id was provided for audit log');
    }

    // Typescript is being dumb here and seems to think it's possible for request and actor_id to both be undefined here
    const auditLogDetails = await this.createAuditLogDetails({
      eventName: options.eventName,
      status: 'failed',
      stage: options.stage,
      errors: options.errors,
      actor_id: options.actor_id!,
      request: options.request,
      response: options.response!,
      metadata: options.metadata,
    });

    this.logger.error(options.message, auditLogDetails);
  }
}
