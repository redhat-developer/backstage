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

import { AuthService, HttpAuthService } from '@backstage/backend-plugin-api';
import { Request } from 'express';

export type AuditLogActor = {
  user_id: string;
  client?: string;
  ip_address?: string;
};

export type AuditEventStatus = 'success' | 'failed';
export type AuditLog = {
  // timestamp is expected to be in ISO format
  timestamp: string;
  actor: AuditLogActor;
  event_name: string;
  status: AuditEventStatus;
  metadata: { [key: string]: any };
};
export type AuditAuthServices = {
  auth: AuthService;
  httpAuth: HttpAuthService;
  request: Request;
};
export type AuditLogOptions = {
  eventName: string;
  status: AuditEventStatus;
  metadata: { [key: string]: any };
  actor_id?: string;
  authServices?: AuditAuthServices;
};

// TODO: Move this entire file into a common package
export async function createAuditLog(
  options: AuditLogOptions,
): Promise<AuditLog> {
  let actor_id = 'unknown';
  if (options.authServices) {
    const credentials = await options.authServices.httpAuth.credentials(
      options.authServices.request,
    );

    const userEntityRef = options.authServices.auth.isPrincipal(
      credentials,
      'user',
    )
      ? credentials.principal.userEntityRef
      : undefined;

    const serviceEntityRef = options.authServices.auth.isPrincipal(
      credentials,
      'service',
    )
      ? credentials.principal.subject
      : undefined;

    actor_id = userEntityRef ?? serviceEntityRef ?? 'unknown';
  }
  if (options.actor_id) {
    actor_id = options.actor_id;
  }
  return {
    timestamp: new Date().toISOString(),
    actor: {
      user_id: actor_id,
      client: options.authServices?.request.get('user-agent'),
      ip_address: options.authServices?.request.ip,
    },
    event_name: options.eventName,
    status: options.status,
    metadata: options.metadata,
  };
}
