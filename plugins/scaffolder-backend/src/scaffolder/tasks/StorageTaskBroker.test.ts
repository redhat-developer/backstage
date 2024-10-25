/*
 * Copyright 2021 The Backstage Authors
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
  DatabaseManager,
  loggerToWinstonLogger,
} from '@backstage/backend-common';
import { ConfigReader } from '@backstage/config';
import { TaskSpec } from '@backstage/plugin-scaffolder-common';
import {
  TaskSecrets,
  SerializedTaskEvent,
} from '@backstage/plugin-scaffolder-node';
import { DatabaseTaskStore } from './DatabaseTaskStore';
import { StorageTaskBroker, TaskManager } from './StorageTaskBroker';
import { mockCredentials, mockServices } from '@backstage/backend-test-utils';
import { DefaultAuditLogger } from '@janus-idp/backstage-plugin-audit-log-node';

async function createStore(): Promise<DatabaseTaskStore> {
  const manager = DatabaseManager.fromConfig(
    new ConfigReader({
      backend: {
        database: {
          client: 'better-sqlite3',
          connection: ':memory:',
        },
      },
    }),
  ).forPlugin('scaffolder');

  return await DatabaseTaskStore.create({
    database: manager,
  });
}

const commonAuditLogMeta = {
  actor: {
    actorId: 'scaffolder-backend',
  },
  isAuditLog: true,
  status: 'succeeded',
};

const commonAuditErrorMeta = {
  ...commonAuditLogMeta,
  status: 'failed',
  stage: 'completion',
  errors: [],
};

describe('StorageTaskBroker', () => {
  let storage: DatabaseTaskStore;
  const fakeSecrets = { backstageToken: 'secret' } as TaskSecrets;
  const logger = loggerToWinstonLogger(mockServices.logger.mock());

  const auditLogger = new DefaultAuditLogger({
    logger,
    authService: mockServices.auth({
      pluginId: 'scaffolder',
      disableDefaultAuthPolicy: false,
    }),
    httpAuthService: mockServices.httpAuth({
      pluginId: 'scaffolder',
      defaultCredentials: mockCredentials.user(),
    }),
  });

  let loggerSpy: jest.SpyInstance;
  let loggerErrorSpy: jest.SpyInstance;

  beforeAll(async () => {
    storage = await createStore();
  });

  beforeEach(async () => {
    loggerSpy = jest.spyOn(logger, 'info');
    loggerErrorSpy = jest.spyOn(logger, 'error');
  });
  afterEach(() => {
    jest.resetAllMocks();
    jest.restoreAllMocks();
  });
  const emptyTaskSpec = { spec: { steps: [] } as unknown as TaskSpec };
  const loginTaskSpec = {
    apiVersion: 'scaffolder.backstage.io/v1beta3',
    parameters: { test: 'test', backstageToken: '****' },
    output: { result: 'welcome' },
    steps: [{ id: 'login', name: 'login attempt', action: 'login-action' }],
  } as TaskSpec;

  const loginTask = {
    spec: loginTaskSpec,
    secrets: fakeSecrets,
  };
  const emptyTaskWithFakeSecretsSpec = {
    spec: { steps: [] } as unknown as TaskSpec,
    secrets: fakeSecrets,
  };

  it('should claim a dispatched work item', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    await broker.dispatch(emptyTaskSpec);
    await expect(broker.claim()).resolves.toEqual(
      expect.any(TaskManager as any),
    );
  });

  it('should wait for a dispatched work item', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const promise = broker.claim();

    await expect(Promise.race([promise, 'waiting'])).resolves.toBe('waiting');

    await broker.dispatch(emptyTaskSpec);
    await expect(promise).resolves.toEqual(expect.any(TaskManager as any));
  });

  it('should dispatch multiple items and claim them in order', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    await broker.dispatch({ spec: { steps: [{ id: 'a' }] } as TaskSpec });
    await broker.dispatch({ spec: { steps: [{ id: 'b' }] } as TaskSpec });
    await broker.dispatch({ spec: { steps: [{ id: 'c' }] } as TaskSpec });

    const taskA = await broker.claim();
    const taskB = await broker.claim();
    const taskC = await broker.claim();
    expect(taskA).toEqual(expect.any(TaskManager as any));
    expect(taskB).toEqual(expect.any(TaskManager as any));
    expect(taskC).toEqual(expect.any(TaskManager as any));
    expect(taskA.spec.steps[0].id).toBe('a');
    expect(taskB.spec.steps[0].id).toBe('b');
    expect(taskC.spec.steps[0].id).toBe('c');
  });

  it('should store secrets', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    await broker.dispatch(emptyTaskWithFakeSecretsSpec);
    const task = await broker.claim();
    expect(task.secrets).toEqual(fakeSecrets);
  }, 10000);

  it('should complete a task', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const dispatchResult = await broker.dispatch(emptyTaskSpec);
    const task = await broker.claim();
    await task.complete('completed');
    const taskRow = await storage.getTask(dispatchResult.taskId);

    const auditLogEntry = {
      ...commonAuditLogMeta,
      eventName: 'ScaffolderTaskExecution',
      stage: 'completion',
      meta: {
        taskId: dispatchResult.taskId,
        taskParameters: task.spec.parameters,
      },
    };
    expect(taskRow.status).toBe('completed');
    expect(loggerSpy).toHaveBeenCalledTimes(1);
    expect(loggerSpy).toHaveBeenNthCalledWith(
      1,
      `Scaffolding task with taskId: ${dispatchResult.taskId} completed successfully`,
      { ...auditLogEntry, isAuditLog: true },
    );
  }, 10000);

  it('should remove secrets after picking up a task', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const dispatchResult = await broker.dispatch(emptyTaskWithFakeSecretsSpec);
    await broker.claim();

    const taskRow = await storage.getTask(dispatchResult.taskId);
    expect(taskRow.secrets).toBeUndefined();
  }, 10000);

  it('should fail a task', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const dispatchResult = await broker.dispatch(emptyTaskSpec);
    const task = await broker.claim();
    const error = {
      name: 'TaskError',
      message: 'The task failed',
    };
    await task.complete('failed', {
      error: error,
    });
    const taskRow = await storage.getTask(dispatchResult.taskId);
    expect(taskRow.status).toBe('failed');

    const auditLogEntry = {
      ...commonAuditErrorMeta,
      eventName: 'ScaffolderTaskExecution',
      stage: 'completion',
      meta: {
        taskId: dispatchResult.taskId,
        taskParameters: task.spec.parameters,
      },
      errors: [error],
    };
    expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
    expect(loggerErrorSpy).toHaveBeenNthCalledWith(
      1,
      `Scaffolding task with taskId: ${dispatchResult.taskId} failed`,
      { ...auditLogEntry, isAuditLog: true },
    );
  });

  it('should audit log details of the task after completing a task successfully', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const dispatchResult = await broker.dispatch(loginTask);
    const task = await broker.claim();
    await task.complete('completed', { output: loginTask.spec.output });
    const taskRow = await storage.getTask(dispatchResult.taskId);

    const auditLogEntry = {
      ...commonAuditLogMeta,
      eventName: 'ScaffolderTaskExecution',
      stage: 'completion',
      meta: {
        taskId: dispatchResult.taskId,
        taskParameters: { test: 'test', backstageToken: '****' },
        output: { result: 'welcome' },
      },
    };
    expect(taskRow.status).toBe('completed');
    expect(loggerSpy).toHaveBeenCalledTimes(1);
    expect(loggerSpy).toHaveBeenNthCalledWith(
      1,
      `Scaffolding task with taskId: ${dispatchResult.taskId} completed successfully`,
      { ...auditLogEntry, isAuditLog: true },
    );
  }, 10000);

  it('multiple brokers should be able to observe a single task', async () => {
    const broker1 = new StorageTaskBroker(storage, logger, auditLogger);
    const broker2 = new StorageTaskBroker(storage, logger, auditLogger);

    const { taskId } = await broker1.dispatch(emptyTaskSpec);

    const logPromise = new Promise<SerializedTaskEvent[]>(resolve => {
      const observedEvents = new Array<SerializedTaskEvent>();

      const subscription = broker2
        .event$({ taskId, after: undefined })
        .subscribe(({ events }) => {
          observedEvents.push(...events);
          if (events.some(e => e.type === 'completion')) {
            resolve(observedEvents);
            subscription.unsubscribe();
          }
        });
    });
    const task = await broker1.claim();
    await task.emitLog('log 1');
    await task.emitLog('log 2');
    await task.emitLog('log 3');
    await task.complete('completed');

    const logs = await logPromise;
    expect(logs.map(l => l.body.message, logger)).toEqual([
      'log 1',
      'log 2',
      'log 3',
      'Run completed with status: completed',
    ]);
    const auditLogEntry = {
      ...commonAuditLogMeta,
      eventName: 'ScaffolderTaskExecution',
      stage: 'completion',
      meta: {
        taskId: taskId,
      },
    };
    expect(loggerSpy).toHaveBeenCalledTimes(1);
    expect(loggerSpy).toHaveBeenNthCalledWith(
      1,
      `Scaffolding task with taskId: ${taskId} completed successfully`,
      { ...auditLogEntry, isAuditLog: true },
    );

    const afterLogs = await new Promise<string[]>(resolve => {
      const subscription = broker2
        .event$({ taskId, after: logs[1].id })
        .subscribe(({ events }) => {
          resolve(events.map(e => e.body.message as string));
          subscription.unsubscribe();
        });
    });
    expect(afterLogs).toEqual([
      'log 3',
      'Run completed with status: completed',
    ]);
  });

  it('should heartbeat', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const { taskId } = await broker.dispatch(emptyTaskSpec);
    const task = await broker.claim();

    const initialTask = await storage.getTask(taskId);

    for (;;) {
      const maybeTask = await storage.getTask(taskId);
      if (maybeTask.lastHeartbeatAt !== initialTask.lastHeartbeatAt) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    await task.complete('completed');
    expect.assertions(0);
  });

  it('should be update the status to failed if heartbeat fails', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const { taskId } = await broker.dispatch(emptyTaskSpec);
    const task = await broker.claim();

    jest
      .spyOn((task as any).storage, 'heartbeatTask')
      .mockRejectedValue(new Error('nah m8'));

    const intervalId = setInterval(() => {
      broker.vacuumTasks({ timeoutS: 2 });
    }, 500);

    for (;;) {
      const maybeTask = await storage.getTask(taskId);
      if (maybeTask.status === 'failed') {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    clearInterval(intervalId);

    expect(task.done).toBe(true);
    const auditLogInitMeta = {
      ...commonAuditLogMeta,
      eventName: 'ScaffolderStaleTaskCancellation',
      stage: 'initiation',
      meta: {
        taskId: taskId,
      },
    };
    expect(loggerSpy).toHaveBeenCalledWith(
      `Attempting to cancel Stale scaffolding task ${task.taskId} because the task worker lost connection to the task broker`,
      auditLogInitMeta,
    );
    const auditLogCompletionMeta = {
      ...commonAuditLogMeta,
      eventName: 'ScaffolderStaleTaskCancellation',
      stage: 'completion',
      meta: {
        taskId: taskId,
      },
    };
    expect(loggerSpy).toHaveBeenCalledWith(
      `Stale scaffolding task ${task.taskId} successfully cancelled`,
      auditLogCompletionMeta,
    );
  });

  it('should list all tasks', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const { taskId } = await broker.dispatch(emptyTaskSpec);

    const promise = broker.list();
    await expect(promise).resolves.toEqual({
      tasks: expect.arrayContaining([
        expect.objectContaining({
          id: taskId,
        }),
      ]),
    });
  });

  it('should list only tasks createdBy a specific user', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);
    const { taskId } = await broker.dispatch({
      spec: { steps: [] } as unknown as TaskSpec,
      createdBy: 'user:default/foo',
    });

    const task = await storage.getTask(taskId);

    const promise = broker.list({ createdBy: 'user:default/foo' });
    await expect(promise).resolves.toEqual({ tasks: [task] });
  });

  it('should handle checkpoints in task state', async () => {
    const broker = new StorageTaskBroker(storage, logger, auditLogger);

    await broker.dispatch({
      spec: { steps: [] } as unknown as TaskSpec,
      createdBy: 'user:default/foo',
    });

    const taskA = await broker.claim();
    await taskA.updateCheckpoint?.({
      key: 'repo.create',
      status: 'success',
      value: 'https://github.com/backstage/backstage.git',
    });

    expect(await taskA.getTaskState?.()).toEqual({
      state: {
        checkpoints: {
          'repo.create': {
            status: 'success',
            value: 'https://github.com/backstage/backstage.git',
          },
        },
      },
    });
  });
});
