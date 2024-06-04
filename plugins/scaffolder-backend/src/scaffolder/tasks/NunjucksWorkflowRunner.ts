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

import { ScmIntegrations } from '@backstage/integration';
import { TaskTrackType, WorkflowResponse, WorkflowRunner } from './types';
import * as winston from 'winston';
import fs from 'fs-extra';
import path from 'path';
import nunjucks from 'nunjucks';
import { JsonArray, JsonObject, JsonValue } from '@backstage/types';
import { InputError, NotAllowedError, stringifyError } from '@backstage/errors';
import { PassThrough } from 'stream';
import { generateExampleOutput, isTruthy } from './helper';
import { validate as validateJsonSchema } from 'jsonschema';
import { TemplateActionRegistry } from '../actions';
import {
  SecureTemplater,
  SecureTemplateRenderer,
} from '../../lib/templating/SecureTemplater';
import {
  TaskRecovery,
  TaskSpec,
  TaskSpecV1beta3,
  TaskStep,
} from '@backstage/plugin-scaffolder-common';

import {
  TemplateAction,
  TemplateFilter,
  TemplateGlobal,
  TaskContext,
} from '@backstage/plugin-scaffolder-node';
import { createConditionAuthorizer } from '@backstage/plugin-permission-node';
import { UserEntity } from '@backstage/catalog-model';
import { createCounterMetric, createHistogramMetric } from '../../util/metrics';
import { createDefaultFilters } from '../../lib/templating/filters';
import {
  AuthorizeResult,
  PolicyDecision,
} from '@backstage/plugin-permission-common';
import { scaffolderActionRules } from '../../service/rules';
import { actionExecutePermission } from '@backstage/plugin-scaffolder-common/alpha';
import { PermissionsService } from '@backstage/backend-plugin-api';
import { loggerToWinstonLogger } from '@backstage/backend-common';
import { BackstageLoggerTransport, WinstonLogger } from './logger';

import { AuditLogger } from '@janus-idp/backstage-plugin-audit-log-node';

type NunjucksWorkflowRunnerOptions = {
  workingDirectory: string;
  actionRegistry: TemplateActionRegistry;
  integrations: ScmIntegrations;
  logger: winston.Logger;
  auditLogger: AuditLogger;
  additionalTemplateFilters?: Record<string, TemplateFilter>;
  additionalTemplateGlobals?: Record<string, TemplateGlobal>;
  permissions?: PermissionsService;
};

type TemplateContext = {
  parameters: JsonObject;
  EXPERIMENTAL_recovery?: TaskRecovery;
  steps: {
    [stepName: string]: { output: { [outputName: string]: JsonValue } };
  };
  secrets?: Record<string, string>;
  user?: {
    entity?: UserEntity;
    ref?: string;
  };
  each?: JsonValue;
};

type CheckpointState =
  | {
      status: 'failed';
      reason: string;
    }
  | {
      status: 'success';
      value: JsonValue;
    };

const isValidTaskSpec = (taskSpec: TaskSpec): taskSpec is TaskSpecV1beta3 => {
  return taskSpec.apiVersion === 'scaffolder.backstage.io/v1beta3';
};

const createStepLogger = ({
  task,
  step,
  rootLogger,
}: {
  task: TaskContext;
  step: TaskStep;
  rootLogger: winston.Logger;
}) => {
  const stepLogStream = new PassThrough();
  stepLogStream.on('data', async data => {
    const message = data.toString().trim();
    if (message?.length > 1) {
      await task.emitLog(message, { stepId: step.id });
    }
  });

  const taskLogger = WinstonLogger.create({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple(),
    ),
    transports: [
      new winston.transports.Stream({ stream: stepLogStream }),
      new BackstageLoggerTransport(rootLogger),
    ],
  });

  taskLogger.addRedactions(Object.values(task.secrets ?? {}));

  // This stream logger should be deprecated. We're going to replace it with
  // just using the logger directly, as all those logs get written to step logs
  // using the stepLogStream above.
  // Initially this stream used to be the only way to write to the client logs, but that
  // has changed over time, there's not really a need for this anymore.
  // You can just create a simple wrapper like the below in your action to write to the main logger.
  // This way we also get redactions for free.
  const streamLogger = new PassThrough();
  streamLogger.on('data', async data => {
    const message = data.toString().trim();
    if (message?.length > 1) {
      taskLogger.info(message);
    }
  });

  return { taskLogger, streamLogger };
};

const isActionAuthorized = createConditionAuthorizer(
  Object.values(scaffolderActionRules),
);

export class NunjucksWorkflowRunner implements WorkflowRunner {
  private readonly defaultTemplateFilters: Record<string, TemplateFilter>;

  constructor(private readonly options: NunjucksWorkflowRunnerOptions) {
    this.defaultTemplateFilters = createDefaultFilters({
      integrations: this.options.integrations,
    });
  }

  private readonly tracker = scaffoldingTracker(this.options.auditLogger);

  private isSingleTemplateString(input: string) {
    const { parser, nodes } = nunjucks as unknown as {
      parser: {
        parse(
          template: string,
          ctx: object,
          options: nunjucks.ConfigureOptions,
        ): { children: { children?: unknown[] }[] };
      };
      nodes: { TemplateData: Function };
    };

    const parsed = parser.parse(
      input,
      {},
      {
        autoescape: false,
        tags: {
          variableStart: '${{',
          variableEnd: '}}',
        },
      },
    );

    return (
      parsed.children.length === 1 &&
      !(parsed.children[0]?.children?.[0] instanceof nodes.TemplateData)
    );
  }

  private render<T>(
    input: T,
    context: TemplateContext,
    renderTemplate: SecureTemplateRenderer,
  ): T {
    return JSON.parse(JSON.stringify(input), (_key, value) => {
      try {
        if (typeof value === 'string') {
          try {
            if (this.isSingleTemplateString(value)) {
              // Lets convert ${{ parameters.bob }} to ${{ (parameters.bob) | dump }} so we can keep the input type
              const wrappedDumped = value.replace(
                /\${{(.+)}}/g,
                '${{ ( $1 ) | dump }}',
              );

              // Run the templating
              const templated = renderTemplate(wrappedDumped, context);

              // If there's an empty string returned, then it's undefined
              if (templated === '') {
                return undefined;
              }

              // Reparse the dumped string
              return JSON.parse(templated);
            }
          } catch (ex) {
            this.options.logger.error(
              `Failed to parse template string: ${value} with error ${ex.message}`,
            );
          }

          // Fallback to default behaviour
          const templated = renderTemplate(value, context);

          if (templated === '') {
            return undefined;
          }

          return templated;
        }
      } catch {
        return value;
      }
      return value;
    });
  }

  async executeStep(
    task: TaskContext,
    step: TaskStep,
    context: TemplateContext,
    renderTemplate: (template: string, values: unknown) => string,
    taskTrack: TaskTrackType,
    workspacePath: string,
    decision: PolicyDecision,
  ) {
    const stepTrack = await this.tracker.stepStart(task, step);

    if (task.cancelSignal.aborted) {
      throw new Error(
        `Step ${step.id} (${step.name}) of task ${task.taskId} has been cancelled.`,
      );
    }

    try {
      const redactedSecrets = Object.fromEntries(
        Object.entries(task.secrets ?? {}).map(secret => [
          secret[0],
          '[REDACTED]',
        ]),
      );
      const stepInputs =
        (step.input &&
          this.render(
            step.input,
            {
              ...context,
              secrets: redactedSecrets,
            },
            renderTemplate,
          )) ??
        {};
      const commonStepAuditMetadata = {
        templateRef: task.spec.templateInfo?.entityRef || '',
        taskId: task.taskId,
        stepId: step.id,
        stepName: step.name,
        stepAction: step.action,
        stepInputs: stepInputs,
        stepConditional: step.if,
        stepEach: step.each,
        isDryRun: task.isDryRun || false,
      };
      if (step.if) {
        const ifResult = this.render(step.if, context, renderTemplate);
        if (!isTruthy(ifResult)) {
          await stepTrack.skipFalsy();
          await this.options.auditLogger.auditLog({
            eventName: 'ScaffolderTaskStepSkip',
            actorId: 'scaffolder-backend',
            stage: 'completion',
            status: 'succeeded',
            metadata: commonStepAuditMetadata,
            message: `Skipped step ${step.name} (id: ${step.id}) of task ${task.taskId}`,
          });
          return;
        }
      }

      const action: TemplateAction<JsonObject> =
        this.options.actionRegistry.get(step.action);
      const { taskLogger, streamLogger } = createStepLogger({
        task,
        step,
        rootLogger: this.options.logger,
      });

      await this.options.auditLogger.auditLog({
        actorId: 'scaffolder-backend',
        eventName: 'ScaffolderTaskStepExecution',
        stage: 'initiation',
        status: 'succeeded',
        metadata: commonStepAuditMetadata,
        message: `Started ${step.name} (id: ${step.id}) of task ${task.taskId} triggering the ${step.action} action`,
      });

      if (task.isDryRun) {
        taskLogger.info(
          `Running ${
            action.id
          } in dry-run mode with inputs (secrets redacted): ${JSON.stringify(
            stepInputs,
            undefined,
            2,
          )}`,
        );
        if (!action.supportsDryRun) {
          await taskTrack.skipDryRun(step, action);
          const outputSchema = action.schema?.output;
          if (outputSchema) {
            context.steps[step.id] = {
              output: generateExampleOutput(outputSchema) as {
                [name in string]: JsonValue;
              },
            };
          } else {
            context.steps[step.id] = { output: {} };
          }
          return;
        }
      }
      const iterations = (
        step.each
          ? Object.entries(this.render(step.each, context, renderTemplate)).map(
              ([key, value]) => ({
                each: { key, value },
              }),
            )
          : [{}]
      ).map(i => ({
        ...i,
        // Secrets are only passed when templating the input to actions for security reasons
        input: step.input
          ? this.render(
              step.input,
              { ...context, secrets: task.secrets ?? {}, ...i },
              renderTemplate,
            )
          : {},
      }));
      for (const iteration of iterations) {
        const actionId = `${action.id}${
          iteration.each ? `[${iteration.each.key}]` : ''
        }`;

        if (action.schema?.input) {
          const validateResult = validateJsonSchema(
            iteration.input,
            action.schema.input,
          );
          if (!validateResult.valid) {
            const errors = validateResult.errors.join(', ');
            throw new InputError(
              `Invalid input passed to action ${actionId}, ${errors}`,
            );
          }
        }
        if (
          !isActionAuthorized(decision, {
            action: action.id,
            input: iteration.input,
          })
        ) {
          throw new NotAllowedError(
            `Unauthorized action: ${actionId}. The action is not allowed. Input: ${JSON.stringify(
              iteration.input,
              null,
              2,
            )}`,
          );
        }
      }
      const tmpDirs = new Array<string>();
      const stepOutput: { [outputName: string]: JsonValue } = {};
      const prevTaskState = await task.getTaskState?.();
      let iterationCount: number = 0;
      for (const iteration of iterations) {
        if (iteration.each) {
          taskLogger.info(
            `Running step each: ${JSON.stringify(
              iteration.each,
              (k, v) => (k ? v.toString() : v),
              0,
            )}`,
          );

          await this.options.auditLogger.auditLog({
            actorId: 'scaffolder-backend',
            eventName: 'ScaffolderTaskStepIteration',
            stage: 'initiation',
            status: 'succeeded',
            metadata: {
              ...commonStepAuditMetadata,
              stepInputs: undefined,
              stepAction: `${step.action}[${iteration.each.key}]`,
              stepIterationInputs: iteration.input,
              stepIterationCount: ++iterationCount,
              stepIterationValue: iteration.each.value,
              totalIterations: iterations.length,
            },
            message: `Iteration ${iterationCount}/${iterations.length} of action ${step.action} of step ${step.name} (id: ${step.id}) of task ${task.taskId} started`,
          });
        }

        await action.handler({
          input: iteration.input,
          secrets: task.secrets ?? {},
          // TODO(blam): move to LoggerService and away from Winston
          logger: loggerToWinstonLogger(taskLogger),
          logStream: streamLogger,
          workspacePath,
          async checkpoint<U extends JsonValue>(
            keySuffix: string,
            fn: () => Promise<U>,
          ) {
            const key = `v1.task.checkpoint.${keySuffix}`;
            try {
              let prevValue: U | undefined;
              if (prevTaskState) {
                const prevState = (
                  prevTaskState.state?.checkpoints as {
                    [key: string]: CheckpointState;
                  }
                )?.[key];
                if (prevState && prevState.status === 'success') {
                  prevValue = prevState.value as U;
                }
              }

              const value = prevValue ? prevValue : await fn();

              if (!prevValue) {
                task.updateCheckpoint?.({
                  key,
                  status: 'success',
                  value,
                });
              }
              return value;
            } catch (err) {
              task.updateCheckpoint?.({
                key,
                status: 'failed',
                reason: stringifyError(err),
              });
              throw err;
            }
          },
          createTemporaryDirectory: async () => {
            const tmpDir = await fs.mkdtemp(
              `${workspacePath}_step-${step.id}-`,
            );
            tmpDirs.push(tmpDir);
            return tmpDir;
          },
          output(name: string, value: JsonValue) {
            if (step.each) {
              stepOutput[name] = stepOutput[name] || [];
              (stepOutput[name] as JsonArray).push(value);
            } else {
              stepOutput[name] = value;
            }
          },
          templateInfo: task.spec.templateInfo,
          user: task.spec.user,
          isDryRun: task.isDryRun,
          signal: task.cancelSignal,
          getInitiatorCredentials: () => task.getInitiatorCredentials(),
        });
        if (iteration.each) {
          await this.options.auditLogger.auditLog({
            actorId: 'scaffolder-backend',
            eventName: 'ScaffolderTaskStepIteration',
            stage: 'completion',
            status: 'succeeded',
            metadata: {
              ...commonStepAuditMetadata,
              stepInputs: undefined,
              stepAction: `${step.action}[${iteration.each.key}]`,
              stepIterationCount: iterationCount,
              stepIterationValue: iteration.each.value,
              stepIterationInputs: iteration.input,
              totalIterations: iterations.length,
            },
            message: `Iteration ${iterationCount}/${iterations.length} of action ${step.action} of step ${step.name} (id: ${step.id}) of task ${task.taskId} succeeded`,
          });
        }
      }

      // Remove all temporary directories that were created when executing the action
      for (const tmpDir of tmpDirs) {
        await fs.remove(tmpDir);
      }

      context.steps[step.id] = { output: stepOutput };

      if (task.cancelSignal.aborted) {
        throw new Error(
          `Step ${step.id} (${step.name}) of task ${task.taskId} has been cancelled.`,
        );
      }

      await stepTrack.markSuccessful();
    } catch (err) {
      await taskTrack.markFailed(step, err);
      await stepTrack.markFailed(err);
      throw err;
    }
  }

  async execute(task: TaskContext): Promise<WorkflowResponse> {
    if (!isValidTaskSpec(task.spec)) {
      throw new InputError(
        'Wrong template version executed with the workflow engine',
      );
    }
    const workspacePath = path.join(
      this.options.workingDirectory,
      await task.getWorkspaceName(),
    );

    const { additionalTemplateFilters, additionalTemplateGlobals } =
      this.options;

    const renderTemplate = await SecureTemplater.loadRenderer({
      templateFilters: {
        ...this.defaultTemplateFilters,
        ...additionalTemplateFilters,
      },
      templateGlobals: additionalTemplateGlobals,
    });

    try {
      const taskTrack = await this.tracker.taskStart(task);
      await fs.ensureDir(workspacePath);

      const context: TemplateContext = {
        parameters: task.spec.parameters,
        steps: {},
        user: task.spec.user,
      };

      const [decision]: PolicyDecision[] =
        this.options.permissions && task.spec.steps.length
          ? await this.options.permissions.authorizeConditional(
              [{ permission: actionExecutePermission }],
              { credentials: await task.getInitiatorCredentials() },
            )
          : [{ result: AuthorizeResult.ALLOW }];

      for (const step of task.spec.steps) {
        await this.executeStep(
          task,
          step,
          context,
          renderTemplate,
          taskTrack,
          workspacePath,
          decision,
        );
      }

      const output = this.render(task.spec.output, context, renderTemplate);
      await taskTrack.markSuccessful();

      return { output };
    } finally {
      if (workspacePath) {
        await fs.remove(workspacePath);
      }
    }
  }
}

function scaffoldingTracker(auditLogger: AuditLogger) {
  const taskCount = createCounterMetric({
    name: 'scaffolder_task_count',
    help: 'Count of task runs',
    labelNames: ['template', 'user', 'result'],
  });
  const taskDuration = createHistogramMetric({
    name: 'scaffolder_task_duration',
    help: 'Duration of a task run',
    labelNames: ['template', 'result'],
  });
  const stepCount = createCounterMetric({
    name: 'scaffolder_step_count',
    help: 'Count of step runs',
    labelNames: ['template', 'step', 'result'],
  });
  const stepDuration = createHistogramMetric({
    name: 'scaffolder_step_duration',
    help: 'Duration of a step runs',
    labelNames: ['template', 'step', 'result'],
  });

  async function taskStart(task: TaskContext) {
    await task.emitLog(`Starting up task with ${task.spec.steps.length} steps`);
    const template = task.spec.templateInfo?.entityRef || '';
    const user = task.spec.user?.ref || '';

    const taskTimer = taskDuration.startTimer({
      template,
    });

    async function skipDryRun(
      step: TaskStep,
      action: TemplateAction<JsonObject>,
    ) {
      task.emitLog(`Skipping because ${action.id} does not support dry-run`, {
        stepId: step.id,
        status: 'skipped',
      });
    }

    async function markSuccessful() {
      taskCount.inc({
        template,
        user,
        result: 'ok',
      });
      taskTimer({ result: 'ok' });
    }

    async function markFailed(step: TaskStep, err: Error) {
      await task.emitLog(String(err.stack), {
        stepId: step.id,
        status: 'failed',
      });
      taskCount.inc({
        template,
        user,
        result: 'failed',
      });
      taskTimer({ result: 'failed' });
    }

    async function markCancelled(step: TaskStep) {
      await task.emitLog(`Step ${step.id} has been cancelled.`, {
        stepId: step.id,
        status: 'cancelled',
      });
      taskCount.inc({
        template,
        user,
        result: 'cancelled',
      });
      taskTimer({ result: 'cancelled' });
    }

    return {
      skipDryRun,
      markCancelled,
      markSuccessful,
      markFailed,
    };
  }

  async function stepStart(task: TaskContext, step: TaskStep) {
    await task.emitLog(`Beginning step ${step.name}`, {
      stepId: step.id,
      status: 'processing',
    });
    const template = task.spec.templateInfo?.entityRef || '';

    const stepTimer = stepDuration.startTimer({
      template,
      step: step.name,
    });

    async function markSuccessful() {
      await task.emitLog(`Finished step ${step.name}`, {
        stepId: step.id,
        status: 'completed',
      });
      stepCount.inc({
        template,
        step: step.name,
        result: 'ok',
      });
      stepTimer({ result: 'ok' });
      await auditLogger.auditLog({
        actorId: 'scaffolder-backend',
        eventName: 'ScaffolderTaskStepExecution',
        stage: 'completion',
        status: 'succeeded',
        metadata: {
          templateRef: template,
          taskId: task.taskId,
          stepId: step.id,
          stepName: step.name,
          stepAction: step.action,
          isDryRun: task.isDryRun || false,
        },
        message: `Step ${step.name} (id: ${step.id}) of task ${task.taskId} succeeded`,
      });
    }

    async function markCancelled() {
      stepCount.inc({
        template,
        step: step.name,
        result: 'cancelled',
      });
      stepTimer({ result: 'cancelled' });
    }

    async function markFailed(err: Error) {
      stepCount.inc({
        template,
        step: step.name,
        result: 'failed',
      });
      stepTimer({ result: 'failed' });
      await auditLogger.auditLog({
        actorId: 'scaffolder-backend',
        eventName: 'ScaffolderTaskStepExecution',
        stage: 'completion',
        status: 'failed',
        level: 'error',
        metadata: {
          templateRef: template,
          taskId: task.taskId,
          stepId: step.id,
          stepName: step.name,
          stepAction: step.action,
          isDryRun: task.isDryRun || false,
        },
        errors: [
          {
            name: err.name,
            message: err.message,
            stack: err.stack,
          },
        ],
        message: `Step ${step.name} (id: ${step.id}) of task ${task.taskId} failed`,
      });
    }

    async function skipFalsy() {
      await task.emitLog(
        `Skipping step ${step.id} because its if condition was false`,
        { stepId: step.id, status: 'skipped' },
      );
      stepTimer({ result: 'skipped' });
    }

    return {
      markCancelled,
      markFailed,
      markSuccessful,
      skipFalsy,
    };
  }

  return {
    taskStart,
    stepStart,
  };
}
