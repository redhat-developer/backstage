# Scaffolder Backend

This is the backend for the default Backstage [software
templates](https://backstage.io/docs/features/software-templates/).
This provides the API for the frontend [scaffolder
plugin](https://github.com/backstage/backstage/tree/master/plugins/scaffolder),
as well as the built-in template actions, tasks and stages.

## Installation

This `@backstage/plugin-scaffolder-backend` package comes installed by default
in any Backstage application created with `npx @backstage/create-app`, so
installation is not usually required.

To check if you already have the package, look under
`packages/backend/package.json`, in the `dependencies` block, for
`@backstage/plugin-scaffolder-backend`. The instructions below walk through
restoring the plugin, if you previously removed it.

### Install the package

```bash
# From your Backstage root directory
yarn --cwd packages/backend add @backstage/plugin-scaffolder-backend
```

### Adding the plugin to your `packages/backend`

You'll need to add the plugin to the router in your `backend` package. You can
do this by creating a file called `packages/backend/src/plugins/scaffolder.ts`
with contents matching [scaffolder.ts in the create-app
template](https://github.com/backstage/backstage/blob/master/packages/create-app/templates/default-app/packages/backend/src/plugins/scaffolder.ts).

With the `scaffolder.ts` router setup in place, add the router to
`packages/backend/src/index.ts`:

```diff
+import scaffolder from './plugins/scaffolder';

async function main() {
  ...
  const createEnv = makeCreateEnv(config);

  const catalogEnv = useHotMemoize(module, () => createEnv('catalog'));
+  const scaffolderEnv = useHotMemoize(module, () => createEnv('scaffolder'));

  const apiRouter = Router();
+  apiRouter.use('/scaffolder', await scaffolder(scaffolderEnv));
  ...
  apiRouter.use(notFoundHandler());

```

### Adding templates

At this point the scaffolder backend is installed in your backend package, but
you will not have any templates available to use. These need to be [added to the
software
catalog](https://backstage.io/docs/features/software-templates/adding-templates).

To get up and running and try out some templates quickly, you can or copy the
catalog locations from the [create-app
template](https://github.com/backstage/backstage/blob/master/packages/create-app/templates/default-app/app-config.yaml.hbs).

### Audit Logging

This package supports audit logging for the endpoints and scaffolder task executions. Audit logs will provide the following information:

- `eventName`: The event associated with the audit log, see the [audited events](#audit-log-events) for the list of events that are audited
- `actor`: An object containing information about the actor who triggered the event being audited. Contains the following fields:
  - `actorId`: The name/id/`entityRef` of the associated backstage user or service. Can be `null` if default auth policy is disabled, and endpoints are accessed with an unauthenticated user.
  - `ip`: The IP address of the actor (optional)
  - `hostname`: The hostname of the actor (optional)
  - `client`: The user agent of the actor (optional)
- `stage`: The stage the event was at when the audit log was generated. In the case of the scaffolder-backend, it is either `initiation` or `completion`
- `status`: Whether the event `succeeded` or `failed`
- `meta`: An optional object containing event specific data. Ex: `taskId` for a task might be a field in this metadata object
- `request`: An optional field that contains information about the HTTP request sent to an endpoint. Contains the following fields:
  - `method`: The HTTP method of the request
  - `query`: The `query` fields of the request
  - `params`: The `params` fields of the request
  - `body`: The request `body`. Note: the `secrets` provided when creating a task are redacted and will appear as `***`
  - `url`: The endpoint url of the request.
- `response`: An optional field that contains information about the HTTP response sent from an endpoint. Contains the following fields:
  - `status`: The status code of the HTTP response
  - `body`: The contents of the request body
- `isAuditLog`: A flag set to `true` to differentiate audit logs from normal logs. Always `true` for audit logs.
- `errors`: A list of errors containing the `name`, `message` and potentially the `stack` field of the error. Only appears when `status` is `failed`.

#### Audit Log Events

The following are the events that are audit logged:

- `ScaffolderParameterSchemaFetch`: Tracks `GET` requests to the `/v2/templates/:namespace/:kind/:name/parameter-schema` endpoint which return template parameter schemas
- `ScaffolderInstalledActionsFetch`: Tracks `GET` requests to the `/v2/actions` endpoint which grabs the list of installed actions
- `ScaffolderTaskCreation`: Tracks `POST` requests to the `/v2/tasks` endpoint which creates tasks that the scaffolder executes
- `ScaffolderTaskListFetch`: Tracks `GET` requests to the `/v2/tasks` endpoint which fetches details of all tasks in the scaffolder.
- `ScaffolderTaskFetch`: Tracks `GET` requests to the `/v2/tasks/:taskId` endpoint which fetches details of a specified task `:taskId`
- `ScaffolderTaskCancellation`: Tracks `POST` requests to the `/v2/tasks/:taskId/cancel` endpoint which cancels a running task
- `ScaffolderTaskStream`: Tracks `GET` requests to the `/v2/tasks/:taskId/eventstream` endpoint which returns an event stream of the task logs of task `:taskId`
- `ScaffolderTaskEventFetch`: Tracks `GET` requests to the `/v2/tasks/:taskId/events` endpoint which returns a snapshot of the task logs of task `:taskId`
- `ScaffolderTaskDryRun`: Tracks `POST` requests to the `/v2/dry-run` endpoint which creates a dry-run task. All audit logs for events associated with dry runs have the `meta.isDryLog` flag set to `true`.
- `ScaffolderStaleTaskCancellation`: Tracks automated cancellation of stale tasks
- `ScaffolderTaskExecution`: Tracks the `initiation` and `completion` of a real scaffolder task execution (will not occur during dry runs)
- `ScaffolderTaskStepExecution`: Tracks `initiation` and `completion` of a scaffolder task step execution
- `ScaffolderTaskStepSkip`: Tracks steps skipped due to `if` conditionals not being met
- `ScaffolderTaskStepIteration`: Tracks the step execution of each iteration of a task step that contains the `each` field.

#### Example Audit Log Output

The following is an example audit log when a user creates a task with the `POST /v2/tasks` endpoint:

Example cURL Request being used:

```bash
curl -X POST localhost:7007/api/scaffolder/v2/tasks \
        -H "Authorization: Bearer ${BACKSTAGE_TOKEN}" \
        -H "Content-Type: application/json" \        --data '{"templateRef":"template:default/test-template", "values": {"username": "user", "password": "******"}, "secrets": { "password": "secret" }}'
```

Example of a prettified version of the Audit Log of the scaffolder task being successfully created:

```json
{
  "actor": {
    "actorId": "user:development/guest",
    "hostname": "localhost",
    "ip": "::1",
    "userAgent": "curl/8.2.1"
  },
  "eventName": "ScaffolderTaskCreation",
  "isAuditLog": true,
  "level": "info",
  "message": "Scaffolding task for template:default/test-template with taskId: b06058bf-4d56-4309-b7ab-3d6ed7fe49a9 successfully created by user:development/guest",
  "meta": {
    "taskId": "b06058bf-4d56-4309-b7ab-3d6ed7fe49a9",
    "templateRef": "template:default/test-template"
  },
  "plugin": "scaffolder",
  "request": {
    "body": {
      "secrets": { "password": "***" },
      "templateRef": "template:default/test-template",
      "values": { "password": "******", "username": "user" }
    },
    "method": "POST",
    "params": {},
    "query": {},
    "url": "/api/scaffolder/v2/tasks"
  },
  "response": {
    "body": { "id": "b06058bf-4d56-4309-b7ab-3d6ed7fe49a9" },
    "status": 201
  },
  "service": "backstage",
  "stage": "completion",
  "status": "succeeded",
  "timestamp": "2024-05-22 15:15:55",
  "type": "plugin"
}
```
