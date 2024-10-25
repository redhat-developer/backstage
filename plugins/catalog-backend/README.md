# Catalog Backend

This is the backend for the default Backstage [software catalog](http://backstage.io/docs/features/software-catalog/).
This provides an API for consumers such as the frontend [catalog plugin](https://github.com/backstage/backstage/tree/master/plugins/catalog).

It comes with a builtin database-backed implementation of the catalog that can
store and serve your catalog for you.

It can also act as a bridge to your existing catalog solutions, either ingesting
data to store in the database, or by effectively proxying calls to an
external catalog service.

## Installation

This `@backstage/plugin-catalog-backend` package comes installed by default in
any Backstage application created with `npx @backstage/create-app`, so
installation is not usually required.

To check if you already have the package, look under
`packages/backend/package.json`, in the `dependencies` block, for
`@backstage/plugin-catalog-backend`. The instructions below walk through
restoring the plugin, if you previously removed it.

### Install the package

```bash
# From your Backstage root directory
yarn --cwd packages/backend add @backstage/plugin-catalog-backend
```

Then add the plugin to your backend, typically in `packages/backend/src/index.ts`:

```ts
const backend = createBackend();
// ...
backend.add(import('@backstage/plugin-catalog-backend/alpha'));
```

#### Old backend system

In the old backend system there's a bit more wiring required. You'll need to
create a file called `packages/backend/src/plugins/catalog.ts` with contents
matching [catalog.ts in the create-app template](https://github.com/backstage/backstage/blob/ad9314d3a7e0405719ba93badf96e97adde8ef83/packages/create-app/templates/default-app/packages/backend/src/plugins/catalog.ts).

With the `catalog.ts` router setup in place, add the router to
`packages/backend/src/index.ts`:

```diff
+import catalog from './plugins/catalog';

async function main() {
  ...
  const createEnv = makeCreateEnv(config);

+  const catalogEnv = useHotMemoize(module, () => createEnv('catalog'));
  const scaffolderEnv = useHotMemoize(module, () => createEnv('scaffolder'));

  const apiRouter = Router();
+  apiRouter.use('/catalog', await catalog(catalogEnv));
  ...
  apiRouter.use(notFoundHandler());

```

### Adding catalog entities

At this point the `catalog-backend` is installed in your backend package, but
you will not have any catalog entities loaded. See [Catalog Configuration](https://backstage.io/docs/features/software-catalog/configuration)
for how to add locations, or copy the catalog locations from the [create-app template](https://github.com/backstage/backstage/blob/master/packages/create-app/templates/default-app/app-config.yaml.hbs)
to get up and running quickly.

## Development

This backend plugin can be started in a standalone mode from directly in this
package with `yarn start`. However, it will have limited functionality and that
process is most convenient when developing the catalog backend plugin itself.

To evaluate the catalog and have a greater amount of functionality available,
run the entire Backstage example application from the root folder:

```bash
# in one terminal window, run this from from the very root of the Backstage project
cd packages/backend
yarn start
```

This will launch both frontend and backend in the same window, populated with
some example entities.

## Links

- [catalog](https://github.com/backstage/backstage/tree/master/plugins/catalog)
  is the frontend interface for this plugin.

## Audit Logging

This package supports audit logging for the endpoints. Audit logs will provide the following information:

- `eventName`: The event associated with the audit log, see the [audited events](#audit-log-events) for the list of events that are audited
- `actor`: An object containing information about the actor who triggered the event being audited. Contains the following fields:
  - `actorId`: The name/id/`entityRef` of the associated backstage user or service. Can be `null` if default auth policy is disabled, and endpoints are accessed with an unauthenticated user.
  - `ip`: The IP address of the actor (optional)
  - `hostname`: The hostname of the actor (optional)
  - `client`: The user agent of the actor (optional)
- `stage`: The stage the event was at when the audit log was generated. In the case of the `catalog-backend`, it is either `initiation` or `completion`
- `status`: Whether the event `succeeded` or `failed`
- `meta`: An optional object containing event specific data. Ex: `entityRef` for an entity request might be a field in this metadata object
- `request`: An optional field that contains information about the HTTP request sent to an endpoint. Contains the following fields:
  - `method`: The HTTP method of the request
  - `query`: The `query` fields of the request
  - `params`: The `params` fields of the request
  - `body`: The request `body`
  - `url`: The endpoint url of the request.
- `response`: An optional field that contains information about the HTTP response sent from an endpoint. Contains the following fields:
  - `status`: The status code of the HTTP response
  - `body`: The contents of the request body
- `isAuditLog`: A flag set to `true` to differentiate audit logs from normal logs. Always `true` for audit logs.
- `errors`: A list of errors containing the `name`, `message` and potentially the `stack` field of the error. Only appears when `status` is `failed`.

#### Audit Log Events

The following are the events that are audit logged:

- `CatalogEntityAncestryFetch`: Tracks `GET` requests to the `/entities/by-name/:kind/:namespace/:name/ancestry` endpoint which return the ancestry of an entity
- `CatalogEntityBatchFetch`: Tracks `POST` requests to the `/entities/by-refs` endpoint which return a batch of entities
- `CatalogEntityDeletion`: Tracks `DELETE` requests to the `/entities/by-uid/:uid` endpoint which delete an entity. Note: this will not be a permanent deletion and the entity will be restored if the parent location is still present in the catalog
- `CatalogEntityFacetFetch`: Tracks `GET` requests to the `/entity-facets` endpoint which return the facets of an entity
- `CatalogEntityFetch`: Tracks `GET` requests to the `/entities` endpoint which returns a list of entities
- `CatalogEntityFetchByName`: Tracks `GET` requests to the `/entities/by-name/:kind/:namespace/:name` endpoint which return an entity matching the specified entity ref
- `CatalogEntityFetchByUid`: Tracks `GET` requests to the `/entities/by-uid/:uid` endpoint which return an entity matching the specified entity uid
- `CatalogEntityRefresh`: Tracks `POST` requests to the `/entities/refresh` endpoint which schedules the specified entity to be refreshed
- `CatalogEntityValidate`: Tracks `POST` requests to the `/entities/validate` endpoint which validates the specified entity
- `CatalogLocationAnalyze`: Tracks `POST` requests to the `/locations/analyze` endpoint which analyzes the specified location
- `CatalogLocationCreation`: Tracks `POST` requests to the `/locations` endpoint which creates a location
- `CatalogLocationDeletion`: Tracks `DELETE` requests to the `/locations/:id` endpoint which deletes a location as well as all child entities associated with it
- `CatalogLocationFetch`: Tracks `GET` requests to the `/locations` endpoint which returns a list of locations
- `CatalogLocationFetchByEntityRef`: Tracks `GET` requests to the `/locations/by-entity` endpoint which returns a list of locations associated with the specified entity ref
- `CatalogLocationFetchById`: Tracks `GET` requests to the `/locations/:id` endpoint which returns a location matching the specified location id
- `QueriedCatalogEntityFetch`: Tracks `GET` requests to the `/entities/by-query` endpoint which returns a list of entities matching the specified query

#### Example Audit Log Output

The following is an example audit log when a user creates a location with the `POST /locations` endpoint:

Example cURL Request being used:

```bash
curl -X POST localhost:7007/api/catalog/locations \
      -H "Authorization: Bearer ${BACKSTAGE_TOKEN}" \
      -H "Content-Type: application/json" \
      --data '{"type":"url", "target":"https://github.com/backstage/backstage/blob/master/plugins/catalog-backend/catalog-info.yaml"}'
```

Example of a prettified version of the Audit Log of the location being successfully created:

```json
{
  "actor": {
    "actorId": "user:development/guest",
    "hostname": "localhost",
    "ip": "::1",
    "userAgent": "curl/8.2.1"
  },
  "eventName": "CatalogLocationCreation",
  "isAuditLog": true,
  "level": "info",
  "message": "Creation of location entity for https://github.com/backstage/backstage/blob/master/plugins/catalog-backend/catalog-info.yaml initiated by user:development/guest succeeded",
  "meta": {
    "isDryRun": false,
    "location": {
      "id": "4a73775b-c632-4789-8a87-c70006794979",
      "target": "https://github.com/backstage/backstage/blob/master/plugins/catalog-backend/catalog-info.yaml",
      "type": "url"
    }
  },
  "plugin": "catalog",
  "request": {
    "body": {
      "target": "https://github.com/backstage/backstage/blob/master/plugins/catalog-backend/catalog-info.yaml",
      "type": "url"
    },
    "method": "POST",
    "params": {},
    "query": {},
    "url": "/api/catalog/locations"
  },
  "response": {
    "status": 201
  },
  "service": "backstage",
  "span_id": "6ad39b002b2838ec",
  "stage": "completion",
  "status": "succeeded",
  "timestamp": "2024-08-01 10:54:50",
  "trace_flags": "01",
  "trace_id": "010a768196471f78d7ddae817c582c7b"
}
```
