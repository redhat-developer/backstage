# @backstage/backend-app-api

## 0.7.2

### Patch Changes

- b6b59c5: Redact `meta` fields too with the logger

## 0.7.1

### Patch Changes

- 3554ebe: Move the JWKS registration outside of the lifecycle middleware

## 0.7.0

### Minor Changes

- 3256f14: **BREAKING**: Modules are no longer loaded unless the plugin that they extend is present.

### Patch Changes

- 10327fb: Deprecate the `getPath` option for the `httpRouterServiceFactory` and more generally the ability to configure plugin API paths to be anything else than `/api/:pluginId/`. Requests towards `/api/*` that do not match an installed plugin will also no longer be handled by the index router, typically instead returning a 404.
- 2c50516: Fix auth cookie issuance for split backend deployments by preferring to set it against the request target host instead of origin
- 7e584d6: Fixed a bug where expired cookies would not be refreshed.
- 1a20b12: Make the auth service create and validate dedicated OBO tokens, containing the user identity proof.
- 00fca28: Implemented support for external access using both the legacy token form and static tokens.
- d5a1fe1: Replaced winston logger with `LoggerService`
- bce0879: Service-to-service authentication has been improved.

  Each plugin now has the capability to generate its own signing keys for token issuance. The generated public keys are stored in a database, and they are made accessible through a newly created endpoint: `/.backstage/auth/v1/jwks.json`.

  `AuthService` can now issue tokens with a reduced scope using the `getPluginRequestToken` method. This improvement enables plugins to identify the plugin originating the request.

- 54f2ac8: Added `initialization` option to `createServiceFactory` which defines the initialization strategy for the service. The default strategy mimics the current behavior where plugin scoped services are initialized lazily by default and root scoped services are initialized eagerly.
- 56f81b5: Improved error message thrown by `AuthService` when requesting a token for plugins that don't support the new authentication tokens.
- 25ea3d2: Minor internal restructuring
- d62bc51: Add support for limited user tokens by using user identity proof provided by the auth backend.
- c884b9a: Automatically creates a get and delete cookie endpoint when a `user-cookie` policy is added.
- Updated dependencies
  - @backstage/backend-common@0.21.7
  - @backstage/config-loader@1.8.0
  - @backstage/plugin-permission-node@0.7.28
  - @backstage/backend-plugin-api@0.6.17
  - @backstage/backend-tasks@0.5.22
  - @backstage/plugin-auth-node@0.4.12
  - @backstage/cli-node@0.2.5
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.2.0
  - @backstage/errors@1.2.4
  - @backstage/types@1.1.1

## 0.7.0-next.1

### Minor Changes

- 3256f14: **BREAKING**: Modules are no longer loaded unless the plugin that they extend is present.

### Patch Changes

- 10327fb: Deprecate the `getPath` option for the `httpRouterServiceFactory` and more generally the ability to configure plugin API paths to be anything else than `/api/:pluginId/`. Requests towards `/api/*` that do not match an installed plugin will also no longer be handled by the index router, typically instead returning a 404.
- 1a20b12: Make the auth service create and validate dedicated OBO tokens, containing the user identity proof.
- bce0879: Service-to-service authentication has been improved.

  Each plugin now has the capability to generate its own signing keys for token issuance. The generated public keys are stored in a database, and they are made accessible through a newly created endpoint: `/.backstage/auth/v1/jwks.json`.

  `AuthService` can now issue tokens with a reduced scope using the `getPluginRequestToken` method. This improvement enables plugins to identify the plugin originating the request.

- 54f2ac8: Added `initialization` option to `createServiceFactory` which defines the initialization strategy for the service. The default strategy mimics the current behavior where plugin scoped services are initialized lazily by default and root scoped services are initialized eagerly.
- d62bc51: Add support for limited user tokens by using user identity proof provided by the auth backend.
- c884b9a: Automatically creates a get and delete cookie endpoint when a `user-cookie` policy is added.
- Updated dependencies
  - @backstage/backend-common@0.21.7-next.1
  - @backstage/backend-plugin-api@0.6.17-next.1
  - @backstage/plugin-auth-node@0.4.12-next.1
  - @backstage/backend-tasks@0.5.22-next.1
  - @backstage/plugin-permission-node@0.7.28-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4
  - @backstage/config@1.2.0
  - @backstage/config-loader@1.8.0-next.0
  - @backstage/errors@1.2.4
  - @backstage/types@1.1.1

## 0.6.3-next.0

### Patch Changes

- 7e584d6: Fixed a bug where expired cookies would not be refreshed.
- Updated dependencies
  - @backstage/backend-common@0.21.7-next.0
  - @backstage/config-loader@1.8.0-next.0
  - @backstage/backend-plugin-api@0.6.17-next.0
  - @backstage/backend-tasks@0.5.22-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4
  - @backstage/config@1.2.0
  - @backstage/errors@1.2.4
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.12-next.0
  - @backstage/plugin-permission-node@0.7.28-next.0

## 0.6.2

### Patch Changes

- e848644: Temporarily revert the rate limiting
- Updated dependencies
  - @backstage/plugin-auth-node@0.4.11
  - @backstage/backend-common@0.21.6
  - @backstage/backend-plugin-api@0.6.16
  - @backstage/plugin-permission-node@0.7.27
  - @backstage/backend-tasks@0.5.21
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4
  - @backstage/config@1.2.0
  - @backstage/config-loader@1.7.0
  - @backstage/errors@1.2.4
  - @backstage/types@1.1.1

## 0.6.1

### Patch Changes

- de1f45d: Temporarily revert the rate limiting
- Updated dependencies
  - @backstage/backend-common@0.21.5
  - @backstage/plugin-auth-node@0.4.10
  - @backstage/backend-tasks@0.5.20
  - @backstage/plugin-permission-node@0.7.26
  - @backstage/backend-plugin-api@0.6.15
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4
  - @backstage/config@1.2.0
  - @backstage/config-loader@1.7.0
  - @backstage/errors@1.2.4
  - @backstage/types@1.1.1

## 0.6.0

### Minor Changes

- 4a3d434: **BREAKING**: For users that have migrated to the new backend system, incoming requests will now be rejected if they are not properly authenticated (e.g. with a Backstage bearer token or a backend token). Please see the [Auth Service Migration tutorial](https://backstage.io/docs/tutorials/auth-service-migration) for more information on how to circumvent this behavior in the short term and how to properly leverage it in the longer term.

  Added service factories for the new [`auth`](https://backstage.io/docs/backend-system/core-services/auth/), [`httpAuth`](https://backstage.io/docs/backend-system/core-services/http-auth), and [`userInfo`](https://backstage.io/docs/backend-system/core-services/user-info) services that were created as part of [BEP-0003](https://github.com/backstage/backstage/tree/master/beps/0003-auth-architecture-evolution).

### Patch Changes

- 999224f: Bump dependency `minimatch` to v9
- 81e0120: Fixed an issue where configuration schema for the purpose of redacting secrets from logs was not being read correctly.
- 15fda44: Provide some sane defaults for `WinstonLogger.create` making some of the arguments optional
- 0502d82: Updated the `permissionsServiceFactory` to forward the `AuthService` to the implementation.
- 9d91128: Add the possibility to disable watching files in the new backend system
- a5d341e: Adds an initial rate-limiting implementation so that any incoming requests that have a `'none'` principal are rate-limited automatically.
- 9802004: Made the `DefaultUserInfoService` claims check stricter
- f235ca7: Make sure to not filter out schemas in `createConfigSecretEnumerator`
- af5f7a6: The experimental feature discovery service exported at the `/alpha` sub-path will no longer attempt to load packages that are not Backstage backend packages.
- Updated dependencies
  - @backstage/backend-common@0.21.4
  - @backstage/plugin-auth-node@0.4.9
  - @backstage/config@1.2.0
  - @backstage/errors@1.2.4
  - @backstage/backend-plugin-api@0.6.14
  - @backstage/config-loader@1.7.0
  - @backstage/backend-tasks@0.5.19
  - @backstage/plugin-permission-node@0.7.25
  - @backstage/cli-node@0.2.4
  - @backstage/cli-common@0.1.13
  - @backstage/types@1.1.1

## 0.6.0-next.2

### Patch Changes

- 15fda44: Provide some sane defaults for `WinstonLogger.create` making some of the arguments optional
- 9d91128: Add the possibility to disable watching files in the new backend system
- Updated dependencies
  - @backstage/backend-common@0.21.4-next.2
  - @backstage/plugin-auth-node@0.4.9-next.2
  - @backstage/backend-plugin-api@0.6.14-next.2
  - @backstage/backend-tasks@0.5.19-next.2
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4-next.0
  - @backstage/config@1.2.0-next.1
  - @backstage/config-loader@1.7.0-next.1
  - @backstage/errors@1.2.4-next.0
  - @backstage/types@1.1.1
  - @backstage/plugin-permission-node@0.7.25-next.2

## 0.6.0-next.1

### Patch Changes

- 81e0120: Fixed an issue where configuration schema for the purpose of redacting secrets from logs was not being read correctly.
- f235ca7: Make sure to not filter out schemas in `createConfigSecretEnumerator`
- Updated dependencies
  - @backstage/config@1.2.0-next.1
  - @backstage/config-loader@1.7.0-next.1
  - @backstage/backend-common@0.21.4-next.1
  - @backstage/backend-plugin-api@0.6.14-next.1
  - @backstage/backend-tasks@0.5.19-next.1
  - @backstage/plugin-auth-node@0.4.9-next.1
  - @backstage/plugin-permission-node@0.7.25-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.4-next.0
  - @backstage/errors@1.2.4-next.0
  - @backstage/types@1.1.1

## 0.6.0-next.0

### Minor Changes

- 4a3d434: **BREAKING**: For users that have migrated to the new backend system, incoming requests will now be rejected if they are not properly authenticated (e.g. with a Backstage bearer token or a backend token). Please see the [Auth Service Migration tutorial](https://backstage.io/docs/tutorials/auth-service-migration) for more information on how to circumvent this behavior in the short term and how to properly leverage it in the longer term.

  Added service factories for the new [`auth`](https://backstage.io/docs/backend-system/core-services/auth/), [`httpAuth`](https://backstage.io/docs/backend-system/core-services/http-auth), and [`userInfo`](https://backstage.io/docs/backend-system/core-services/user-info) services that were created as part of [BEP-0003](https://github.com/backstage/backstage/tree/master/beps/0003-auth-architecture-evolution).

### Patch Changes

- 999224f: Bump dependency `minimatch` to v9
- 0502d82: Updated the `permissionsServiceFactory` to forward the `AuthService` to the implementation.
- 9802004: Made the `DefaultUserInfoService` claims check stricter
- Updated dependencies
  - @backstage/backend-common@0.21.3-next.0
  - @backstage/plugin-auth-node@0.4.8-next.0
  - @backstage/errors@1.2.4-next.0
  - @backstage/backend-plugin-api@0.6.13-next.0
  - @backstage/backend-tasks@0.5.18-next.0
  - @backstage/plugin-permission-node@0.7.24-next.0
  - @backstage/cli-node@0.2.4-next.0
  - @backstage/config-loader@1.6.3-next.0
  - @backstage/config@1.1.2-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/types@1.1.1

## 0.5.11

### Patch Changes

- e0c18ef: Include the extension point ID and the module ID in the backend init error message.
- 7ae5704: Updated the default error handling middleware to filter out certain known error types that should never be returned in responses. The errors are instead logged along with a correlation ID, which is also returned in the response. Initially only PostgreSQL protocol errors from the `pg-protocol` package are filtered out.
- 9aac2b0: Use `--cwd` as the first `yarn` argument
- 54ad8e1: Allow the `createConfigSecretEnumerator` to take an optional `schema` argument with an already-loaded global configuration schema.
- 6bb6f3e: Updated dependency `fs-extra` to `^11.2.0`.
  Updated dependency `@types/fs-extra` to `^11.0.0`.
- Updated dependencies
  - @backstage/backend-common@0.21.0
  - @backstage/plugin-auth-node@0.4.4
  - @backstage/cli-node@0.2.3
  - @backstage/backend-plugin-api@0.6.10
  - @backstage/backend-tasks@0.5.15
  - @backstage/config-loader@1.6.2
  - @backstage/plugin-permission-node@0.7.21
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.11-next.3

### Patch Changes

- 54ad8e1: Allow the `createConfigSecretEnumerator` to take an optional `schema` argument with an already-loaded global configuration schema.
- Updated dependencies
  - @backstage/backend-common@0.21.0-next.3
  - @backstage/cli-node@0.2.3-next.0
  - @backstage/backend-tasks@0.5.15-next.3
  - @backstage/config-loader@1.6.2-next.0
  - @backstage/plugin-auth-node@0.4.4-next.3
  - @backstage/plugin-permission-node@0.7.21-next.3
  - @backstage/backend-plugin-api@0.6.10-next.3
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.11-next.2

### Patch Changes

- 9aac2b0: Use `--cwd` as the first `yarn` argument
- Updated dependencies
  - @backstage/backend-common@0.21.0-next.2
  - @backstage/backend-plugin-api@0.6.10-next.2
  - @backstage/backend-tasks@0.5.15-next.2
  - @backstage/plugin-auth-node@0.4.4-next.2
  - @backstage/plugin-permission-node@0.7.21-next.2
  - @backstage/config@1.1.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.2
  - @backstage/config-loader@1.6.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.11-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-plugin-api@0.6.10-next.1
  - @backstage/backend-common@0.21.0-next.1
  - @backstage/backend-tasks@0.5.15-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.2
  - @backstage/config@1.1.1
  - @backstage/config-loader@1.6.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.4-next.1
  - @backstage/plugin-permission-node@0.7.21-next.1

## 0.5.11-next.0

### Patch Changes

- e0c18ef: Include the extension point ID and the module ID in the backend init error message.
- Updated dependencies
  - @backstage/backend-common@0.21.0-next.0
  - @backstage/backend-tasks@0.5.15-next.0
  - @backstage/cli-node@0.2.2
  - @backstage/config-loader@1.6.1
  - @backstage/plugin-auth-node@0.4.4-next.0
  - @backstage/plugin-permission-node@0.7.21-next.0
  - @backstage/backend-plugin-api@0.6.10-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.10

### Patch Changes

- 516fd3e: Updated README to reflect release status
- Updated dependencies
  - @backstage/backend-common@0.20.1
  - @backstage/config-loader@1.6.1
  - @backstage/cli-node@0.2.2
  - @backstage/backend-plugin-api@0.6.9
  - @backstage/plugin-permission-node@0.7.20
  - @backstage/backend-tasks@0.5.14
  - @backstage/plugin-auth-node@0.4.3
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.10-next.2

### Patch Changes

- 516fd3e: Updated README to reflect release status
- Updated dependencies
  - @backstage/backend-plugin-api@0.6.9-next.2
  - @backstage/backend-common@0.20.1-next.2
  - @backstage/plugin-auth-node@0.4.3-next.2
  - @backstage/plugin-permission-node@0.7.20-next.2
  - @backstage/backend-tasks@0.5.14-next.2
  - @backstage/cli-node@0.2.2-next.0
  - @backstage/config-loader@1.6.1-next.0

## 0.5.10-next.1

### Patch Changes

- Updated dependencies
  - @backstage/config-loader@1.6.1-next.0
  - @backstage/cli-node@0.2.2-next.0
  - @backstage/backend-common@0.20.1-next.1
  - @backstage/config@1.1.1
  - @backstage/backend-tasks@0.5.14-next.1
  - @backstage/plugin-auth-node@0.4.3-next.1
  - @backstage/plugin-permission-node@0.7.20-next.1
  - @backstage/backend-plugin-api@0.6.9-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.10-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.20.1-next.0
  - @backstage/backend-plugin-api@0.6.9-next.0
  - @backstage/backend-tasks@0.5.14-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.1
  - @backstage/config@1.1.1
  - @backstage/config-loader@1.6.0
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.3-next.0
  - @backstage/plugin-permission-node@0.7.20-next.0

## 0.5.9

### Patch Changes

- 1da5f43: Ensure redaction of secrets that have accidental extra whitespace around them
- 9f8f266: Add redacting for secrets in stack traces of logs
- Updated dependencies
  - @backstage/backend-common@0.20.0
  - @backstage/config-loader@1.6.0
  - @backstage/backend-tasks@0.5.13
  - @backstage/plugin-auth-node@0.4.2
  - @backstage/plugin-permission-node@0.7.19
  - @backstage/cli-node@0.2.1
  - @backstage/backend-plugin-api@0.6.8
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.9-next.3

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.20.0-next.3
  - @backstage/backend-plugin-api@0.6.8-next.3
  - @backstage/backend-tasks@0.5.13-next.3
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.0
  - @backstage/config@1.1.1
  - @backstage/config-loader@1.6.0-next.0
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.2-next.3
  - @backstage/plugin-permission-node@0.7.19-next.3

## 0.5.9-next.2

### Patch Changes

- Updated dependencies
  - @backstage/config-loader@1.6.0-next.0
  - @backstage/backend-common@0.20.0-next.2
  - @backstage/plugin-auth-node@0.4.2-next.2
  - @backstage/backend-plugin-api@0.6.8-next.2
  - @backstage/backend-tasks@0.5.13-next.2
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.0
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-permission-node@0.7.19-next.2

## 0.5.9-next.1

### Patch Changes

- 1da5f434f3: Ensure redaction of secrets that have accidental extra whitespace around them
- 9f8f266ff4: Add redacting for secrets in stack traces of logs
- Updated dependencies
  - @backstage/backend-common@0.20.0-next.1
  - @backstage/backend-plugin-api@0.6.8-next.1
  - @backstage/backend-tasks@0.5.13-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.0
  - @backstage/config@1.1.1
  - @backstage/config-loader@1.5.3
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.2-next.1
  - @backstage/plugin-permission-node@0.7.19-next.1

## 0.5.9-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.20.0-next.0
  - @backstage/backend-tasks@0.5.13-next.0
  - @backstage/plugin-auth-node@0.4.2-next.0
  - @backstage/plugin-permission-node@0.7.19-next.0
  - @backstage/backend-plugin-api@0.6.8-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.0
  - @backstage/config@1.1.1
  - @backstage/config-loader@1.5.3
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.8

### Patch Changes

- bc9a18d5ec: Added a workaround for double `default` wrapping when dynamically importing CommonJS modules with default exports.
- Updated dependencies
  - @backstage/config-loader@1.5.3
  - @backstage/cli-node@0.2.0
  - @backstage/backend-common@0.19.9
  - @backstage/backend-plugin-api@0.6.7
  - @backstage/backend-tasks@0.5.12
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.1
  - @backstage/plugin-permission-node@0.7.18

## 0.5.8-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-plugin-api@0.6.7-next.2
  - @backstage/backend-common@0.19.9-next.2
  - @backstage/backend-tasks@0.5.12-next.2
  - @backstage/plugin-auth-node@0.4.1-next.2
  - @backstage/plugin-permission-node@0.7.18-next.2
  - @backstage/config-loader@1.5.3-next.0

## 0.5.8-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.9-next.1
  - @backstage/backend-tasks@0.5.12-next.1
  - @backstage/config-loader@1.5.3-next.0
  - @backstage/plugin-auth-node@0.4.1-next.1
  - @backstage/plugin-permission-node@0.7.18-next.1
  - @backstage/backend-plugin-api@0.6.7-next.1
  - @backstage/cli-common@0.1.13
  - @backstage/cli-node@0.2.0-next.0
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1

## 0.5.8-next.0

### Patch Changes

- bc9a18d5ec: Added a workaround for double `default` wrapping when dynamically importing CommonJS modules with default exports.
- Updated dependencies
  - @backstage/config-loader@1.5.2-next.0
  - @backstage/cli-node@0.2.0-next.0
  - @backstage/backend-common@0.19.9-next.0
  - @backstage/backend-plugin-api@0.6.7-next.0
  - @backstage/backend-tasks@0.5.12-next.0
  - @backstage/cli-common@0.1.13
  - @backstage/config@1.1.1
  - @backstage/errors@1.2.3
  - @backstage/types@1.1.1
  - @backstage/plugin-auth-node@0.4.1-next.0
  - @backstage/plugin-permission-node@0.7.18-next.0

## 0.5.6

### Patch Changes

- 74491c9602: Moved `HostDiscovery` from `@backstage/backend-common`.
- a4617c422a: Added `watch` option to configuration loaders that can be used to disable file watching by setting it to `false`.
- Updated dependencies
  - @backstage/backend-tasks@0.5.11
  - @backstage/backend-common@0.19.8
  - @backstage/plugin-auth-node@0.4.0
  - @backstage/config-loader@1.5.1
  - @backstage/errors@1.2.3
  - @backstage/cli-common@0.1.13
  - @backstage/backend-plugin-api@0.6.6
  - @backstage/plugin-permission-node@0.7.17
  - @backstage/cli-node@0.1.5
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1

## 0.5.6-next.2

### Patch Changes

- 74491c9602: Moved `HostDiscovery` from `@backstage/backend-common`.
- a4617c422a: Added `watch` option to configuration loaders that can be used to disable file watching by setting it to `false`.
- Updated dependencies
  - @backstage/backend-common@0.19.8-next.2
  - @backstage/plugin-auth-node@0.4.0-next.2
  - @backstage/config-loader@1.5.1-next.1
  - @backstage/errors@1.2.3-next.0
  - @backstage/backend-tasks@0.5.11-next.2
  - @backstage/plugin-permission-node@0.7.17-next.2
  - @backstage/backend-plugin-api@0.6.6-next.2
  - @backstage/cli-common@0.1.13-next.0
  - @backstage/cli-node@0.1.5-next.1
  - @backstage/config@1.1.1-next.0
  - @backstage/types@1.1.1

## 0.5.5-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.5.10-next.1
  - @backstage/backend-common@0.19.7-next.1
  - @backstage/backend-plugin-api@0.6.5-next.1
  - @backstage/plugin-auth-node@0.3.2-next.1
  - @backstage/plugin-permission-node@0.7.16-next.1
  - @backstage/config@1.1.0
  - @backstage/cli-common@0.1.13-next.0
  - @backstage/cli-node@0.1.5-next.0
  - @backstage/config-loader@1.5.1-next.0
  - @backstage/errors@1.2.2
  - @backstage/types@1.1.1

## 0.5.5-next.0

### Patch Changes

- Updated dependencies
  - @backstage/plugin-auth-node@0.3.2-next.0
  - @backstage/config-loader@1.5.1-next.0
  - @backstage/cli-common@0.1.13-next.0
  - @backstage/backend-common@0.19.7-next.0
  - @backstage/config@1.1.0
  - @backstage/backend-plugin-api@0.6.5-next.0
  - @backstage/backend-tasks@0.5.10-next.0
  - @backstage/cli-node@0.1.5-next.0
  - @backstage/errors@1.2.2
  - @backstage/types@1.1.1
  - @backstage/plugin-permission-node@0.7.16-next.0

## 0.5.3

### Patch Changes

- 154632d8753b: Add support for discovering additional service factories during startup.
- 37a20c7f14aa: Adds include and exclude configuration to feature discovery of backend packages
  Adds alpha modules to feature discovery
- cb7fc410ed99: The experimental backend feature discovery now only considers default exports from packages. It no longer filters packages to include based on the package role, except that `'cli'` packages are ignored. However, the `"backstage"` field is still required in `package.json`.
- 3fc64b9e2f8f: Extension points are now tracked via their ID rather than reference, in order to support package duplication.
- 3b30b179cb38: Add support for installing features as package imports, for example `backend.add(import('my-plugin'))`.
- b219d097b3f4: Backend startup will now fail if any circular service dependencies are detected.
- Updated dependencies
  - @backstage/backend-tasks@0.5.8
  - @backstage/backend-common@0.19.5
  - @backstage/plugin-auth-node@0.3.0
  - @backstage/config@1.1.0
  - @backstage/errors@1.2.2
  - @backstage/types@1.1.1
  - @backstage/plugin-permission-node@0.7.14
  - @backstage/backend-plugin-api@0.6.3
  - @backstage/config-loader@1.5.0
  - @backstage/cli-common@0.1.12
  - @backstage/cli-node@0.1.4

## 0.5.3-next.3

### Patch Changes

- 154632d8753b: Add support for discovering additional service factories during startup.
- cb7fc410ed99: The experimental backend feature discovery now only considers default exports from packages. It no longer filters packages to include based on the package role, except that `'cli'` packages are ignored. However, the `"backstage"` field is still required in `package.json`.
- 3b30b179cb38: Add support for installing features as package imports, for example `backend.add(import('my-plugin'))`.
- Updated dependencies
  - @backstage/config@1.1.0-next.2
  - @backstage/errors@1.2.2-next.0
  - @backstage/types@1.1.1-next.0
  - @backstage/plugin-permission-node@0.7.14-next.3
  - @backstage/backend-plugin-api@0.6.3-next.3
  - @backstage/backend-common@0.19.5-next.3
  - @backstage/backend-tasks@0.5.8-next.3
  - @backstage/cli-common@0.1.12
  - @backstage/cli-node@0.1.4-next.0
  - @backstage/config-loader@1.5.0-next.3
  - @backstage/plugin-auth-node@0.3.0-next.3

## 0.5.3-next.2

### Patch Changes

- 37a20c7f14aa: Adds include and exclude configuration to feature discovery of backend packages
  Adds alpha modules to feature discovery
- 3fc64b9e2f8f: Extension points are now tracked via their ID rather than reference, in order to support package duplication.
- b219d097b3f4: Backend startup will now fail if any circular service dependencies are detected.
- Updated dependencies
  - @backstage/config-loader@1.5.0-next.2
  - @backstage/config@1.1.0-next.1
  - @backstage/backend-tasks@0.5.8-next.2
  - @backstage/backend-common@0.19.5-next.2
  - @backstage/plugin-auth-node@0.3.0-next.2
  - @backstage/plugin-permission-node@0.7.14-next.2
  - @backstage/backend-plugin-api@0.6.3-next.2
  - @backstage/cli-common@0.1.12
  - @backstage/cli-node@0.1.3
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0

## 0.5.3-next.1

### Patch Changes

- Updated dependencies
  - @backstage/config@1.1.0-next.0
  - @backstage/backend-tasks@0.5.8-next.1
  - @backstage/backend-common@0.19.5-next.1
  - @backstage/backend-plugin-api@0.6.3-next.1
  - @backstage/config-loader@1.5.0-next.1
  - @backstage/plugin-auth-node@0.3.0-next.1
  - @backstage/plugin-permission-node@0.7.14-next.1
  - @backstage/cli-common@0.1.12
  - @backstage/cli-node@0.1.3
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0

## 0.5.2-next.0

### Patch Changes

- Updated dependencies
  - @backstage/plugin-auth-node@0.3.0-next.0
  - @backstage/backend-common@0.19.4-next.0
  - @backstage/config-loader@1.5.0-next.0
  - @backstage/backend-tasks@0.5.7-next.0
  - @backstage/backend-plugin-api@0.6.2-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/cli-node@0.1.3
  - @backstage/config@1.0.8
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0
  - @backstage/plugin-permission-node@0.7.13-next.0

## 0.5.0

### Minor Changes

- b9c57a4f857e: **BREAKING**: Renamed `configServiceFactory` to `rootConfigServiceFactory`.
- a6d7983f349c: **BREAKING**: Removed the `services` option from `createBackend`. Service factories are now `BackendFeature`s and should be installed with `backend.add(...)` instead. The following should be migrated:

  ```ts
  const backend = createBackend({ services: [myCustomServiceFactory] });
  ```

  To instead pass the service factory via `backend.add(...)`:

  ```ts
  const backend = createBackend();
  backend.add(customRootLoggerServiceFactory);
  ```

### Patch Changes

- e65c4896f755: Do not throw in backend.stop, if start failed
- c7aa4ff1793c: Allow modules to register extension points.
- 57a10c6c69cc: Add validation to make sure that extension points do not cross plugin boundaries.
- cc9256a33bcc: Added new experimental `featureDiscoveryServiceFactory`, available as an `/alpha` export.
- Updated dependencies
  - @backstage/backend-common@0.19.2
  - @backstage/config-loader@1.4.0
  - @backstage/backend-plugin-api@0.6.0
  - @backstage/cli-node@0.1.3
  - @backstage/plugin-auth-node@0.2.17
  - @backstage/backend-tasks@0.5.5
  - @backstage/plugin-permission-node@0.7.11
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0

## 0.5.0-next.2

### Patch Changes

- e65c4896f755: Do not throw in backend.stop, if start failed
- cc9256a33bcc: Added new experimental `featureDiscoveryServiceFactory`, available as an `/alpha` export.
- Updated dependencies
  - @backstage/backend-plugin-api@0.6.0-next.2
  - @backstage/backend-tasks@0.5.5-next.2
  - @backstage/backend-common@0.19.2-next.2
  - @backstage/plugin-permission-node@0.7.11-next.2
  - @backstage/plugin-auth-node@0.2.17-next.2
  - @backstage/config-loader@1.4.0-next.1

## 0.5.0-next.1

### Minor Changes

- b9c57a4f857e: **BREAKING**: Renamed `configServiceFactory` to `rootConfigServiceFactory`.

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.2-next.1
  - @backstage/config-loader@1.4.0-next.1
  - @backstage/plugin-auth-node@0.2.17-next.1
  - @backstage/backend-plugin-api@0.6.0-next.1
  - @backstage/backend-tasks@0.5.5-next.1
  - @backstage/plugin-permission-node@0.7.11-next.1
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0

## 0.4.6-next.0

### Patch Changes

- Updated dependencies
  - @backstage/config-loader@1.4.0-next.0
  - @backstage/backend-common@0.19.2-next.0
  - @backstage/backend-plugin-api@0.5.5-next.0
  - @backstage/backend-tasks@0.5.5-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8
  - @backstage/errors@1.2.1
  - @backstage/types@1.1.0
  - @backstage/plugin-auth-node@0.2.17-next.0
  - @backstage/plugin-permission-node@0.7.11-next.0

## 0.4.5

### Patch Changes

- Updated dependencies
  - @backstage/errors@1.2.1
  - @backstage/backend-common@0.19.1
  - @backstage/backend-plugin-api@0.5.4
  - @backstage/backend-tasks@0.5.4
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8
  - @backstage/config-loader@1.3.2
  - @backstage/types@1.1.0
  - @backstage/plugin-auth-node@0.2.16
  - @backstage/plugin-permission-node@0.7.10

## 0.4.5-next.0

### Patch Changes

- Updated dependencies
  - @backstage/errors@1.2.1-next.0
  - @backstage/backend-common@0.19.1-next.0
  - @backstage/backend-plugin-api@0.5.4-next.0
  - @backstage/backend-tasks@0.5.4-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8
  - @backstage/config-loader@1.3.2-next.0
  - @backstage/types@1.1.0
  - @backstage/plugin-auth-node@0.2.16-next.0
  - @backstage/plugin-permission-node@0.7.10-next.0

## 0.4.4

### Patch Changes

- 3bb4158a8aa4: Switched startup strategy to initialize all plugins in parallel, as well as hook into the new startup lifecycle hooks.
- 68a21956ef52: Remove reference to deprecated import
- a5c5491ff50c: Use `durationToMilliseconds` from `@backstage/types` instead of our own
- 2c9f67e6f166: Introduced built-in middleware into the default `HttpService` implementation that throws a `ServiceNotAvailable` error when plugins aren't able to serve request. Also introduced a request stalling mechanism that pauses incoming request until plugins have been fully initialized.
- c4e8fefd9f13: Added handling of `ServiceUnavailableError` to error handling middleware.
- Updated dependencies
  - @backstage/backend-common@0.19.0
  - @backstage/types@1.1.0
  - @backstage/config-loader@1.3.1
  - @backstage/errors@1.2.0
  - @backstage/backend-plugin-api@0.5.3
  - @backstage/backend-tasks@0.5.3
  - @backstage/plugin-auth-node@0.2.15
  - @backstage/plugin-permission-node@0.7.9
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.8

## 0.4.4-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.0-next.2
  - @backstage/backend-plugin-api@0.5.3-next.2
  - @backstage/backend-tasks@0.5.3-next.2
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/config-loader@1.3.1-next.1
  - @backstage/errors@1.2.0-next.0
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.15-next.2
  - @backstage/plugin-permission-node@0.7.9-next.2

## 0.4.4-next.1

### Patch Changes

- 3bb4158a8aa4: Switched startup strategy to initialize all plugins in parallel, as well as hook into the new startup lifecycle hooks.
- 2c9f67e6f166: Introduced built-in middleware into the default `HttpService` implementation that throws a `ServiceNotAvailable` error when plugins aren't able to serve request. Also introduced a request stalling mechanism that pauses incoming request until plugins have been fully initialized.
- c4e8fefd9f13: Added handling of `ServiceUnavailableError` to error handling middleware.
- Updated dependencies
  - @backstage/backend-common@0.19.0-next.1
  - @backstage/errors@1.2.0-next.0
  - @backstage/backend-plugin-api@0.5.3-next.1
  - @backstage/backend-tasks@0.5.3-next.1
  - @backstage/plugin-auth-node@0.2.15-next.1
  - @backstage/plugin-permission-node@0.7.9-next.1
  - @backstage/config-loader@1.3.1-next.1
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/types@1.0.2

## 0.4.4-next.0

### Patch Changes

- Updated dependencies
  - @backstage/config-loader@1.3.1-next.0
  - @backstage/backend-common@0.18.6-next.0
  - @backstage/config@1.0.7
  - @backstage/backend-plugin-api@0.5.3-next.0
  - @backstage/backend-tasks@0.5.3-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.15-next.0
  - @backstage/plugin-permission-node@0.7.9-next.0

## 0.4.3

### Patch Changes

- cf13b482f9e: Switch `configServiceFactory` to use `ConfigSources` from `@backstage/config-loader` to load config.
- Updated dependencies
  - @backstage/backend-common@0.18.5
  - @backstage/config-loader@1.3.0
  - @backstage/plugin-permission-node@0.7.8
  - @backstage/backend-tasks@0.5.2
  - @backstage/plugin-auth-node@0.2.14
  - @backstage/backend-plugin-api@0.5.2
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2

## 0.4.3-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.5-next.1
  - @backstage/backend-tasks@0.5.2-next.1
  - @backstage/plugin-auth-node@0.2.14-next.1
  - @backstage/plugin-permission-node@0.7.8-next.1
  - @backstage/backend-plugin-api@0.5.2-next.1
  - @backstage/config-loader@1.3.0-next.0
  - @backstage/config@1.0.7

## 0.4.3-next.0

### Patch Changes

- cf13b482f9e: Switch `configServiceFactory` to use `ConfigSources` from `@backstage/config-loader` to load config.
- Updated dependencies
  - @backstage/backend-common@0.18.5-next.0
  - @backstage/config-loader@1.3.0-next.0
  - @backstage/plugin-permission-node@0.7.8-next.0
  - @backstage/backend-tasks@0.5.2-next.0
  - @backstage/plugin-auth-node@0.2.14-next.0
  - @backstage/backend-plugin-api@0.5.2-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2

## 0.4.2

### Patch Changes

- 5c7ce585824: Allow an additionalConfig to be provided to loadBackendConfig that fetches config values during runtime.
- 8cce2205a39: Register unhandled rejection and uncaught exception handlers to avoid backend crashes.
- Updated dependencies
  - @backstage/backend-common@0.18.4
  - @backstage/config-loader@1.2.0
  - @backstage/plugin-permission-node@0.7.7
  - @backstage/backend-tasks@0.5.1
  - @backstage/plugin-auth-node@0.2.13
  - @backstage/backend-plugin-api@0.5.1
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2

## 0.4.2-next.2

### Patch Changes

- 5c7ce585824: Allow an additionalConfig to be provided to loadBackendConfig that fetches config values during runtime.
- Updated dependencies
  - @backstage/backend-common@0.18.4-next.2
  - @backstage/plugin-permission-node@0.7.7-next.2
  - @backstage/backend-plugin-api@0.5.1-next.2
  - @backstage/backend-tasks@0.5.1-next.2
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/config-loader@1.1.9
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.13-next.2

## 0.4.2-next.1

### Patch Changes

- Updated dependencies
  - @backstage/plugin-permission-node@0.7.7-next.1
  - @backstage/backend-tasks@0.5.1-next.1
  - @backstage/backend-common@0.18.4-next.1
  - @backstage/backend-plugin-api@0.5.1-next.1
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/config-loader@1.1.9
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.13-next.1

## 0.4.2-next.0

### Patch Changes

- 8cce2205a39: Register unhandled rejection and uncaught exception handlers to avoid backend crashes.
- Updated dependencies
  - @backstage/backend-common@0.18.4-next.0
  - @backstage/config@1.0.7
  - @backstage/backend-plugin-api@0.5.1-next.0
  - @backstage/backend-tasks@0.5.1-next.0
  - @backstage/cli-common@0.1.12
  - @backstage/config-loader@1.1.9
  - @backstage/errors@1.1.5
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.13-next.0
  - @backstage/plugin-permission-node@0.7.7-next.0

## 0.4.1

### Patch Changes

- 928a12a9b3e: Internal refactor of `/alpha` exports.
- 482dae5de1c: Updated link to docs.
- 915e46622cf: Add support for `NotImplementedError`, properly returning 501 as status code.
- Updated dependencies
  - @backstage/plugin-permission-node@0.7.6
  - @backstage/plugin-auth-node@0.2.12
  - @backstage/backend-tasks@0.5.0
  - @backstage/backend-common@0.18.3
  - @backstage/errors@1.1.5
  - @backstage/backend-plugin-api@0.5.0
  - @backstage/config-loader@1.1.9
  - @backstage/cli-common@0.1.12
  - @backstage/config@1.0.7
  - @backstage/types@1.0.2

## 0.4.1-next.2

### Patch Changes

- Updated dependencies
  - @backstage/plugin-auth-node@0.2.12-next.2
  - @backstage/backend-tasks@0.5.0-next.2
  - @backstage/backend-common@0.18.3-next.2
  - @backstage/backend-plugin-api@0.4.1-next.2
  - @backstage/plugin-permission-node@0.7.6-next.2
  - @backstage/config@1.0.7-next.0

## 0.4.1-next.1

### Patch Changes

- 482dae5de1c: Updated link to docs.
- 915e46622cf: Add support for `NotImplementedError`, properly returning 501 as status code.
- Updated dependencies
  - @backstage/plugin-permission-node@0.7.6-next.1
  - @backstage/errors@1.1.5-next.0
  - @backstage/backend-common@0.18.3-next.1
  - @backstage/config-loader@1.1.9-next.0
  - @backstage/plugin-auth-node@0.2.12-next.1
  - @backstage/backend-plugin-api@0.4.1-next.1
  - @backstage/backend-tasks@0.4.4-next.1
  - @backstage/cli-common@0.1.12-next.0
  - @backstage/config@1.0.7-next.0
  - @backstage/types@1.0.2

## 0.4.1-next.0

### Patch Changes

- 928a12a9b3: Internal refactor of `/alpha` exports.
- Updated dependencies
  - @backstage/backend-tasks@0.4.4-next.0
  - @backstage/backend-plugin-api@0.4.1-next.0
  - @backstage/backend-common@0.18.3-next.0
  - @backstage/cli-common@0.1.11
  - @backstage/config@1.0.6
  - @backstage/config-loader@1.1.8
  - @backstage/errors@1.1.4
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.12-next.0
  - @backstage/plugin-permission-node@0.7.6-next.0

## 0.4.0

### Minor Changes

- 01a075ec1d: **BREAKING**: Renamed `RootHttpRouterConfigureOptions` to `RootHttpRouterConfigureContext`, and removed the unused type `ServiceOrExtensionPoint`.
- 4ae71b7f2e: **BREAKING** Renaming `*Factory` exports to `*ServiceFactory` instead. For example `configFactory` now is exported as `configServiceFactory`.
- d31d8e00b3: **BREAKING** `HttpServerCertificateOptions` when specified with a `key` and `cert` should also have the `type: 'pem'` instead of `type: 'plain'`

### Patch Changes

- a18da2f8b5: Fixed an issue were the log redaction didn't properly escape RegExp characters.
- 5febb216fe: Updated to match the new `CacheService` interface.
- e716946103: Updated usage of the lifecycle service.
- f60cca9da1: Updated database factory to pass service deps required for restoring database state during development.
- 610d65e143: Updates to match new `BackendFeature` type.
- 725383f69d: Tweaked messaging in the README.
- b86efa2d04: Updated usage of `ServiceFactory`.
- ab22515647: The shutdown signal handlers are now installed as part of the backend instance rather than the lifecycle service, and explicitly cause the process to exit.
- b729f9f31f: Moved the options of the `config` and `rootHttpRouter` services out to the factories themselves, where they belong
- ed8b5967d7: `HttpRouterFactoryOptions.getPath` is now optional as a default value is always provided in the factory.
- 71a5ec0f06: Updated usages of `LogMeta`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.4.0
  - @backstage/backend-common@0.18.2
  - @backstage/backend-tasks@0.4.3
  - @backstage/cli-common@0.1.11
  - @backstage/config@1.0.6
  - @backstage/config-loader@1.1.8
  - @backstage/errors@1.1.4
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.11
  - @backstage/plugin-permission-node@0.7.5

## 0.4.0-next.2

### Minor Changes

- 01a075ec1d: **BREAKING**: Renamed `RootHttpRouterConfigureOptions` to `RootHttpRouterConfigureContext`, and removed the unused type `ServiceOrExtensionPoint`.
- 4ae71b7f2e: **BREAKING** Renaming `*Factory` exports to `*ServiceFactory` instead. For example `configFactory` now is exported as `configServiceFactory`.
- d31d8e00b3: **BREAKING** `HttpServerCertificateOptions` when specified with a `key` and `cert` should also have the `type: 'pem'` instead of `type: 'plain'`

### Patch Changes

- e716946103: Updated usage of the lifecycle service.
- f60cca9da1: Updated database factory to pass service deps required for restoring database state during development.
- 610d65e143: Updates to match new `BackendFeature` type.
- ab22515647: The shutdown signal handlers are now installed as part of the backend instance rather than the lifecycle service, and explicitly cause the process to exit.
- b729f9f31f: Moved the options of the `config` and `rootHttpRouter` services out to the factories themselves, where they belong
- 71a5ec0f06: Updated usages of `LogMeta`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.4.0-next.2
  - @backstage/backend-common@0.18.2-next.2
  - @backstage/backend-tasks@0.4.3-next.2
  - @backstage/plugin-auth-node@0.2.11-next.2
  - @backstage/plugin-permission-node@0.7.5-next.2
  - @backstage/cli-common@0.1.11
  - @backstage/config@1.0.6
  - @backstage/config-loader@1.1.8
  - @backstage/errors@1.1.4
  - @backstage/types@1.0.2

## 0.3.2-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.2-next.1
  - @backstage/backend-plugin-api@0.3.2-next.1
  - @backstage/backend-tasks@0.4.3-next.1
  - @backstage/cli-common@0.1.11
  - @backstage/config@1.0.6
  - @backstage/config-loader@1.1.8
  - @backstage/errors@1.1.4
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.11-next.1
  - @backstage/plugin-permission-node@0.7.5-next.1

## 0.3.2-next.0

### Patch Changes

- a18da2f8b5: Fixed an issue were the log redaction didn't properly escape RegExp characters.
- ed8b5967d7: `HttpRouterFactoryOptions.getPath` is now optional as a default value is always provided in the factory.
- Updated dependencies
  - @backstage/backend-common@0.18.2-next.0
  - @backstage/backend-tasks@0.4.3-next.0
  - @backstage/plugin-auth-node@0.2.11-next.0
  - @backstage/plugin-permission-node@0.7.5-next.0
  - @backstage/backend-plugin-api@0.3.2-next.0

## 0.3.0

### Minor Changes

- 02b119ff93: **BREAKING**: The `httpRouterFactory` now accepts a `getPath` option rather than `indexPlugin`. To set up custom index path, configure the new `rootHttpRouterFactory` with a custom `indexPath` instead.

  Added an implementation for the new `rootHttpRouterServiceRef`.

### Patch Changes

- ecc6bfe4c9: Use new `ServiceFactoryOrFunction` type.
- b99c030f1b: Moved over implementation of the root HTTP service from `@backstage/backend-common`, and replaced the `middleware` option with a `configure` callback option.
- 170282ece6: Fixed a bug in the default token manager factory where it created multiple incompatible instances.
- 843a0a158c: Added service factory for the new core identity service.
- 150a7dd790: An error will now be thrown if attempting to override the plugin metadata service.
- 483e907eaf: Internal updates of `createServiceFactory` from `@backstage/backend-plugin-api`.
- 015a6dced6: The `createSpecializedBackend` function will now throw an error if duplicate service implementations are provided.
- e3fca10038: Tweaked the plugin logger to use `plugin` as the label for the plugin ID, rather than `pluginId`.
- ecbec4ec4c: Internal refactor to match new options pattern in the experimental backend system.
- 51b7a7ed07: Exported the default root HTTP router implementation as `DefaultRootHttpRouter`. It only implements the routing layer and needs to be exposed via an HTTP server similar to the built-in setup in the `rootHttpRouterFactory`.
- 0e63aab311: Moved over logging and configuration loading implementations from `@backstage/backend-common`. There is a now `WinstonLogger` which implements the `RootLoggerService` through Winston with accompanying utilities. For configuration the `loadBackendConfig` function has been moved over, but it now instead returns an object with a `config` property.
- 8e06f3cf00: Switched imports of `loggerToWinstonLogger` to `@backstage/backend-common`.
- 3b8fd4169b: Internal folder structure refactor.
- 6cfd4d7073: Updated implementations for the new `RootLifecycleService`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.3.0
  - @backstage/backend-common@0.18.0
  - @backstage/backend-tasks@0.4.1
  - @backstage/config@1.0.6
  - @backstage/cli-common@0.1.11
  - @backstage/config-loader@1.1.8
  - @backstage/errors@1.1.4
  - @backstage/types@1.0.2
  - @backstage/plugin-auth-node@0.2.9
  - @backstage/plugin-permission-node@0.7.3

## 0.3.0-next.1

### Minor Changes

- 02b119ff93: **BREAKING**: The `httpRouterFactory` now accepts a `getPath` option rather than `indexPlugin`. To set up custom index path, configure the new `rootHttpRouterFactory` with a custom `indexPath` instead.

  Added an implementation for the new `rootHttpRouterServiceRef`.

### Patch Changes

- ecc6bfe4c9: Use new `ServiceFactoryOrFunction` type.
- b99c030f1b: Moved over implementation of the root HTTP service from `@backstage/backend-common`, and replaced the `middleware` option with a `configure` callback option.
- 150a7dd790: An error will now be thrown if attempting to override the plugin metadata service.
- 015a6dced6: The `createSpecializedBackend` function will now throw an error if duplicate service implementations are provided.
- e3fca10038: Tweaked the plugin logger to use `plugin` as the label for the plugin ID, rather than `pluginId`.
- 8e06f3cf00: Switched imports of `loggerToWinstonLogger` to `@backstage/backend-common`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.3.0-next.1
  - @backstage/backend-common@0.18.0-next.1
  - @backstage/backend-tasks@0.4.1-next.1
  - @backstage/plugin-permission-node@0.7.3-next.1
  - @backstage/config@1.0.6-next.0
  - @backstage/errors@1.1.4

## 0.2.5-next.0

### Patch Changes

- 6cfd4d7073: Updated implementations for the new `RootLifecycleService`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.2.1-next.0
  - @backstage/backend-common@0.18.0-next.0
  - @backstage/backend-tasks@0.4.1-next.0
  - @backstage/errors@1.1.4
  - @backstage/plugin-permission-node@0.7.3-next.0

## 0.2.4

### Patch Changes

- cb1c2781c0: Updated logger implementations to match interface changes.
- 884d749b14: Refactored to use `coreServices` from `@backstage/backend-plugin-api`.
- afa3bf5657: Added `.stop()` method to `Backend`.
- d6dbf1792b: Added `lifecycleFactory` implementation.
- 05a928e296: Updated usages of types from `@backstage/backend-plugin-api`.
- 5260d8fc7d: Root scoped services are now always initialized, regardless of whether they're used by any features.
- Updated dependencies
  - @backstage/backend-common@0.17.0
  - @backstage/backend-tasks@0.4.0
  - @backstage/plugin-permission-node@0.7.2
  - @backstage/errors@1.1.4
  - @backstage/backend-plugin-api@0.2.0

## 0.2.4-next.3

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.4.0-next.3
  - @backstage/plugin-permission-node@0.7.2-next.3
  - @backstage/backend-common@0.17.0-next.3
  - @backstage/backend-plugin-api@0.2.0-next.3
  - @backstage/errors@1.1.4-next.1

## 0.2.4-next.2

### Patch Changes

- 884d749b14: Refactored to use `coreServices` from `@backstage/backend-plugin-api`.
- Updated dependencies
  - @backstage/backend-common@0.17.0-next.2
  - @backstage/backend-plugin-api@0.2.0-next.2
  - @backstage/backend-tasks@0.4.0-next.2
  - @backstage/plugin-permission-node@0.7.2-next.2
  - @backstage/errors@1.1.4-next.1

## 0.2.4-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.17.0-next.1
  - @backstage/backend-tasks@0.4.0-next.1
  - @backstage/backend-plugin-api@0.1.5-next.1
  - @backstage/plugin-permission-node@0.7.2-next.1
  - @backstage/errors@1.1.4-next.1

## 0.2.4-next.0

### Patch Changes

- d6dbf1792b: Added `lifecycleFactory` implementation.
- Updated dependencies
  - @backstage/backend-common@0.16.1-next.0
  - @backstage/plugin-permission-node@0.7.2-next.0
  - @backstage/backend-plugin-api@0.1.5-next.0
  - @backstage/backend-tasks@0.3.8-next.0
  - @backstage/errors@1.1.4-next.0

## 0.2.3

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.16.0
  - @backstage/backend-tasks@0.3.7
  - @backstage/backend-plugin-api@0.1.4
  - @backstage/plugin-permission-node@0.7.1
  - @backstage/errors@1.1.3

## 0.2.3-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.16.0-next.1
  - @backstage/backend-plugin-api@0.1.4-next.1
  - @backstage/backend-tasks@0.3.7-next.1
  - @backstage/plugin-permission-node@0.7.1-next.1
  - @backstage/errors@1.1.3-next.0

## 0.2.3-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.16.0-next.0
  - @backstage/backend-tasks@0.3.7-next.0
  - @backstage/backend-plugin-api@0.1.4-next.0
  - @backstage/plugin-permission-node@0.7.1-next.0
  - @backstage/errors@1.1.3-next.0

## 0.2.2

### Patch Changes

- 0027a749cd: Added possibility to configure index plugin of the HTTP router service.
- 45857bffae: Properly export `rootLoggerFactory`.
- Updated dependencies
  - @backstage/backend-common@0.15.2
  - @backstage/backend-tasks@0.3.6
  - @backstage/plugin-permission-node@0.7.0
  - @backstage/backend-plugin-api@0.1.3
  - @backstage/errors@1.1.2

## 0.2.2-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.3.6-next.2
  - @backstage/backend-common@0.15.2-next.2
  - @backstage/plugin-permission-node@0.7.0-next.2
  - @backstage/backend-plugin-api@0.1.3-next.2
  - @backstage/errors@1.1.2-next.2

## 0.2.2-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.15.2-next.1
  - @backstage/backend-plugin-api@0.1.3-next.1
  - @backstage/backend-tasks@0.3.6-next.1
  - @backstage/errors@1.1.2-next.1
  - @backstage/plugin-permission-node@0.6.6-next.1

## 0.2.2-next.0

### Patch Changes

- 0027a749cd: Added possibility to configure index plugin of the HTTP router service.
- 45857bffae: Properly export `rootLoggerFactory`.
- Updated dependencies
  - @backstage/backend-plugin-api@0.1.3-next.0
  - @backstage/backend-common@0.15.2-next.0
  - @backstage/backend-tasks@0.3.6-next.0
  - @backstage/plugin-permission-node@0.6.6-next.0
  - @backstage/errors@1.1.2-next.0

## 0.2.1

### Patch Changes

- 2c57c0c499: Made `ApiRef.defaultFactory` internal.
- 854ba37357: Updated to support new `ServiceFactory` formats.
- af6bb42c68: Updated `ServiceRegistry` to not initialize factories more than once.
- 409ed984e8: Updated service implementations and backend wiring to support scoped service.
- de3347ca74: Updated usages of `ServiceFactory`.
- 1f384c5644: Improved error messaging when failing to instantiate services.
- Updated dependencies
  - @backstage/backend-plugin-api@0.1.2
  - @backstage/backend-common@0.15.1
  - @backstage/plugin-permission-node@0.6.5
  - @backstage/backend-tasks@0.3.5
  - @backstage/errors@1.1.1

## 0.2.1-next.2

### Patch Changes

- 854ba37357: Updated to support new `ServiceFactory` formats.
- 409ed984e8: Updated service implementations and backend wiring to support scoped service.
- Updated dependencies
  - @backstage/backend-plugin-api@0.1.2-next.2
  - @backstage/errors@1.1.1-next.0
  - @backstage/backend-common@0.15.1-next.3
  - @backstage/backend-tasks@0.3.5-next.1
  - @backstage/plugin-permission-node@0.6.5-next.3

## 0.2.1-next.1

### Patch Changes

- 2c57c0c499: Made `ApiRef.defaultFactory` internal.
- af6bb42c68: Updated `ServiceRegistry` to not initialize factories more than once.
- 1f384c5644: Improved error messaging when failing to instantiate services.
- Updated dependencies
  - @backstage/backend-plugin-api@0.1.2-next.1
  - @backstage/backend-common@0.15.1-next.2
  - @backstage/plugin-permission-node@0.6.5-next.2

## 0.2.1-next.0

### Patch Changes

- de3347ca74: Updated usages of `ServiceFactory`.
- Updated dependencies
  - @backstage/backend-common@0.15.1-next.0
  - @backstage/backend-tasks@0.3.5-next.0
  - @backstage/backend-plugin-api@0.1.2-next.0
  - @backstage/plugin-permission-node@0.6.5-next.0

## 0.2.0

### Minor Changes

- 5df230d48c: Introduced a new `backend-defaults` package carrying `createBackend` which was previously exported from `backend-app-api`.
  The `backend-app-api` package now exports the `createSpecializedBacked` that does not add any service factories by default.

### Patch Changes

- 0599732ec0: Refactored experimental backend system with new type names.
- Updated dependencies
  - @backstage/backend-common@0.15.0
  - @backstage/backend-plugin-api@0.1.1
  - @backstage/backend-tasks@0.3.4
  - @backstage/plugin-permission-node@0.6.4

## 0.1.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.15.0-next.0
  - @backstage/backend-tasks@0.3.4-next.0
  - @backstage/backend-plugin-api@0.1.1-next.0
  - @backstage/plugin-permission-node@0.6.4-next.0

## 0.1.0

### Minor Changes

- 91c1d12123: Add initial plumbing for creating backends using the experimental backend framework.

  This package is highly **EXPERIMENTAL** and should not be used in production.

### Patch Changes

- Updated dependencies
  - @backstage/backend-plugin-api@0.1.0
  - @backstage/backend-common@0.14.1
  - @backstage/plugin-permission-node@0.6.3
  - @backstage/backend-tasks@0.3.3

## 0.1.0-next.0

### Minor Changes

- 91c1d12123: Add initial plumbing for creating backends using the experimental backend framework.

  This package is highly **EXPERIMENTAL** and should not be used in production.

### Patch Changes

- Updated dependencies
  - @backstage/backend-plugin-api@0.1.0-next.0
  - @backstage/backend-common@0.14.1-next.3
  - @backstage/plugin-permission-node@0.6.3-next.2
  - @backstage/backend-tasks@0.3.3-next.3
