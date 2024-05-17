## API Report File for "@backstage/plugin-cloudbuild"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
/// <reference types="react" />

import { ApiRef } from '@backstage/core-plugin-api';
import { BackstagePlugin } from '@backstage/core-plugin-api';
import { Entity } from '@backstage/catalog-model';
import { JSX as JSX_2 } from 'react';
import { OAuthApi } from '@backstage/core-plugin-api';
import { default as React_2 } from 'react';
import { RouteRef } from '@backstage/core-plugin-api';

// @public (undocumented)
export type ActionsGetWorkflowResponseData = {
  id: string;
  status: string;
  source: Source;
  createTime: string;
  startTime: string;
  steps: Step[];
  timeout: string;
  projectId: string;
  logsBucket: string;
  sourceProvenance: SourceProvenance;
  buildTriggerId: string;
  options: Options;
  logUrl: string;
  substitutions: Substitutions;
  tags: string[];
  queueTtl: string;
  name: string;
  finishTime: any;
  results: Results;
  timing: Timing2;
};

// @public (undocumented)
export interface ActionsListWorkflowRunsForRepoResponseData {
  // (undocumented)
  builds: ActionsGetWorkflowResponseData[];
}

// @public (undocumented)
export interface BUILD {
  // (undocumented)
  endTime: string;
  // (undocumented)
  startTime: string;
}

// @public (undocumented)
export const CLOUDBUILD_ANNOTATION = 'google.com/cloudbuild-project-slug';

// @public (undocumented)
export type CloudbuildApi = {
  listWorkflowRuns: (options: {
    projectId: string;
    location: string;
    cloudBuildFilter: string;
  }) => Promise<ActionsListWorkflowRunsForRepoResponseData>;
  getWorkflow: (options: {
    projectId: string;
    location: string;
    id: string;
  }) => Promise<ActionsGetWorkflowResponseData>;
  getWorkflowRun: (options: {
    projectId: string;
    location: string;
    id: string;
  }) => Promise<ActionsGetWorkflowResponseData>;
  reRunWorkflow: (options: {
    projectId: string;
    location: string;
    runId: string;
  }) => Promise<any>;
};

// @public (undocumented)
export const cloudbuildApiRef: ApiRef<CloudbuildApi>;

// @public (undocumented)
export class CloudbuildClient implements CloudbuildApi {
  constructor(googleAuthApi: OAuthApi);
  // (undocumented)
  getToken(): Promise<string>;
  // (undocumented)
  getWorkflow(options: {
    projectId: string;
    location: string;
    id: string;
  }): Promise<ActionsGetWorkflowResponseData>;
  // (undocumented)
  getWorkflowRun(options: {
    projectId: string;
    location: string;
    id: string;
  }): Promise<ActionsGetWorkflowResponseData>;
  // (undocumented)
  listWorkflowRuns(options: {
    projectId: string;
    location: string;
    cloudBuildFilter: string;
  }): Promise<ActionsListWorkflowRunsForRepoResponseData>;
  // (undocumented)
  reRunWorkflow(options: {
    projectId: string;
    location: string;
    runId: string;
  }): Promise<void>;
}

// @public (undocumented)
const cloudbuildPlugin: BackstagePlugin<
  {
    entityContent: RouteRef<undefined>;
  },
  {}
>;
export { cloudbuildPlugin };
export { cloudbuildPlugin as plugin };

// @public (undocumented)
export const EntityCloudbuildContent: () => JSX_2.Element;

// @public (undocumented)
export const EntityLatestCloudbuildRunCard: (props: {
  branch: string;
}) => JSX_2.Element;

// @public (undocumented)
export const EntityLatestCloudbuildsForBranchCard: (props: {
  branch: string;
}) => JSX_2.Element;

// @public (undocumented)
export interface FETCHSOURCE {
  // (undocumented)
  endTime: string;
  // (undocumented)
  startTime: string;
}

// @public (undocumented)
const isCloudbuildAvailable: (entity: Entity) => boolean;
export { isCloudbuildAvailable };
export { isCloudbuildAvailable as isPluginApplicableToEntity };

// @public (undocumented)
export const LatestWorkflowRunCard: (props: {
  branch: string;
}) => React_2.JSX.Element;

// @public (undocumented)
export const LatestWorkflowsForBranchCard: (props: {
  branch: string;
}) => React_2.JSX.Element;

// @public (undocumented)
export interface Options {
  // (undocumented)
  dynamicSubstitutions: boolean;
  // (undocumented)
  logging: string;
  // (undocumented)
  machineType: string;
  // (undocumented)
  substitutionOption: string;
}

// @public (undocumented)
export interface PullTiming {
  // (undocumented)
  endTime: string;
  // (undocumented)
  startTime: string;
}

// @public (undocumented)
export interface ResolvedStorageSource {
  // (undocumented)
  bucket: string;
  // (undocumented)
  generation: string;
  // (undocumented)
  object: string;
}

// @public (undocumented)
export interface Results {
  // (undocumented)
  buildStepImages: string[];
  // (undocumented)
  buildStepOutputs: string[];
}

// @public (undocumented)
export const Router: () => React_2.JSX.Element;

// @public (undocumented)
export interface Source {
  // (undocumented)
  storageSource: StorageSource;
}

// @public (undocumented)
export interface SourceProvenance {
  // (undocumented)
  fileHashes: {};
  // (undocumented)
  resolvedStorageSource: {};
}

// @public (undocumented)
export interface Step {
  // (undocumented)
  args: string[];
  // (undocumented)
  dir: string;
  // (undocumented)
  entrypoint: string;
  // (undocumented)
  id: string;
  // (undocumented)
  name: string;
  // (undocumented)
  pullTiming: PullTiming;
  // (undocumented)
  status: string;
  // (undocumented)
  timing: Timing;
  // (undocumented)
  volumes: Volume[];
  // (undocumented)
  waitFor: string[];
}

// @public (undocumented)
export interface StorageSource {
  // (undocumented)
  bucket: string;
  // (undocumented)
  object: string;
}

// @public (undocumented)
export interface Substitutions {
  // (undocumented)
  COMMIT_SHA: string;
  // (undocumented)
  REF_NAME: string;
  // (undocumented)
  REPO_NAME: string;
  // (undocumented)
  REVISION_ID: string;
  // (undocumented)
  SHORT_SHA: string;
  // (undocumented)
  TRIGGER_NAME: string;
}

// @public (undocumented)
export interface Timing {
  // (undocumented)
  endTime: string;
  // (undocumented)
  startTime: string;
}

// @public (undocumented)
export interface Timing2 {
  // (undocumented)
  BUILD: BUILD;
  // (undocumented)
  FETCHSOURCE: FETCHSOURCE;
}

// @public (undocumented)
export interface Volume {
  // (undocumented)
  name: string;
  // (undocumented)
  path: string;
}
```