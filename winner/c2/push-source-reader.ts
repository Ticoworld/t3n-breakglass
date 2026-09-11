import { createHash } from "node:crypto";

import {
  appJwt,
  mintContentsReadInstallationToken,
  repositoryContentAtRef,
  repositoryRead,
  revokeInstallationToken,
  type AppConfig,
  type GithubResponse,
} from "../broker/github-app.js";
import type { ImmutablePushReadPlan } from "./push-read-plan.js";
import type { ImmutablePathObservation } from "./push-transition.js";
import { C2_PUSH_REPOSITORY, C2_PUSH_SECRET_PATH } from "./push-source.js";

export interface PushSourceReaderTokenRequest {
  repositories: [typeof C2_PUSH_REPOSITORY];
  permissions: { contents: "read" };
}

export interface ImmutableContentReadOperation {
  method: "GET";
  repository: typeof C2_PUSH_REPOSITORY;
  path: string;
  ref: string;
}

/** The source reader has no administration or write scope. */
export function pushSourceReaderTokenRequest(): PushSourceReaderTokenRequest {
  return {
    repositories: [C2_PUSH_REPOSITORY],
    permissions: { contents: "read" },
  };
}

/** Exactly two immutable GETs; no mutable branch-head read is permitted. */
export function immutableContentReadOperations(
  plan: ImmutablePushReadPlan,
): [ImmutableContentReadOperation, ImmutableContentReadOperation] {
  return [
    { method: "GET", repository: plan.repository, path: plan.path, ref: plan.before_sha },
    { method: "GET", repository: plan.repository, path: plan.path, ref: plan.after_sha },
  ];
}

export interface PushImmutableContentReader {
  read(operation: ImmutableContentReadOperation): Promise<ImmutablePathObservation>;
}

export interface PushSourceReaderResult {
  before: ImmutablePathObservation;
  after: ImmutablePathObservation;
  token_minted: boolean;
  token_revoked: boolean;
  revoked_token_refused: boolean;
}

export interface GithubPushSourceReaderProvider {
  mintContentsReadToken(config: AppConfig): Promise<string>;
  readImmutableContent(
    token: string,
    operation: ImmutableContentReadOperation,
  ): Promise<ImmutablePathObservation>;
  revokeToken(token: string): Promise<GithubResponse>;
  probeRevokedToken(token: string, config: AppConfig): Promise<GithubResponse>;
}

export class PushSourceReaderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PushSourceReaderError";
  }
}

function responseBodyRecord(response: GithubResponse): Record<string, unknown> {
  if (!response.body || typeof response.body !== "object") {
    throw new PushSourceReaderError("GitHub content response body is not an object");
  }
  return response.body as Record<string, unknown>;
}

function digestGithubContent(body: Record<string, unknown>): string {
  if (body.encoding !== "base64" || typeof body.content !== "string") {
    throw new PushSourceReaderError(
      "GitHub immutable content response is not base64 content",
    );
  }
  const content = Buffer.from(body.content.replace(/\s+/g, ""), "base64");
  return createHash("sha256").update(content).digest("hex");
}

function assertImmutableObservation(observation: ImmutablePathObservation, operation: ImmutableContentReadOperation): void {
  if (observation.repository !== operation.repository || observation.path !== operation.path || observation.commit_sha.toLowerCase() !== operation.ref.toLowerCase() || (observation.status !== 200 && observation.status !== 404)) {
    throw new PushSourceReaderError("GitHub immutable content observation does not match its exact read operation");
  }
  if (observation.status === 200 && !/^[0-9a-f]{64}$/.test(observation.content_sha256 ?? "")) {
    throw new PushSourceReaderError("GitHub immutable content observation has no valid digest");
  }
}

function defaultProvider(): GithubPushSourceReaderProvider {
  return {
    async mintContentsReadToken(config) {
      const jwt = await appJwt(config);
      const result = await mintContentsReadInstallationToken(config, jwt);
      if (result.response.status !== 201 || !result.token) {
        throw new PushSourceReaderError(
          `contents:read token exchange failed with HTTP ${result.response.status}`,
        );
      }
      return result.token;
    },

    async readImmutableContent(token, operation) {
      const [owner, repository] = operation.repository.split("/", 2);
      if (!owner || !repository) {
        throw new PushSourceReaderError("immutable operation repository is invalid");
      }
      const response = await repositoryContentAtRef(
        token,
        owner,
        repository,
        operation.path,
        operation.ref,
      );
      if (response.status === 404) {
        return {
          repository: operation.repository,
          commit_sha: operation.ref,
          path: operation.path,
          status: 404,
        };
      }
      if (response.status !== 200) {
        throw new PushSourceReaderError(
          `immutable content read failed with HTTP ${response.status}`,
        );
      }
      return {
        repository: operation.repository,
        commit_sha: operation.ref,
        path: operation.path,
        status: 200,
        content_sha256: digestGithubContent(responseBodyRecord(response)),
      };
    },

    revokeToken(token) {
      return revokeInstallationToken(token);
    },

    probeRevokedToken(token, config) {
      return repositoryRead(token, config.owner, config.repository);
    },
  };
}

export interface GithubPushSourceReader extends PushImmutableContentReader {
  readPlan(plan: ImmutablePushReadPlan): Promise<PushSourceReaderResult>;
}

/**
 * Reusable production source reader. It returns only immutable observations;
 * the installation token remains inside this adapter and is always revoked.
 */
export function createGithubPushSourceReader(
  config: AppConfig,
  provider: GithubPushSourceReaderProvider = defaultProvider(),
): GithubPushSourceReader {
  const readPlan = async (plan: ImmutablePushReadPlan): Promise<PushSourceReaderResult> => {
    const expectedRepository = `${config.owner}/${config.repository}`;
    if (expectedRepository !== C2_PUSH_REPOSITORY || plan.repository !== expectedRepository) {
      throw new PushSourceReaderError("source reader repository is outside fixed policy scope");
    }
    if (plan.path !== C2_PUSH_SECRET_PATH) {
      throw new PushSourceReaderError("source reader path is outside fixed policy scope");
    }

    const operations = immutableContentReadOperations(plan);
    const token = await provider.mintContentsReadToken(config);
    let before: ImmutablePathObservation | undefined;
    let after: ImmutablePathObservation | undefined;
    let tokenRevoked = false;
    let revokedTokenRefused = false;
    try {
      before = await provider.readImmutableContent(token, operations[0]);
      after = await provider.readImmutableContent(token, operations[1]);
      assertImmutableObservation(before, operations[0]);
      assertImmutableObservation(after, operations[1]);
    } finally {
      const revoked = await provider.revokeToken(token);
      if (revoked.status !== 204) {
        throw new PushSourceReaderError(
          `contents:read token revocation failed with HTTP ${revoked.status}`,
        );
      }
      tokenRevoked = true;
      const refused = await provider.probeRevokedToken(token, config);
      revokedTokenRefused = refused.status === 401 || refused.status === 403;
      if (!revokedTokenRefused) {
        throw new PushSourceReaderError(
          `revoked contents:read token was not refused (HTTP ${refused.status})`,
        );
      }
    }
    if (!before || !after) {
      throw new PushSourceReaderError("source reader did not produce both immutable observations");
    }
    return {
      before,
      after,
      token_minted: true,
      token_revoked: tokenRevoked,
      revoked_token_refused: revokedTokenRefused,
    };
  };

  return {
    async read(operation) {
      if (operation.path !== C2_PUSH_SECRET_PATH) throw new PushSourceReaderError("source reader path is outside fixed policy scope");
      const result = await readPlan({
        repository: operation.repository,
        before_sha: operation.ref,
        after_sha: operation.ref,
        path: C2_PUSH_SECRET_PATH,
      });
      return result.before;
    },
    readPlan,
  };
}
