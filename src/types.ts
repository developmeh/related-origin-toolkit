/**
 * AuthenticatorStatus represents the status of a WebAuthn authentication request.
 * This mirrors the Go implementation's AuthenticatorStatus enum.
 */
export enum AuthenticatorStatus {
  /** Indicates that the authentication request was successful */
  SUCCESS = 0,
  /** Indicates that the relying party ID JSON could not be parsed */
  BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR = 1,
  /** Indicates that the relying party ID JSON did not match the caller origin */
  BAD_RELYING_PARTY_ID_NO_JSON_MATCH = 2,
  /** Indicates that the relying party ID JSON did not match the caller origin and hit the label limit */
  BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS = 3,
  /** Indicates that the relying party ID is not a valid subdomain of the caller origin */
  BAD_RELYING_PARTY_ID_NOT_SUBDOMAIN_OF_ORIGIN = 4,
}

/**
 * WebAuthnResponse represents the JSON structure of a .well-known/webauthn response.
 */
export interface WebAuthnResponse {
  origins: string[];
}

/**
 * LabelCount represents the count of unique labels found in a .well-known/webauthn endpoint.
 */
export interface LabelCount {
  url: string;
  uniqueLabels: Set<string>;
  count: number;
  exceedsLimit: boolean;
  labelsFound: string[];
  errorMessage?: string;
  rawJSON: string;
}

/**
 * ValidationResult represents the result of validating an origin against a .well-known/webauthn endpoint.
 */
export interface ValidationResult {
  status: AuthenticatorStatus;
  message: string;
}

/**
 * Constants used in the validation process.
 */
export const CONSTANTS = {
  /** Maximum number of unique labels allowed in a .well-known/webauthn endpoint */
  MAX_LABELS: 5,
  /** Path to the .well-known/webauthn endpoint */
  WELL_KNOWN_PATH: '/.well-known/webauthn',
  /** Maximum size of the response body in bytes (256KB) */
  MAX_BODY_SIZE: 1 << 18,
  /** Timeout for HTTP requests in milliseconds */
  TIMEOUT: 10000,
} as const;

/**
 * LoggingAdapter is a function that handles logging with error handling.
 * It accepts a message and an optional error object.
 */
export type LoggingAdapter = (message: string, error?: Error) => void;

/**
 * Converts AuthenticatorStatus enum to a user-friendly string representation.
 * These messages are designed to be spec-compliant while preserving informational detail.
 */
export function authenticatorStatusToString(status: AuthenticatorStatus): string {
  switch (status) {
    case AuthenticatorStatus.SUCCESS:
      return 'Success';
    case AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR:
      return 'Invalid format in .well-known/webauthn file';
    case AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH:
      return 'Origin not authorized by the relying party';
    case AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS:
      return 'Origin not authorized by the relying party (exceeded maximum of 5 unique domains)';
    case AuthenticatorStatus.BAD_RELYING_PARTY_ID_NOT_SUBDOMAIN_OF_ORIGIN:
      return 'Relying Party ID is not a valid subdomain of the origin';
    default:
      return `Unknown status (${status})`;
  }
}