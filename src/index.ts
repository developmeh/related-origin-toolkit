/**
 * Passkey Origin Validator - TypeScript Library
 * 
 * A TypeScript library for validating passkey/WebAuthn origin constraints in .well-known/webauthn endpoints.
 * This library is based on the Chromium project's implementation of WebAuthn security checking and helps ensure
 * that your WebAuthn implementation follows the same constraints as browsers.
 * 
 * Designed for use with password manager browser extensions and other WebAuthn implementations.
 */

// Export all types
export {
  AuthenticatorStatus,
  WebAuthnResponse,
  LabelCount,
  ValidationResult,
  CONSTANTS,
  authenticatorStatusToString,
  LoggingAdapter
} from './types';

// Export logging utilities
export {
  createLoggingAdapter,
  defaultLogger
} from './logger';

// Export validation functions
export {
  validateWellKnownJSON,
  fetchWellKnownWebAuthn,
  validateOrigin
} from './validator';

// Re-export for convenience
import { AuthenticatorStatus, authenticatorStatusToString, LoggingAdapter } from './types';
import { validateWellKnownJSON, fetchWellKnownWebAuthn, validateOrigin } from './validator';
import { createLoggingAdapter, defaultLogger } from './logger';

/**
 * Main validation function that provides a simple interface for validating origins.
 * This is the primary function that browser extensions should use.
 * 
 * @param rpId The Relying Party ID (domain) to check
 * @param origin The caller origin to validate
 * @param logger Optional logging adapter for logging messages
 * @returns Promise resolving to validation result with status and message
 */
export async function validatePasskeyOrigin(
  rpId: string, 
  origin: string, 
  logger?: LoggingAdapter
): Promise<{
  isValid: boolean;
  status: AuthenticatorStatus;
  message: string;
}> {
  const log = createLoggingAdapter(logger || defaultLogger);
  try {
    log(`Validating origin "${origin}" against rpId "${rpId}"`);
    // The validateOrigin function expects (callerOrigin, domain) parameters
    // where callerOrigin is the origin to validate and domain is the rpId to check against
    const status = await validateOrigin(origin, rpId, logger);
    const isValid = status === AuthenticatorStatus.SUCCESS;
    const message = authenticatorStatusToString(status);
    
    log(`Validation result: ${isValid ? 'Valid' : 'Invalid'}, status: ${message}`);
    return {
      isValid,
      status,
      message
    };
  } catch (error) {
    log(`Validation error`, error instanceof Error ? error : new Error(String(error)));
    return {
      isValid: false,
      status: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
      message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Validates an origin against JSON data from a .well-known/webauthn endpoint.
 * This function can be used when you already have the JSON data and don't need to fetch it.
 * 
 * @param origin The caller origin to validate
 * @param wellKnownJson The JSON string from the .well-known/webauthn endpoint
 * @param logger Optional logging adapter for logging messages
 * @returns Validation result with status and message
 */
export function validatePasskeyOriginFromJSON(
  origin: string, 
  wellKnownJson: string, 
  logger?: LoggingAdapter
): {
  isValid: boolean;
  status: AuthenticatorStatus;
  message: string;
} {
  const log = createLoggingAdapter(logger || defaultLogger);
  try {
    log(`Validating origin "${origin}" against well-known JSON data`);
    const status = validateWellKnownJSON(origin, wellKnownJson, logger);
    const isValid = status === AuthenticatorStatus.SUCCESS;
    const message = authenticatorStatusToString(status);
    
    log(`Validation result: ${isValid ? 'Valid' : 'Invalid'}, status: ${message}`);
    return {
      isValid,
      status,
      message
    };
  } catch (error) {
    log(`Validation error`, error instanceof Error ? error : new Error(String(error)));
    return {
      isValid: false,
      status: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
      message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Utility function to check if a status indicates success.
 * 
 * @param status The AuthenticatorStatus to check
 * @returns true if the status indicates success
 */
export function isValidationSuccessful(status: AuthenticatorStatus): boolean {
  return status === AuthenticatorStatus.SUCCESS;
}

/**
 * Utility function to check if a status indicates a parsing error.
 * 
 * @param status The AuthenticatorStatus to check
 * @returns true if the status indicates a JSON parsing error
 */
export function isParsingError(status: AuthenticatorStatus): boolean {
  return status === AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
}

/**
 * Utility function to check if a status indicates hitting the label limit.
 * 
 * @param status The AuthenticatorStatus to check
 * @returns true if the status indicates the label limit was hit
 */
export function isLabelLimitHit(status: AuthenticatorStatus): boolean {
  return status === AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS;
}