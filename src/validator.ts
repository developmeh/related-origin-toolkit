import * as psl from 'psl';
import { AuthenticatorStatus, WebAuthnResponse, CONSTANTS, LoggingAdapter } from './types';
import { createLoggingAdapter, defaultLogger } from './logger';

/**
 * Extracts the eTLD+1 label from a domain using the psl package.
 * This mirrors the behavior of net::registry_controlled_domains::GetDomainAndRegistry in Chromium.
 * 
 * @param domain The domain to extract the label from
 * @returns The extracted label or throws an error if invalid
 */
function getLabel(domain: string): string {
  // Find the first dot in the domain
  const dotIndex = domain.indexOf('.');
  if (dotIndex === -1) {
    // If there's no dot, domain isn't valid and we don't care
    throw new Error('Skip Domain not valid');
  }

  // Parse the domain using psl to get the parsed result
  const parsed = psl.parse(domain);
  
  // If parsing failed or no domain, throw an error
  if (!parsed || typeof parsed === 'string' || !('domain' in parsed) || !parsed.domain) {
    throw new Error('Skip Domain not valid');
  }

  // Get the domain part (equivalent to eTLD+1)
  const etldPlus1 = parsed.domain;
  if (!etldPlus1) {
    throw new Error('Skip Domain not valid');
  }

  // Extract the label (the part before the first dot in the eTLD+1)
  const labelDotIndex = etldPlus1.indexOf('.');
  if (labelDotIndex === -1) {
    return etldPlus1;
  }
  
  return etldPlus1.substring(0, labelDotIndex);
}

/**
 * Validates if a caller origin is authorized by a relying party's .well-known/webauthn file.
 * This function is based on the Chromium implementation of ValidateWellKnownJSON.
 * It checks if the caller origin is in the list of authorized origins in the .well-known/webauthn file.
 * It also enforces a limit on the number of unique eTLD+1 labels (MAX_LABELS) that can be processed.
 * If the limit is reached before finding the caller origin, it returns BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS.
 * 
 * @param callerOrigin The origin to validate
 * @param jsonData The JSON data from the .well-known/webauthn endpoint
 * @param logger Optional logging adapter for logging messages
 * @returns AuthenticatorStatus indicating the validation result
 */
export function validateWellKnownJSON(callerOrigin: string, jsonData: string, logger?: LoggingAdapter): AuthenticatorStatus {
  const log = createLoggingAdapter(logger || defaultLogger);
  let webAuthnResp: WebAuthnResponse;
  
  // Parse the JSON
  try {
    log(`Parsing JSON data for validation`);
    webAuthnResp = JSON.parse(jsonData);
  } catch (error) {
    log(`Failed to parse JSON data`, error instanceof Error ? error : new Error(String(error)));
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
  }

  // Check if the origins array exists and is an array
  if (!webAuthnResp.origins || !Array.isArray(webAuthnResp.origins)) {
    log(`Invalid JSON format: origins property missing or not an array`);
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
  }

  // Validate that all origins are strings
  for (const origin of webAuthnResp.origins) {
    if (typeof origin !== 'string') {
      log(`Invalid JSON format: origin is not a string`);
      return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
    }
  }
  
  log(`JSON validation passed, found ${webAuthnResp.origins.length} origins`);

  // Parse the caller origin
  let callerURL: URL;
  try {
    log(`Parsing caller origin: ${callerOrigin}`);
    callerURL = new URL(callerOrigin);
  } catch (error) {
    log(`Failed to parse caller origin: ${callerOrigin}`, error instanceof Error ? error : new Error(String(error)));
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
  }

  // Count unique labels and check if the caller origin is authorized
  const uniqueLabels = new Set<string>();
  let hitLimits = false;

  log(`Checking origins for a match with caller origin: ${callerOrigin}`);
  for (const originStr of webAuthnResp.origins) {
    let originURL: URL;
    try {
      log(`Parsing origin from JSON: ${originStr}`);
      originURL = new URL(originStr);
    } catch (error) {
      log(`Skipping invalid origin: ${originStr}`, error instanceof Error ? error : new Error(String(error)));
      continue;
    }

    // Extract the domain
    const domain = originURL.hostname;
    if (!domain) {
      log(`Skipping origin with no hostname: ${originStr}`);
      continue;
    }

    // Extract the eTLD+1 label using psl package
    let etldPlus1Label: string;
    try {
      log(`Extracting eTLD+1 label from domain: ${domain}`);
      etldPlus1Label = getLabel(domain);
    } catch (error) {
      // Skip this origin if we can't extract the label
      log(`Failed to extract eTLD+1 label from domain: ${domain}`, error instanceof Error ? error : new Error(String(error)));
      continue;
    }

    if (!uniqueLabels.has(etldPlus1Label)) {
      if (uniqueLabels.size >= CONSTANTS.MAX_LABELS) {
        log(`Hit label limit (${CONSTANTS.MAX_LABELS}), skipping further label checks`);
        hitLimits = true;
        continue;
      }
      log(`Adding new unique label: ${etldPlus1Label}`);
      uniqueLabels.add(etldPlus1Label);
    } else {
      log(`Label already processed: ${etldPlus1Label}`);
    }

    // Check if the origin matches the caller origin
    // We need case-sensitive comparison like Go, but URL constructor normalizes hostnames
    // So we'll extract and compare scheme and host manually
    const originScheme = originStr.split('://')[0];
    const originHost = originStr.split('://')[1]?.split('/')[0] || '';
    const callerScheme = callerOrigin.split('://')[0];
    const callerHost = callerOrigin.split('://')[1]?.split('/')[0] || '';
    
    log(`Comparing origin "${originScheme}://${originHost}" with caller "${callerScheme}://${callerHost}"`);
    if (originScheme === callerScheme && originHost === callerHost) {
      log(`Found matching origin: ${originStr}`);
      return AuthenticatorStatus.SUCCESS;
    }
  }

  if (hitLimits) {
    log(`Validation failed: Hit label limit without finding a match`);
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS;
  }
  log(`Validation failed: No matching origin found`);
  return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
}

/**
 * Fetches the .well-known/webauthn endpoint for the given domain.
 * 
 * @param domain The domain to fetch from (with or without protocol)
 * @param logger Optional logging adapter for logging messages
 * @returns Promise resolving to the JSON response as string
 */
export async function fetchWellKnownWebAuthn(domain: string, logger?: LoggingAdapter): Promise<string> {
  const log = createLoggingAdapter(logger || defaultLogger);
  // Ensure domain is properly formatted
  if (!domain.startsWith('https://') && !domain.startsWith('http://')) {
    log(`Adding https:// prefix to domain: ${domain}`);
    domain = 'https://' + domain;
  }

  // Parse the domain to ensure it's valid
  let parsedURL: URL;
  try {
    log(`Parsing domain URL: ${domain}`);
    parsedURL = new URL(domain);
  } catch (error) {
    log(`Failed to parse domain URL: ${domain}`, error instanceof Error ? error : new Error(String(error)));
    throw new Error(`Invalid domain: ${error}`);
  }

  // Construct the well-known URL
  const wellKnownURL = `${parsedURL.protocol}//${parsedURL.hostname}${CONSTANTS.WELL_KNOWN_PATH}`;
  log(`Constructed well-known URL: ${wellKnownURL}`);

  // Fetch with timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONSTANTS.TIMEOUT);
  log(`Fetching well-known endpoint with ${CONSTANTS.TIMEOUT}ms timeout`);

  try {
    const response = await fetch(wellKnownURL, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'passkey-origin-validator/1.0.0'
      }
    });

    clearTimeout(timeoutId);
    log(`Received response: HTTP ${response.status} ${response.statusText}`);

    if (!response.ok) {
      const errorMsg = `HTTP ${response.status}: ${response.statusText}`;
      log(`Error response: ${errorMsg}`);
      throw new Error(errorMsg);
    }

    // Check content length
    const contentLength = response.headers.get('content-length');
    if (contentLength) {
      log(`Content-Length header: ${contentLength} bytes`);
      if (parseInt(contentLength) > CONSTANTS.MAX_BODY_SIZE) {
        const errorMsg = `Response too large: ${contentLength} bytes`;
        log(errorMsg);
        throw new Error(errorMsg);
      }
    }

    const text = await response.text();
    log(`Received response body: ${text.length} bytes`);
    
    // Additional size check after reading
    if (text.length > CONSTANTS.MAX_BODY_SIZE) {
      const errorMsg = `Response too large: ${text.length} bytes`;
      log(errorMsg);
      throw new Error(errorMsg);
    }

    return text;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      log(`Request timed out after ${CONSTANTS.TIMEOUT}ms`);
      throw new Error('Request timeout');
    }
    log(`Fetch error`, error instanceof Error ? error : new Error(String(error)));
    throw error;
  }
}

/**
 * Checks if a domain (rpId) is a valid registrable domain suffix of an origin or matches it.
 * According to WebAuthn spec, a Relying Party ID (rpid) should be either:
 * 1. Equal to the origin's effective domain, or
 * 2. A registrable domain suffix of the origin's effective domain
 * 
 * For example, if the origin is 'https://sub.example.com', then 'example.com' is a valid rpId.
 * But if the origin is 'https://notexample.com', then 'example.com' is not a valid rpId.
 * 
 * @param callerOrigin The origin to validate
 * @param domain The domain (rpId) to check against
 * @returns true if the domain is valid for the origin, false otherwise
 */
function isValidDomainForOrigin(callerOrigin: string, domain: string): boolean {
  try {
    // Parse the caller origin
    const originURL = new URL(callerOrigin);
    const originHostname = originURL.hostname;
    
    // If domain exactly matches the hostname, it's valid
    if (domain === originHostname) {
      return true;
    }
    
    // Check if domain is a registrable domain suffix of the origin's hostname
    // For example, if origin is sub.example.com, then example.com is valid
    // But if origin is notexample.com, then example.com is not valid
    
    // First, ensure there's a proper subdomain boundary
    // The domain should be a suffix of the origin hostname, preceded by a dot
    if (!originHostname.endsWith('.' + domain)) {
      return false;
    }
    
    // Use psl to get the effective TLD+1 for both
    const originParsed = psl.parse(originHostname);
    const domainParsed = psl.parse(domain);
    
    // If either parsing fails, it's not valid
    if (!originParsed || typeof originParsed === 'string' || !('domain' in originParsed) || !originParsed.domain) {
      return false;
    }
    if (!domainParsed || typeof domainParsed === 'string' || !('domain' in domainParsed) || !domainParsed.domain) {
      return false;
    }
    
    // For the domain to be a valid rpId, it must be either:
    // 1. Equal to the origin's hostname, or
    // 2. A registrable domain suffix of the origin's hostname
    
    // Check if the domain is a registrable domain suffix of the origin's hostname
    // This means the domain must be either:
    // - The same as the origin's eTLD+1, or
    // - A parent domain of the origin's eTLD+1
    
    // Get the eTLD+1 for the origin (e.g., example.com from sub.example.com)
    const originETLDPlus1 = originParsed.domain;
    
    // Get the eTLD+1 for the domain (e.g., example.com from example.com)
    const domainETLDPlus1 = domainParsed.domain;
    
    // If the domain is the same as the origin's eTLD+1, it's valid
    if (domain === originETLDPlus1) {
      return true;
    }
    
    // If the domain's eTLD+1 is the same as the origin's eTLD+1,
    // and the domain is a suffix of the origin's hostname, it's valid
    if (domainETLDPlus1 === originETLDPlus1 && originHostname.endsWith('.' + domain)) {
      return true;
    }
    
    return false;
  } catch (error) {
    // If there's any error parsing the URLs, it's not valid
    return false;
  }
}

/**
 * Validates if a caller origin is authorized by first checking if the domain is a valid
 * effective subdomain of the origin or matches it. If not, it tries the .well-known/webauthn endpoint.
 * 
 * @param callerOrigin The origin to validate
 * @param domain The domain to check against
 * @param logger Optional logging adapter for logging messages
 * @returns Promise resolving to AuthenticatorStatus
 */
export async function validateOrigin(callerOrigin: string, domain: string, logger?: LoggingAdapter): Promise<AuthenticatorStatus> {
  const log = createLoggingAdapter(logger || defaultLogger);
  // First check if the domain is a valid effective subdomain of the origin or matches it
  log(`Validating if domain "${domain}" is a valid subdomain of origin "${callerOrigin}"`);
  if (isValidDomainForOrigin(callerOrigin, domain)) {
    log(`Domain "${domain}" is a valid subdomain of origin "${callerOrigin}"`);
    return AuthenticatorStatus.SUCCESS;
  }
  
  // If not, try the well-known endpoint
  log(`Domain "${domain}" is not a valid subdomain of origin "${callerOrigin}", trying .well-known/webauthn endpoint`);
  try {
    const jsonData = await fetchWellKnownWebAuthn(domain, logger);
    log(`Successfully fetched .well-known/webauthn data for domain "${domain}", validating JSON`);
    return validateWellKnownJSON(callerOrigin, jsonData, logger);
  } catch (error) {
    // If there's an error fetching or parsing the well-known endpoint, it's not valid
    log(`Failed to fetch or parse .well-known/webauthn for domain "${domain}"`, error instanceof Error ? error : new Error(String(error)));
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
  }
}