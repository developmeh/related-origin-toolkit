import * as psl from 'psl';
import { AuthenticatorStatus, WebAuthnResponse, CONSTANTS } from './types';

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
 * @returns AuthenticatorStatus indicating the validation result
 */
export function validateWellKnownJSON(callerOrigin: string, jsonData: string): AuthenticatorStatus {
  let webAuthnResp: WebAuthnResponse;
  
  // Parse the JSON
  try {
    webAuthnResp = JSON.parse(jsonData);
  } catch (error) {
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
  }

  // Check if the origins array exists and is an array
  if (!webAuthnResp.origins || !Array.isArray(webAuthnResp.origins)) {
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
  }

  // Validate that all origins are strings
  for (const origin of webAuthnResp.origins) {
    if (typeof origin !== 'string') {
      return AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR;
    }
  }

  // Parse the caller origin
  let callerURL: URL;
  try {
    callerURL = new URL(callerOrigin);
  } catch (error) {
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
  }

  // Count unique labels and check if the caller origin is authorized
  const uniqueLabels = new Set<string>();
  let hitLimits = false;

  for (const originStr of webAuthnResp.origins) {
    let originURL: URL;
    try {
      originURL = new URL(originStr);
    } catch (error) {
      continue;
    }

    // Extract the domain
    const domain = originURL.hostname;
    if (!domain) {
      continue;
    }

    // Extract the eTLD+1 label using psl package
    let etldPlus1Label: string;
    try {
      etldPlus1Label = getLabel(domain);
    } catch (error) {
      // Skip this origin if we can't extract the label
      continue;
    }

    if (!uniqueLabels.has(etldPlus1Label)) {
      if (uniqueLabels.size >= CONSTANTS.MAX_LABELS) {
        hitLimits = true;
        continue;
      }
      uniqueLabels.add(etldPlus1Label);
    }

    // Check if the origin matches the caller origin
    // We need case-sensitive comparison like Go, but URL constructor normalizes hostnames
    // So we'll extract and compare scheme and host manually
    const originScheme = originStr.split('://')[0];
    const originHost = originStr.split('://')[1]?.split('/')[0] || '';
    const callerScheme = callerOrigin.split('://')[0];
    const callerHost = callerOrigin.split('://')[1]?.split('/')[0] || '';
    
    if (originScheme === callerScheme && originHost === callerHost) {
      return AuthenticatorStatus.SUCCESS;
    }
  }

  if (hitLimits) {
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS;
  }
  return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
}

/**
 * Fetches the .well-known/webauthn endpoint for the given domain.
 * 
 * @param domain The domain to fetch from (with or without protocol)
 * @returns Promise resolving to the JSON response as string
 */
export async function fetchWellKnownWebAuthn(domain: string): Promise<string> {
  // Ensure domain is properly formatted
  if (!domain.startsWith('https://') && !domain.startsWith('http://')) {
    domain = 'https://' + domain;
  }

  // Parse the domain to ensure it's valid
  let parsedURL: URL;
  try {
    parsedURL = new URL(domain);
  } catch (error) {
    throw new Error(`Invalid domain: ${error}`);
  }

  // Construct the well-known URL
  const wellKnownURL = `${parsedURL.protocol}//${parsedURL.hostname}${CONSTANTS.WELL_KNOWN_PATH}`;

  // Fetch with timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONSTANTS.TIMEOUT);

  try {
    const response = await fetch(wellKnownURL, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'passkey-origin-validator/1.0.0'
      }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    // Check content length
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > CONSTANTS.MAX_BODY_SIZE) {
      throw new Error(`Response too large: ${contentLength} bytes`);
    }

    const text = await response.text();
    
    // Additional size check after reading
    if (text.length > CONSTANTS.MAX_BODY_SIZE) {
      throw new Error(`Response too large: ${text.length} bytes`);
    }

    return text;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
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
 * @returns Promise resolving to AuthenticatorStatus
 */
export async function validateOrigin(callerOrigin: string, domain: string): Promise<AuthenticatorStatus> {
  // First check if the domain is a valid effective subdomain of the origin or matches it
  if (isValidDomainForOrigin(callerOrigin, domain)) {
    return AuthenticatorStatus.SUCCESS;
  }
  
  // If not, try the well-known endpoint
  try {
    const jsonData = await fetchWellKnownWebAuthn(domain);
    return validateWellKnownJSON(callerOrigin, jsonData);
  } catch (error) {
    // If there's an error fetching or parsing the well-known endpoint, it's not valid
    return AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH;
  }
}