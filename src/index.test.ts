import {
  validatePasskeyOrigin,
  validatePasskeyOriginFromJSON,
  isValidationSuccessful,
  isParsingError,
  isLabelLimitHit,
  AuthenticatorStatus,
  authenticatorStatusToString
} from './index';

describe('validatePasskeyOrigin', () => {
  const originalFetch = global.fetch;
  
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it('should return valid result for successful validation', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://foo.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validatePasskeyOrigin('foo.com', 'https://foo.com');
    
    expect(result.isValid).toBe(true);
    expect(result.status).toBe(AuthenticatorStatus.SUCCESS);
    expect(result.message).toBe('Success');
  });

  it('should return invalid result for non-matching origin', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://bar.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    // Use a different domain that is not a valid rpId for the origin
    // 'bar.com' is not a valid rpId for 'https://foo.com'
    const result = await validatePasskeyOrigin('bar.com', 'https://foo.com');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(result.message).toBe('Origin not authorized by the relying party');
  });

  it('should return invalid result for fetch errors', async () => {
    (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

    // Use a different domain that is not a valid rpId for the origin
    // 'bar.com' is not a valid rpId for 'https://foo.com'
    const result = await validatePasskeyOrigin('bar.com', 'https://foo.com');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(result.message).toBe('Origin not authorized by the relying party');
  });

  it('should return invalid result for 404 responses', async () => {
    const mockResponse = {
      ok: false,
      status: 404,
      statusText: 'Not Found',
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    // Use a different domain that is not a valid rpId for the origin
    // 'bar.com' is not a valid rpId for 'https://foo.com'
    const result = await validatePasskeyOrigin('bar.com', 'https://foo.com');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(result.message).toBe('Origin not authorized by the relying party');
  });

  it('should handle label limit hit scenario', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://foo.com"]}'),
      headers: new Map([['content-length', '200']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    // Use a different domain that is not a valid rpId for the origin
    // 'bar.com' is not a valid rpId for 'https://foo.com'
    const result = await validatePasskeyOrigin('bar.com', 'https://foo.com');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS);
    expect(result.message).toBe('Origin not authorized by the relying party (exceeded maximum of 5 unique domains)');
  });
});

describe('validatePasskeyOriginFromJSON', () => {
  it('should return valid result for successful validation', () => {
    const result = validatePasskeyOriginFromJSON('https://foo.com', '{"origins": ["https://foo.com"]}');
    
    expect(result.isValid).toBe(true);
    expect(result.status).toBe(AuthenticatorStatus.SUCCESS);
    expect(result.message).toBe('Success');
  });

  it('should return invalid result for non-matching origin', () => {
    const result = validatePasskeyOriginFromJSON('https://foo.com', '{"origins": ["https://bar.com"]}');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(result.message).toBe('Origin not authorized by the relying party');
  });

  it('should return invalid result for malformed JSON', () => {
    const result = validatePasskeyOriginFromJSON('https://foo.com', '{invalid json}');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR);
    expect(result.message).toBe('Invalid format in .well-known/webauthn file');
  });

  it('should return invalid result for empty origins array', () => {
    const result = validatePasskeyOriginFromJSON('https://foo.com', '{"origins": []}');
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(result.message).toBe('Origin not authorized by the relying party');
  });

  it('should handle label limit hit scenario', () => {
    const json = '{"origins": ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://foo.com"]}';
    const result = validatePasskeyOriginFromJSON('https://foo.com', json);
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS);
    expect(result.message).toBe('Origin not authorized by the relying party (exceeded maximum of 5 unique domains)');
  });

  it('should handle exceptions gracefully', () => {
    // This should not happen in normal usage, but test error handling
    const result = validatePasskeyOriginFromJSON('https://foo.com', null as any);
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR);
    expect(result.message).toContain('Validation failed');
  });
});

describe('utility functions', () => {
  describe('isValidationSuccessful', () => {
    it('should return true for SUCCESS status', () => {
      expect(isValidationSuccessful(AuthenticatorStatus.SUCCESS)).toBe(true);
    });

    it('should return false for non-SUCCESS statuses', () => {
      expect(isValidationSuccessful(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR)).toBe(false);
      expect(isValidationSuccessful(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH)).toBe(false);
      expect(isValidationSuccessful(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS)).toBe(false);
    });
  });

  describe('isParsingError', () => {
    it('should return true for JSON_PARSE_ERROR status', () => {
      expect(isParsingError(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR)).toBe(true);
    });

    it('should return false for non-parsing-error statuses', () => {
      expect(isParsingError(AuthenticatorStatus.SUCCESS)).toBe(false);
      expect(isParsingError(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH)).toBe(false);
      expect(isParsingError(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS)).toBe(false);
    });
  });

  describe('isLabelLimitHit', () => {
    it('should return true for HIT_LIMITS status', () => {
      expect(isLabelLimitHit(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS)).toBe(true);
    });

    it('should return false for non-hit-limits statuses', () => {
      expect(isLabelLimitHit(AuthenticatorStatus.SUCCESS)).toBe(false);
      expect(isLabelLimitHit(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR)).toBe(false);
      expect(isLabelLimitHit(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH)).toBe(false);
    });
  });

  describe('authenticatorStatusToString', () => {
    it('should convert all status values to correct strings', () => {
      expect(authenticatorStatusToString(AuthenticatorStatus.SUCCESS)).toBe('Success');
      expect(authenticatorStatusToString(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR)).toBe('Invalid format in .well-known/webauthn file');
      expect(authenticatorStatusToString(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH)).toBe('Origin not authorized by the relying party');
      expect(authenticatorStatusToString(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS)).toBe('Origin not authorized by the relying party (exceeded maximum of 5 unique domains)');
      expect(authenticatorStatusToString(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NOT_SUBDOMAIN_OF_ORIGIN)).toBe('Relying Party ID is not a valid subdomain of the origin');
    });

    it('should handle unknown status values', () => {
      expect(authenticatorStatusToString(999 as AuthenticatorStatus)).toBe('Unknown status (999)');
    });
  });
});

describe('integration tests', () => {
  const originalFetch = global.fetch;
  
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it('should work end-to-end for a typical browser extension use case', async () => {
    // Simulate a typical scenario where a browser extension validates an origin
    // 'example.com' is a valid rpId for 'https://app.example.com'
    const rpId = 'example.com';
    const origin = 'https://app.example.com';
    
    // No need for mock response since the direct validation should succeed
    const result = await validatePasskeyOrigin(rpId, origin);
    
    expect(result.isValid).toBe(true);
    expect(result.status).toBe(AuthenticatorStatus.SUCCESS);
    expect(result.message).toBe('Success');
    
    // Direct validation should succeed, so fetch should not be called
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should handle real-world edge cases with well-known fallback', async () => {
    // Test with a case where direct validation fails but well-known succeeds
    // 'other.com' is not a valid rpId for 'https://example.com'
    const rpId = 'other.com';
    const origin = 'https://example.com';
    const wellKnownResponse = {
      origins: [
        'https://example.com'
      ]
    };

    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue(JSON.stringify(wellKnownResponse)),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validatePasskeyOrigin(rpId, origin);
    
    expect(result.isValid).toBe(true);
    expect(result.status).toBe(AuthenticatorStatus.SUCCESS);
    expect(result.message).toBe('Success');
    
    // Verify the correct URL was fetched
    expect(global.fetch).toHaveBeenCalledWith(
      'https://other.com/.well-known/webauthn',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Accept': 'application/json',
          'User-Agent': 'passkey-origin-validator/1.0.0'
        })
      })
    );
  });

  it('should handle label limit hit scenario in well-known endpoint', async () => {
    // Test with a complex .well-known response that hits the label limit
    // 'other.com' is not a valid rpId for 'https://target.example.com'
    const rpId = 'other.com';
    const origin = 'https://target.example.com';
    const wellKnownResponse = {
      origins: [
        'https://a.com',
        'https://b.net',
        'https://c.org',
        'https://d.co.uk',
        'https://e.de',
        'https://target.example.com', // This should not be found due to label limit
      ]
    };

    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue(JSON.stringify(wellKnownResponse)),
      headers: new Map([['content-length', '300']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validatePasskeyOrigin(rpId, origin);
    
    expect(result.isValid).toBe(false);
    expect(result.status).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS);
    expect(isLabelLimitHit(result.status)).toBe(true);
  });
});