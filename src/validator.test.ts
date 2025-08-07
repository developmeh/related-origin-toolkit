import { validateWellKnownJSON, fetchWellKnownWebAuthn, validateOrigin } from './validator';
import { AuthenticatorStatus } from './types';

describe('validateWellKnownJSON', () => {
  const testCases = [
    {
      name: 'Empty JSON',
      callerOrigin: 'https://foo.com',
      json: '[]',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
    },
    {
      name: 'Empty object',
      callerOrigin: 'https://foo.com',
      json: '{}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
    },
    {
      name: 'Missing origins key',
      callerOrigin: 'https://foo.com',
      json: '{"foo": "bar"}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
    },
    {
      name: 'Origins not an array',
      callerOrigin: 'https://foo.com',
      json: '{"origins": "bar"}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
    },
    {
      name: 'Empty origins array',
      callerOrigin: 'https://foo.com',
      json: '{"origins": []}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
    },
    {
      name: 'Origins array with non-string',
      callerOrigin: 'https://foo.com',
      json: '{"origins": [1]}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR,
    },
    {
      name: 'Origins array with matching origin',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://foo.com"]}',
      expected: AuthenticatorStatus.SUCCESS,
    },
    {
      name: 'Origins array with non-matching origin',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://foo2.com"]}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
    },
    {
      name: 'Origins array with invalid domain',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://com"]}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
    },
    {
      name: 'Origins array with different scheme',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["other://foo.com"]}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
    },
    {
      name: 'Origins array with 5 different labels and matching origin',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://foo.com"]}',
      expected: AuthenticatorStatus.SUCCESS,
    },
    {
      name: 'Origins array with 6 different labels and matching origin at the end',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://foo.com"]}',
      expected: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS,
    },
    {
      name: 'Origins array with 6 different labels and matching origin in the middle',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://foo.com", "https://e.com"]}',
      expected: AuthenticatorStatus.SUCCESS,
    },
    {
      name: 'Origins array with different TLDs but same domain name',
      callerOrigin: 'https://foo.com',
      json: '{"origins": ["https://foo.co.uk", "https://foo.de", "https://foo.in", "https://foo.net", "https://foo.org", "https://foo.com"]}',
      expected: AuthenticatorStatus.SUCCESS,
    },
  ];

  testCases.forEach((testCase) => {
    it(testCase.name, () => {
      const result = validateWellKnownJSON(testCase.callerOrigin, testCase.json);
      expect(result).toBe(testCase.expected);
    });
  });

  // Additional edge cases
  it('should handle malformed JSON', () => {
    const result = validateWellKnownJSON('https://foo.com', '{invalid json}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR);
  });

  it('should handle invalid caller origin', () => {
    const result = validateWellKnownJSON('invalid-url', '{"origins": ["https://foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
  });

  it('should handle origins with invalid URLs', () => {
    const result = validateWellKnownJSON('https://foo.com', '{"origins": ["invalid-url", "https://foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
  });

  it('should handle origins with empty strings', () => {
    const result = validateWellKnownJSON('https://foo.com', '{"origins": ["", "https://foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
  });

  it('should handle case sensitivity in protocol', () => {
    const result = validateWellKnownJSON('https://foo.com', '{"origins": ["HTTPS://foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
  });

  it('should handle case sensitivity in hostname', () => {
    const result = validateWellKnownJSON('https://foo.com', '{"origins": ["https://FOO.COM"]}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
  });

  it('should handle ports in origins', () => {
    const result = validateWellKnownJSON('https://foo.com:8080', '{"origins": ["https://foo.com:8080"]}');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
  });

  it('should handle different ports', () => {
    const result = validateWellKnownJSON('https://foo.com:8080', '{"origins": ["https://foo.com:9090"]}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
  });

  it('should handle paths in origins (should be ignored)', () => {
    const result = validateWellKnownJSON('https://foo.com', '{"origins": ["https://foo.com/path"]}');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
  });

  it('should handle subdomains correctly', () => {
    const result = validateWellKnownJSON('https://sub.foo.com', '{"origins": ["https://sub.foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
  });

  it('should not match different subdomains', () => {
    const result = validateWellKnownJSON('https://sub1.foo.com', '{"origins": ["https://sub2.foo.com"]}');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
  });
});

describe('fetchWellKnownWebAuthn', () => {
  // Mock fetch for testing
  const originalFetch = global.fetch;
  
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it('should construct correct URL with https prefix', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://example.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    await fetchWellKnownWebAuthn('example.com');

    expect(global.fetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/webauthn',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Accept': 'application/json',
          'User-Agent': 'passkey-origin-validator/1.0.0'
        })
      })
    );
  });

  it('should handle domain with existing protocol', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://example.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    await fetchWellKnownWebAuthn('https://example.com');

    expect(global.fetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/webauthn',
      expect.any(Object)
    );
  });

  it('should throw error for invalid domain', async () => {
    await expect(fetchWellKnownWebAuthn('invalid domain with spaces')).rejects.toThrow('Invalid domain');
  });

  it('should throw error for HTTP error responses', async () => {
    const mockResponse = {
      ok: false,
      status: 404,
      statusText: 'Not Found',
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    await expect(fetchWellKnownWebAuthn('example.com')).rejects.toThrow('HTTP 404: Not Found');
  });

  it('should throw error for responses that are too large', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('x'.repeat(300000)), // Larger than MAX_BODY_SIZE
      headers: new Map([['content-length', '300000']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    await expect(fetchWellKnownWebAuthn('example.com')).rejects.toThrow('Response too large');
  });

  it('should handle network errors', async () => {
    (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

    await expect(fetchWellKnownWebAuthn('example.com')).rejects.toThrow('Network error');
  });
});

describe('validateOrigin', () => {
  const originalFetch = global.fetch;
  
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
  });

  // Direct domain validation tests
  it('should return SUCCESS when domain exactly matches origin hostname', async () => {
    // No fetch call should be made
    const result = await validateOrigin('https://example.com', 'example.com');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should return SUCCESS when domain is a valid registrable domain suffix of origin hostname', async () => {
    // No fetch call should be made
    const result = await validateOrigin('https://sub.example.com', 'example.com');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should return SUCCESS for multi-level subdomains', async () => {
    // No fetch call should be made
    const result = await validateOrigin('https://deep.sub.example.com', 'example.com');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('should not validate when domain is not a proper suffix (no subdomain boundary)', async () => {
    // This should fail the direct validation and try the well-known endpoint
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://other.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validateOrigin('https://notexample.com', 'example.com');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should not validate when domain is a different TLD', async () => {
    // This should fail the direct validation and try the well-known endpoint
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://other.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validateOrigin('https://example.com', 'example.org');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(global.fetch).toHaveBeenCalled();
  });

  // Well-known endpoint fallback tests
  it('should fallback to well-known endpoint and return SUCCESS when it matches', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://foo.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validateOrigin('https://foo.com', 'bar.com');
    expect(result).toBe(AuthenticatorStatus.SUCCESS);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should return BAD_RELYING_PARTY_ID_NO_JSON_MATCH when both checks fail', async () => {
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue('{"origins": ["https://bar.com"]}'),
      headers: new Map([['content-length', '100']]),
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validateOrigin('https://foo.com', 'baz.com');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should return BAD_RELYING_PARTY_ID_NO_JSON_MATCH for fetch errors', async () => {
    (global.fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

    const result = await validateOrigin('https://foo.com', 'bar.com');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('should return BAD_RELYING_PARTY_ID_NO_JSON_MATCH for 404 responses', async () => {
    const mockResponse = {
      ok: false,
      status: 404,
      statusText: 'Not Found',
    };
    (global.fetch as jest.Mock).mockResolvedValue(mockResponse);

    const result = await validateOrigin('https://foo.com', 'bar.com');
    expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH);
    expect(global.fetch).toHaveBeenCalled();
  });
});