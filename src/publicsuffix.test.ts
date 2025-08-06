import { validateWellKnownJSON } from './validator';
import { AuthenticatorStatus } from './types';

describe('Public Suffix (eTLD+1) Validation', () => {
  describe('Complex TLD handling', () => {
    it('should handle .co.uk domains correctly', () => {
      // Test that example.co.uk and test.co.uk are treated as different labels
      const json = JSON.stringify({
        origins: [
          'https://example.co.uk',
          'https://test.co.uk',
          'https://another.co.uk',
          'https://fourth.co.uk',
          'https://fifth.co.uk',
          'https://target.co.uk' // This should hit the limit
        ]
      });

      const result = validateWellKnownJSON('https://target.co.uk', json);
      expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS);
    });

    it('should handle .com.au domains correctly', () => {
      // Test that example.com.au and test.com.au are treated as different labels
      const json = JSON.stringify({
        origins: [
          'https://example.com.au',
          'https://test.com.au',
          'https://another.com.au',
          'https://fourth.com.au',
          'https://target.com.au' // This should be found within the limit
        ]
      });

      const result = validateWellKnownJSON('https://target.com.au', json);
      expect(result).toBe(AuthenticatorStatus.SUCCESS);
    });

    it('should handle mixed complex TLDs correctly', () => {
      // Test mixing different complex TLDs
      const json = JSON.stringify({
        origins: [
          'https://example.co.uk',    // Label: example
          'https://test.com.au',      // Label: test
          'https://another.co.jp',    // Label: another
          'https://fourth.org.uk',    // Label: fourth
          'https://fifth.net.au',     // Label: fifth
          'https://target.co.uk'      // This should hit the limit
        ]
      });

      const result = validateWellKnownJSON('https://target.co.uk', json);
      expect(result).toBe(AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS);
    });

    it('should treat subdomains of same eTLD+1 as same label', () => {
      // Test that sub1.example.co.uk and sub2.example.co.uk are treated as same label
      const json = JSON.stringify({
        origins: [
          'https://sub1.example.co.uk',
          'https://sub2.example.co.uk',
          'https://example.co.uk',
          'https://www.example.co.uk',
          'https://api.example.co.uk',
          'https://target.co.uk' // Different eTLD+1, should be found
        ]
      });

      const result = validateWellKnownJSON('https://target.co.uk', json);
      expect(result).toBe(AuthenticatorStatus.SUCCESS);
    });

    it('should handle regular .com domains correctly', () => {
      // Test that regular .com domains work as expected
      const json = JSON.stringify({
        origins: [
          'https://example.com',
          'https://test.com',
          'https://another.com',
          'https://fourth.com',
          'https://target.com'
        ]
      });

      const result = validateWellKnownJSON('https://target.com', json);
      expect(result).toBe(AuthenticatorStatus.SUCCESS);
    });

    it('should handle edge case with invalid public suffix', () => {
      // Test with domains that might not have valid public suffixes
      const json = JSON.stringify({
        origins: [
          'https://localhost',
          'https://example.invalid',
          'https://target.com'
        ]
      });

      const result = validateWellKnownJSON('https://target.com', json);
      expect(result).toBe(AuthenticatorStatus.SUCCESS);
    });
  });

  describe('Label extraction consistency', () => {
    it('should extract correct labels from various domain formats', () => {
      // This test verifies that our label extraction matches expected behavior
      const testCases = [
        {
          domain: 'example.co.uk',
          expectedToWork: true,
          description: 'UK second-level domain'
        },
        {
          domain: 'test.com.au', 
          expectedToWork: true,
          description: 'Australian second-level domain'
        },
        {
          domain: 'sample.org.uk',
          expectedToWork: true, 
          description: 'UK organization domain'
        },
        {
          domain: 'demo.net.au',
          expectedToWork: true,
          description: 'Australian network domain'
        }
      ];

      testCases.forEach(testCase => {
        const json = JSON.stringify({
          origins: [`https://${testCase.domain}`]
        });

        const result = validateWellKnownJSON(`https://${testCase.domain}`, json);
        
        if (testCase.expectedToWork) {
          expect(result).toBe(AuthenticatorStatus.SUCCESS);
        } else {
          expect(result).not.toBe(AuthenticatorStatus.SUCCESS);
        }
      });
    });
  });
});