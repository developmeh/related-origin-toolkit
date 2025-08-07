# Passkey Origin Validator (TypeScript)

A TypeScript library for validating passkey/WebAuthn origin constraints in .well-known/webauthn endpoints. This library is based on the Chromium project's implementation of WebAuthn security checking and helps ensure that your WebAuthn implementation follows the same constraints as browsers.

**Designed specifically for password manager browser extensions** and other WebAuthn implementations that need to validate origin requests.

## Features

- ✅ **Chromium-compatible validation** - Uses the same validation logic as Chromium browsers
- ✅ **Browser extension ready** - Designed for use in browser extensions with proper CORS handling
- ✅ **TypeScript support** - Full TypeScript definitions included
- ✅ **Comprehensive testing** - Extensive test suite matching the original Go implementation
- ✅ **Label limit enforcement** - Enforces the 5-label limit per .well-known/webauthn endpoint
- ✅ **Case-sensitive validation** - Proper case-sensitive origin matching
- ✅ **Timeout and size limits** - Built-in protection against large responses and timeouts

## Installation

```bash
npm install passkey-origin-validator
```

## Quick Start

### Basic Usage

```typescript
import { validatePasskeyOrigin } from 'passkey-origin-validator';

// Validate an origin against a relying party's .well-known/webauthn endpoint
const result = await validatePasskeyOrigin('example.com', 'https://app.example.com');

if (result.isValid) {
  console.log('Origin is authorized!');
} else {
  console.log(`Validation failed: ${result.message}`);
}
```

### Browser Extension Usage

```typescript
import { validatePasskeyOrigin, AuthenticatorStatus } from 'passkey-origin-validator';

// In your browser extension's content script or background script
async function validateWebAuthnRequest(rpId: string, origin: string) {
  try {
    const result = await validatePasskeyOrigin(rpId, origin);
    
    if (result.isValid) {
      // Allow the WebAuthn request
      return { allowed: true };
    } else {
      // Block the request and provide reason
      return { 
        allowed: false, 
        reason: result.message,
        status: result.status 
      };
    }
  } catch (error) {
    // Handle network errors, invalid domains, etc.
    return { 
      allowed: false, 
      reason: `Validation error: ${error.message}` 
    };
  }
}
```

### Using Pre-fetched JSON

If you already have the .well-known/webauthn JSON data:

```typescript
import { validatePasskeyOriginFromJSON } from 'passkey-origin-validator';

const wellKnownJson = '{"origins": ["https://example.com", "https://app.example.com"]}';
const result = validatePasskeyOriginFromJSON('https://app.example.com', wellKnownJson);

console.log(result.isValid); // true
```

## API Reference

### Main Functions

#### `validatePasskeyOrigin(rpId: string, origin: string)`

Validates an origin against a relying party's .well-known/webauthn endpoint.

**Parameters:**
- `rpId` - The Relying Party ID (domain) to check
- `origin` - The caller origin to validate

**Returns:** `Promise<ValidationResult>`

```typescript
interface ValidationResult {
  isValid: boolean;
  status: AuthenticatorStatus;
  message: string;
}
```

#### `validatePasskeyOriginFromJSON(origin: string, wellKnownJson: string)`

Validates an origin against pre-fetched .well-known/webauthn JSON data.

**Parameters:**
- `origin` - The caller origin to validate
- `wellKnownJson` - The JSON string from the .well-known/webauthn endpoint

**Returns:** `ValidationResult`

### Status Codes

The library uses the same status codes as the Chromium implementation:

```typescript
enum AuthenticatorStatus {
  SUCCESS = 0,
  BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR = 1,
  BAD_RELYING_PARTY_ID_NO_JSON_MATCH = 2,
  BAD_RELYING_PARTY_ID_NO_JSON_MATCH_HIT_LIMITS = 3,
}
```

### Utility Functions

#### `isValidationSuccessful(status: AuthenticatorStatus): boolean`

Checks if a status indicates successful validation.

#### `isParsingError(status: AuthenticatorStatus): boolean`

Checks if a status indicates a JSON parsing error.

#### `isLabelLimitHit(status: AuthenticatorStatus): boolean`

Checks if a status indicates the label limit was exceeded.

### Low-level Functions

For advanced use cases, you can use the low-level functions:

#### `validateWellKnownJSON(callerOrigin: string, jsonData: string): AuthenticatorStatus`

Core validation function that takes JSON data and returns a status code.

#### `fetchWellKnownWebAuthn(domain: string): Promise<string>`

Fetches the .well-known/webauthn endpoint for a domain.

#### `validateOrigin(callerOrigin: string, domain: string): Promise<AuthenticatorStatus>`

Validates if a caller origin is authorized by fetching and checking a domain's .well-known/webauthn file.

## Validation Rules

The library follows the same validation rules as Chromium:

1. **JSON Structure**: The .well-known/webauthn file must contain a valid JSON object with an "origins" array
2. **Origin Matching**: Origins are matched case-sensitively using scheme + host comparison
3. **Label Limit**: Maximum of 5 unique eTLD+1 labels are processed per .well-known file
4. **Size Limit**: Response bodies are limited to 256KB
5. **Timeout**: Requests timeout after 10 seconds

## Error Handling

The library handles various error conditions:

- **Network errors**: DNS failures, connection timeouts, etc.
- **HTTP errors**: 404, 500, etc.
- **JSON parsing errors**: Invalid JSON format
- **Size limit exceeded**: Response too large
- **Label limit exceeded**: Too many unique domains in origins array

## Browser Compatibility

This library is designed to work in:

- ✅ Browser extensions (Chrome, Firefox, Safari, Edge)
- ✅ Node.js applications
- ✅ Modern browsers with fetch API support

## Security Considerations

- The library enforces the same security constraints as Chromium browsers
- Case-sensitive origin matching prevents bypass attempts
- Label limits prevent abuse of .well-known endpoints
- Size and timeout limits prevent DoS attacks

## Examples

### Complete Browser Extension Example

```typescript
// background.js or content script
import { 
  validatePasskeyOrigin, 
  AuthenticatorStatus,
  isLabelLimitHit 
} from 'passkey-origin-validator';

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
  if (request.type === 'VALIDATE_WEBAUTHN_ORIGIN') {
    const { rpId, origin } = request;
    
    try {
      const result = await validatePasskeyOrigin(rpId, origin);
      
      if (result.isValid) {
        sendResponse({ 
          allowed: true,
          message: 'Origin validated successfully' 
        });
      } else {
        let reason = 'Origin not authorized';
        
        if (isLabelLimitHit(result.status)) {
          reason = 'Too many domains in .well-known file';
        } else if (result.status === AuthenticatorStatus.BAD_RELYING_PARTY_ID_JSON_PARSE_ERROR) {
          reason = 'Invalid .well-known/webauthn format';
        }
        
        sendResponse({ 
          allowed: false, 
          reason,
          status: result.status 
        });
      }
    } catch (error) {
      sendResponse({ 
        allowed: false, 
        reason: `Validation failed: ${error.message}` 
      });
    }
  }
});
```

### Node.js Server Example

```typescript
import express from 'express';
import { validatePasskeyOrigin } from 'passkey-origin-validator';

const app = express();

app.post('/validate-origin', async (req, res) => {
  const { rpId, origin } = req.body;
  
  try {
    const result = await validatePasskeyOrigin(rpId, origin);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      isValid: false,
      message: `Validation error: ${error.message}`
    });
  }
});

app.listen(3000);
```

### React Hook Example

```typescript
import { useState, useCallback } from 'react';
import { validatePasskeyOrigin, ValidationResult } from 'passkey-origin-validator';

export function usePasskeyValidation() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ValidationResult | null>(null);

  const validate = useCallback(async (rpId: string, origin: string) => {
    setIsLoading(true);
    try {
      const validationResult = await validatePasskeyOrigin(rpId, origin);
      setResult(validationResult);
      return validationResult;
    } catch (error) {
      const errorResult = {
        isValid: false,
        status: AuthenticatorStatus.BAD_RELYING_PARTY_ID_NO_JSON_MATCH,
        message: `Validation failed: ${error.message}`
      };
      setResult(errorResult);
      return errorResult;
    } finally {
      setIsLoading(false);
    }
  }, []);

  return { validate, isLoading, result };
}
```

## Development

### Building

```bash
make build
# or
npm run build
```

### Testing

```bash
make test
# or
npm test
```

## Continuous Integration and Deployment

This project uses GitHub Actions for continuous integration and deployment:

### Automated Testing

Tests are automatically run on:
- Every push to the master branch
- Every pull request targeting the master branch

The test workflow runs across multiple Node.js versions (16.x, 18.x, 20.x) to ensure compatibility.

### Automated Releases

When you push a tag starting with 'v' (e.g., v1.0.0), GitHub Actions will:
1. Run tests to ensure everything is working
2. Build the project
3. Create a GitHub release with the tag name
4. Attach the compiled dist directory as a tarball to the release
5. Publish the package to npm

To create a new release:
```bash
# Update version in package.json first
npm version patch  # or minor, or major
git push --follow-tags
```

### Testing with Watch Mode

```bash
make test-watch
# or
npm run test:watch
```

### Development Mode

```bash
make dev
# or
npm run dev
```

### Running Examples

```bash
# Test with webauthn.io
make run DOMAIN=webauthn.io ORIGIN=https://webauthn.io

# Test with custom domain
make run DOMAIN=example.com ORIGIN=https://app.example.com
```

### Private Registry Support

```bash
# Install from private registry
make deps PRIVATE_REGISTRY=https://npm.company.com/

# Publish to private registry
make publish PRIVATE_REGISTRY=https://npm.company.com/
```

## TypeScript Configuration

The library is built with strict TypeScript settings:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020", "DOM"],
    "module": "CommonJS",
    "strict": true,
    "declaration": true,
    "sourceMap": true
  }
}
```

## Testing

The library includes comprehensive tests covering:

- ✅ All validation scenarios from the Go implementation
- ✅ Edge cases and error conditions
- ✅ Network error handling
- ✅ Browser extension compatibility
- ✅ Label limit enforcement
- ✅ Case sensitivity validation

Run tests with:
```bash
npm test
```

## License

MIT

## Contributing

Contributions are welcome! Please ensure that any changes maintain compatibility with the Chromium WebAuthn implementation.

### Development Setup

1. Clone the repository
2. Navigate to the typescript directory: `cd typescript/`
3. Install dependencies: `make deps`
4. Run tests: `make test`
5. Build the library: `make build`

### Running Tests

```bash
# Run all tests
make test

# Run tests in watch mode
make test-watch

# Run with coverage
npm test -- --coverage
```

## Related Projects

- [Original Go Implementation](../README.md) - The Go version this library is based on
- [Chromium WebAuthn Implementation](https://source.chromium.org/) - The reference implementation