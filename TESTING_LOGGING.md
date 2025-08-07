# Testing the Logging Functionality

This document describes how to test the logging functionality in the Related Origin Toolkit.

## Overview

The Related Origin Toolkit includes a logging system that allows for:
1. Default logging using `console.log`
2. Custom logging through a `LoggingAdapter` interface
3. Error handling for logging functions

The logging functionality is implemented in `src/logger.ts` and is used throughout the codebase.

## Test Files

The logging functionality is tested in the following files:

1. `src/logger.test.ts` - Tests for the core logging functionality
2. `src/validator.test.ts` - Tests for logging in validator functions
3. `src/index.test.ts` - Tests for logging in index functions

## Testing Approach

### Testing the Core Logging Functionality

The core logging functionality is tested in `src/logger.test.ts`. This file includes tests for:

1. `defaultLogger` - Tests that it correctly logs messages with and without errors
2. `createLoggingAdapter` - Tests that it:
   - Uses the defaultLogger when no logger is provided
   - Uses the provided logger when one is provided
   - Handles errors in the logger and falls back to console.log
   - Passes both message and error to the logger when provided

### Testing Logging in Validator Functions

The validator functions are tested in `src/validator.test.ts`. This file includes tests that verify:

1. `validateWellKnownJSON` uses the provided logger
2. `fetchWellKnownWebAuthn` uses the provided logger
3. `validateOrigin` uses the provided logger for both direct validation and well-known validation

### Testing Logging in Index Functions

The index functions are tested in `src/index.test.ts`. This file includes tests that verify:

1. `validatePasskeyOrigin` uses the provided logger for both successful and failing validation
2. `validatePasskeyOriginFromJSON` uses the provided logger for successful validation, failed validation, and exception handling

## How to Run the Tests

To run all tests, use:

```bash
npm test
```

To run only the logging tests, use:

```bash
npm test -- -t "logger"
```

## Adding New Tests for Logging

When adding new functionality that uses logging, follow these guidelines:

1. Always test that the function accepts a logger parameter
2. Test that the function uses the provided logger
3. Test that the function falls back to the default logger when none is provided
4. For functions that can fail, test that logging occurs in both success and failure cases

## Mocking Loggers for Testing

To test logging functionality, create a mock logger using Jest's mocking capabilities:

```typescript
const mockLogger: LoggingAdapter = jest.fn();
yourFunction(params, mockLogger);
expect(mockLogger).toHaveBeenCalled();
```

For more complex testing, you can implement a custom mock logger:

```typescript
const mockLogger: LoggingAdapter = jest.fn().mockImplementation((message, error) => {
  // Custom implementation
});
```

## Testing Error Handling

To test error handling in logging, create a logger that throws an error:

```typescript
const errorLogger: LoggingAdapter = jest.fn().mockImplementation(() => {
  throw new Error('Logger error');
});
```

Then verify that the function handles the error gracefully and falls back to console.log.