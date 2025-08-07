import { defaultLogger, createLoggingAdapter } from './logger';
import { LoggingAdapter } from './types';

describe('defaultLogger', () => {
  // Save original console.log
  const originalConsoleLog = console.log;
  
  beforeEach(() => {
    // Mock console.log for testing
    console.log = jest.fn();
  });
  
  afterEach(() => {
    // Restore original console.log
    console.log = originalConsoleLog;
    jest.clearAllMocks();
  });
  
  it('should log message without error', () => {
    const message = 'Test message';
    
    defaultLogger(message);
    
    expect(console.log).toHaveBeenCalledWith(message);
  });
  
  it('should log message with error', () => {
    const message = 'Test message';
    const error = new Error('Test error');
    
    defaultLogger(message, error);
    
    expect(console.log).toHaveBeenCalledWith(message, error);
  });
});

describe('createLoggingAdapter', () => {
  // Save original console methods
  const originalConsoleLog = console.log;
  const originalConsoleError = console.error;
  
  beforeEach(() => {
    // Mock console methods for testing
    console.log = jest.fn();
    console.error = jest.fn();
  });
  
  afterEach(() => {
    // Restore original console methods
    console.log = originalConsoleLog;
    console.error = originalConsoleError;
    jest.clearAllMocks();
  });
  
  it('should use defaultLogger when no logger is provided', () => {
    const message = 'Test message';
    const adapter = createLoggingAdapter();
    
    adapter(message);
    
    expect(console.log).toHaveBeenCalledWith(message);
  });
  
  it('should use provided logger', () => {
    const message = 'Test message';
    const mockLogger: LoggingAdapter = jest.fn();
    const adapter = createLoggingAdapter(mockLogger);
    
    adapter(message);
    
    expect(mockLogger).toHaveBeenCalledWith(message);
    expect(console.log).not.toHaveBeenCalled();
  });
  
  it('should handle errors in logger and fallback to console.log', () => {
    const message = 'Test message';
    const error = new Error('Original error');
    const loggerError = new Error('Logger failed');
    
    const mockLogger: LoggingAdapter = jest.fn().mockImplementation(() => {
      throw loggerError;
    });
    
    const adapter = createLoggingAdapter(mockLogger);
    
    adapter(message, error);
    
    expect(mockLogger).toHaveBeenCalledWith(message, error);
    expect(console.error).toHaveBeenCalledWith(loggerError);
    expect(console.log).toHaveBeenCalledWith(message, error);
  });
  
  it('should handle errors in logger when no error is provided', () => {
    const message = 'Test message';
    const loggerError = new Error('Logger failed');
    
    const mockLogger: LoggingAdapter = jest.fn().mockImplementation(() => {
      throw loggerError;
    });
    
    const adapter = createLoggingAdapter(mockLogger);
    
    adapter(message);
    
    expect(mockLogger).toHaveBeenCalledWith(message);
    expect(console.error).toHaveBeenCalledWith(loggerError);
    expect(console.log).toHaveBeenCalledWith(message);
  });
  
  it('should pass both message and error to logger when provided', () => {
    const message = 'Test message';
    const error = new Error('Test error');
    const mockLogger: LoggingAdapter = jest.fn();
    const adapter = createLoggingAdapter(mockLogger);
    
    adapter(message, error);
    
    expect(mockLogger).toHaveBeenCalledWith(message, error);
  });
});