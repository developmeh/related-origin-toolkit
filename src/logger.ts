import { LoggingAdapter } from './types';

/**
 * Default logging implementation that uses console.log
 * 
 * @param message The message to log
 * @param error Optional error object to log
 */
export const defaultLogger: LoggingAdapter = (message: string, error?: Error) => {
  if (error) {
    console.log(message, error);
  } else {
    console.log(message);
  }
};

/**
 * Creates a logging adapter that wraps a logging function with error handling.
 * If the provided logging function throws an error, it will be caught and logged using console.error,
 * and the original message will be logged using console.log as a fallback.
 * 
 * @param loggingFunction The logging function to wrap
 * @returns A logging adapter that handles errors
 */
export function createLoggingAdapter(loggingFunction: LoggingAdapter = defaultLogger): LoggingAdapter {
  return (message: string, error?: Error) => {
    try {
      if (error) {
        loggingFunction(message, error);
      } else {
        loggingFunction(message);
      }
    } catch (e) {
      console.error(e);
      if (error) {
        console.log(message, error);
      } else {
        console.log(message);
      }
    }
    
    return;
  };
}