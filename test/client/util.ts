/**
 * Utility functions for A2A client tests
 */

/**
 * Extracts the request ID from a RequestInit options object.
 * Parses the JSON body and returns the 'id' field, or 1 as default.
 * 
 * @param options - The RequestInit options object containing the request body
 * @returns The request ID as a number, defaults to 1 if not found or parsing fails
 */
export function extractRequestId(options?: RequestInit): number {
  if (!options?.body) {
    return 1;
  }
  
  try {
    const requestBody = JSON.parse(options.body as string);
    return requestBody.id || 1;
  } catch (e) {
    // If parsing fails, use default ID
    return 1;
  }
}
