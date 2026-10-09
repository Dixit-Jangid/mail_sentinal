export async function authRequest(endpoint, options) {
  const response = await fetch(`/api/auth/${endpoint}`, options);
  const contentType = response.headers.get("content-type") || "";

  if (!contentType.includes("application/json")) {
    throw new Error(
      "Authentication service returned an invalid response. Restart the backend and try again."
    );
  }

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || "Authentication request failed.");
  }
  return result;
}
