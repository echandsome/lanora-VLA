// Client for the administrator API. Authentication is the HttpOnly cookie the
// server sets on sign-in, so every call is a plain same-origin fetch.

const BASE = '/api/admin';

class ApiError extends Error {
  constructor(status, code, message, retryAfter = 0) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter; // seconds; only set on rate-limit responses
  }
}

const hooks = { unauthorized() {}, forbidden() {} };

// The app registers what to do when the session has ended (401 anywhere) and
// when the account turns out to have fewer rights than the page assumed (403).
export function onUnauthorized(fn) {
  hooks.unauthorized = fn;
}

export function onForbidden(fn) {
  hooks.forbidden = fn;
}

function query(params) {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== '' && value !== null && value !== undefined) q.set(key, value);
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

async function request(method, path, body, { signIn = false } = {}) {
  let response;
  try {
    response = await fetch(BASE + path, {
      method,
      cache: 'no-store',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'network', 'The server could not be reached. Check the connection and try again.');
  }

  // Errors are JSON too, unless something in front of the server (a proxy
  // that is restarting, say) answered instead.
  let data = null;
  try {
    data = await response.json();
  } catch {
    /* handled below */
  }
  if (response.ok && data !== null) return data;

  const detail = (data && data.error) || {};
  const error = new ApiError(
    response.status,
    detail.code || 'unexpected',
    detail.message || `The server gave an unexpected answer (HTTP ${response.status}).`,
    detail.retry_after || 0,
  );
  // A 401 from the sign-in call itself only means the password was wrong.
  if (response.status === 401 && !signIn) hooks.unauthorized(error);
  if (response.status === 403 && error.code === 'forbidden') hooks.forbidden(error);
  throw error;
}

// The first `count` entries of a paged list, as { items, total }. The server
// hands out at most 500 per request, so a longer list is fetched in steps.
// `field` is the name of the array in the answer; `id` names the property
// that identifies an entry, in case the list shifts between two steps.
async function list(path, field, id, params, count) {
  const items = new Map();
  let total = 0;
  for (let offset = 0; offset < count; offset += 500) {
    const page = await request('GET', path + query({ ...params, limit: Math.min(500, count - offset), offset }));
    total = page.total;
    page[field].forEach((item) => items.set(item[id], item));
    if (offset + page[field].length >= total) break;
  }
  return { items: [...items.values()], total };
}

export const api = {
  list,
  get: (path, params) => request('GET', path + query(params)),
  // Endpoints that take a body reject an empty one, so POST always sends an object.
  post: (path, body = {}) => request('POST', path, body),
  put: (path, body) => request('PUT', path, body),
  patch: (path, body) => request('PATCH', path, body),
  del: (path) => request('DELETE', path),
  signIn: (username, password) => request('POST', '/login', { username, password }, { signIn: true }),
};
