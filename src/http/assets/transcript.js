async function loadTranscriptBody(body) {
  if (body.dataset.loadState === 'loading' || body.dataset.loadState === 'loaded') return;
  const route = body.dataset.transcriptBodyUrl;
  const basePath = resolveAppBasePath(window.location.pathname);
  const url = new URL(route.replace(/^\//, ''), `${window.location.origin}${basePath}`);
  body.dataset.loadState = 'loading';
  body.setAttribute('aria-busy', 'true');
  body.textContent = 'Loading entry body…';
  try {
    const response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`Entry body request failed: ${response.status}`);
    // This endpoint returns escaped or sanitized server-rendered markup only.
    body.innerHTML = await response.text();
    body.dataset.loadState = 'loaded';
  } catch (error) {
    console.error(error);
    body.dataset.loadState = 'failed';
    body.textContent = 'Entry body did not load. Retry or reload the page. ';
    const retry = document.createElement('a');
    retry.href = url;
    retry.className = 'secondary-button';
    retry.textContent = 'Retry';
    body.append(retry);
  } finally {
    body.removeAttribute('aria-busy');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-transcript-body-url]').forEach((body) => {
    const entry = body.closest('details');
    entry.addEventListener('toggle', () => {
      if (entry.open) loadTranscriptBody(body);
    });
    body.addEventListener('click', (event) => {
      if (!event.target.closest('a')) return;
      event.preventDefault();
      loadTranscriptBody(body);
    });
    if (entry.open) loadTranscriptBody(body);
  });
});
