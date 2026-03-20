function resolveAppBasePath(pathname) {
  const patterns = [
    /\/mr\/[^/]+\/[^/]+\/history\/?$/,
    /\/history\/[^/]+\/?$/,
    /\/history\/?$/,
    /\/status\/?$/
  ];
  for (const pattern of patterns) {
    if (pattern.test(pathname)) {
      return pathname.replace(pattern, '/');
    }
  }
  return pathname.endsWith('/') ? pathname : `${pathname}/`;
}

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-feature-flag]');
  if (!button) return;
  const flagName = button.getAttribute('data-feature-flag');
  const rawValue = button.getAttribute('data-feature-flag-value');
  const csrfToken = document.querySelector('meta[name="codex-status-csrf"]')?.getAttribute('content');
  if (!flagName || !rawValue) return;
  if (!csrfToken) {
    window.alert('Feature flag controls are unavailable.');
    return;
  }
  const enabled = rawValue === 'default' ? null : rawValue === 'true';
  const basePath = resolveAppBasePath(window.location.pathname);
  const featureFlagUrl = new URL(
    `api/feature-flags/${encodeURIComponent(flagName)}`,
    `${window.location.origin}${basePath.endsWith('/') ? basePath : `${basePath}/`}`
  );
  button.disabled = true;
  try {
    const response = await fetch(featureFlagUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Codex-Status-Csrf': csrfToken,
      },
      body: JSON.stringify({ enabled }),
      credentials: 'same-origin',
    });
    if (!response.ok) {
      throw new Error(`feature flag update failed: ${response.status}`);
    }
    window.location.reload();
  } catch (error) {
    console.error(error);
    button.disabled = false;
    window.alert('Feature flag update failed.');
  }
});
