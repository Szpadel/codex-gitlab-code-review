(() => {
  const absoluteFormatter = new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  });
  const relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const relativeUnits = [
    ['year', 365 * 24 * 60 * 60],
    ['month', 30 * 24 * 60 * 60],
    ['week', 7 * 24 * 60 * 60],
    ['day', 24 * 60 * 60],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1],
  ];

  function formatRelative(date) {
    const diffSeconds = Math.round((date.getTime() - Date.now()) / 1000);
    const absoluteSeconds = Math.abs(diffSeconds);
    for (const [unit, unitSeconds] of relativeUnits) {
      if (absoluteSeconds >= unitSeconds || unit === 'second') {
        return relativeFormatter.format(Math.round(diffSeconds / unitSeconds), unit);
      }
    }
    return '';
  }

  function localizeTimestamp(node) {
    const rawTimestamp = node.getAttribute('data-timestamp');
    if (!rawTimestamp) {
      return;
    }
    const date = new Date(rawTimestamp);
    if (Number.isNaN(date.getTime())) {
      return;
    }
    const timeNode = node.querySelector('time');
    if (timeNode) {
      timeNode.textContent = absoluteFormatter.format(date);
      timeNode.setAttribute('datetime', rawTimestamp);
    }
    const relativeNode = node.querySelector('.timestamp-relative');
    if (relativeNode) {
      const relativeText = formatRelative(date);
      relativeNode.textContent = relativeText ? `(${relativeText})` : '';
    }
  }

  function applyLocalizedTimestamps() {
    document
      .querySelectorAll('.localized-timestamp[data-timestamp]')
      .forEach(localizeTimestamp);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyLocalizedTimestamps, { once: true });
  } else {
    applyLocalizedTimestamps();
  }
})();
