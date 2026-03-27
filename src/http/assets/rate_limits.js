(() => {
  const dialog = document.querySelector('[data-role="rate-limit-modal"]');
  if (!dialog) {
    return;
  }

  const parseJson = (id) => {
    const node = document.getElementById(id);
    if (!node) {
      return [];
    }
    try {
      return JSON.parse(node.textContent || '[]');
    } catch (_err) {
      return [];
    }
  };

  const rules = parseJson('rate-limit-rules-json');
  const suggestions = parseJson('rate-limit-target-suggestions-json');
  const rulesById = new Map(rules.map((rule) => [rule.id, rule]));

  const form = dialog.querySelector('[data-role="rate-limit-form"]');
  const title = dialog.querySelector('[data-role="rate-limit-modal-title"]');
  const submit = dialog.querySelector('[data-role="rate-limit-submit"]');
  const label = dialog.querySelector('[data-role="rate-limit-label"]');
  const scope = dialog.querySelector('[data-role="rate-limit-scope"]');
  const scopeHelp = dialog.querySelector('[data-role="rate-limit-scope-help"]');
  const targetKind = dialog.querySelector('[data-role="rate-limit-target-kind"]');
  const targetInput = dialog.querySelector('[data-role="rate-limit-target-input"]');
  const targetList = dialog.querySelector('[data-role="rate-limit-target-list"]');
  const targetSuggestions = dialog.querySelector('#rate-limit-target-suggestions');
  const targetsJson = dialog.querySelector('[data-role="rate-limit-targets-json"]');
  const addTargetButton = dialog.querySelector('[data-role="rate-limit-add-target"]');
  const sharedRow = dialog.querySelector('[data-role="rate-limit-shared-row"]');
  const sharedToggle = dialog.querySelector('[data-role="rate-limit-shared-toggle"]');
  const bucketMode = dialog.querySelector('[data-role="rate-limit-bucket-mode"]');
  const bucketModeHelp = dialog.querySelector('[data-role="rate-limit-bucket-mode-help"]');
  const capacity = dialog.querySelector('[data-role="rate-limit-capacity"]');
  const windowText = dialog.querySelector('[data-role="rate-limit-window-text"]');
  const review = dialog.querySelector('[data-role="rate-limit-review"]');
  const security = dialog.querySelector('[data-role="rate-limit-security"]');

  let currentTargets = [];

  const normalizePath = (value) => value.trim().replace(/^\/+|\/+$/g, '');

  const syncBucketMode = () => {
    if (scope.value === 'project') {
      sharedRow.hidden = true;
      sharedToggle.checked = true;
      sharedToggle.disabled = true;
      bucketModeHelp.textContent = 'Project scope always creates one bucket per matched repository.';
    } else {
      sharedRow.hidden = false;
      bucketModeHelp.textContent = 'Choose whether all selected targets share one pool or each target keeps its own pool.';
      if (currentTargets.length === 0) {
        sharedToggle.checked = true;
        sharedToggle.disabled = true;
      } else {
        sharedToggle.disabled = false;
      }
    }
    bucketMode.value = sharedToggle.checked ? 'shared' : 'independent';
  };

  const syncScopeState = () => {
    if (scope.value === 'project') {
      scopeHelp.textContent = 'Per repository creates one bucket per matched repository.';
    } else {
      scopeHelp.textContent = 'Per merge request creates an independent pool for every matching MR.';
    }
    syncBucketMode();
  };

  const syncTargetSuggestions = () => {
    targetSuggestions.replaceChildren();
    suggestions
      .filter((item) => item.kind === targetKind.value)
      .forEach((item) => {
        const option = document.createElement('option');
        option.value = item.path;
        targetSuggestions.appendChild(option);
      });
  };

  const syncTargetState = () => {
    syncScopeState();
    syncTargets();
  };

  const syncTargets = () => {
    targetsJson.value = JSON.stringify(currentTargets);
    targetList.innerHTML = '';
    if (currentTargets.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      if (scope.value === 'project') {
        empty.textContent = 'No targets selected. This rule will apply globally with one bucket per matched repository.';
      } else {
        empty.textContent = 'No targets selected. This rule will apply globally within the selected scope.';
      }
      targetList.appendChild(empty);
      return;
    }
    currentTargets.forEach((target, index) => {
      const chip = document.createElement('span');
      chip.className = 'target-chip';

      const labelNode = document.createElement('span');
      labelNode.className = 'target-chip-label';
      labelNode.textContent = target.kind === 'group' ? 'Group' : 'Repo';
      chip.appendChild(labelNode);

      const valueNode = document.createElement('span');
      valueNode.textContent = target.path;
      chip.appendChild(valueNode);

      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'target-chip-remove';
      remove.textContent = 'Remove';
      remove.addEventListener('click', () => {
        currentTargets = currentTargets.filter((_, itemIndex) => itemIndex !== index);
        syncTargetState();
      });
      chip.appendChild(remove);
      targetList.appendChild(chip);
    });
  };

  const resolveInputTarget = () => {
    const path = normalizePath(targetInput.value);
    if (!path) {
      return null;
    }
    const suggested = suggestions.find(
      (item) => item.kind === targetKind.value && item.path === path,
    );
    return {
      kind: suggested?.kind || targetKind.value,
      path,
    };
  };

  const addTarget = () => {
    const next = resolveInputTarget();
    if (!next) {
      targetInput.focus();
      return;
    }
    const alreadyExists = currentTargets.some(
      (item) => item.kind === next.kind && item.path === next.path,
    );
    if (!alreadyExists) {
      currentTargets = [...currentTargets, next];
      syncTargetState();
    }
    targetInput.value = '';
    targetInput.focus();
  };

  const openModal = (mode, ruleId) => {
    const rule = mode === 'edit' ? rulesById.get(ruleId) : null;
    title.textContent = mode === 'edit' ? 'Edit rule' : 'Create rule';
    submit.textContent = mode === 'edit' ? 'Save rule' : 'Create rule';
    form.action = mode === 'edit' && rule ? `/rate-limits/${rule.id}/update` : '/rate-limits/create';
    label.value = rule?.label || '';
    scope.value = rule?.scope || 'project';
    currentTargets = Array.isArray(rule?.targets) ? [...rule.targets] : [];
    targetKind.value = currentTargets[0]?.kind || 'repo';
    sharedToggle.checked = (rule?.bucket_mode || 'shared') === 'shared';
    capacity.value = rule?.capacity == null ? '1' : String(rule.capacity);
    windowText.value = rule?.window_seconds == null ? '2h 15m' : formatDuration(rule.window_seconds);
    review.checked = rule ? !!rule.applies_to_review : true;
    security.checked = rule ? !!rule.applies_to_security : false;
    syncTargetSuggestions();
    syncTargetState();
    if (typeof dialog.showModal === 'function' && !dialog.open) {
      dialog.showModal();
    } else {
      dialog.setAttribute('open', 'open');
    }
  };

  const closeModal = () => {
    if (typeof dialog.close === 'function' && dialog.open) {
      dialog.close();
    } else {
      dialog.removeAttribute('open');
    }
  };

  const formatDuration = (seconds) => {
    let remaining = Number(seconds) || 0;
    const hours = Math.floor(remaining / 3600);
    remaining -= hours * 3600;
    const minutes = Math.floor(remaining / 60);
    remaining -= minutes * 60;
    const parts = [];
    if (hours > 0) {
      parts.push(`${hours}h`);
    }
    if (minutes > 0) {
      parts.push(`${minutes}m`);
    }
    if (remaining > 0 || parts.length === 0) {
      parts.push(`${remaining}s`);
    }
    return parts.join(' ');
  };

  document.querySelectorAll('[data-open-rate-limit-modal]').forEach((button) => {
    button.addEventListener('click', () => {
      openModal(button.getAttribute('data-open-rate-limit-modal'), button.getAttribute('data-rule-id'));
    });
  });

  dialog.querySelectorAll('[data-close-rate-limit-modal]').forEach((button) => {
    button.addEventListener('click', closeModal);
  });

  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) {
      closeModal();
    }
  });

  scope.addEventListener('change', syncTargetState);
  targetKind.addEventListener('change', syncTargetSuggestions);
  sharedToggle.addEventListener('change', syncBucketMode);
  addTargetButton.addEventListener('click', addTarget);
  targetInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      addTarget();
    }
  });
  form.addEventListener('submit', (event) => {
    syncTargetState();
  });

  syncTargetSuggestions();
  syncTargetState();
})();
