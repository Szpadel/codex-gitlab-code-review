-- History token statistics group runs by kind without a temporary B-tree.
CREATE INDEX idx_run_history_kind ON run_history (kind);

-- Startup and fast-stop reconciliation select only interrupted runs.
CREATE INDEX idx_run_history_in_progress ON run_history (status)
WHERE status = 'in_progress';
