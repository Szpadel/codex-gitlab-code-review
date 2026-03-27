UPDATE runtime_review_rate_limit_rule
SET bucket_mode = 'shared',
    updated_at = CAST(strftime('%s', 'now') AS INTEGER)
WHERE scope = 'project'
  AND bucket_mode <> 'shared';

DELETE FROM runtime_review_rate_limit_bucket
WHERE rule_id IN (
    SELECT id
    FROM runtime_review_rate_limit_rule
    WHERE scope = 'project'
);
