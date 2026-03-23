UPDATE run_history
SET kind = 'security'
WHERE review_lane = 'security' AND kind = 'review';
