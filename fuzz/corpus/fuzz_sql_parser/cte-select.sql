WITH recent_orders AS (SELECT id FROM orders WHERE created_at > '2026-01-01') SELECT id FROM recent_orders
