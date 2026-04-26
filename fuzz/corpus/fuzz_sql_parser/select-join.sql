SELECT orders.id, users.email FROM orders JOIN users ON orders.user_id = users.id WHERE orders.id = 7
