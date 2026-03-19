DELETE FROM reports WHERE employee_id IN (SELECT id FROM employees WHERE role = 'admin');
DELETE FROM announcements WHERE sender_id IN (SELECT id FROM employees WHERE role = 'admin');
DELETE FROM employees WHERE role = 'admin';