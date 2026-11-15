-- The username format becomes a formula the organisation writes, e.g.
-- {first}.{last} or {first:1}{last} (store/usernames.go), instead of one of
-- six fixed formats. Existing choices become the same formula.
ALTER TABLE organisations DROP CONSTRAINT IF EXISTS organisations_username_format_check;
UPDATE organisations SET username_format = CASE username_format
    WHEN 'first.last' THEN '{first}.{last}'
    WHEN 'firstlast'  THEN '{first}{last}'
    WHEN 'f.last'     THEN '{first:1}.{last}'
    WHEN 'flast'      THEN '{first:1}{last}'
    WHEN 'first.l'    THEN '{first}.{last:1}'
    WHEN 'last.first' THEN '{last}.{first}'
    ELSE username_format END;
ALTER TABLE organisations ALTER COLUMN username_format SET DEFAULT '{first}.{last}';
ALTER TABLE organisations ADD CONSTRAINT organisations_username_format_length CHECK (length(username_format) BETWEEN 1 AND 100);
