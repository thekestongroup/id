-- How Keston Admin suggests a new user's username from their name
-- (Settings → Username format), e.g. first.last → jo.bloggs.
ALTER TABLE organisations ADD COLUMN username_format TEXT NOT NULL DEFAULT 'first.last'
    CHECK (username_format IN ('first.last', 'firstlast', 'f.last', 'flast', 'first.l', 'last.first'));
