-- Richer profiles: built-in fields on each user, and per-organisation custom
-- attributes. Both are kept in their own tables (not on users) and shaped to
-- be queried: the dynamic groups that come later match on these columns.

-- Built-in fields. One row per user that has any (a missing row is all blank).
CREATE TABLE user_profiles (
    user_id     UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    job_title   TEXT NOT NULL DEFAULT '',
    department  TEXT NOT NULL DEFAULT '',
    office      TEXT NOT NULL DEFAULT '',
    -- E.164, like +442071234567 (empty: none).
    phone       TEXT NOT NULL DEFAULT '',
    mobile      TEXT NOT NULL DEFAULT '',
    employee_id TEXT NOT NULL DEFAULT '',
    -- Another user in the same organisation (never themselves, never a cycle:
    -- checked in the store). Deleting the manager just clears it.
    manager_id  UUID REFERENCES users (id) ON DELETE SET NULL,
    start_date  DATE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (manager_id IS NULL OR manager_id <> user_id)
);
CREATE INDEX user_profiles_manager_idx ON user_profiles (manager_id) WHERE manager_id IS NOT NULL;
CREATE INDEX user_profiles_department_idx ON user_profiles (lower(department)) WHERE department <> '';
CREATE INDEX user_profiles_job_title_idx ON user_profiles (lower(job_title)) WHERE job_title <> '';

-- Custom attributes an organisation's admins define (Settings → User attributes).
CREATE TABLE user_attribute_defs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    -- Lowercase letters, numbers and underscores: used in CSV headers, filters and rules.
    key             TEXT NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,39}$'),
    label           TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN ('text', 'number', 'date', 'boolean', 'choice')),
    choices         TEXT[] NOT NULL DEFAULT '{}',
    position        INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organisation_id, key)
);

-- Values: one row per user and attribute, with the value in the column for
-- the attribute's type (a choice is in text_value), so each can be indexed
-- and compared properly.
CREATE TABLE user_attribute_values (
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    attribute_id UUID NOT NULL REFERENCES user_attribute_defs (id) ON DELETE CASCADE,
    text_value   TEXT,
    number_value NUMERIC,
    date_value   DATE,
    bool_value   BOOLEAN,
    PRIMARY KEY (user_id, attribute_id),
    CHECK (num_nonnulls(text_value, number_value, date_value, bool_value) = 1)
);
CREATE INDEX user_attribute_values_text_idx ON user_attribute_values (attribute_id, lower(text_value)) WHERE text_value IS NOT NULL;
CREATE INDEX user_attribute_values_number_idx ON user_attribute_values (attribute_id, number_value) WHERE number_value IS NOT NULL;
CREATE INDEX user_attribute_values_date_idx ON user_attribute_values (attribute_id, date_value) WHERE date_value IS NOT NULL;
CREATE INDEX user_attribute_values_bool_idx ON user_attribute_values (attribute_id, bool_value) WHERE bool_value IS NOT NULL;
