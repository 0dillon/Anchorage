UPDATE challenges SET client_domain = '' WHERE client_domain IS NULL;
ALTER TABLE challenges ALTER COLUMN client_domain SET DEFAULT '';
ALTER TABLE challenges ALTER COLUMN client_domain SET NOT NULL;

UPDATE sessions SET memo = '' WHERE memo IS NULL;
ALTER TABLE sessions ALTER COLUMN memo SET DEFAULT '';
ALTER TABLE sessions ALTER COLUMN memo SET NOT NULL;

UPDATE sessions SET client_domain = '' WHERE client_domain IS NULL;
ALTER TABLE sessions ALTER COLUMN client_domain SET DEFAULT '';
ALTER TABLE sessions ALTER COLUMN client_domain SET NOT NULL;
