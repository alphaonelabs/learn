-- Migration 0010: Add survey system
--
-- Survey content (title/description/questions/options) is treated as
-- public-facing data (not PII), so it is stored in plaintext to support
-- server-side search and CSV export, unlike encrypted activity fields.

CREATE TABLE IF NOT EXISTS surveys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    is_public   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS survey_questions (
    id             TEXT PRIMARY KEY,
    survey_id      TEXT NOT NULL,
    question_text  TEXT NOT NULL,
    question_type  TEXT NOT NULL CHECK (
        question_type IN ('multiple_choice', 'checkbox', 'text', 'true_false', 'scale')
    ),
    required       INTEGER NOT NULL DEFAULT 0,
    display_order  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS survey_options (
    id            TEXT PRIMARY KEY,
    question_id   TEXT NOT NULL,
    option_text   TEXT NOT NULL,
    display_order INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (question_id) REFERENCES survey_questions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS survey_responses (
    id           TEXT PRIMARY KEY,
    survey_id    TEXT NOT NULL,
    user_id      TEXT,
    submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (survey_id, user_id),
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS survey_answers (
    id          TEXT PRIMARY KEY,
    response_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    answer_text TEXT,
    FOREIGN KEY (response_id) REFERENCES survey_responses(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES survey_questions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_surveys_user            ON surveys(user_id);
CREATE INDEX IF NOT EXISTS idx_surveys_public           ON surveys(is_public);
CREATE INDEX IF NOT EXISTS idx_survey_questions_survey  ON survey_questions(survey_id);
CREATE INDEX IF NOT EXISTS idx_survey_options_question  ON survey_options(question_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_survey  ON survey_responses(survey_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_user    ON survey_responses(user_id);
CREATE INDEX IF NOT EXISTS idx_survey_answers_response  ON survey_answers(response_id);
CREATE INDEX IF NOT EXISTS idx_survey_answers_question  ON survey_answers(question_id);
