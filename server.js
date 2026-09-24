THIRAL – FAST QUESTION LOADING UPDATE
========================================

நோக்கம்:
- எந்த existing question-ஐயும் delete செய்யக்கூடாது.
- Group 4-ல் உள்ள அனைத்து questions அப்படியே இருக்க வேண்டும்.
- ஒவ்வொரு subject/subtopic-ல் உள்ள சுமார் 1200 questions-ல் இருந்து Practice-க்கு தேவையான 10/20/50 questions மட்டும் browser-க்கு அனுப்ப வேண்டும்.
- மாணவர் ஏற்கனவே Practice-ல் பார்த்த question மீண்டும் வரக்கூடாது.
- Mock Test தற்போதையபடி தனியாக வேலை செய்ய வேண்டும்.
- Frontend design / buttons / Study Material / Mock Test ஆகியவற்றை மாற்ற வேண்டாம்.

முக்கியம்:
இந்த மாற்றம் questions table-ஐ delete அல்லது modify செய்யாது.
புதிய question_history table மட்டும் உருவாக்கப்படும்.


1. SERVER.JS – புதிய HISTORY TABLE
----------------------------------

Database connection உருவான பிறகு, இந்த code-ஐ ஒருமுறை server startup பகுதியில் சேர்க்கவும்:

await pool.query(`
  CREATE TABLE IF NOT EXISTS question_history (
    user_id BIGINT NOT NULL,
    question_id BIGINT NOT NULL,
    mode VARCHAR(20) NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, question_id, mode)
  )
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_question_history_user_mode_question
  ON question_history(user_id, mode, question_id)
`);


2. SERVER.JS – PRACTICE QUESTIONS API
--------------------------------------

ஏற்கனவே உள்ள /questions API-ஐ உடனடியாக delete/replace செய்ய வேண்டாம்.
அதற்குப் பதிலாக புதிய endpoint-ஐ சேர்க்கவும்:

api.get('/practice/questions', requireAuth, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const subject = String(req.query.subject || '').trim();
    const language = String(req.query.language || 'ta').trim();
    const subtopic = String(req.query.subtopic || '').trim();

    const limit = Math.min(
      Math.max(parseInt(req.query.limit || '10', 10) || 10, 1),
      200
    );

    if (!exam || !subject || !['ta', 'en'].includes(language)) {
      return sendError(res, 400, 'Invalid question request.');
    }

    const params = [
      req.user.id,
      exam,
      subject,
      language
    ];

    let n = 5;

    let where = `
      q.exam = $2
      AND q.subject = $3
      AND q.language = $4
      AND q.is_active = true
    `;

    if (subtopic) {
      where += ` AND q.subtopic = $${n}`;
      params.push(subtopic);
      n++;
    }

    params.push(limit);

    const sql = `
      SELECT
        q.id,
        q.exam,
        q.subject,
        q.subtopic,
        q.language,
        q.question,
        q.options,
        q.explanation
      FROM questions q
      WHERE ${where}
        AND NOT EXISTS (
          SELECT 1
          FROM question_history h
          WHERE h.user_id = $1
            AND h.question_id = q.id
            AND h.mode = 'practice'
        )
      ORDER BY random()
      LIMIT $${n}
    `;

    const result = await pool.query(sql, params);

    if (result.rows.length < limit) {
      return sendError(
        res,
        409,
        `இந்த பகுதியில் மீதமுள்ள புதிய கேள்விகள் ${result.rows.length} மட்டுமே உள்ளன.`
      );
    }

    res.json({
      questions: result.rows,
      count: result.rows.length
    });

  } catch (e) {
    console.error('Practice question error:', e);
    sendError(res, 500, 'Practice question service error.');
  }
});


3. SERVER.JS – ATTEMPT உருவான பிறகு HISTORY SAVE
--------------------------------------------------

ஏற்கனவே உள்ள:

const ins = await pool.query(
  `INSERT INTO attempts(
     user_id,
     exam,
     subject,
     mode,
     language,
     question_ids
   )
   VALUES($1,$2,$3,$4,$5,$6)
   RETURNING id`,
  [
    req.user.id,
    exam,
    subject,
    mode,
    language,
    clean
  ]
);

இதற்குப் பிறகு, res.json(...) க்கு முன்பு இந்த code-ஐ சேர்க்கவும்:

await pool.query(
  `
  INSERT INTO question_history(user_id, question_id, mode)
  SELECT $1, x, $2
  FROM unnest($3::bigint[]) AS x
  ON CONFLICT (user_id, question_id, mode)
  DO NOTHING
  `,
  [req.user.id, clean, mode]
);

பிறகு ஏற்கனவே இருக்கும்:

res.json({id:ins.rows[0].id});

அப்படியே இருக்கலாம்.


4. FRONTEND – PRACTICE API URL மட்டும் மாற்றவும்
------------------------------------------------

தற்போதைய Practice code-ல்:

const d = await api()(
  '/questions?exam=' +
  encodeURIComponent(exam) +
  '&subject=' +
  encodeURIComponent(subject) +
  '&language=' +
  encodeURIComponent(language) +
  '&limit=' +
  count
);

இதற்குப் பதிலாக:

const d = await api()(
  '/practice/questions?exam=' +
  encodeURIComponent(exam) +
  '&subject=' +
  encodeURIComponent(subject) +
  '&language=' +
  encodeURIComponent(language) +
  '&subtopic=' +
  encodeURIComponent(
    typeof currentSubtopic !== 'undefined' ? currentSubtopic : ''
  ) +
  '&limit=' +
  count
);


5. RESULT
----------

முன்பு:

1200 questions
      ↓
பல questions load
      ↓
10 select

பிறகு:

1200 questions
      ↓
Database-ல் already-seen questions exclude
      ↓
Random 10
      ↓
Browser-க்கு 10 மட்டும்


6. PRACTICE HISTORY
-------------------

மாணவர்:

Practice 1 → Q10, Q25, Q90...
Practice 2 → புதிய questions
Practice 3 → புதிய questions
...

ஒரே question மீண்டும் வராது.

History database-ல்:

user_id
question_id
mode = practice
seen_at

என்று பதிவு செய்யப்படும்.


7. MOCK TEST
------------

Mock Test-ஐ இப்போது மாற்ற வேண்டாம்.

Existing:

mode = 'mock'

அப்படியே தொடரும்.

Practice:

mode = 'practice'

என்று தனித்தனியாக history வைத்திருக்கும்.


8. எதையும் DELETE செய்யக்கூடாது
--------------------------------

DELETE செய்ய வேண்டியவை:

எதுவும் இல்லை.

questions table:
அப்படியே.

1,200 questions:
அப்படியே.

மொத்த Group 4 question bank:
அப்படியே.

Study Material:
அப்படியே.

Practice buttons:
அப்படியே.

Mock Test:
அப்படியே.

Frontend design:
அப்படியே.


9. DEPLOY
---------

server.js மாற்றிய பிறகு:

GitHub
→ server.js update
→ Commit changes

பிறகு Render:

Manual Deploy
→ Deploy latest commit

Deployment முடிந்த பிறகு Practice-ல் 10 questions test செய்யவும்.


10. IMPORTANT TEST
------------------

முதலில் ஒரு student account-ல்:

Practice → 10 Questions

எடுக்கவும்.

பிறகு மீண்டும்:

Practice → 10 Questions

எடுக்கவும்.

இரண்டு attempts-ல் வந்த question IDs ஒன்றாக இருக்கக்கூடாது.

முதல் attempt-ல் வந்த questions:
மீண்டும் வரக்கூடாது.

எந்த existing question-மும் database-ல் இருந்து delete ஆகக்கூடாது.


குறிப்பு:
இந்த implementation-ல் ORDER BY random() பயன்படுத்தப்பட்டுள்ளது.
1 லட்சம் questions-க்கு இது ஆரம்ப fast-loading solution.
Database மிகப் பெரியதாக வளர்ந்தால் பின்னர் indexed random selection முறைக்கு மாற்றலாம்.
