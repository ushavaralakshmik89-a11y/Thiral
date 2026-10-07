THIRAL – EXACT PATCH ONLY
GROUP 4 MOCK TEST QUESTION SELECTION FIX
CURRENT server.js பாதுகாப்பு விதிமுறை
============================================================

மிக முக்கியமானது
----------------
இந்த instruction-ஐ பயன்படுத்தி CURRENT server.js-ஐ முழுவதுமாக replace செய்யக்கூடாது.

CURRENT server.js அப்படியே பாதுகாக்கப்பட வேண்டும்.

இந்த server.js-ல் ஏற்கனவே உள்ள:
- Login
- Authentication
- Security
- Admin
- Supabase/PostgreSQL connection
- Sessions
- OTP
- Registration
- Question Bank
- Practice
- Model Exam
- Results
- Telemetry
- Other APIs
- Existing database handling
- Existing question data

எதையும் மாற்றக்கூடாது.

இரண்டு மாதங்களாக உருவாக்கப்பட்ட working code-ல் தேவையில்லாத ஒரு மாற்றமும் செய்யக்கூடாது.

இந்த task-ன் ஒரே நோக்கம்:

GROUP 4 MOCK TEST-ல் கேள்விகளை தேர்வு செய்யும் QUALITY / COVERAGE / ROTATION மட்டும் மாற்றுவது.

============================================================
1. CURRENT FILE
============================================================

Uploaded/current server.js:

மொத்தம் சுமார் 3474 lines.

இந்த file-ஐ புதிய குறைந்த வரி code-ஆக replace செய்யக்கூடாது.

முழு file structure பாதுகாக்கப்பட வேண்டும்.

இந்த task:

    PATCH ONLY

முறைப்படி செய்யப்பட வேண்டும்.

============================================================
2. EXACT SCOPE
============================================================

மாற்ற அனுமதி உள்ள பகுதி:

    api.get('/mock/questions', requirePasswordReady, async (req,res)=>{

இந்த route-ன் உள்ளே இருக்கும் QUESTION SELECTION LOGIC மட்டும்.

அதாவது:

A. Candidate question pool எடுக்கும் query

B. Random/broad question selection

C. Difficulty quality selection

D. Subtopic/division diversity

E. Duplicate prevention

F. Previous Mock history exclusion

G. Final 200-question selection

இவை மட்டும்.

============================================================
3. எதை எந்த காரணத்திற்கும் மாற்றக்கூடாது
============================================================

இந்த பகுதிகளை TOUCH செய்யக்கூடாது:

1. Login
2. Registration
3. Password
4. OTP
5. Session
6. Authentication
7. Security
8. Admin
9. Device/security controls
10. API rate limiting
11. CSRF
12. CORS
13. Helmet
14. Database connection
15. Pool configuration
16. Environment variables
17. Supabase/PostgreSQL configuration
18. Question Bank API
19. /questions
20. /practice/questions
21. Practice selection
22. Model Exam
23. Results
24. Attempts unrelated to Mock
25. Telemetry
26. Frontend
27. HTML
28. CSS
29. JavaScript frontend
30. Existing question rows
31. Existing question text
32. Existing options
33. Existing explanations
34. Existing IDs
35. Existing subjects
36. Existing subtopics
37. Existing languages
38. Existing database schema
39. Any unrelated server route

============================================================
4. DATABASE QUESTIONS MUST REMAIN UNTOUCHED
============================================================

இந்த task-ல்:

UPDATE questions
DELETE FROM questions
ALTER TABLE questions
TRUNCATE questions

போன்ற எந்த database modification-மும் செய்யக்கூடாது.

கேள்விகளின்:

- question
- options
- explanation
- difficulty
- level
- subject
- subtopic
- language
- ID

எதையும் மாற்றக்கூடாது.

Database data READ மட்டும்.

============================================================
5. CURRENT PROBLEM
============================================================

CURRENT /mock/questions code-ல் subject-wise query:

    ORDER BY id
    LIMIT 3000

என்று உள்ளது.

இதுதான் முக்கிய bottleneck.

Database-ல் 2 லட்சத்துக்கும் மேற்பட்ட questions இருந்தாலும்:

    first ID range
          ↓
    3000 rows
          ↓
    Mock selection

என்று நடக்கிறது.

இதனால் database-ன் பிற பகுதிகளில் இருக்கும் questions Mock selection-க்கு வராமல் போகின்றன.

இதனால் ஒரே சில topics/areas மட்டும் மீண்டும் மீண்டும் வருவது ஏற்படுகிறது.

============================================================
6. முக்கிய மாற்றம்
============================================================

இந்த:

    ORDER BY id
    LIMIT 3000

என்ற first-ID selection-ஐ Mock candidate selection-ல் பயன்படுத்தக்கூடாது.

ஆனால் இதை சரி செய்யும் போது முழு server.js-ஐ மாற்றக்கூடாது.

இந்த query block மட்டும் narrow patch ஆக மாற்ற வேண்டும்.

============================================================
7. 2 LAKH+ QUESTIONS – முழு pool coverage
============================================================

Mock Test selection database-ன் முதல் சில ஆயிரம் IDs-ல் மட்டும் சிக்கக்கூடாது.

Eligible questions database-ன் பல பகுதிகளில் இருந்தும் candidate ஆக வர வேண்டும்.

அதாவது:

    1–3000 மட்டும்

என்று அல்ல.

Database-ல் இருக்கும்:

    பல ஆயிரம்
    பல பத்தாயிரம்
    2 லட்சம்+

eligible questions

அனைத்தும் selection population-ல் representation பெறும் வகையில் broad/random sampling வேண்டும்.

============================================================
8. PERFORMANCE – FULL TABLE LOAD செய்யக்கூடாது
============================================================

முழு 2 லட்சம்+ rows-ஐ Node.js memory-க்கு ஒரே request-ல் SELECT செய்து கொண்டு வரக்கூடாது.

Performance பாதுகாக்க வேண்டும்.

எனவே PostgreSQL-ல் efficient broad/random candidate sampling பயன்படுத்த வேண்டும்.

Implementation எதுவாக இருந்தாலும்:

- first 3000 ID bias இருக்கக்கூடாது
- full eligible population represent ஆக வேண்டும்
- current user history exclusion இருக்க வேண்டும்
- duplicate detection இருக்க வேண்டும்
- quality selection இருக்க வேண்டும்

============================================================
9. SUBJECT STRUCTURE மாற்றக்கூடாது
============================================================

Current Mock structure அப்படியே:

Tamil:
    100

General Knowledge:
    75

Aptitude:
    25

Total:
    200

இந்த எண்ணிக்கையை மாற்றக்கூடாது.

============================================================
10. CURRENT SUBJECT ALIASES மாற்றக்கூடாது
============================================================

Current code-ல் இருக்கும் subject candidates-ஐ preserve செய்ய வேண்டும்.

Tamil:

    tamil
    தமிழ்

GS:

    பொது அறிவு
    General Knowledge
    general knowledge
    பொது அறிவு / General Studies
    General Studies
    general studies

Aptitude:

    apt
    திறனறிவு / Aptitude
    Aptitude
    aptitude

இவற்றை தேவையில்லாமல் மாற்றக்கூடாது.

============================================================
11. LANGUAGE BEHAVIOR மாற்றக்கூடாது
============================================================

Current:

    requestedLanguage

behavior preserve செய்ய வேண்டும்.

Tamil:

    ta

English:

    en

என்ற current behavior மாற்றக்கூடாது.

============================================================
12. USER MOCK HISTORY
============================================================

Current history protection முக்கியமானது.

இந்த logic preserve செய்ய வேண்டும்:

    question_history

    mode='mock'

Current student முன்பு Mock-ல் பார்த்த question fresh selection-ல் மீண்டும் வரக்கூடாது.

Question ID மட்டும் அல்லாமல் current code-ல் இருக்கும் content-level protection-யும் preserve செய்ய வேண்டும்.

============================================================
13. CONTENT DUPLICATE
============================================================

Current:

    normalizeText()
    contentKey()
    questionOnlyKey()

போன்ற functions ஏற்கனவே உள்ளன.

அவற்றை delete செய்யக்கூடாது.

அவற்றை பயன்படுத்தியே duplicate prevention தொடர வேண்டும்.

Duplicate என்றால்:

Same question text
+
same options

DB ID வேறாக இருந்தாலும் duplicate.

Options order மட்டும் மாறினாலும் duplicate.

Whitespace/case/normalization வேறுபாடு இருந்தாலும் duplicate.

============================================================
14. DIFFICULTY QUALITY
============================================================

Current server.js-ல் difficultyInfo() ஏற்கனவே உள்ளது.

அதை பாதுகாக்க வேண்டும்.

Current difficulty categories:

    0 = Easy
    1 = Moderate
    2 = Hard
    3 = Very Hard

Current Mock-ன் நோக்கம்:

    Moderate
    Hard
    Very Hard

questions-க்கு priority.

Easy/direct-fact questions அதிகமாக வரக்கூடாது.

ஆனால் existing difficultyInfo() logic-ஐ அழித்து புதிதாக unrelated difficulty system உருவாக்கக்கூடாது.

============================================================
15. CURRENT DIFFICULTY QUOTAS
============================================================

Current intended quotas preserve செய்ய வேண்டும்.

Tamil:

    Moderate 20
    Hard 60
    Very Hard 20

GS:

    Moderate 15
    Hard 45
    Very Hard 15

Aptitude:

    Moderate 5
    Hard 15
    Very Hard 5

இந்த distribution-ஐ unnecessary ஆக மாற்றக்கூடாது.

============================================================
16. "QUALITY" என்றால் QUESTION TEXT மாற்றுவது அல்ல
============================================================

மிக முக்கியம்:

கேள்வியின் தரத்தை மாற்ற வேண்டும் என்றால் question text-ஐ edit செய்யக்கூடாது.

Question quality improvement என்பது:

    existing better questions
    +
    better selection
    +
    wider coverage
    +
    difficulty preference
    +
    subtopic diversity

மூலம் வர வேண்டும்.

============================================================
17. ALL SECTIONS / ALL SUBTOPICS
============================================================

User-ன் முக்கிய requirement:

2 லட்சத்துக்கும் மேலான questions இருந்தாலும் சில பகுதிகளில் இருந்து மட்டும் questions வரக்கூடாது.

Database-ல் உள்ள eligible subtopics/sections அனைத்துக்கும் selection opportunity இருக்க வேண்டும்.

Tamil:
    available Tamil subtopics அனைத்தும்

GS:
    available GS subtopics அனைத்தும்

Aptitude:
    available Aptitude subtopics அனைத்தும்

எல்லாவற்றிலிருந்தும் balanced representation பெற வேண்டும்.

ஒரே topic-ல் 75 GS questions நிரம்பக்கூடாது.

ஒரே Aptitude topic-ல் 25 questions நிரம்பக்கூடாது.

Tamil-லும் ஒரே topic domination தவிர்க்க வேண்டும்.

============================================================
18. SUBTOPIC NAMES HARD-CODE செய்யக்கூடாது
============================================================

Existing database-ல் என்ன subtopics உள்ளனவோ அவற்றையே பயன்படுத்த வேண்டும்.

புதிய subtopic names உருவாக்கக்கூடாது.

Existing subtopic values மாற்றக்கூடாது.

Hard-coded short list வைத்து:

    History மட்டும்
    Geography மட்டும்
    Aptitude சில topics மட்டும்

என்று கட்டுப்படுத்தக்கூடாது.

Dynamic subtopic discovery வேண்டும்.

============================================================
19. SUBTOPIC DIVERSITY
============================================================

Selection concept:

    candidate pool
          ↓
    group by subtopic
          ↓
    quality/difficulty
          ↓
    rotate across subtopics
          ↓
    fill required count

ஒரே subtopic தொடர்ந்து தேர்வு செய்யப்படக்கூடாது.

போதுமான subtopics இருந்தால் பல subtopics-ல் இருந்து questions வர வேண்டும்.

ஒரு subtopic-ல் questions குறைவாக இருந்தால் available count மட்டும் பயன்படுத்த வேண்டும்.

மற்ற subtopics-ல் இருந்து selection தொடர வேண்டும்.

============================================================
20. GS – SPECIAL REQUIREMENT
============================================================

GS-ல் diversity கட்டாயம்.

Current code-ல் Aptitude-க்கு second diversity pass உள்ளது.

GS-க்கும் அதே நோக்கத்துடன் dynamic subtopic diversity selection தேவை.

ஆனால் existing data/subtopic aliases மாற்றக்கூடாது.

GS-ல் database-ல் இருக்கும் அனைத்து available areas-க்கும் வாய்ப்பு கிடைக்க வேண்டும்.

============================================================
21. APTITUDE – SPECIAL REQUIREMENT
============================================================

Aptitude-ல் ஏற்கனவே diversity logic உள்ளது.

அதை பாதுகாக்க வேண்டும்.

அதை delete செய்யக்கூடாது.

அதே logic-ஐ broader candidate pool-ல் செயல்படச் செய்ய வேண்டும்.

Database-ல் இருக்கும் அனைத்து aptitude subtopics-க்கும் selection opportunity வேண்டும்.

============================================================
22. TAMIL – SPECIAL REQUIREMENT
============================================================

Tamil = 100.

Tamil-லும் first IDs மட்டும் பயன்படுத்தக்கூடாது.

Database-ல் இருக்கும் அனைத்து eligible Tamil areas/subtopics-ல் இருந்து quality questions வர வேண்டும்.

Existing Tamil question data untouched.

============================================================
23. RANDOMIZATION
============================================================

Randomization வேண்டும்.

ஆனால்:

    ORDER BY RANDOM()

மட்டும் போட்டு task முடிந்தது என்று கருதக்கூடாது.

Correct model:

    broad candidate population
        +
    history exclusion
        +
    duplicate exclusion
        +
    difficulty ranking
        +
    subtopic diversity
        +
    randomization

============================================================
24. RANDOMIZATION WITH QUALITY
============================================================

Randomization மட்டும் செய்தால் easy questions அதிகமாக வர வாய்ப்பு உள்ளது.

எனவே random selection quality ranking-க்கு பிறகு அல்லது quality-aware selection-ல் இருக்க வேண்டும்.

ஒரே quality bucket-க்குள் randomize செய்யலாம்.

============================================================
25. cycleTo() பிரச்சனை
============================================================

Current code-ல்:

    const cycleTo=(rows,count)=>{
      if(!rows.length) return [];
      const out=[];
      for(let i=0;i<count;i++) out.push(rows[i%rows.length]);
      return out;
    };

இந்த logic:

    8 questions
    required 25

என்றால்:

    1 2 3 4 5 6 7 8
    1 2 3 4 5 6 7 8
    ...

என்று duplicate questions உருவாக்கும்.

Mock quality requirement-க்கு இது ஏற்றுக்கொள்ளக்கூடாது.

============================================================
26. RECYCLE FALLBACK
============================================================

Current code-ல் fresh pool குறைந்தால்:

    LIMIT 5000

உள்ள recycle query உள்ளது.

இந்த fallback-லும் first-ID bias உள்ளது.

மேலும் current user history மற்றும் broad coverage நோக்கத்துக்கு இது பொருந்தவில்லை.

இந்த Mock selection fallback-ஐ broad/random unique candidate logic-க்கு மாற்ற வேண்டும்.

ஆனால் route-ன் மற்ற code untouched.

============================================================
27. INSUFFICIENT QUESTIONS
============================================================

ஒரு subject-ல் உண்மையில் unique questions போதவில்லை என்றால்:

    duplicate question வைத்து count நிரப்பக்கூடாது.

Example:

Aptitude unique eligible = 18

Required = 25

என்றால் same 18 questions-ஐ மீண்டும் போட்டு 25 ஆக்கக்கூடாது.

Clear error return செய்ய வேண்டும்.

Mock quality-ஐ காப்பாற்ற வேண்டும்.

============================================================
28. FINAL UNIQUE VALIDATION
============================================================

Final 200 questions return செய்வதற்கு முன்:

    ID uniqueness
    content uniqueness
    question text uniqueness
    history exclusion

verify செய்ய வேண்டும்.

ஒரே question இரண்டு முறை இருந்தால் response அனுப்பக்கூடாது.

============================================================
29. EXACT FINAL STRUCTURE
============================================================

Final:

    Tamil = 100
    GS = 75
    Aptitude = 25

Total:

    200

இந்த structure மாறக்கூடாது.

============================================================
30. ATTEMPT / HISTORY WRITES
============================================================

Current Mock route இறுதியில் attempt/history records உருவாக்குகிறது.

அந்த existing write behavior-ஐ தேவையில்லாமல் மாற்றக்கூடாது.

Selection logic மட்டும் மாற்ற வேண்டும்.

Current:

    attempts

    question_history

என்ற behavior preserve செய்ய வேண்டும்.

============================================================
31. TRANSACTION / LOCK
============================================================

Current Mock route:

    BEGIN

மற்றும்:

    pg_advisory_xact_lock(...)

போன்ற concurrency protection பயன்படுத்துகிறது.

அதை remove செய்யக்கூடாது.

ஒரே student ஒரே நேரத்தில் இரண்டு Mock starts செய்தால் overlap control தொடர வேண்டும்.

============================================================
32. RESPONSE FORMAT
============================================================

Frontend எதிர்பார்க்கும் response structure மாற்றக்கூடாது.

Current fields:

    attemptId
    questions
    count
    recycled

போன்ற response fields இருந்தால் அவற்றை preserve செய்ய வேண்டும்.

Frontend மாற்றம் தேவையில்லை.

============================================================
33. PRACTICE API – ZERO CHANGE
============================================================

இந்த task-ல்:

    /practice/questions

எந்த மாற்றமும் செய்யக்கூடாது.

Practice 10/20/50/100 behavior:

    EXACTLY AS IS

============================================================
34. QUESTION BANK API – ZERO CHANGE
============================================================

    /questions

எந்த மாற்றமும் செய்யக்கூடாது.

Question Bank pagination/history/subtopic behavior மாற்றக்கூடாது.

============================================================
35. MODEL EXAM – ZERO CHANGE
============================================================

Model Exam module-ல் எந்த மாற்றமும் செய்யக்கூடாது.

============================================================
36. SECURITY – ZERO CHANGE
============================================================

Security middleware-ல் எந்த மாற்றமும் செய்யக்கூடாது.

Authentication:

    requirePasswordReady

என்பது Mock route-ல் இருந்தபடியே இருக்க வேண்டும்.

============================================================
37. FRONTEND – ZERO CHANGE
============================================================

HTML file touch செய்யக்கூடாது.

CSS touch செய்யக்கூடாது.

Frontend JS touch செய்யக்கூடாது.

Mock UI design மாற்றக்கூடாது.

Question display மாற்றக்கூடாது.

Timer மாற்றக்கூடாது.

Navigation மாற்றக்கூடாது.

Submit மாற்றக்கூடாது.

============================================================
38. NO DATABASE MIGRATION
============================================================

இந்த fix-க்கு SQL migration தேவையில்லை.

Schema மாற்றக்கூடாது.

Indexes கூட தேவையில்லாமல் உருவாக்கக்கூடாது.

Question table data touch செய்யக்கூடாது.

============================================================
39. ONLY SELECTION LAYER
============================================================

Allowed conceptual change:

BEFORE:

    questions
      ↓
    first 3000 IDs
      ↓
    difficulty selection
      ↓
    Mock

AFTER:

    all eligible population
      ↓
    broad/random candidate sampling
      ↓
    history exclusion
      ↓
    duplicate exclusion
      ↓
    difficulty quality
      ↓
    dynamic subtopic/division diversity
      ↓
    random selection within quality groups
      ↓
    100 Tamil + 75 GS + 25 Aptitude
      ↓
    final uniqueness validation
      ↓
    Mock

============================================================
40. IMPORTANT – DO NOT REWRITE EXISTING server.js
============================================================

Gemini / developer:

DO NOT generate a new complete server.js.

DO NOT replace the uploaded server.js.

DO NOT copy a short code block and tell the user to replace the entire file.

DO NOT delete unrelated code.

DO NOT refactor the server.

DO NOT rename unrelated variables.

DO NOT move unrelated functions.

DO NOT clean up unrelated code.

DO NOT modify formatting throughout the file.

ONLY make the smallest possible in-place changes inside:

    api.get('/mock/questions', ...)

question selection section.

============================================================
41. EXACT PATCH STYLE
============================================================

Implementation should be done as:

    FIND THIS EXISTING BLOCK
          ↓
    CHANGE ONLY THIS BLOCK
          ↓
    KEEP ALL OTHER LINES EXACTLY AS THEY ARE

When giving the final implementation instructions, provide:

1. Exact existing code marker
2. Exact replacement code
3. Exact reason for replacement
4. Explicit statement that all lines outside this block remain unchanged

Do NOT provide a full replacement server.js.

============================================================
42. IMPORTANT ABOUT THE 3474-LINE FILE
============================================================

Current uploaded server.js has approximately 3474 lines.

The final file after patch should still be approximately the same size.

It should NOT suddenly become 1000–1500 lines.

If the developer returns a new file with hundreds/thousands of unrelated lines missing:

    STOP.

Do not deploy.

The original server.js must be restored.

============================================================
43. VALIDATION AFTER PATCH
============================================================

Before deployment:

[ ] Original server.js backup exists.

[ ] Only /mock/questions selection section changed.

[ ] All other lines remain unchanged.

[ ] File remains approximately 3474 lines.

[ ] No login changes.

[ ] No security changes.

[ ] No Practice changes.

[ ] No Question Bank changes.

[ ] No Model Exam changes.

[ ] No frontend changes.

[ ] No DB question updates.

[ ] No DB question deletes.

[ ] No schema changes.

[ ] No unrelated refactor.

============================================================
44. FUNCTIONAL TEST
============================================================

Start Group 4 Mock.

Expected:

    200 questions

    Tamil = 100
    GS = 75
    Aptitude = 25

Questions should no longer be concentrated in only the first few thousand IDs.

============================================================
45. SUBTOPIC TEST
============================================================

Inspect returned questions.

Expected:

Tamil:
    multiple available Tamil subtopics represented.

GS:
    multiple available GS subtopics represented.

Aptitude:
    multiple available Aptitude subtopics represented.

If database has enough questions in many subtopics, one subtopic must not dominate the complete section.

============================================================
46. QUALITY TEST
============================================================

Expected priority:

    Moderate
    Hard
    Very Hard

Easy/direct-fact questions should not dominate.

============================================================
47. REPEAT TEST
============================================================

Run Mock twice for same student.

Expected:

Previous Mock questions should not be returned as fresh questions while unique eligible questions remain.

============================================================
48. DIFFERENT STUDENT TEST
============================================================

Another student starts Mock.

Expected:

Selection can be different.

There must not be a fixed first-3000 question list.

============================================================
49. DATABASE INTEGRITY TEST
============================================================

Before and after deployment:

Question count unchanged.

Question IDs unchanged.

Question text unchanged.

Options unchanged.

Explanations unchanged.

Subtopics unchanged.

Languages unchanged.

No question rows deleted.

No question rows rewritten.

============================================================
50. PRACTICE REGRESSION TEST
============================================================

Practice:

    10
    20
    50
    100

must work exactly as before.

============================================================
51. FINAL DEPLOYMENT RULE
============================================================

Do not deploy immediately after editing.

First:

    syntax check

Then:

    diff check

Then:

    verify only Mock selection changed

Then:

    test Mock

Then:

    test Practice

Then:

    test Login

Then:

    test Question Bank

Only after these checks deploy to Render.

============================================================
52. MOST IMPORTANT FINAL INSTRUCTION
============================================================

இந்த project-ல் இரண்டு மாதங்களாக இருக்கும் existing work-ஐ பாதுகாப்பது முதன்மை.

இந்த task:

    "SERVER CHANGE"

அல்ல.

இந்த task:

    "MOCK QUESTION SELECTION CHANGE"

மட்டுமே.

Question database-ஐ மாற்றுவது அல்ல.

Frontend-ஐ மாற்றுவது அல்ல.

Practice-ஐ மாற்றுவது அல்ல.

Security-ஐ மாற்றுவது அல்ல.

Existing question content-ஐ மாற்றுவது அல்ல.

ஒரே பிரச்சனை:

    2 லட்சத்துக்கும் மேற்பட்ட questions இருந்தும்
    Mock Test சில ஆரம்ப பகுதிகளில் மட்டும் இருந்து
    சில questions மீண்டும் மீண்டும் வருகிறது.

இதற்கு தீர்வு:

    முழு eligible question population-லிருந்து
    broad/random coverage
    +
    அனைத்து available sections/subtopics
    +
    difficulty quality
    +
    duplicate protection
    +
    history protection

மூலம் கேள்விகளை தேர்வு செய்வது.

============================================================
53. FINAL ACCEPTANCE CRITERIA
============================================================

இந்த patch சரியானதாக கருதப்பட வேண்டுமெனில்:

1. Existing server.js structure பாதுகாக்கப்பட்டிருக்க வேண்டும்.

2. Existing working code untouched.

3. Existing database questions untouched.

4. Mock மட்டும் selection-level-ல் மாற்றப்பட்டிருக்க வேண்டும்.

5. First 3000 ID limitation இல்லாமல் broad coverage இருக்க வேண்டும்.

6. 2 lakh+ question database-ல் பல பகுதிகளில் இருந்து questions தேர்வு செய்யப்பட வேண்டும்.

7. Tamil 100.

8. GS 75.

9. Aptitude 25.

10. Total 200.

11. Difficulty quality maintained.

12. Easy questions dominate ஆகக்கூடாது.

13. GS subtopic diversity இருக்க வேண்டும்.

14. Aptitude subtopic diversity இருக்க வேண்டும்.

15. Tamil subtopic diversity இருக்க வேண்டும்.

16. Previous Mock history exclusion இருக்க வேண்டும்.

17. Duplicate content exclusion இருக்க வேண்டும்.

18. cycle-based duplicate filling இருக்கக்கூடாது.

19. Unique questions போதவில்லை என்றால் duplicate செய்யாமல் error.

20. Practice மற்றும் மற்ற modules எந்த மாற்றமும் இல்லாமல் இயங்க வேண்டும்.

============================================================
END – EXACT PATCH ONLY
============================================================
