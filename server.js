--- server.js (original)
+++ server.js (51GS fixed)
@@ -180,6 +180,105 @@
   'பொருட்பால்':'Porul','Porul':'பொருட்பால்','இன்பத்துப்பால்':'Inbam','Inbam':'இன்பத்துப்பால்',
   'குறள் பொருள்':'Kural Meaning','Kural Meaning':'குறள் பொருள்','குறள் சார்ந்த கருத்துகள்':'Kural Concepts','Kural Concepts':'குறள் சார்ந்த கருத்துகள்'
 };
+
+
+/* ===== ISOLATED FIX: NEW GROUP 4 GENERAL STUDIES (51 SUBTOPICS) =====
+   Existing question-bank paths remain unchanged. This compatibility layer is
+   used only when a request selects one of the 51 newly imported Group 4 GS
+   subtopics. No question rows are inserted, deleted, or rewritten here.
+*/
+const NEW_GROUP4_GS_TA_TO_EN = {
+  'இந்திய பண்பாடு':'Indian Culture',
+  'சிந்து சமவெளி நாகரிகம்':'Indus Valley Civilization',
+  'குப்தர்கள்':'Guptas',
+  'டெல்லி சுல்தான்கள்':'Delhi Sultanate',
+  'முகலாயர்கள்':'Mughals',
+  'மராத்தியர்கள்':'Marathas',
+  'தென்னிந்திய வரலாறு':'South Indian History',
+  'தேசிய மறுமலர்ச்சி':'National Renaissance',
+  'ஆங்கிலேயருக்கு எதிரான ஆரம்ப எழுச்சிகள்':'Early Uprisings against British Rule',
+  'இந்திய தேசிய காங்கிரஸ்':'Indian National Congress',
+  'தேசிய தலைவர்கள்':'National Leaders',
+  'தமிழ்நாட்டின் சுதந்திரப் போராட்ட இயக்கங்கள்':'Movements in Tamil Nadu Freedom Struggle',
+  'இந்திய பண்பாட்டின் சிறப்பம்சங்கள்':'Characteristics of Indian Culture',
+  'வேற்றுமையில் ஒற்றுமை':'Unity in Diversity',
+  'மதச்சார்பின்மை':'Secularism',
+  'தமிழ் சமூக வரலாறு':'History of Tamil Society',
+  'தொல்லியல் கண்டுபிடிப்புகள்':'Archaeological Discoveries',
+  'சங்க காலம் முதல் நவீன காலம் வரையிலான தமிழ் இலக்கியம்':'Tamil Literature from Sangam to Contemporary Times',
+  'தமிழ் பண்பாடு மற்றும் பாரம்பரியம்':'Tamil Culture and Heritage',
+  'திருக்குறள் மற்றும் உலகளாவிய மதிப்புகள்':'Thirukkural and Universal Values',
+  'தமிழ்நாட்டின் சுதந்திரப் போராட்ட பங்கு':'Role of Tamil Nadu in Freedom Struggle',
+  'ஆங்கிலேயருக்கு எதிரான ஆரம்பப் போராட்டங்கள்':'Early Agitations against British Rule',
+  'சுதந்திரப் போராட்டத்தில் பெண்களின் பங்கு':'Role of Women in Freedom Struggle',
+  'சமூக சீர்திருத்தவாதிகள்':'Social Reformers',
+  'சமூக சீர்திருத்த இயக்கங்கள்':'Social Reform Movements',
+  'தமிழ்நாட்டின் சமூக மாற்றங்கள்':'Social Transformation of Tamil Nadu',
+  'சமூக நீதி இயக்கங்கள்':'Social Justice Movements',
+  'சமூக-அரசியல் இயக்கங்கள்':'Socio-Political Movements',
+  'தமிழ்நாடு வளர்ச்சி நிர்வாகம்':'Development Administration in Tamil Nadu',
+  'இந்திய பொருளாதாரத்தின் இயல்பு':'Nature of Indian Economy',
+  'திட்டமிடல் மற்றும் வளர்ச்சி':'Planning and Development',
+  'திட்டக் குழு மற்றும் நிதி ஆயோக்':'Planning Commission and NITI Aayog',
+  'வருவாய் ஆதாரங்கள்':'Sources of Revenue',
+  'இந்திய ரிசர்வ் வங்கி':'Reserve Bank of India',
+  'நிதிக் குழு':'Finance Commission',
+  'மத்திய-மாநில வளப் பகிர்வு':'Resource Sharing between Union and State Governments',
+  'சரக்கு மற்றும் சேவை வரி (GST)':'Goods and Services Tax (GST)',
+  'வேலைவாய்ப்பு உருவாக்கம்':'Employment Generation',
+  'நிலச் சீர்திருத்தங்கள் மற்றும் வேளாண்மை':'Land Reforms and Agriculture',
+  'வேளாண்மையில் அறிவியல் மற்றும் தொழில்நுட்பம்':'Science and Technology in Agriculture',
+  'தொழில் வளர்ச்சி':'Industrial Growth',
+  'கிராமப்புற நலத்திட்டங்கள்':'Rural Welfare Programmes',
+  'மக்கள் தொகை மற்றும் சமூகப் பிரச்சினைகள்':'Population and Social Problems',
+  'கல்வி அமைப்பு':'Education System',
+  'சுகாதார அமைப்பு':'Health System',
+  'வேலைவாய்ப்பு மற்றும் வறுமை':'Employment and Poverty',
+  'சமூக நீதி மற்றும் சமூக நல்லிணக்கம்':'Social Justice and Social Harmony',
+  'தமிழ்நாடு அரசு நலத்திட்டங்கள்':'Tamil Nadu Government Welfare Schemes',
+  'தமிழ்நாட்டின் புவியியல் மற்றும் பொருளாதார வளர்ச்சி':'Geography and Economic Development of Tamil Nadu',
+  'சமூக-பொருளாதார பிரச்சினைகள்':'Socio-Economic Problems',
+  'நடப்பு சமூக-பொருளாதார நிகழ்வுகள்':'Current Socio-Economic Events'
+};
+
+/* Frontend/database spelling aliases found in the existing 51-topic mapping. */
+const NEW_GROUP4_GS_EN_ALIASES = {
+  'Early Uprisings against British Rule':'Early Resistance to British Rule',
+  'Early Agitations against British Rule':'Early Resistances to British Rule',
+  'Role of Tamil Nadu in Freedom Struggle':'Role of Tamil Nadu in the Freedom Struggle',
+  'Industrial Growth':'Industrial Development',
+  'Rural Welfare Programmes':'Rural Welfare Schemes',
+  'Population and Social Problems':'Population and Social Issues',
+  'Government Welfare Schemes in Tamil Nadu':'Tamil Nadu Government Welfare Schemes',
+  'Geography of Tamil Nadu and Economic Growth':'Geography and Economic Development of Tamil Nadu',
+  'Current Socio-Economic Affairs':'Current Socio-Economic Events'
+};
+const NEW_GROUP4_GS_EN_TO_TA = Object.fromEntries(
+  Object.entries(NEW_GROUP4_GS_TA_TO_EN).map(([ta,en])=>[en,ta])
+);
+function isNewGroup4GSRequest(exam, subject, language, subtopic){
+  if(String(exam||'').trim()!=='group4' || String(subject||'').trim()!=='gs' || !['ta','en'].includes(language)) return false;
+  const s=String(subtopic||'').trim();
+  return Object.prototype.hasOwnProperty.call(NEW_GROUP4_GS_TA_TO_EN,s) ||
+         Object.prototype.hasOwnProperty.call(NEW_GROUP4_GS_EN_TO_TA,s) ||
+         Object.prototype.hasOwnProperty.call(NEW_GROUP4_GS_EN_ALIASES,s);
+}
+function newGroup4GSSubtopicCandidates(raw, language){
+  const s=String(raw||'').trim();
+  if(!s) return [];
+  const out=[s];
+  if(language==='ta' && NEW_GROUP4_GS_TA_TO_EN[s]) out.push(s);
+  if(language==='en'){
+    const canonical=NEW_GROUP4_GS_EN_ALIASES[s] || s;
+    out.push(canonical);
+    const ta=NEW_GROUP4_GS_EN_TO_TA[canonical];
+    if(ta) out.push(ta);
+  }
+  const ta=NEW_GROUP4_GS_EN_TO_TA[s];
+  if(ta) out.push(ta);
+  return [...new Set(out.filter(Boolean))];
+}
+
 function canonicalSubject(raw){ return SUBJECT_ALIASES[String(raw||'').trim()] || String(raw||'').trim(); }
 function subjectCandidates(raw){
   const s=String(raw||'').trim();
@@ -1096,20 +1195,24 @@
       subject === 'apt' &&
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
+    const isNewGroup4GS = isNewGroup4GSRequest(exam, subject, language, subtopic);
+    const useGroup4ExamAliases = isNewTamilG4Apt || isNewGroup4GS;
 
     /* Existing requests retain the original exact exam/subject behavior. */
-    const where = isNewTamilG4Apt
+    const where = useGroup4ExamAliases
       ? ['exam = ANY($1::text[])','subject = ANY($2::text[])','language=$3','is_active=true']
       : ['exam=$1','subject = ANY($2::text[])','language=$3','is_active=true'];
 
-    const params = isNewTamilG4Apt
-      ? [['group4','Group 4','Group4'], ['apt','Aptitude'], language]
+    const params = useGroup4ExamAliases
+      ? [['group4','Group 4','Group4'], isNewGroup4GS ? ['gs','General Studies','General Knowledge','general studies','general knowledge','பொது அறிவு','பொது அறிவு / General Studies'] : ['apt','Aptitude'], language]
       : [exam, subjectCandidatesList, language];
 
     let n = 4;
     const subCandidates = isNewTamilG4Apt
       ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
-      : subtopicCandidates(subtopic);
+      : isNewGroup4GS
+        ? newGroup4GSSubtopicCandidates(subtopic, language)
+        : subtopicCandidates(subtopic);
 
     if (subCandidates.length === 1) {
       where.push(`subtopic=$${n++}`); params.push(subCandidates[0]);
@@ -1189,15 +1292,17 @@
       subject === 'apt' &&
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
-
-    const params = isNewTamilG4Apt
-      ? [req.user.id, ['group4','Group 4','Group4'], ['apt','Aptitude'], language]
+    const isNewGroup4GS = isNewGroup4GSRequest(exam, subject, language, subtopic);
+    const useGroup4ExamAliases = isNewTamilG4Apt || isNewGroup4GS;
+
+    const params = useGroup4ExamAliases
+      ? [req.user.id, ['group4','Group 4','Group4'], isNewGroup4GS ? ['gs','General Studies','General Knowledge','general studies','general knowledge','பொது அறிவு','பொது அறிவு / General Studies'] : ['apt','Aptitude'], language]
       : [req.user.id, exam, subjectCandidatesList, language];
 
     let n = 5;
 
     let where = `
-      q.exam ${isNewTamilG4Apt ? '= ANY($2::text[])' : '= $2'}
+      q.exam ${useGroup4ExamAliases ? '= ANY($2::text[])' : '= $2'}
       AND q.subject = ANY($3::text[])
       AND q.language = $4
       AND q.is_active = true
@@ -1205,7 +1310,9 @@
 
     const subCandidates = isNewTamilG4Apt
       ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
-      : subtopicCandidates(subtopic);
+      : isNewGroup4GS
+        ? newGroup4GSSubtopicCandidates(subtopic, language)
+        : subtopicCandidates(subtopic);
     if (subCandidates.length === 1) {
       where += ` AND q.subtopic = $${n}`;
       params.push(subCandidates[0]);
@@ -1267,9 +1374,12 @@
     if(!exam || !subject || !['practice','mock','bank'].includes(mode) || !['ta','en','mixed'].includes(language) || !Array.isArray(questionIds) || !questionIds.length) return sendError(res,400,'Invalid attempt.');
     const ids=[...new Set(questionIds.map(Number).filter(Number.isInteger))];
     if(!ids.length || ids.length>5000) return sendError(res,400,'Invalid question list.');
+    const attemptIsGroup4GS = String(exam).trim()==='group4' && canonicalSubject(subject)==='gs';
+    const attemptExamSql = attemptIsGroup4GS ? '= ANY($2::text[])' : '= $2';
+    const attemptExamValue = attemptIsGroup4GS ? ['group4','Group 4','Group4'] : exam;
     const q = language==='mixed'
-      ? await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND is_active=true`,[ids,exam])
-      : await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND language=$3 AND is_active=true`,[ids,exam,language]);
+      ? await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam${attemptExamSql} AND is_active=true`,[ids,attemptExamValue])
+      : await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam${attemptExamSql} AND language=$3 AND is_active=true`,[ids,attemptExamValue,language]);
     const valid=new Set(q.rows.map(x=>String(x.id)));
     const clean=ids.filter(id=>valid.has(String(id)));
     if(clean.length!==ids.length) return sendError(res,400,'Some questions are not valid for this exam/language.');
@@ -2472,11 +2582,13 @@
 
     const all=[];
     for(const spec of specs){
+      const examCondition = spec.name==='gs' ? 'exam=ANY($1::text[])' : 'exam=$1';
+      const examValue = spec.name==='gs' ? ['group4','Group 4','Group4'] : exam;
       const r=await client.query(
         `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                 COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
            FROM questions
-          WHERE exam=$1
+          WHERE ${examCondition}
             AND subject=ANY($2::text[])
             AND language=$3
             AND is_active=true
@@ -2488,7 +2600,7 @@
             )
           ORDER BY id
           LIMIT 3000`,
-        [exam,spec.candidates,spec.language,req.user.id]
+        [examValue,spec.candidates,spec.language,req.user.id]
       );
       all.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
     }
