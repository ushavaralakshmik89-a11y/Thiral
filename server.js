--- server.js ORIGINAL
+++ server.js 51-GS FIX
@@ -181,6 +181,28 @@
   'குறள் பொருள்':'Kural Meaning','Kural Meaning':'குறள் பொருள்','குறள் சார்ந்த கருத்துகள்':'Kural Concepts','Kural Concepts':'குறள் சார்ந்த கருத்துகள்'
 };
 function canonicalSubject(raw){ return SUBJECT_ALIASES[String(raw||'').trim()] || String(raw||'').trim(); }
+
+/* ===== ISOLATED FIX: NEW GROUP 4 GENERAL STUDIES (51 SUBTOPICS) =====
+   Only these newly imported bilingual GS subtopics use the Group 4 exam-value
+   compatibility below. Existing question-bank data and all other routes keep
+   their original behavior. No question rows are deleted or rewritten.
+*/
+const NEW_GROUP4_GS_SUBTOPICS = new Set([
+  'இந்திய பண்பாடு','சிந்து சமவெளி நாகரிகம்','குப்தர்கள்','டெல்லி சுல்தான்கள்','முகலாயர்கள்','மராத்தியர்கள்','தென்னிந்திய வரலாறு','தேசிய மறுமலர்ச்சி','ஆங்கிலேயருக்கு எதிரான ஆரம்ப எழுச்சிகள்','இந்திய தேசிய காங்கிரஸ்','தேசிய தலைவர்கள்','தமிழ்நாட்டின் சுதந்திரப் போராட்ட இயக்கங்கள்','இந்திய பண்பாட்டின் சிறப்பம்சங்கள்','வேற்றுமையில் ஒற்றுமை','மதச்சார்பின்மை',
+  'தமிழ் சமூக வரலாறு','தொல்லியல் கண்டுபிடிப்புகள்','சங்க காலம் முதல் நவீன காலம் வரையிலான தமிழ் இலக்கியம்','தமிழ் பண்பாடு மற்றும் பாரம்பரியம்','திருக்குறள் மற்றும் உலகளாவிய மதிப்புகள்','தமிழ்நாட்டின் சுதந்திரப் போராட்ட பங்கு','ஆங்கிலேயருக்கு எதிரான ஆரம்பப் போராட்டங்கள்','சுதந்திரப் போராட்டத்தில் பெண்களின் பங்கு','சமூக சீர்திருத்தவாதிகள்','சமூக சீர்திருத்த இயக்கங்கள்','தமிழ்நாட்டின் சமூக மாற்றங்கள்','சமூக நீதி இயக்கங்கள்','சமூக-அரசியல் இயக்கங்கள்',
+  'தமிழ்நாடு வளர்ச்சி நிர்வாகம்','இந்திய பொருளாதாரத்தின் இயல்பு','திட்டமிடல் மற்றும் வளர்ச்சி','திட்டக் குழு மற்றும் நிதி ஆயோக்','வருவாய் ஆதாரங்கள்','இந்திய ரிசர்வ் வங்கி','நிதிக் குழு','மத்திய-மாநில வளப் பகிர்வு','சரக்கு மற்றும் சேவை வரி (GST)','வேலைவாய்ப்பு உருவாக்கம்','நிலச் சீர்திருத்தங்கள் மற்றும் வேளாண்மை','வேளாண்மையில் அறிவியல் மற்றும் தொழில்நுட்பம்','தொழில் வளர்ச்சி','கிராமப்புற நலத்திட்டங்கள்','மக்கள் தொகை மற்றும் சமூகப் பிரச்சினைகள்','கல்வி அமைப்பு','சுகாதார அமைப்பு','வேலைவாய்ப்பு மற்றும் வறுமை','சமூக நீதி மற்றும் சமூக நல்லிணக்கம்','தமிழ்நாடு அரசு நலத்திட்டங்கள்','தமிழ்நாட்டின் புவியியல் மற்றும் பொருளாதார வளர்ச்சி','சமூக-பொருளாதார பிரச்சினைகள்','நடப்பு சமூக-பொருளாதார நிகழ்வுகள்',
+  'Indian Culture','Indus Valley Civilization','Guptas','Delhi Sultanate','Mughals','Marathas','South Indian History','National Renaissance','Early Resistances to British Rule','Indian National Congress','National Leaders','Freedom Movement in Tamil Nadu','Features of Indian Culture','Unity in Diversity','Secularism',
+  'Tamil Social History','Archaeological Discoveries','Tamil Literature from Sangam to Modern Period','Tamil Culture and Heritage','Thirukkural and Universal Values','Role of Tamil Nadu in the Freedom Movement','Early Resistance to British Rule in Tamil Nadu','Women in the Freedom Movement','Social Reformers','Social Reform Movements','Social Changes in Tamil Nadu','Social Justice Movements','Socio-Political Movements',
+  'Development Administration in Tamil Nadu','Nature of Indian Economy','Planning and Development','Planning Commission and NITI Aayog','Sources of Revenue','Reserve Bank of India','Finance Commission','Centre-State Resource Sharing','Goods and Services Tax (GST)','Employment Generation','Land Reforms and Agriculture','Science and Technology in Agriculture','Industrial Development','Rural Welfare Schemes','Population and Social Issues','Education System','Health System','Employment and Poverty','Social Justice and Social Harmony','Tamil Nadu Government Welfare Schemes','Geography and Economic Development of Tamil Nadu','Socio-Economic Issues','Current Socio-Economic Events'
+]);
+
+function isNewGroup4GSRequest(exam, subject, language, subtopic){
+  return exam === 'group4' &&
+    subject === 'gs' &&
+    ['ta','en'].includes(language) &&
+    NEW_GROUP4_GS_SUBTOPICS.has(String(subtopic || '').trim());
+}
+
 function subjectCandidates(raw){
   const s=String(raw||'').trim();
   if(!s) return [];
@@ -1097,13 +1119,16 @@
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
 
+    const isNewGroup4GS = isNewGroup4GSRequest(exam, subject, language, subtopic);
+
     /* Existing requests retain the original exact exam/subject behavior. */
-    const where = isNewTamilG4Apt
+    const useGroup4ExamAliases = isNewTamilG4Apt || isNewGroup4GS;
+    const where = useGroup4ExamAliases
       ? ['exam = ANY($1::text[])','subject = ANY($2::text[])','language=$3','is_active=true']
       : ['exam=$1','subject = ANY($2::text[])','language=$3','is_active=true'];
 
-    const params = isNewTamilG4Apt
-      ? [['group4','Group 4','Group4'], ['apt','Aptitude'], language]
+    const params = useGroup4ExamAliases
+      ? [['group4','Group 4','Group4'], isNewGroup4GS ? ['gs','General Studies','General Knowledge','general studies','general knowledge','பொது அறிவு','பொது அறிவு / General Studies'] : ['apt','Aptitude'], language]
       : [exam, subjectCandidatesList, language];
 
     let n = 4;
@@ -1190,14 +1215,17 @@
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
 
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
@@ -2449,7 +2477,7 @@
 api.get('/mock/questions', requirePasswordReady, async (req,res)=>{
   const exam=String(req.query.exam||'').trim();
   const requestedLanguage=String(req.query.language||'ta').trim();
-  if(exam!=='group4' || !['ta','en'].includes(requestedLanguage)){
+  if(!['group4','Group 4','Group4'].includes(exam) || !['ta','en'].includes(requestedLanguage)){
     return sendError(res,400,'Invalid Group 4 Mock request.');
   }
 
@@ -2476,7 +2504,7 @@
         `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                 COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
            FROM questions
-          WHERE exam=$1
+          WHERE exam=ANY($1::text[])
             AND subject=ANY($2::text[])
             AND language=$3
             AND is_active=true
@@ -2488,7 +2516,7 @@
             )
           ORDER BY id
           LIMIT 3000`,
-        [exam,spec.candidates,spec.language,req.user.id]
+        [['group4','Group 4','Group4'],spec.candidates,spec.language,req.user.id]
       );
       all.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
     }
