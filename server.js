--- /mnt/data/files/server.js	2026-10-06 09:34:53.566758668 +0000
+++ /mnt/data/THIRAL_server_51GS_TA_EN_SAFE.js	2026-10-06 09:35:37.853753310 +0000
@@ -180,6 +180,96 @@
   'பொருட்பால்':'Porul','Porul':'பொருட்பால்','இன்பத்துப்பால்':'Inbam','Inbam':'இன்பத்துப்பால்',
   'குறள் பொருள்':'Kural Meaning','Kural Meaning':'குறள் பொருள்','குறள் சார்ந்த கருத்துகள்':'Kural Concepts','Kural Concepts':'குறள் சார்ந்த கருத்துகள்'
 };
+/* ===== ISOLATED FIX: NEW GROUP 4 GENERAL STUDIES (51 SUBTOPICS) =====
+   Supports the exact Tamil/English labels used by the newly imported 51-topic
+   Group 4 General Studies rows. Existing routes/data remain unchanged.
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
+  'தமிழ்நாட்டின் புவியியல் மற்றும் பொருளாதார வளர்ச்சி':'Geography of Tamil Nadu and Economic Growth',
+  'சமூக-பொருளாதார பிரச்சினைகள்':'Socio-Economic Problems',
+  'நடப்பு சமூக-பொருளாதார நிகழ்வுகள்':'Current Socio-Economic Issues'
+};
+
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
+
+const NEW_GROUP4_GS_TAMIL = new Set(Object.keys(NEW_GROUP4_GS_TA_TO_EN));
+const NEW_GROUP4_GS_EN = new Set(Object.values(NEW_GROUP4_GS_TA_TO_EN));
+const NEW_GROUP4_GS_CANONICAL_EN = new Set([
+  ...NEW_GROUP4_GS_EN,
+  ...Object.values(NEW_GROUP4_GS_EN_ALIASES)
+]);
+
+function newGroup4GSSubtopic(raw, language){
+  const s=String(raw||'').trim();
+  if(!s || !['ta','en'].includes(language)) return null;
+  if(language==='ta' && NEW_GROUP4_GS_TAMIL.has(s)) return s;
+  if(language==='en') {
+    if(NEW_GROUP4_GS_EN.has(s)) return s;
+    if(Object.prototype.hasOwnProperty.call(NEW_GROUP4_GS_EN_ALIASES,s)) {
+      return NEW_GROUP4_GS_EN_ALIASES[s];
+    }
+  }
+  return null;
+}
+
 function canonicalSubject(raw){ return SUBJECT_ALIASES[String(raw||'').trim()] || String(raw||'').trim(); }
 function subjectCandidates(raw){
   const s=String(raw||'').trim();
@@ -1097,19 +1187,28 @@
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
 
+    const newGSSubtopic = newGroup4GSSubtopic(subtopic, language);
+    const isNewGroup4GS =
+      exam === 'group4' &&
+      subject === 'gs' &&
+      newGSSubtopic !== null;
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
     const subCandidates = isNewTamilG4Apt
       ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
-      : subtopicCandidates(subtopic);
+      : isNewGroup4GS
+        ? [newGSSubtopic]
+        : subtopicCandidates(subtopic);
 
     if (subCandidates.length === 1) {
       where.push(`subtopic=$${n++}`); params.push(subCandidates[0]);
@@ -1190,14 +1289,21 @@
       language === 'ta' &&
       Object.prototype.hasOwnProperty.call(NEW_TAMIL_G4_APT_MAP, subtopic);
 
-    const params = isNewTamilG4Apt
-      ? [req.user.id, ['group4','Group 4','Group4'], ['apt','Aptitude'], language]
+    const newGSSubtopic = newGroup4GSSubtopic(subtopic, language);
+    const isNewGroup4GS =
+      exam === 'group4' &&
+      subject === 'gs' &&
+      newGSSubtopic !== null;
+
+    const useGroup4ExamAliases = isNewTamilG4Apt || isNewGroup4GS;
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
@@ -1205,7 +1311,9 @@
 
     const subCandidates = isNewTamilG4Apt
       ? [NEW_TAMIL_G4_APT_MAP[subtopic]]
-      : subtopicCandidates(subtopic);
+      : isNewGroup4GS
+        ? [newGSSubtopic]
+        : subtopicCandidates(subtopic);
     if (subCandidates.length === 1) {
       where += ` AND q.subtopic = $${n}`;
       params.push(subCandidates[0]);
