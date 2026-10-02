import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import pg from 'pg';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// CORS for the separate Render Static Site (student website).
// Credentials are required because student login uses an httpOnly session cookie.
const allowedOrigins = new Set([
  'https://thiral.onrender.com',
  'https://thiral-v138-backend.onrender.com'
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const PORT = process.env.PORT || 10000;
const THIRAL_SECURITY_VERSION = 'V180_SECURITY_HARDENED';
const isProd = process.env.NODE_ENV === 'production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Set it in Render Environment Variables.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: false } : false
}));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

/* CSRF/origin guard for browser state-changing requests. The UI is hosted on
   the exact origin below. Same-origin/server-to-server requests without an
   Origin header are still allowed. */
app.use((req,res,next)=>{
  if(['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin=String(req.headers.origin||'').trim();
    if(origin && !allowedOrigins.has(origin)) {
      return sendError(res,403,'ACCESS DENIED: Untrusted request origin.');
    }
  }
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

function sendError(res, status, error) {
  return res.status(status).json({ error });
}


function clientIp(req){
  return String(req.ip||'').trim() || 'unknown';
}

function clientUserAgent(req){
  return String(req.headers['user-agent']||'').slice(0,500);
}

async function logSecurityEvent({req,eventType,userId=null,email='',details='',sendAlert=false}){
  const ip=clientIp(req);
  const userAgent=clientUserAgent(req);
  try{
    await pool.query(
      `INSERT INTO security_events(event_type,user_id,email,ip,user_agent,details) VALUES($1,$2,$3,$4,$5,$6)`,
      [eventType,userId,email,ip,userAgent,details]
    );
  }catch(e){ console.error('Security event log failed:',e); }

  if(sendAlert){
    try{ await sendSecurityAlertEmail({eventType,email,ip,userAgent,details}); }
    catch(e){ console.error('Security alert email failed:',e.message||e); }
  }
}

async function sendSecurityAlertEmail({eventType,email,ip,userAgent,details}){
  const url=String(process.env.THIRAL_SECURITY_ALERT_URL || '').trim();
  const apiKey=String(process.env.THIRAL_API_KEY || '').trim();
  const to=String(process.env.THIRAL_SECURITY_ALERT_EMAIL || process.env.ADMIN_ID || '').trim().toLowerCase();
  if(!url || !apiKey || !to) return false;
  const subject=`Thiral Security Alert: ${eventType}`;
  const body=[
    `Security event: ${eventType}`,
    `Time: ${new Date().toISOString()}`,
    `Email: ${email || '-'}`,
    `IP: ${ip || '-'}`,
    `Browser: ${userAgent || '-'}`,
    `Details: ${details || '-'}`
  ].join('\n');
  const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},redirect:'follow',body:JSON.stringify({api_key:apiKey,to,subject,body,event_type:eventType})});
  const text=await response.text();
  let data={}; try{data=JSON.parse(text);}catch(_){ }
  if(!response.ok || data.ok!==true) throw new Error(`Security alert bridge failed (${response.status})`);
  return true;
}


/* Group 4 canonical subject/subtopic aliases. The database may contain either
   the Tamil UI key or its English label for bilingual rows. Never delete or
   rewrite existing question data: requests simply match both known labels. */
const SUBJECT_ALIASES = {
  'தமிழ்':'tamil','Tamil':'tamil',
  'பொது அறிவு':'gs','General Knowledge':'gs','general knowledge':'gs',
  'பொது அறிவு / General Studies':'gs','General Studies':'gs','general studies':'gs',
  'திறனறிவு / Aptitude':'apt','Aptitude':'apt','aptitude':'apt'
};
const GROUP4_SUBTOPIC_ALIASES = {
  'பண்டைய இந்தியா':'Ancient India','Ancient India':'பண்டைய இந்தியா',
  'இடைக்கால இந்தியா':'Medieval India','Medieval India':'இடைக்கால இந்தியா',
  'நவீன இந்தியா':'Modern India','Modern India':'நவீன இந்தியா',
  'சுதந்திரப் போராட்டம்':'Indian Freedom Movement','Indian Freedom Movement':'சுதந்திரப் போராட்டம்',
  'சங்க காலம்':'Sangam Age','Sangam Age':'சங்க காலம்',
  'சோழர்':'Cholas','Cholas':'சோழர்','பாண்டியர்':'Pandyas','Pandyas':'பாண்டியர்',
  'பல்லவர்':'Pallavas','Pallavas':'பல்லவர்','நாயக்கர்':'Nayaks','Nayaks':'நாயக்கர்',
  'அரசியலமைப்பு':'Constitution','Constitution':'அரசியலமைப்பு',
  'அடிப்படை உரிமைகள்':'Fundamental Rights','Fundamental Rights':'அடிப்படை உரிமைகள்',
  'பாராளுமன்றம்':'Parliament','Parliament':'பாராளுமன்றம்',
  'மாநில அரசு':'State Government','State Government':'மாநில அரசு',
  'உள்ளாட்சி':'Local Government','Local Government':'உள்ளாட்சி',
  'இந்தியா':'India','India':'இந்தியா','தமிழ்நாடு':'Tamil Nadu','Tamil Nadu':'தமிழ்நாடு',
  'ஆறுகள்':'Rivers','Rivers':'ஆறுகள்','மலைகள்':'Mountains','Mountains':'மலைகள்','வளங்கள்':'Resources','Resources':'வளங்கள்',
  'இயற்பியல்':'Physics','Physics':'இயற்பியல்','வேதியியல்':'Chemistry','Chemistry':'வேதியியல்',
  'உயிரியல்':'Biology','Biology':'உயிரியல்','சுற்றுச்சூழல்':'Environment','Environment':'சுற்றுச்சூழல்',
  'அடிப்படை பொருளாதாரம்':'Basic Economics','Basic Economics':'அடிப்படை பொருளாதாரம்',
  'இந்திய பொருளாதாரம்':'Indian Economy','Indian Economy':'இந்திய பொருளாதாரம்',
  'தமிழ்நாடு பொருளாதாரம்':'Tamil Nadu Economy','Tamil Nadu Economy':'தமிழ்நாடு பொருளாதாரம்',
  'எண்கள்':'Numbers','Numbers':'எண்கள்','பின்னங்கள்':'Fractions','Fractions':'பின்னங்கள்',
  'சதவீதம்':'Percentage','Percentage':'சதவீதம்','விகிதம்':'Ratio','Ratio':'விகிதம்','சராசரி':'Average','Average':'சராசரி',
  'பரப்பளவு':'Area','Area':'பரப்பளவு','சுற்றளவு':'Perimeter','Perimeter':'சுற்றளவு',
  'கனஅளவு':'Volume','Volume':'கனஅளவு','அலகுகள்':'Units','Units':'அலகுகள்',
  'இலாபம் மற்றும் நட்டம்':'Profit and Loss','Profit and Loss':'இலாபம் மற்றும் நட்டம்',
  'வட்டி':'Interest','Interest':'வட்டி','காலம் மற்றும் வேலை':'Time and Work','Time and Work':'காலம் மற்றும் வேலை',
  'வேகம் மற்றும் தூரம்':'Speed and Distance','Speed and Distance':'வேகம் மற்றும் தூரம்',
  'எண் தொடர்':'Number Series','Number Series':'எண் தொடர்','எழுத்துத் தொடர்':'Alphabet Series','Alphabet Series':'எழுத்துத் தொடர்',
  'ஒப்புமை':'Analogy','Analogy':'ஒப்புமை','வகைப்படுத்தல்':'Classification','Classification':'வகைப்படுத்தல்',
  'குறியீடு':'Coding','Coding':'குறியீடு',
  'எழுத்து வகைகள்':'Letter Types','Letter Types':'எழுத்து வகைகள்','சொல் வகைகள்':'Word Types','Word Types':'சொல் வகைகள்',
  'வேற்றுமை':'Cases','Cases':'வேற்றுமை','வினைச்சொல்':'Verb','Verb':'வினைச்சொல்','புணர்ச்சி':'Sandhi','Sandhi':'புணர்ச்சி',
  'ஒருபொருட்பன்மொழி':'Synonyms','Synonyms':'ஒருபொருட்பன்மொழி','எதிர்ச்சொல்':'Antonyms','Antonyms':'எதிர்ச்சொல்',
  'இணைச்சொல்':'Related Words','Related Words':'இணைச்சொல்','மரபுத்தொடர்':'Idioms','Idioms':'மரபுத்தொடர்','கலைச்சொல்':'Technical Terms','Technical Terms':'கலைச்சொல்',
  'சங்க இலக்கியம்':'Sangam Literature','Sangam Literature':'சங்க இலக்கியம்','பதினெண்கீழ்க்கணக்கு':'Pathinenkilkanakku','Pathinenkilkanakku':'பதினெண்கீழ்க்கணக்கு',
  'காப்பியங்கள்':'Epics','Epics':'காப்பியங்கள்','பக்தி இலக்கியம்':'Bhakti Literature','Bhakti Literature':'பக்தி இலக்கியம்',
  'நவீன இலக்கியம்':'Modern Literature','Modern Literature':'நவீன இலக்கியம்','அறத்துப்பால்':'Aram','Aram':'அறத்துப்பால்',
  'பொருட்பால்':'Porul','Porul':'பொருட்பால்','இன்பத்துப்பால்':'Inbam','Inbam':'இன்பத்துப்பால்',
  'குறள் பொருள்':'Kural Meaning','Kural Meaning':'குறள் பொருள்','குறள் சார்ந்த கருத்துகள்':'Kural Concepts','Kural Concepts':'குறள் சார்ந்த கருத்துகள்'
};

/* ===== THIRAL: 5,000-question Tamil Nadu politics batch =====
   These hashes identify only the 5,000 questions from the uploaded batch.
   The database rows themselves are never rewritten. The frontend label
   "நாயக்கருக்கு பிறகு தமிழக அரசியல்" is a virtual filter over these rows.
*/
const THIRAL_TN_POLITICS_5000_SUBTOPIC = 'நாயக்கருக்கு பிறகு தமிழக அரசியல்';
const THIRAL_TN_POLITICS_5000_HASHES = new Set([
  '41df4f6451b966f95a54794de546c477',
  '5cafd0d077a6c02eecb29d60c8a5e45d',
  '9b7f10b79c842a8d689d76fa59f7cdab',
  '0f43760550ca24614162c3d29dc27624',
  '9185462a9aa838d7a93c747104612a01',
  '38450367f26f97da4351342caa01b096',
  '46a05bba50394bbe9bf21d3300c8043c',
  '9a5489f8b413a1bd224b7b843424ef58',
  '275feb1a584642095534f2a93f4ef9a8',
  'a711308eae138ce7baddb5d9d135ce38',
  '13dd1c0fffaed12da381ca5d6e3034c6',
  'ce34312491a45884a157b157319f2da8',
  'dc2513bb3310c06dc662a5efbc4ccfc7',
  'ddd4a1a6848488790afa2562a6341ace',
  '2776d63adff9fce9ebc7b63ebef6f265',
  '403959c5596efa5a69ef52b7eaae5edb',
  'd8fb02318e7092c0e36076315704aeb3',
  '51b134fc2b2aae5f8eb47d6ee3f41961',
  'ba79a80c000d5370e32745bcb66d1f5f',
  'a933e50dd374735eccc7c609d54879c9',
  '2c54b4915a9027573efd6e382e0223ad',
  'ae6e373ea50f4284851cc4ca22889c77',
  'fb50b413e3124351bccdc6e0b61bce5b',
  '794a6dbe5d4aafd46858014f49557165',
  '8fd83de03716776ec9e2a796de72ac88',
  '6419502ef41953b64bef31fd947b596e',
  '706b1b305ab8fd5e7e030acd3a924ce1',
  'c2f93aa2a08a7f6576e2aeebd8f4236d',
  '21b392a28e5b66dd52c6525fb3df7278',
  'c9c2edd6f28c938e852f27f962fce561',
  '2925700c08f2d9a69b83bb2163ed696d',
  '9370d834d9d2d86ac7280753f089b45c',
  '31da3084c12c0b9637f47f415497f195',
  '10554c7dd0441b07a9874ed0034820ee',
  'f3aa9c6debfd58f738c8cd623df64bd2',
  'f49cac562be6170826c089d64d49a1f1',
  '4a9cc4ccdc523957e5ff60b932544fe0',
  'c4b151a8ab0d57d36b4e5acd6494a17a',
  '8eaaf880db4d1c87fcfae06bc412416b',
  '3b690b3d19214a3d1cc2e3108e6b0653',
  'ea26090f66f61966a14cfa3422f7d0c4',
  'fe8634894b5df01393e5ec798401560e',
  '117c28c474f25260ca4110d87383bd5f',
  'da49832807dafb7cd564662916d5479c',
  'e64c99652b093b1cce0ed1b979c02803',
  '55c72e25746c9dbb2202f8f3e42b3742',
  '9f894c2739bdb56a2cd7960a10170238',
  '9c1f2d03a87a4ce985921fb9de8d2d0c',
  '25f1fe278aa72ba1cf300fa3151086bf',
  'ea6acaefc1182f727997e8a1cbf3899a',
  '7437a47e523bae91d4b8f70ef23940c1',
  'ff96e65c81be502edc61920dcdd2b60a',
  '9607513ad0e29c6588a14bb2504d555e',
  '5c19a8fc1069ba68026b22759e7ca3ba',
  'ab99c70329dab8de4ae094d41cf20d30',
  '633bdac17882edbef3c3241d09924e42',
  '88f96b165eb33d1df1fb7a9a132ef094',
  'bba84c027bd18d0c0c31b4f697590843',
  '6258b912b2b2c33cd082aba9fc200e16',
  '5e3d86a87ef00ea043838d473f92bafc',
  '48bf36e9681cd488fb1b8d8008bb7b35',
  'c094029d61a06da5c6799cebac85607f',
  'f3441ea2dc37ba06cef2e6576f5e15d4',
  'aa781314b7937f3ae63e1fd5f430d0ea',
  'bde5a4287f9f363d9bb2ed4d317ec9c3',
  '40212a9d4b23311224019308b0d2bb49',
  '2a25bdc1c681991d74b30cad5566b1a9',
  'c47e1bd4845aa6126b0564283d7796f5',
  '9a9ddee2e4db15f3d7e75c1e2e6addce',
  '562a6aa22bb203e24a98711794393310',
  '02ac089f6e9cf98f920b12d79aed98c2',
  '3f715059a2bfd941ee2ea2607306cd7c',
  'ad3c7325b32483d19f0a250155836a21',
  '3c398cfdd9fcc1e9146bab029fa34a31',
  '5c4104e79e75fdd29cd6ad31f4a3c602',
  '8ffbdf9f2bd5a86f2fcc498433b0a4d5',
  '7402c73940f81837556b654dbfdc91f7',
  '4d935b208cbf609c6a1836d0289038df',
  '4899867c6760484a740d4a6187a105c4',
  '3d45688a312996e17058ec622fda3b20',
  'f2c35a7be0fa0c3ea7d88e123cc8e551',
  '2710900a94ee4750d33b641b0b5b13dd',
  '5d1b57e05f23eb80105e68d548d93c7b',
  'ebe0df9e7d23059b2e54152271c421ec',
  '5f037566ef754711d9ca658196e017f6',
  'bd560f00de323169870448566aedaf0f',
  '8cac0b27c4a48db09b6b4fb64b3d8cc2',
  '5b3c0e85a3efe6318cfdb819c6788e0a',
  '1b0f2be333424539f1ef61fd92aa7d80',
  '3f7f70dc8d00f148c92a81f7b557d099',
  'd0006fbf33e1fefa1d964cb57cde34f9',
  'e8035ccc5507cc5cd4aa8d4b546fa2ed',
  '8df56ab1296e48219920b2d784be44d3',
  '8a46d732a6e5a88f045ceb26a80025b0',
  'a3f05843fc733e1ce92062d55f7b82dc',
  'a501a10e797629bb60a5920c7aa6841a',
  '6ced2bf735f11d507ea342e82383f5b5',
  '1d80a454602343ae54f8eb3cf0505e68',
  'd5a267d511c5c24fd0af533e149b7a65',
  'e6bb176d48750b50f72cb86dee739d5a',
  'cd226e43ec6f5c6b11ffb0792c7b53b7',
  'eb0acbdcd3deda6226f9ba95a31ae6b9',
  'd28e9753cdcbc75bc81ac538f69cf189',
  '89a477930e010815ddcbdb0b75bc1160',
  '025612de30a2f7ce6400fee39713366c',
  '0ee732a723eb7dfc99ff1761e6c7865e',
  'ae42b8283d6e2c798f1a60d617da421b',
  '8bab680207ee45a1e214144eec02e1f0',
  'f49d71ea29b2c153462aa45842512410',
  '55ad06b69b0876c6975da6efb2fb5dbf',
  'f515feed1588400945e84c14f0a41e55',
  '0301cee7ba17f96feae58c7e502d3091',
  'fdccfbea883903aefe86af2e2a0482f3',
  'a7ad03ac476c660a4335e0188b9ba831',
  '8f427dadcfd49ba8167eb62bc77c058c',
  '92e2fcd6e2d954679481cb1965604871',
  'd116f6d37f2daef284f90608a7bb628f',
  'eedebff9f64884b213f88ab2d8bc2925',
  '45b16a3a9983d8c2e6e3adf8723ad925',
  'a57f9352b63264af1ea1fa24cc49c1c4',
  'ce5ee00e69dcb391d34c680af517b646',
  '88c8a4d1ca18c7133a7927d5f8ae168c',
  '7874f0557c1f0a45844648f27cbd226a',
  '6062e256c7235b8b18273670584ddcfb',
  '2bacd18578103283a455ccd4ac7aec0a',
  '3d1278539dba86acc8316a6c9f273adb',
  'cbf2bb5c4ab09b586678f40498748773',
  '7bc5c1ee610a1eeafa43ab4a98126d22',
  '7be9ec917701f351e4b90502bcf4467d',
  '5ae3983652affb66e5d2e50f264cfacf',
  'dd27265bfd29563782cd7016fea0e614',
  '2771a98714b597a0a79a2082dd783102',
  '96618625250f67f1cd65f60cabeaa151',
  'e7251a75717dbddad688f90e0169dcf5',
  '951766eba672d8a842c0348c3287b6fc',
  '1841e813f5cbb8137af7677e6cd89e08',
  '0ec50e4b67372bc53fb4af96f555ca75',
  '091d63347c243129ad94e44899270e31',
  'afd4f5774c696cdf51d921cbc1e1ad5d',
  'cae3c9fa76d11a29d88cce2bd50a9ee0',
  '612c56e7312d54b3ecb8baa840eea8a8',
  'c0fc69f73b0ae5566eb2048c61d7a58b',
  '674ce06ba5d5cfeebe279fdb235e0bfc',
  '9bb19b93c5fac5f7f18776b1bbf9395d',
  '8281900d1b4a36007ad6560843d5c2c9',
  '6a97e1b9102acc4b5bdf5973a809aaeb',
  '3dafd74b8299d90fadd2a5a6a225ba3d',
  'ca6d6eda0a67f8550a72347b9a2c2a55',
  '0063dd39a08e06279fe04d5815341736',
  '8a7256fc42451f2018f1fcade66d9f72',
  '018fae1ebc1da3f8eea0abda06f068ef',
  '6f85236270002093be7ec58967047d66',
  'b21da2b659c43e615c1dc66e5c5c6a1a',
  'c3f3ba69abe46c341cf3c2d2ccc30d07',
  '9a69fd71671694e95ca60c83b36ca4ae',
  '64af29220c31085471774e6b49c2bf08',
  '5a06a8c1a4510ca4d0f6223dd6d89b2e',
  'b96b9dcb1117a0d929048bc30f29f91e',
  'f30c304451d12c6da45bacd42778583f',
  '5d344bfb9263ed918eb0b70965e4906b',
  '1486a100596058002b8c6483a54d2f15',
  '49c5fd25a3a94595c0c3a43b40d8b47a',
  'a6df46e9d04a66aa835b4c949eab6c59',
  '4d27e3467199c485f4938811f8fcc458',
  '13dda6d7ef9887c182b9bf446338514c',
  '7ad86ab6dad7be55c518166c7ff95a44',
  '6da42b0f8d63fcdd703bf8bd7a02f904',
  '35515aee8e2e704eab85152eaed8949e',
  'b72baa89b32f1b40538cc5c37476e781',
  'c8d9ef66340a1ab2a43c09a11f46799e',
  '5b6b7a2e9c3b14c9ef4e6853acb63a77',
  '3247eda6199b3f4dbd05060e8597aed4',
  'f2c6c5b775136442c76f2fecc8006c67',
  'c336de999e59a148436f1bda1ac50ef2',
  '9aa128ff4471ecb963a0785d27fb4696',
  '0bff2309525c66da0da42eca82a2a1ed',
  '3fa4dc321166d76849861a6dc28919f8',
  '320fcd58bce4e0d7b6223343be64b2a8',
  '552e05a0cf7b8e1fe8ab336ad57e7c6b',
  '979fdb9116635ef77e62012217239e23',
  'bfe2e6cc0cd00c92196a6301a0781411',
  'ec3d08d19005a8ad6af9a7cdae06582c',
  '7fc6f6145fce7b1f0a618cb722dbeefa',
  '9de4cb170e3de0c51598bfb27dadb5e9',
  '0307d0abe133c695503ff37cbb08f668',
  'c2feda9fea56a755bbb8d165e63c7782',
  '0623e53974f8075d09caa44d22a13f6e',
  '3509e5528260bc985e6f04418448aeca',
  '3b13004af070bead18a43d4a3a456455',
  'a1e1dbcc0424c54ee5df0fb02edddb40',
  '3b6393272723db57c5a9bda829b57096',
  'ac0cbe87fe1478de97c5839c0b62c73b',
  'cb63212eb683463e7bbed702a966279b',
  '9f150d5db6ca0f2b47056cc3a61e0f4d',
  '0de928fc69e177031160f4cea9e118d9',
  'b4d4d9160dcd1fb29b1faa7b5e80f510',
  '957d7b0723920453c17433d198d61d5c',
  '2d3c6bb43e7f9cab7eb8f89a33226c46',
  '29c62a2ce90f864511ad785920251e22',
  'dc8eac817e65c4c0573914cde0a901d9',
  '673149ced1ce89751badac8cf3532d06',
  '084df5a93f13e10bd1590ff195abe603',
  '7d9762b342997f9799de964d0aacf7f5',
  '5479efb4301218e5fd13504d59152e7c',
  'ff8212074aca3b6bc415ed788f3310d8',
  '17ab6b5d6497f5ba7710ca430b5faa90',
  '227db8ed3d88590ef1068477c5300782',
  '82c7bcac69cf340862b28a3c245af9d5',
  '4725242d73736c0e98785ef8879af22b',
  '00ae3a3a3ca8fc04a541139713fe8a0b',
  '4282ad8d031d02dcc7807e6d9f1fc20a',
  '193807abee7f116a0b8ec6802b4fa686',
  'b433ce0d382d45c6d97c414ddceed7cf',
  '622742ab7b0cbb192219d9075bc1eab1',
  'af1d5de94f9bedc7718ab3e66b5f536a',
  '2be6eb639c16a231731cd25175182656',
  'c79e4d58c5a5ff3a6844d8ff776e67a9',
  '870c0e9299afb8e1123b4e838703348f',
  '2a24bc500df037ccf54544c988d2b717',
  '5550073efd83be3a0a4ec34e114337d8',
  'fd46ac59346bc2288501c7005c4cfd12',
  'af47172696942b629f7f149ed4a1d1a8',
  '23fdd5288b537c7eece1e37cc5c3c5e2',
  '7cfae4f76dd405978b5247803b96c780',
  '779efe7a220bc08cfe0615e94e9866e0',
  '9836ad642aef0ca2f2ff3a8fb572b985',
  '3e804eb3773cad792b6623e107724466',
  '64d8ba2fb325a1f9ed78cb4fc0c0bac7',
  'cd397f056d0355cd3c0ec45975288fe0',
  'fba082442a54145e9c0916ee402aa2a3',
  '8934a507a8ce00d0ab8cc48bb45f6281',
  '1461c7c07e27234f3dc6a233e434413c',
  '336ec206f50a0a5f4dd827a888001df5',
  '7d1430541e0faa66d0f134ccdf33bd62',
  '8d3fe84a28290ebad4e168d153655b39',
  '048495c3e77582e68f28ade4aeeb7156',
  '92e773dcc3672bc7099fedde184b6161',
  '09d766ba89c6b6cef06d948140b0ccf4',
  '02e6826222089b53a52cce72ac641985',
  'aeeb12095060aef002b05d60a0737c08',
  '1d8de144ac27c9179f5b8f3477a47f6f',
  'a3a52c9120d06d3e423abfe7ef6684fa',
  'd66f41f4c15d69a9d32cac3385201b85',
  '98656b21d689fb0aa48c8f2c92f53908',
  '7f2622d4958f24919232776b5578a74d',
  'd16bb43769ef73175d8e0e22ac32837f',
  'd4ef3f980982c8d7bacb060dcf0cb05a',
  'f71f94545ea2765e6ca300db25aa8332',
  '23e222e5ffb5aa070497dcdb0c6a52d9',
  '019e88065117fbbcc1f78352805a0ce9',
  'bd63ba645550e444913cd5193c5c5f54',
  'f6f984fbdd4f1d5f5cf155b26964735f',
  '4b964d133b124ee78477ad5a22484650',
  'c272a085c965095e0c6a1a72f5348566',
  '7a2680298f1be0c488fca5370177db88',
  '3102e2904965e772b5085d66b2bac429',
  'e82ee8e6c2b9cbe09ecf6aa13e66f1a9',
  '67519973a31b2ab5afa5250edb281e9a',
  '224c4662393ff942aba82b6b24b71cce',
  '32f964d024f11739b1250459895fb43c',
  '22c545ee19c20357cfdc8232eb005c69',
  'cf613c64a30dce528e3ace906f305083',
  '60a2fe0fecd2d35224b4f2342ab3c3b7',
  'e1078e6760aa41baa19b6eace29cb619',
  '75ee72eea33a3ae89f093756af361b13',
  '7ede40e7b5a20e520c1b9397246feba8',
  'a9b9adc7ac5922cc4680970f6138bb43',
  'a7af034dd511e9f1445e614bf827e544',
  'abdd73b92c319d3bdd2d3318446b5b89',
  'fe97ac1075924ee6085f1363619a2ed5',
  '8722dfe1187a256768c55a23fcd34234',
  'a0a463c5bf4901ec55153c71b3e5ad53',
  'c9f270f0cf9d68bfac9686d640382b18',
  '9af93a96142b3dfef6120b9abc2046ae',
  '6532882150c469cacea16acca5fc622d',
  '30372f9993e906cb1832cb160debe773',
  'f4ea1437f0dae907f8521c73c1f5879c',
  '25662d7c363b3bc7a4a49057bbe2fc2e',
  'a6e26865eac06d1568a868a6859d3307',
  '7c7e62243a95ae3910541859bd6aa96f',
  '5baa7da98912335059b8cb8c8abb6662',
  '673d5cc55c6c269d767771faf9669bf5',
  '906fd0a147b190d53ed4de20b008fa6b',
  'f37e8395ca9247b8d102376eec83f490',
  'c0299c358a8d2c080315b8dcd9e2c013',
  '6dea5dc27e09d239771e934ceb9aecf8',
  'ae85eae03d0bf85ede621e2c4a99b85c',
  '47dc04f0c4473899ec7b7dfcdd1abb7d',
  '5a2f43bb1b7635681d2723f3cdd0eb24',
  '43a97450d84dbfa63b2ca8575f5b934d',
  'e01591b54607f1ecc418b768e514b99a',
  '11f88c7a8f93032f15b4f40e72a5e5f8',
  '91a20229a8fc96fed013a4e2330d4786',
  '4a31a3ed2069e5dadbf5cff1162c748d',
  '0c981e35a6b7a364c2eec8a35c80288c',
  '5ef71b60d0b4db1e7466d8ec686f60df',
  'bf075a2d7c4367cab69c5d83a822bc8d',
  '1df9073f576854db72abfb1a3c4f68a4',
  'fbfa48ecbe60c5ef32115e3010e47f8d',
  '60689567679cfe3e27df1812b1b8d086',
  '44ff61b3b64c3b8909eb23ed367a1bfe',
  'b3d47c0a795c702f8d91895304801a33',
  'aa0fc7e08d7d1f6e56da9452344c0204',
  'b8d5c3682c6d872681bf82284f236aaa',
  'ae995c48cc2b7fec4aa2f5dd2ba8fd19',
  '3d76b3b9e3aa0960d424c2ee6677ebd2',
  'f4503bb5f7f5300c8ac9cfb922a295b1',
  '31630aee8d8cd1ed34e6aa91ef2c4ebf',
  '46ea03a2b0688f98141cea9c259b6ffe',
  '52d413f38e4aef0957415859f1028df4',
  'f55d4690908cbacb841de8cc47f5c036',
  '2ae9f91d75cadb0b6e615c521d4ecbcb',
  '64169dd9564da2cd6b5e10b0d4fa035c',
  '732a746241cd1f5d285a5670aadf87aa',
  '4f4c45aa1491bdef03133c719b21039b',
  'ee03ef25d9f2011ed71e76c78b52aebe',
  'a5588aa6c9795d0e55037711546739d1',
  'a2251ef2da25262e5a1599ec42814a33',
  'd329795f82e7eeb114bfc43a47395b0c',
  '22c21ace88ba24d85736109cddff347b',
  '30c7ccead3355da195f3581113f9be7a',
  '5004c507e02b320687317b78037b8f99',
  '96eea76e59986d6d132c23928f68b9fb',
  '411042df45d81ca473599095d6401bfe',
  '4f2ca32baa25420089bebbaebce63c5a',
  'ec8e8b95f2df1c6f3e812d6d45157bf5',
  'c3897fb79dc365d3c3cfd454efa63e88',
  'db7405e86d9787edd25ad2a54b10d84e',
  'd3cf2cf198620633ca1ae46a69400c52',
  '27bed626349696634062566d035c18a9',
  'fe0563e60d55f3968aa16864bed7f9b9',
  '988069250828dd51ca5e2823ba6e1d64',
  '9515ba35e6519587facd3db96e702825',
  '2b7ff64e6163df91a04721c5eb876eaf',
  '3a97ecdc4dde0df7575cefe1a8e6d475',
  '412006eb298bbbdf0f8c7854cf9cbc33',
  'f6d7c9892007d2848d730b75565da533',
  '9e416aa8445d444b769cc5d5eee9da98',
  'bebfd53a0ee8d88521d43393f6f0b937',
  '3b3c1d1b68102e5d7341efe93af7825e',
  '78cddc0dffe8519c0f4cec36f0f741d3',
  'b902bab93b6d0c4cbdc42536c1862708',
  'cfefa5027799b7aa980ce21cfa47f8f6',
  '312318eb9d47a09e33c9165508c010f9',
  '552f4abff9388b8b0fe77f6d49472d8d',
  '860aa717d2fae1a8cd49d6ef1e9c6e4e',
  '29beb02cf94f4b82e1b5e80af3effabe',
  '4589b7d0d61a38adf2a51b298e96c9b1',
  'a6d7bda4925e0c974e1826cf6b0c40f8',
  'fa31ea79eec9c8f00ddc1318ce919029',
  'd42573e3c555b7564d56e7b0fa8a5ca0',
  '11e3d88c850728501e4ede87c6d617fa',
  'b6777411ac42546d06811308b8eb974f',
  'c4cf523244b0a67128ba8a2bdee315af',
  '35a25db07861498adf3a2b4f572d34ae',
  'f247def9a469c91c418ebcee470911a1',
  '4ad49f74eb2c5194b71a595e4a00e813',
  'b30dcc7242c68d5676e1b1af30ae34a9',
  '1b5ec0df8426f11cac49a5fc32a876d7',
  '85c416dfd6ab629ac82c4ba1dca2a360',
  '7f8274979c8b702598963adae25d7cfb',
  'd54e17437116e49c8a81fb541b66ba27',
  '08d5b72973dcd9b3154895153d0a048f',
  '9a3c3208fa122768f7d98d594ca52801',
  '6851edb986390a02fd83b7c4571b0b97',
  'e1c3575ba6af689d1d34e9b47bd1ec4a',
  '0e0be2db4716188737d3e716106080e9',
  'b45143787bf080ec46e526822996693c',
  '01abc8cf058256585eba88fec0030bef',
  'e6038badfe58fff42df79b4873538323',
  '9dceaf61d7af9cfa1ef12973612df3b0',
  '4aab81e8f578dfa8a2d7b5e86b7957cb',
  '83ab224ae4b959c2be27f4d7fe2ddec2',
  'fd9c542f9ded6dcb538f0ecf4ed8d1f8',
  'faa86754f17d2ce189b5109c398198a8',
  'fa62b7f5b01d9451891421be6fee7142',
  '124930a16312e41b133c8bc8a196dad2',
  '676ce9d394fdf3fc8792e02503b057fc',
  '7b5855be45aac0bf605b3f7c6d8aded2',
  '8f93aff779285874be7942c0897dd4ca',
  '23838bf0cfeb74118a82519f2b844474',
  'ba577bda8aca5525bfb15f180a708722',
  '35c523c02908dc9ecef46a01db49d299',
  '811e11ae64ac3e61e868734c53f08a71',
  'bed5fc0b65e7dd094fd336a5dba475d3',
  '4cbd4271195f199aa62e59053db9d8a5',
  '568002598016d25719d6dc7313b63c16',
  'bb8e92f17317d74bafda888f0517652e',
  '8119f14b6db2dd0bdc2c479dde9ae6da',
  '7c518c71ed903db08843ba9957a0629d',
  'bb66257a943d4e18924ab404d05c6451',
  'b907ad4ea4334f40a844992857e00033',
  'fbf76dee841e6ce552f2fa28abe890a2',
  'b10a2e1386d3ac04e81b9650cf6b0d10',
  '271391d2faef936c4c7b1713d4284f0e',
  '601502d24e5a815bb70917779817c8ae',
  '5e6259d7aab249285f12335daa5f35fd',
  '515b2c2ce5cec2018bc098bf3f4c5701',
  '7e655d5b6b62e5e4120dfd3c3429c441',
  '1e9e9fcb8e17c4894345f4bf58a498ff',
  '2ee9ab92cba78788b7b84a0c3e8971f1',
  '508128930fc2fc0889502e88834f2621',
  '804dd7c2062938b06bbf8a7490d819b8',
  '920dd431cd3a0e45fef354d1fb8a9ccc',
  '34f83521a0f50e180cc75fe186a22e0e',
  '139fd97cf3b368f337434d7d42eb875f',
  '4c3b77a21e88c692fb0f4d1ac20c8d48',
  '8f4682232c147e76f62c56625d8e79de',
  'f34dbc495edde7b1e7c2ee165516acb4',
  '7581da43855f994e49a53ada37a51dee',
  '912987f8950bea5480503adbd575bae7',
  'd21b9e506f5deac384b670d774676e81',
  'bb5f699edbb414e27b96abf243fda8ec',
  '1c25fd6f08625b18df1b5e3df9be3450',
  'a528d9eeb2b7867567ffdd742b325cbb',
  '10397dae8904c3576cfd59721d867cf3',
  'c797eb68cb529acd4780213ce35a8d0a',
  '110d1103860e5d117f6069a168183b05',
  '5b9f524e27c0167e0a986d8a17e31c49',
  'c2e3371639447732bc6b98fdd64413ca',
  '51745227974200c519d7faa285979272',
  'af4d5c5be67b84000f815b24df51ff18',
  '710066e2a1f0331499c8cd32664cd040',
  '9362a223582c88a766e38fce1646040e',
  'ce0f32f42320f5e1f1deb22a1e0a33dc',
  'af6655bb37f2377f075c618712302c28',
  '2efbc6a69143f64dcf9a890dc9a8d731',
  '51417a523d8adaef979b5274379836d0',
  'd3dc9745bd881dba25044ed6f43b7979',
  '24480ef0766f87e2d9f0f1062c645517',
  'a75a37ea5ea51037436d271932908b48',
  'fc226e2e8bd482bbcb663dd29e3e102d',
  '9c99fadf2197e28d206fa7a099691bbe',
  '0f9774f0f303cf7f9631281be6006b3f',
  '68aefcc1ef8ca9191961d7b620c0869e',
  '28e1a7d3680d8e8eb6cf012442f33659',
  '06ae73591a649b48c0fb9962e98641a8',
  '91ae380f334e78417f543305aca1deb6',
  '03874214bcc93535b22acdb293484dc2',
  'c1ea8380fd0fc3be8d0e3aeafcfaeae1',
  '86c36416b8f00937a53b945fc2aee1d6',
  '9979bfa8f84e5afe3f442fd084c62d01',
  'b605b82e8082ba7f73761b187e7cc0af',
  '14f952df5830fcd6204ad5b7a8b84e99',
  'a5e05d02ced47d501779db76f19ffe5c',
  'b9a3fd096fd87f7fdb5c86983f9189e2',
  'f82812d8652d256743d054655d9d7bc1',
  '18b88ed94eddef9c67abd464c7e20ad4',
  'e0f002fc6b3909da2ad4f32a61f73807',
  'fb64a333e4d7f8f31d3303076adb8a95',
  '328a3169b8d2176d0a610f738a3162aa',
  '7e3f527b070c85209104d6a634cef1ce',
  '129a9f96565761e901aa403d2b147993',
  '785edb9d8e240d021bb6df7f1cd9b3d5',
  '010bb5932d914f433c8a1f2e6ad6face',
  'd768c97f5ee62a4594fbe58fbb9a0f06',
  '825fdfebe55dab32684de212c4aee6f1',
  'aa9d73ce28ad5552456d634483a42325',
  '1086dd90ea15f68a2073f81e0a02b508',
  '98167b7045cd9a21aabbfb68807a93d9',
  'c924d4ce5573a8e70fbc7ecc2cba371e',
  '0e1952d49ff68a3960d1a74f8aaf460d',
  '03d85c9d4a322b6b72c620661947a47e',
  'cda4ded6613bc70c2d2b13c1c3c071c8',
  '0776eb25c88b58b57d4fe7942bfe89bb',
  '447f8021b64d6cd3555f508cef1b5be6',
  'c8a4e37ee1197e497ed99d2faaf357f8',
  '9cd79b6f0e381742f6e3a4d7e30768ea',
  '046551011cd124261fcced1a5a19dde8',
  '402d97a40f407f720ab51e0400a87964',
  'a2f253365c516b02ee72e3163f619382',
  '954fba7f4cee6c32c6218a04d88389c8',
  '786a68b50489b69a130a0d717754cb6c',
  '95394a9561724fdd7140054dab34f96b',
  'fec530ddd889829ee620e8cfec2d4936',
  'f0373be79ce7df0c02a16ca9b8fbb994',
  '6ce1c3f0e25c6ccf27ac55c6224c1b51',
  'aa9aa3c20586890644e07fb4f7dbd5cc',
  'df6672bd1dae4ea83fa51b226d9ae5c2',
  'd5d41c8b8f1352228bf9cb0534b743bd',
  '089e29abcee6e96f2fb54bdf147f311f',
  '5780395b4ab218a0d83a4d4e2af8a632',
  '1bf4bf67233f5d23dde8c926589020dc',
  'e6d3e11ce6b2e2300ee7b3c355f5271b',
  'dd8a50fe4d8a6bd5b7005c9729da7e03',
  'aa59a8115395c0fabfc85df58baada83',
  'dacdad63b970a17635e7a37e6824fdf9',
  '1b189aef9becc09037ddd43bc6bc47f2',
  'd93e5fccef144a23293f784363f9bff9',
  '14c80bb3b5d8faf2981abf230fb8af80',
  '5c704c2405f2c5c2be522fb3f949b502',
  '308f3af011bc753751f855ff2d6d381c',
  'e85954c2dee0b4d13b837b00b341818b',
  'da0e0fd0872e306eeb158ddc4bfac25c',
  '8e6f78b698e387f19f7633e7e35c5043',
  'f529e93db983aab92cf2ea1b8ef86500',
  '48ffaea906e15b3427ddb53c096de351',
  '52eb5744c7bf340a9741597ea693c3c0',
  '90eef94fa6264de38cd8e12a462323b1',
  '5474e5d2485482f52089e4f74db535bf',
  '6c4f200c1253fb9e8d6ed711affd19eb',
  'adda0de41696859b41903b217c25ce41',
  '41330562e36d9145b2764b943b2d0005',
  'b705db0a84fe2e4869202f93f6f81500',
  'f73f5c02b19eabd0639740e0b9cefb84',
  'ffdc1fe9fe4ea13af70c6337c50c8de1',
  '0ba6bf648e99614c14c8262488dae563',
  'ff20f59b183bcacea4fde9a2205d80b9',
  '4da80add5d8585d3ea357f1b1f66cd52',
  '41a480826d3210c35c6ee2714cf72971',
  'f68d998977e948c54ec28959e9644af4',
  '0b29e4b9e4c7331dcbddc29cdd043748',
  '07b6863fb3db8b88f98c842dbed540d3',
  'cb6315f42cbc621b0084671f13d44eef',
  '4ed6ad3120fe008ad46d9d7e76f92027',
  '6c881e7aaa3e1baef23810ea6536c640',
  'd1fc65937c3b463381db8a833f7f8142',
  'a6d7896aba4e6856607ccf350a274110',
  '0b910c3cbaa1737db9611b923cbbf1a3',
  'd021d531a6f98a1167f11438c4f6ca1f',
  '48c97b2d3e9213ce99da5627e71ee1fc',
  'a27afd1092fda0b97e611d007b0297be',
  'e066c30b677fbe92d0981c2c66acda80',
  '19fe1037bc4440a0dbe3052555322ef0',
  'd2e906261aec11f405af19ef337f5f86',
  '14137c85baadd3b96a30fc6fca05ac24',
  '033766b1abb99fd8eec8786ff4308ffc',
  'e38ece89a075e1a6596b0a3819a698e3',
  'c01d3982003d97ec87411ffe2ea29dab',
  '2cf5d415f7586f636052277cc5028b65',
  'f445a2de8bef73fe66054179a80cd9bf',
  'e1fe721662db346ae508b2dfb1779fcc',
  '587bbe5323162a7169a1c61d3c7dffa9',
  '6dc74821bc5d01eb87cfb876d67cfeb7',
  '7b5649c4c27edf3758e64149bfa491b4',
  '9bc6bf31f2e489ceb720a7edd03d85ca',
  '89881204bfc3c71da2a6eb2b44e1d271',
  'dfc582ec27afa6c72a84872b2e27ca9f',
  '285579c80f10f90da3365d0391442b8d',
  '5ca78be29e38e4df68832820abea8b9a',
  '4bf92b8cedfd2bbc1eddc014d872b130',
  '3fd9251e47b40544b835adecf6cddfcd',
  '72bb7cca61e938d98bb6368d0c8e3bd9',
  'c3b2099b2ee605ecf30063db59b7ea47',
  '4871c7486c9aea3ff995a623f62ce74f',
  '77a7fba1a51e4b9776e4543d3be831e6',
  'a27aeb91a40779b94fe3e48bb60628e2',
  '25d14f3322f3207157b188a472976297',
  '03fcf6b4331f7b569d49d40f91ad319d',
  'ed898f89f184e60c627852dc18f24176',
  '84094987c0b498fbcf10d88a44589859',
  'c39d457f971926b7c8aeec4894972d61',
  '81f8acd62f57f2fc023370c83eb632c8',
  '86c1e040ac377fcf4d3359c0adb60ebc',
  'b1b3c9b5de250185e44a1634d91e1cc1',
  'e0f11d4f21b65c30fa7d02b9a7f0525c',
  'c31a793206fbf92633885a7305f4b7bc',
  'd246c91f7389f9190ba52496c1d85406',
  '9d67c3a5f5494b56e190e5403a0366a1',
  '1f4beb905d015ff95f68b7c69e165318',
  '563ac0f70baf88c9a167941b0140b1f8',
  '38363c8eeffabf89c4f8b3cacf6add2a',
  'c93096e6b440c338b85ab937f54dd650',
  'a8f3d431328f7c7faf7d2a494629901e',
  '8fc089878864b0e2d4e4caeb6642546b',
  '36ea9f7368c173751b9c9df7dae39326',
  'b7b11524e1a636cdfa85cbfc7c962a81',
  'fb3a8ac0196219f314b20231a5f31fab',
  'ec41707321c70c6013cd04501d301b72',
  '37b01f088aaacd4a3bdba6ff6f0aa3d4',
  'a6b531b02a299ccb2360b68629ce66d0',
  'cd43eef489e0c1aed0ccabf67b1be775',
  'a85349ea4860f018d9e8c67bf13e2416',
  'c7c07094438ee3b8376129ea11aa440c',
  'c611d39bc987d6610f672e7d668f3c2b',
  '809e0171acec56fa19509660fb381c2c',
  'b3dcc53784b23256f38f234d9920eb43',
  'e90c0ae51d06fdabb6709f592dc652bf',
  'aa83b7ebd94860d1b1552623923d5dec',
  '13c4458e0c11ffac58e595b82c2dba98',
  'c5ed8217773692b306a50bdaacacb8e2',
  '2b6179c2342f2a0b2e8611ddbb31f711',
  'f44a15f1c66aa9b9c3e49c8da6c65bcf',
  '44372687d311412b5f2afbf28d58a922',
  'c330138471096dbf132d1337e3a7381c',
  'b8da5e8967d0deda24f984c368d78d9e',
  '23c53396ab78a5569ad3e549364182c9',
  '6d9c76925d55af087f023b51b3c0cf91',
  '774d943eae8a5d4eacc68fba378ab6c3',
  'fa7a1ea8e0ec2bdc223894dd6ec64ee8',
  '4feca8a12f941b40ef08d49d3c9c068a',
  '558044b3ec09e1118c18d0a4ebbef1a5',
  '105cdcf280faf07810ee8e41a219c7f7',
  '3eaecb71307edcd1c52807138a2c281d',
  '7d3ec27d442809a8eb9dd735a203f68d',
  '4dc557e793df41748e81a59d578ae505',
  '4478775a0d2b2f54302eab2d39e46435',
  '199fc2185aedea8be19ff15d940a73f9',
  'afd402de4bf4d6160609485df3e378ae',
  'cafbba8df8fc994804053639a1015f10',
  '70b8ce89e4b651972c6ae8a5a462fa1b',
  '623d08fce550d943af2df51664a0566f',
  '292a70b9e2f9ef8a1e8a5a1ff37ff151',
  '2f2925c3b1a40af4057f7a5b2d8d4f50',
  '1ee7af24af08fdd693d38e35f649ba90',
  'e5d567c98a91aa552975ad076e7aaf26',
  'c892eeb302d320c1d915bc84a176ef67',
  'b43481ff24188029a20caa315da9bed4',
  '3f145431a6114ad9a9a8e7a038da5e50',
  'e0e523b7335c327e194af02ff7e73116',
  '924086dfc9926baf5f1f8571bc5de969',
  '35181165bfc6e98d14b14a7ee97a5075',
  '943209941b0cdd39680e80da90b27bb2',
  'c1d3781ed35a462c491e138b575e8728',
  '3e24e10fd8dfb9a525db0fbd9c8369d1',
  '9f1f1354f4bc9df8f9a5441ec2903d61',
  '1408d5fb30f77e27bab0ff72de3ee1b8',
  '57495321a78a472518a78338635613fb',
  '18d9fb9be54a4f6fc9a3fc95b7352526',
  'e4c9129df305b2e0b3693b83e8508d26',
  'b7b6bcf6dfbca59efff1ab9ef8c47017',
  '7c228106a9cbd21f765cffe6945e4e3b',
  '916643eab5ec4bc89d57681a651fefa2',
  'f9c95ba102a5d5f6965e9dd488b946d3',
  'c15e9fd489cad859c0ec29cadd5278f4',
  '4c3d3e85711eb02421f942959e839d83',
  '223dbd2a24840a1f7083495e1c54dd87',
  '150dd13c46db994f90ecc4f2bc4fccd1',
  'c0ed3d2e47fd1be5e780b68a58ef0ae0',
  '86f2b3c4bb99061666383b8aebe204d1',
  '72da23649cd6e855f8b572104ba02132',
  '11544bf31a4d50aa2d88c8f66d0232c4',
  'ad5d75f6ef6c30e5b50ead7ccf1a350e',
  '1d55ebcbea091dd2297ea95117f5a071',
  '55cca7ad1303fb25ba895000ed944a06',
  '09646827caf003c4a3ea2bed4b6cbda5',
  'bb1952764a089337b33aefdf8c669126',
  'c57fae9ea3c31c4a1f837c15ae580ec8',
  '2276dca10bb7a9cb630748594e6a026c',
  'ac52fe31c9ef8535dbe9e424ebe9141e',
  'a3414c10f21daf89f223de608b7a6f9c',
  '2e2441691af0c14783051981262f02bb',
  '084307aca880dca307d8ae7b81efb847',
  'af779d72ecd8bef8898a93ae2c5f6d33',
  '38df7d1692d6b5eba44ce5004a0f677e',
  '316dcbda2423ac5a7db27496b6a17008',
  '1f963ca3bcdf0789f8ecf6742080a1e1',
  '6a7f9fba99ce25b14798557ab6c5f404',
  'b077e98629fca1f46ee2b5676eb88043',
  '31f174cd5a197af356403e9ac3937211',
  'cd234b6004428925c453480d2c0745f6',
  '7a1e77b53d125e179715c6495d6e7681',
  '6619caa61463b3b7d2414a7ae3e889a5',
  'e0ba1c1eb799a31b69b16cd6b8cec032',
  '464e40960c76ef759eddc59fa2acb805',
  '602289e26d174dc6d9711a0bb6f6005a',
  'a060655180c2f34927e749474c8076b2',
  'aca2733ab67120dff91012b477a159d7',
  '71b17b8d4a25b0f625ae6a95517be799',
  '96f5b0a5b46e15325aab2a1ce5f1502b',
  '9d8d41b56eb08726e74b4e50e1efd81c',
  '68ba8ad5b36306731ac09e05631bdab7',
  'c22478ea611ee4829b020ff42a99fbfc',
  'df078dfc8b474c89609446d5ef734478',
  '672806b2e0d6274a1a87ff519cc6312f',
  '00ef806ccb67e4854548a97855576d46',
  'df6ceecf1017eed039a6081b35856b21',
  '464e1090eb7468c31ce168db1ba381c8',
  '093fe7fe4b26d99f2ba5b91c68fcb7ff',
  'a71d4c174765cf5218ad12edf1d04df6',
  '4adef18071f2043054345324a2fe3191',
  '012b04723b750bc4c2db663c9acf0f4a',
  'c6837bbe7a4e6bf19421409876b7f2eb',
  'fce75040905f54de57b01833f39d4753',
  'c3a9996f22c579f05c7e41248b2e6bdd',
  '1270a494073bf5c4363e2138c5298214',
  'bb9241a8527b84fa5dd7887e278068de',
  '172621e81642d3c6741c09e9e7e3e862',
  '086ffc9f5a4b9a62b439d0e51d07b7c5',
  '3ee39b76afef19d05bbe34a615ddab24',
  'ff2b932afa8fb7b702c7a3279e763baa',
  'e8341563e6e9a5be8f0731276bf8eadf',
  '70e0d27085221c7132fd86003d5a1de6',
  'c38af742b8fb80d2a9f5b03f775543da',
  '237a4ffda1c99416d6749c000ece5734',
  '55d1528ce87fbd2ae99e551208a2d75c',
  '3e7cd6bfcd193095a4ed5ecc511f437a',
  'db90c5f000429c06b2fa67ac2d7288b5',
  'd52557a71c98d9a556891588fd3e77bf',
  'ab16786ddd2428887989fffe75d211b5',
  '4c653eb5f980857ca37f4820e5c6a93f',
  '8e9623d1f92e212122058668e3a0318d',
  '9aa4a912327bb274cf3c4cef0546830b',
  '9816760fe7ef6d2f3da78bbcf0f0db9a',
  '999fde1df4c73686e9537db42a88371f',
  'ca276613cc2b0c3801ede0a666a6591a',
  '530a34cb432f69906f8b3d312772f132',
  '7f7989ea098d8e50725ab4e9f0a647b8',
  'f593d1cd251c68266d1e939fa811f28c',
  'c19f614f0f4d0ce917c977ee318654cc',
  'f87b8222e8ac593f885cde1462693ceb',
  '5661f04c887a0985e8783ca36ff4bf0b',
  'ba027bfbd358d50012c955fbf0e59f5b',
  '14b8fc633f05cca57b41a508bd3654dd',
  '143a86d5574f54f6c75e7e4facea9723',
  '55c3b4c6652ac67a0e750957fd0e3a41',
  '3dc3e771b979da603b5e666a1b7be9b5',
  'a5e74af72812cf3b290cf6c973e6a2e9',
  '12f8231aeef0077b73ba38db2bb34f4a',
  'fa57654dd62b27dab663b5281c654e23',
  'e8ecbdf00b23c4e6f32b18eba6789253',
  '36370fc5d6f2582410722ce7ca976911',
  'be8a29c43eb7a8acf637786e92b35d2a',
  '7e2df365ec9d5986d3a88259bc08dc47',
  'e943a07c435341921e8bb149f52733e0',
  '332205eb198d418dcc32fa4bc9e33999',
  '1869446f56adacc90c8bfd16be74ab2f',
  '7670fc9f5ceef5c2fe851ee61645c01a',
  '491e794bb4524d2dc3432c01d9d4bdcf',
  '220bab3e2065f8355c26070dad428103',
  '1eebe3c9a56ed83535b76518899422f3',
  'd32ecd6a7e5855cced2dde52e9621d92',
  'f6eb957f0c58d6417941ee4cdbb60464',
  '324a4d0bd7676f61590c022c8d615721',
  'eacc9fd55e7a70d969c101a20b1a42e4',
  '77c7ea7fd3471e1c27064204b7860e8c',
  '2f07d9222e409d8bf467dd6a5cc1c2ec',
  'e0a08e5ca01a461fe5a6c5ac31f8abfa',
  '013a3a4fba58209b9ef8dd72b77f46e0',
  '03704738276e11fd42674c16fa0af249',
  '18d709cbdf342d13fa4ad59b4860bb76',
  'dd69ba8adb3d9b2684b8998ca482cbf9',
  '1cdb2033ebe7cc913c950319c071fcee',
  'f7849e1e62240e922428d6abc0ccd3ab',
  'd3e1cee9d9f10309e2c74d145cb7dab7',
  '93bb8a9eb9875c9c1399baa3f90b56da',
  'befdba44ff45c49affc2dec1079a6077',
  '32e1c4d117256de4378110b309ef0335',
  '0f8132816c4d32d694937ecbef8e9b1d',
  '73acb0344bbbe0ece8dbae0028ca041d',
  '4531dddd9d227f8d933e875c3a21ea5c',
  '505237f4b37d47ff027acca197549872',
  'ac42fcaf853d462c8219949ac75fa021',
  '5091596a4d83d50a6ef85b3cfdd3ca24',
  '14895b32bcc5f4f295489195022fd9d4',
  '1acfb33bc8ed5d22743cb7dcb8331456',
  '0d997ec6251c85866cbac27702e81680',
  'c411bc24a7dae9d07795a3fcb9aaf746',
  'f20c5a9cdf695522a69df45409bc1730',
  '82f6d59defeb5e51dcc05492c1ed10f3',
  '7f532383ed7e699b73634c68ffaad383',
  'e18646c4ac20164c227c1ef9a9d7ceb7',
  '7374f7294c958b5b4fb7540eee500fd9',
  'f9fc98b45561454346ab9c5ef10ad4ba',
  'badb5d1625111f15678a7c7cb17c30f7',
  '431ff93b1e2541e679b3675ade0c82f6',
  'a665de71fc5f99329a8f2c2104e8cdc9',
  '6272adbae0dc8c12d656b9affc120a79',
  '5879aefb668d94cb1c22e5f2353cacc9',
  'f7d389b988bd46ece6c01c3349c5abc3',
  '8a7b322bf449651839141580e545f6f0',
  '21d167d66e13d4cbcc9073b94f34ac37',
  'b514bb180073def6b583326172b48fe8',
  '9734ff4321473c6506ec335e950646e6',
  'e104cc584436c928368b727bb8675c25',
  '7f6316e29dc83b77fc36503f53ce3349',
  '62fdf22c182893a02fac5dbfc70123f0',
  '4fcf1723537549810614e0a81681268e',
  '19b719a64b10d050d29d50a059b55ae9',
  '8d48865f4179cafc234589473fc93625',
  '7c8fe0910ead8caa5c7bac69ad770b59',
  '15e1ea2f0d1b6479171dfa79054ac99b',
  'b6ce48ab65a6f651e0ba947ce61193b8',
  '234db857c96a00696042b85bf1a5150d',
  '3cd968f5ba5651e5704dac2a527188f2',
  '68c6c76311ac7accedb10af3f7f766be',
  'b2371491f8fe16e383b03e2e0553d325',
  'd83d8eee04623cbb4b247c5db4c8727a',
  '7383426f3c6a51347654369fe63ebb13',
  '93aae6b2895d91ff84d625a2a2178276',
  '73f86a2896c3ba40a44f07225638e28a',
  '6c1b271a0940a8603851607e979c656e',
  'f91b4953e0233a9de232c6f04b552734',
  '1def2852f2b1fc57cf1b100bcf25c255',
  'ae9715e71837d9a68225f83b1f0e5baa',
  'c4cc32f183a06a5cae3a7ae039386156',
  '4701d7ac32bbbc1d67c100032b8ae345',
  'b02add1531c235b303429f75982a339d',
  'b1c93368c3e13ac1f47e758842d03d8a',
  '80b6cfdf4779745e2131913a53564e6f',
  '6a556a8ff5a9c19d9e40fc316332b384',
  '372c839dba71feb929175a6ea40ff95d',
  '22f9525590bb5f848c1c13af4ce10610',
  '9e64e99bf8c2555a4a6414d2ea75c6d7',
  '3dd31bdafe7aad3834957158ef923e99',
  '5b71cf845c5c8c8a8fe218426fc302eb',
  'fa4fc81cef382668395c6e3f9451501b',
  '4703fe6656b3a73248342efcd48bc9f9',
  '7e6e42174a3b30a0cf6f119b1960d625',
  '0c07ab4a078fb5fb5b6c52a71c6527db',
  '6cf383c0e9459587a5bcd429a56f711c',
  '5c9182d65fe23d9a45aa2af6f0df6147',
  '10c63704d634abbb534ec4668eb6d410',
  '3bd846fd723a663d45e24776f4e013e8',
  'bf387c213c2449265c6edc14b71fa0e5',
  '42016d316a37e4732607ed01a27a922e',
  'b8b4461d3dac297174e38cf0d9034d6c',
  '0699b3588284e09404ea2c57033d8975',
  'd1118f42ada92346f50e2ea6fc1d855d',
  '24bb8aaa95b3367bad50374f2e4ff3b9',
  'd819ac56916f425b17441d4c40520bb2',
  'cafd8877be67e44f60c14eb8584a639b',
  'a0171284a741ad54680d7333701bd86c',
  '0a82592a430f6289b60a476a557b3bc4',
  'b791d5f5e59e75b8b84bd1f201ed3bf7',
  '7b461db03b2a866ad819b09b0cb8d896',
  '7f6955280271318114d1cd589a9db6ae',
  'b8933249771d46146dd6e8801cb81322',
  'ff2dd6308469741a49f852c5279eaf35',
  '7912cd8d07fd70ec5c15535530eeba4c',
  '0495790a4b15e1a995824637262aac40',
  'dca56c2f42766a1f07d5a5ee90524b61',
  'e51ef7146c562074cc850220cdd93746',
  '75738b19a0669c809880fce734be3a8c',
  '8aabc57cc9664b726c5d8ff1153d8746',
  'f38f5934465b8c50f0e2fc51654425a4',
  '360260d4711d57a5b401c01bd8f57efe',
  'f906a7317652c66d46422bafef48f1b3',
  '67303f228485020151076eb6f138e2a0',
  '065a8e999ca9832019d3960b5daf8f91',
  '5c511570cbf30f671b7c0ce44b6fe285',
  '6c985554f1e0fef04f8ef533cda506f0',
  'bf9099bc101428cba7526a19d86aa656',
  '9fd7e4b283d84f87164546c28c185182',
  '75534d1401786d4680286b1b3529e2e5',
  'b8a8b488e1c3141fc56535b0249c3c32',
  'ee7ea6945766e1613ab0d927067356ea',
  '277eec835fec116a93940bc5064f73e1',
  '3d450d77fd8bd7969b8ec6db9996d936',
  '765ab33dbb4533f4e83c6028d24f8c27',
  '4fdb70ce2d2280ae2f4a2194f2befe8b',
  'fab84bc83a902c3e404c4e75302d1d91',
  '3f4d565a972bccc6a5de565d361df85b',
  '8ecc53747e31871513da1efc5b2025ba',
  'c58826d76673414d8be6773c67ea364d',
  'a077d61e47cd5a17c287e3c5cad40310',
  '25b6d1a01ebe0d6720a335ae83c82356',
  'f59f55665d89cf9f410d63b5f3dadeb2',
  'f2b5327d209e8a01231ea0a313e384c8',
  '8cc114cb8ca83294e49e687579c16ffa',
  'f08dfedf64c097eb21f53bffd1fa1995',
  'f32002406c316799abc9cb117db8b125',
  'c490f4db67751e545d8efb2aa3f20009',
  'a5835a907b1fee8d4b926b331172a3d6',
  '9c58ed3efaa9dea33d76a66ce74f03c9',
  'dcfb54b0f06584e96b5bb0c377965382',
  '940f01941bdaaf4bb6c9055e12a78c3c',
  'ab5750eb5f79a86d4ac4085901c19628',
  'a91d8e182a73a7aeb5cc45fd29bec214',
  '7e9d450736a43b7a9f8c6c5123367d54',
  '65921fe42a2d02bdcdc324815f527baa',
  '10126c64d62e4ad0aad2c0e96985820c',
  '2cf28a3de096e17de99e72a9a806a63f',
  'dfb8904c66a0f7614aa93fcf4a1b3d43',
  '736f045816af3ad96bb012f30d012118',
  'a7632a75142f2280d17ccb64578bd48c',
  '60b4948f95166fd17dc109619908f820',
  'd09187c671e0ab9095b2eadcebb4af46',
  '24b329f6c482f41804bd499f8a63e20d',
  '8f052d96c414c5f5156683e5980c473a',
  '7d2b227027399ab7447c5695a9c1e2ee',
  '0a3c767603511ed519eb0f940dcd2aa4',
  'a1f2a5abba50fe62b34fae2ab4427ad9',
  'f2d6c72cf2e44a46c7abf2925d789018',
  'f4546fbc35db82dbec2cc27fb7f61c16',
  '3618f98bb8428a37ef4b7a6adfc85197',
  '8ae2c6864fedf5185f992c3672070299',
  '58829f856dc7df07bf8170e9feaf5b0a',
  'e206badccae0a85596c7b7ffb93d750f',
  'bffcbed8c42f37eca849d2603bf8010c',
  '1fa517e81e04bffd778bfb46590b50c4',
  '7bd6bbb231c345f326b285d61a5131d8',
  '184e7cd88b1fb4b7880d3ddfa6cf11e9',
  '3f720d33d0ffc6ed85c1b76a415f882a',
  '49f42eb845a21e120de55cfea114b928',
  'f98e6f5932ee00d508b503ea49034710',
  'ac015776d64ba24608066fdd9f167c57',
  'dfb1adc012b0b4cb9b08fb536ecf81e2',
  '5ff3c65220c87da47109d6f8f564abda',
  '9430261087bdc9c92797c28ee5f7b1b0',
  '02fdce32bce32d87adeec803d970c6ad',
  'd1c9550c5d84a5ef47baab3b6b6c1a50',
  'ee52295ce3fca5b4178ebbd0c402745e',
  'ee6a1a43f85bb407fcd0461c69635e7c',
  '309e8029f0b947d67a90e09bd6f6c366',
  'e1b9341c4762d43dc1bc58b956719baf',
  'a896bbaca713abe77b0b4c2f2d656377',
  '35f19c7ba6de7f9bbedebf9f5640b3ce',
  '78d43636251a8fa915166389da4b9dbf',
  '75b4a74368ac951ba0b740edd96732a3',
  '4122ccc21ca9f8f34acecec721c94a2c',
  'c8ac72488545ae434d2fedd9d7704570',
  '147695f476dfab085c96189b5d40b299',
  '3de1ab2d959daf06931a2e8ec523de79',
  '291255e40631a5552c0a670160b2ae77',
  '4cb4cdc9bf95a9f8b323d4455ba8ea2a',
  'b12cda12dd997300288c10453e52649d',
  'f097b8177a95603a9c16cd9475ccf221',
  '7cc9cd2e9b3f2457b4485fc4620b0e2e',
  '01f6ee6d2c8dbf01d1af4e559300327b',
  '4ce4ea0ce946b1507b4443640583a1d1',
  '9d632d2276708d027eec758780061c40',
  '0bca3ab9806037b565fd8effe646debb',
  '09d750fb5e9db2e4ac2f3e13a8c9c0cb',
  '093ad9657b50ded83ccb71e13ce17e13',
  'f64b3745b0116627ec3eedcadbc9d57e',
  '803b99e27f9420e1b47f014bd4766104',
  '4aa82558bbeac9bd7299f097a21c10b5',
  '9d6f68af95d2ddef129a0186b6586682',
  '89b63be5099bfffda6ee93dc53face77',
  '0aa3b9fee420f299dda7b82146bde081',
  '0e1f9e76cab6041f80c4753190a0daa2',
  'e9ffbf1baf4f5f319068638d69140d51',
  '06e23e04b8d289f9ce989b2227ea22a5',
  '9ef037b3ab5316a49d21d3c92495b6a8',
  'ede26f768f76388f6a7f11c7a3dbeef4',
  '138cd89a7da962c521bf2af15c39a44d',
  '9782f8405377e2cab6f793a6a64872a9',
  '26ec2029dd773fe305c63295cc3ed199',
  '00d37a7e0ad1007ac73656177167718b',
  'd1496b45d05afcc9d1eb191344d08b43',
  '6ee9f5d4df4ac5188b2969373eb9a4d3',
  'aff064197c8c59f9c40d5423e62d545e',
  'ed3f316710f6b363bd365c443f6adc5a',
  'ae5b4b91af387fd3d9d60cdc95de8d0c',
  'f8bd307f8d14dd51466c869e66c82805',
  'fde859347ba1adc7e23ba314d9bce5a1',
  'f76389f6f561248a284b173d9e03e1f6',
  '8db002260eb9169c3b3492071722f73f',
  '68c4af7a6ebbe4d075a7e876845e102c',
  'bdd634ffa9f8820f2eb79ce80d4c0885',
  '53aeb8e5fc4e380f271aacf36fc6025a',
  'ffb65773edb86b86592665e43c781be2',
  '1eb185045550a452e8d5fb4a99261fde',
  'a2ca610ce70c2b95e73f0394e27e2c42',
  '17ba8b258aff251c94b92450cfbb800d',
  '1765d6cc0a214f23fad37591cfbe7bf5',
  '62ca1a8c171e0273900b2838d8940658',
  '73784b5528272c7d741cf09a62b7cafa',
  '93096e40d47ac3572a7361dfd58c1b47',
  '6e6c97006aeeb76113b84f28b13f8d82',
  '6f70ea8d53053577fe2840fcaa97d1c1',
  '000d1a9991ea9fa1548e9563cca22467',
  '57b5fc32e8dc40255bdfd845647103ba',
  'cf8bf1470b9854a0279e8564ccb140a2',
  'f736a3eeecd7f75c58a1815c6093fe0f',
  'fa336c46765395181e8e02e5ef6965eb',
  '73b3f3f4f7d4d4e95e375f2264a5c88c',
  '2b1053a68ba52a1e9aa4aafb09c567b1',
  '1e2fdc4a6f393c8b514f3b53fe3dcd82',
  'f304978066e2949b4404c03e35dda041',
  'f30bf83241630944ffc5274d83d77f3d',
  'b6b90e28be8e24839dbfff4fc826413f',
  'd154c8488fdb4208fc25e08fa4e295e7',
  'b2ec450d9f5eb0d5f58514bc905c3406',
  '5fbdaed559e9f2afaf794e7beed72b09',
  '90661074da021ffdbdcf6ed5934ce17c',
  '857fed3095af847c085546f516608d29',
  'bbbafb447338cd6d37316f1dd6f7413e',
  '966916f08e52436be2cf3004810753e4',
  'eacf0788a7854fa3e6a75a1e379e67d6',
  '687bd5d2581487595af0361ea06601a0',
  '70a417d9ccdbe40390d989df76d469c0',
  '4f70f433034b8484ca5593ee8cfcb90f',
  'a8539acee7150668f41a76de6777d12c',
  '046c0c6d9c4e1127285495a0cf46fb22',
  '64dd74519ae704179bc28bae88f18ab9',
  '5dd3350fdf3f1c5c4bed379a19f94daf',
  '8707c5b6eba999bd7e7411ab46a1c616',
  'ddec116ae150196227ea9eda0fc752f9',
  '4ad185267a4d3ca70a290137041f1ab8',
  '163168566fc985f360aa8bb3e2dabce1',
  '472f15f9e4e2e51364207fbe5d51dada',
  'fb4248a3587a86e8e64b18b6b1390973',
  '5e53a359b0f42aeaeb2ef4d0bd3de0cf',
  '05eb2f52e3c714e41d113e468cb16fbc',
  '2d0ac014be145630c6ee666727e5bca8',
  'a9610b8b51c205d31f0d55501af33325',
  '0771c6703cb464552906117dbc9c624f',
  '2bae9910cd421913ed96a3d201190a4a',
  '73aa0f3700f4ee1a5a176e28c917f426',
  'db969d4d9b395ce3e3dd016e0d234222',
  '4638e6df0f3416429e0b9b74231b056a',
  '1d519dd958138dab9caf905747f3cc2c',
  '6edb6a067e30d6e055717a182f194428',
  '1233b759286afc4fab778054b5ee316d',
  '710091e3fccd2358ab2edbe5d2e6c311',
  '7dc1e0bc8815dedbb8c72d9d806fb082',
  'f6da3714583ddd25bb8f54ad7e699ba9',
  'dc3800733194a5c389d4946ea92b6b5d',
  'a897f69cf945f0ba3d74656e0a34fe2d',
  '204925f27879140e79aba218666836cd',
  '267bac8309498cfb0cd210d2ea23c68a',
  'b4b85ec11e5c4984eba9e22dde2c105c',
  '5fc8c5a93ab3c77085e57174863b19f2',
  '294cbf42e848bda03459f465a2db7b90',
  '0d61a6e8867cd8a6b61fb7643ba9aeaa',
  '7b752ec6a0039a408ea0149286627b4a',
  'fd0fd1574d36133bf0e708cb5b4e8500',
  '02270ca62451424caba6d04b89b95ee6',
  '257e50ed39012587d3d6a2aa4a084179',
  '26ed27a06ecf229aa0f3e5f83ddce02d',
  '855f97ea602b8458be4feb6457e720a3',
  '44cad80958441f1ed6386a6aaf060f27',
  '990645d31a11244fd268295696aff1fb',
  'e8bb472c027c1595d5e53f258a9ac200',
  '36524caf474c299dbf85525e684ade22',
  '286a2b1117998247af80b64341bbd3ad',
  '84f0b250396e94da91f6ee8f2cd3b0cc',
  'a5a65b708e32f045f014f29a0e746b5c',
  '93ca33838f32b8b53a64ec601a49cf90',
  '7555b893c339afd1cc7d2658abd4d18a',
  '18fe09d71ba4077c73960aa9ba8dd6d8',
  'a8bd5ddda1578b679b37b93eee48d5c7',
  '5e0afec54691447a441dff844ce77fa5',
  'b94cd2093d2e2c35be65ccc830ccab01',
  'be3d96e84fda662e332c61a3b3a8be01',
  'ca0eb1f631c4eb423de8c0a20149b6a9',
  'd3ba6b6a52494873e134d830d693ab94',
  '560d94c5b6dad8da01363dc246bd28d4',
  'ced9a7512046a4770d8a48fbe7909a49',
  '32b96df2e090d665f8017a13f0687a41',
  '732ecb0079cc47e23913e083b66722cd',
  '95a77b22fbb588977b54ffad640992fc',
  '6116fd90b2785f09e529ce469f8938c7',
  '4c5e4d032f7742b3b618127dcb93ebe9',
  'eb41202333ba887a09645a5d916dcf67',
  '246e6c02df465be34dbaad2214b9a496',
  '043494f4d613146e3f6bee58e5e40896',
  'ec79c843eba001f37e6bd14372f6f4ad',
  'a1ae5dbc2d5aa0ca1d53d49ba898b21c',
  '986cb2e2c3e9a769859b007da6538664',
  '74ac40b3df78df61c9636a43110f1fe0',
  '64d654e0d3391aa797102ced7aed778e',
  '50d6f98485aa8d34bd0e436c158cb0c1',
  '688f6f8976492becd13bfcd1aa5672c7',
  '50a41722fd1a833c0b7de7bc8203d1e0',
  '4204126d84a7b8288b800c740084590e',
  '12ba6234a2d17bc1e9f3c8fbd45f8d95',
  '325226b4d965a08e955278d50814b528',
  'fe5110cc72eba192cb776c7bc01ac2d0',
  'dfb3ac240073955144f7b78aa12ca5ef',
  'b038e81bff7228cd9ea306aeecc22a4a',
  '304a1a126f72598e01d00a7cfa7cf146',
  'f8b182ed65b47a9cb008480906f5888a',
  'd89ea41cdeb03a8e41a3f6cdb43faa86',
  '92f1b7ab07ef6fcd89db600ebe4ef9eb',
  '419129e0b17621efb9057360a4543c1c',
  '0d1d43dbcfa7cdee78b2d8091161ef8b',
  'e96ee61c3f127e2a74dbd8e451ad885f',
  '9e32e7877a61ddbcf7f793fb49f15d53',
  '72f1b8506481021f45e2466c9dea630c',
  'dd43e7787ff33b8c1f5e3474cc463903',
  '4bb6a88234d24888ce4032b7b2018324',
  'cd02227dc9c50cabd08636114525ecc5',
  '52304d1e7da856afd95543b6a4df3a11',
  '237668d64d583627dbae016e2d5660df',
  '5b154ef32bf1864aab7a35d59f348416',
  '184960394ddeda616450b139a3769ae9',
  'eaad7e7cf0331989e1afc99a46a887fa',
  '959fa4dcc7ed0442bc2e1a6a090bbf1d',
  '9b1037c9094de68cab894de139a8ed6e',
  'ce169d5b37944681ad6b050755892302',
  'bc716de2da07c835ca072233aee0a4d5',
  '1d701bee199e13b2c475aff0f55586eb',
  '67616a798f5e06dbbccb9194e240a8b0',
  '6f72b0dd8fde53c5f054a8665efa3019',
  'cd16b334e6d4fc6d4e29729bdb82467f',
  'e4df6b2715699180ac20aa6a25b7f0e4',
  'fc48d1134110f86b4acbfcea3698a548',
  'd61393fde317dd797ce289cae4488dda',
  '3c1b3108dfb122153984387c0ae6fcfb',
  'de4871d2b7b9b2120bec09addc1bdd5a',
  '59ca84825e3bef404d32b8f4aa9612ba',
  'e27baa2d3907eac53edc07d05f6cc7d1',
  '9fa2b2812cdeef33f9e39f3a5de7ecae',
  'a507c5c30b9cb3fcbd8a8ab8cbe24fd1',
  '9e6660e34b4dd460c4733a0698e29fc4',
  'fba85ee83d82077877e0b22405a08f79',
  '5bd0b8249b8afd33d15c10640c1cd5e3',
  'b34d02f6f117ed22e8c2ac48a901282a',
  '99dd116bcf5990857b57590bec04ecb3',
  '28629974d0f9c5530351b9aff5952421',
  '4a69781a1c4bfb0c984241806448370a',
  '6e64f39444e30b068b349f198417b3ad',
  'be3ea2821feb6e241d11ed35e400f13e',
  '66635c2193412147d4b6bc3fb67aa005',
  '4ad5793eb3bb8f415a8458377f3d48c5',
  'b60c3ed7bad608921f70239ef2ac5e9a',
  '38c5e8aeb13e70a82267697ee5325efb',
  'f838767bb0f5642f88c5d46262d65b29',
  '66232a10eac41ee5bbdb44b16b2fe0ea',
  '81572f21bd012ac4b46bf827c0dbba80',
  '2c65a602162ce0722445a39f054809bf',
  'ef20f279c8a5d68930577838d8926eb9',
  '4fa1de5cb8991f05fd9d628f9d2ccf3a',
  'd713b9ca601bfb5b813a9f94f2d22b65',
  '0e07f7f7b4c366b6e32dd604e6a95b63',
  'bca03b528ae80f68b5ff77a01a6479f3',
  '92a5b96ec50578590a52e299da5b8419',
  'ae4a15c5f75a9bd0e4933ec436377c25',
  '57d8a4432fdeb74832b76a69d13f5662',
  '453b72d34a94502feeeb909a76afcadd',
  '4a864678c7bc01ff02aa4de6100bc35b',
  '98ccecd594e5ae3fb94ed396a4a500a1',
  '9914a747ff252b70c16c95084f35715e',
  'f526ac9d042a5eeed0ad0bfb9abd64c6',
  '295172636b08029148838e757d991076',
  '3c14219a261d46202a5c882445cbb5c3',
  '8f11d2f879a7ac505a4d19292e3fc517',
  '1ca4764fe446e6581cf98f906062f4df',
  'b13baa9d45815c02565afac2f8c11adb',
  '450fd7b42ef9e5be34b11206e486ea96',
  'b06ccb1317040c2ea3d0e7205196369c',
  'fc01dd777e0daacb7c38f0300f847f89',
  'e0b30d30af52afe09b10db71b9ba9083',
  '9a6e107ee89b6c258009e350d15b6dca',
  '7114c63d29f2d2b89818a7cef485bf14',
  'ff1c748c3689c323bbae05cfc7f3731c',
  '7675d6f4116a943c835c94e3758f58b3',
  '5cabe9f5b788342ce53d405e1f67a905',
  'ad30616b98c097121f1e4b9fa2c59cc6',
  'bbf7e33d415d385bbf12bdef82aead34',
  '71c98858c564aea5ed57981cea383bb5',
  '779825f5ddc4eb0f04d9a94e221bcd27',
  '42d128bfbd1cb90a3637d66fb9fb5e0d',
  '35fba82bf75a278e1370aa9e7e6af9ec',
  '299daf2337e14bd3c23372344c3e09b7',
  '5fb6e2dd83ca0d17e719e55ae3899267',
  'ee818ba76789ab6de638285950a4c1bc',
  '4ccd62fb5012b35580fa84be217fb121',
  'aa886c3f859772a79a8e64a2fadbcfe1',
  '74efedec861a15a26d563db6fc13cc54',
  'd13897a959281afe858dfa6eff3b86b9',
  '1948dd228eadad9cd6e640ed6f6ec750',
  '662b330f27f5771a0b2c00e4485a6be3',
  'dbf06b66cd0688d3fd4a7bf877600c2e',
  '6aa79e8591bc6b3ce9bdd3a8ff28622f',
  '43c7820a21787a084e98b4118b3dc2d7',
  'ac4a1ea4e21eb247e3ddda53128d94cf',
  'df4e88e880b388e36b96615bb37def91',
  '6bd34c9a39fe203644ac07763a2b915f',
  '7ef08375dfd64dc9a6e1d5c6dc63edbf',
  '248ecd6a696d8eb127051e53e34166ac',
  'ed7c3bd2741e37a558b7a135bee6b3ef',
  'bf2717e8312118d87081d6a310e8017f',
  'e7483a372ece97fe3a4642da8dd6e4ce',
  '9838c4f9d3cff5ded8e763de63c7b265',
  '527d1d097eedc6abb952e278794a38d0',
  'b96116a22bf27f2afc9a44a391036c12',
  'b8fa58916508dc2950e20b120951a8cc',
  '7969ba79d114002497c6169c2e9564dd',
  '1604733adcf0bbad5b2feea50fa48372',
  '5d6e305856e0ccb6c9546b9cafaf93e6',
  '800d111137b79716b211ce79d04822a5',
  '8341b1dc1d03605d9b42c6041a99daac',
  'b35275ea45865f32734c8f3083c46e76',
  '83dd42eba47a62ed7c87dc08c60c925f',
  'b8f9de80892b3cd6888d91d20acddc2e',
  'a1d6e8aee38b514d298b32a3c5ea6f35',
  'c1a0cbf036946f523af0e514d463bfbb',
  'fcbc805fca3af1025e2c18edc3df465c',
  'f98143c2659d72ea4f7e759cd530c0ef',
  '73268a3510c618512543d4ce02bc5537',
  'cf283710d0212762235bbcd63ce0e1a4',
  'd164c703ea0f458467d0f62c355bc450',
  '5cf673f2408760b1a00b4c264dfa7628',
  'c2ea7a86b332fd27fa1894277ebfeac5',
  'a7ebf5901589ed67098b5690eabb0895',
  '07411415055daa1985280b3469e8ff60',
  '5861a7dde8c2f9f29fc947452ee27883',
  'a53c713f5be0a30a133ee0eddaa219f5',
  'f440b365ccb3b089f6ec10843c171e2c',
  'eb725e4c535788a115a7fdc9ba713f08',
  '1bfebef9974375e7170b23d171e2f911',
  'a424674fc9d95229373fc1a786216e97',
  'efe4fd3be3984150fabdf2677dcb7245',
  '0d4d7027e179fc38cec0833d269bc4df',
  '322bee55a315c37f1b8cb55ee2fd26e8',
  '468f32c92354f07b9a6f0487f405ccd2',
  '27f9f7ec0f275fce94e9c3311c0235a7',
  '10cee757151fcc2bd595edfa6633d76f',
  'c44b3de95b971906bec50b71441b6384',
  'c8a9cafbeda6e1a313eb61613bad797e',
  'f4b72d9cf675b2e04149a72038b192b6',
  '23774b31d0e98c5c119a497f8af6cf9a',
  '931be48dddddbb92cd64d0e390e38a1a',
  'e52128a5890c116376638afa15feec94',
  '34b02b9317b75b2c457471829d7b71ae',
  'a5c041b99b7944d8736eb717d939786e',
  '3c624e720880d83119d845f334238279',
  '0681b49d308cf58fbb8fec982d0e8ff1',
  'd92e56eea8836ec669510e85c400d67c',
  'c9aa8166812851b0f149c4dbde654627',
  '067923258ea8edd899ac74a4db40d902',
  'e8a66e035151b1383a4392c1b9abd872',
  'e80aead0854b57e0769418c68f7c710a',
  '5c95787e2c193575229ec726e9ef5a6e',
  'be556fa15207dbe59df37c1d6b985d0f',
  '2f94924ee4f553483a2284b793094287',
  'ce73a056c24e682b2fe93923e5601c52',
  '504b5539ff08f924026b49033d87c0aa',
  '611266834f4d1e281d8ba7212e677fd0',
  '407b982c4372441bb9f32f7113edac81',
  'ed6eb3f712136548338b9329309ea3ba',
  'e23e9c6006608b92bbe70fda4bd7f4fe',
  'f41b40aae98f3722e3d894a087ead1e3',
  'd1160e833790a17032e5ff13813758a5',
  'b636e9dd990b5c9c43bee2e243018a4e',
  '046175cbced6c352c430b267ec4f0b9f',
  'c64121708ca3f9633617fd05b2acde2f',
  '051d2a83b44736ffbc8397a20e9796f6',
  'd60ff040cec99e8a070f80824788f583',
  'a1265d9b01d77764360fdb01c7616015',
  '8d0c7056de628cfbe9cd922310bba3b7',
  '7fcabe357725289fda5b8f950f6482d9',
  '811fc996ac7b5c269590e2b6e580d497',
  'bfc3a931d3e422c26a3e31647f82bbb3',
  'b58dc85b0fd54a4820fbe33dc76c370a',
  '2f69930525b5e8f67d28c49db0cc86cb',
  'ed721e04a535e1288a4a11dc7f6bde6d',
  '3ff25cc8a38ffdf2b65e5f4f2b596597',
  '90f62469c925ee53686ec65fe2d4e384',
  '3fc9b9706d77ec48254d4e9c3583c3d3',
  'd95e9d1278a9587d85359112e7e8bfdd',
  '3829e22dd0056c00e8fe23fbef9ab456',
  '6cfa92c36c2f6a6046d5949825e4a766',
  'e2d264a39d182e518ce6097e2e3da98c',
  '8d1894edd3ac222ff9dc4bc576ed5c1f',
  'cd75be1f39329b14169fa91d8ef23ad1',
  '231cc91edc6370d7e35ec74074329058',
  '6a95229a3e62e209877258f1a72c7668',
  'aa10cb8ada779620e83e21825d7c2ed4',
  'f41e247f796cee67d22ed369469454a4',
  '8820fd1c513e6780c9d5c3d358e0349b',
  '117c3e119c333b6144fad9259ec60f44',
  'fc4b1813d34fb8ad5da94e4e1d728d48',
  '931663b74f4207ca212b91b89f044a56',
  'c6ab0fc85082d559bcd640783587f725',
  'f19856b20302b5fe2e4cc286d8ddb234',
  '4ee766e0369e853d5a6653510d282265',
  '1ed4d2f28908d434c7a69f0d76cdf563',
  '99821b38b50511a1a0b4b26455342dc3',
  'ed5d42c4742db573d53c4d9b00336c86',
  '1722dd37e20acccd81b4e55728ccca3e',
  '8c334ae4c7843adf7de8e9ceed7fcef7',
  'f057a395edaf2f7eac2300aea75b527d',
  '33abff436880aa87b4fd523b6b291ed7',
  '9f4f8beb9e96719a49d1309be7441d6e',
  'd4f4a8b9542b94684437d7cc753dcf15',
  'a80aaff6fe1c71a5d7b302b56a03bc6d',
  '6e09ff18082195588c6232dce115a3dd',
  'd14e657a06d2e147d0193e3bb943f4e0',
  '31363a957b895c62907a44426fc33fa4',
  '170cb6beb0832a27433b87b3a88ed100',
  '811a5b2e1b7c908d978f3f61609e01fc',
  '46310d0dcca1c7b62bd39fefc03eb33a',
  'efcb9c7aad20d63a1f488a8f9ce2e5be',
  '2b0dfcbf5c0693c97c077406af316a6e',
  '5bceb119b899dc0da91f1bd962862206',
  '237365f6327e9a8889b766f2c019af51',
  '3648e8f6f31248c80bdc5c14381781f1',
  'ca5715d50f7e459c3f18f694308fc3fd',
  'ea893d1a97580e049becc1beb62cb600',
  '34e547d5d5e827b2bc3c3f445539a667',
  'b95bbf27e8c2596b26a24b4c38ae6af7',
  '963229e46891247386bcbe24680ced65',
  '5ffed731fef8239ac843213548db8701',
  '9e372ec9cd08cb3d5b9a1d1127d26136',
  'b5f98cd96bb3102cb511e53080e1933d',
  '706be97b21fec708e0a56aad467794aa',
  'f4408932cac77d8365e23f1a63ce5469',
  '8cabb1b38d4c65456f7ac574453c4fcb',
  '04c34d8a895f04d27bef50fb92a46a7a',
  'bc0baaa76021f2101d7ed291a778a734',
  '793614ca1abb63376bdd79dace6531a1',
  '4f913843725342f39fb31726445ee955',
  'f48745ac822fcd33e54d382df6590149',
  '6081a027134b5c3c94f3f95c02a97fc0',
  '7576b5b2cdbef03e4f26caa2b29037e9',
  '48a98a1dcdf249d2ad9c4671ecb958f2',
  '3053dab68571cb8850e4207dcf48b4fa',
  'f32852cb6b9341a4c879eadca72934c9',
  '5318e7b497bbf7c76556c738803626ba',
  '02ed5bdeb2f6fce58e6cc3a93e9c068d',
  '50a4b715041b6b73a4747f7a7ccbc03e',
  '7354ca8da193fb5976eee960fc4f8214',
  '6543bdfa2cfc4f9ed30b07e0f0045fe1',
  '404835a3a6c056aff26c3b7e991d3694',
  'cf34adbb1c5a6e299db0ae81c80f946b',
  '545196a592bb8200d531034cbd4cc8c9',
  '41f8ae8ad5d5bd96725598d536e9c811',
  'd84ac200b73c921a8fc04083bf2d0ae1',
  '5ce55d9f00ad64642e4a61c8924244b5',
  'a6e476bfe91f663a59f81fc7f50988bb',
  'cc4e8eb13ea029b969a22ac43d9729a0',
  '82201de26ed30cd9dc0cc8358a9973aa',
  '8553127002a2c45c64fc829afd8d1a6b',
  '8de74f0cf46bf08251dc8c5809d084b4',
  '338bddf259e9769ff48e24e68e569479',
  'fb8d960df32bf1d0942cd2db06d8d316',
  'cb0d970a1e513467f059fac558ea4ae6',
  '16aa070bfc6151cb0f43608a3f5d9655',
  'e053baf2e5464263588f0583c2c76312',
  'f7353d3d6899fe29f1c45016853edc77',
  'e33d32b3e203077198b05a82134a79be',
  '220fd069971e1d7a0fe0dc8b8cff12bb',
  '1f44c33ead53420bf1c9b2d5ab8e3eb4',
  'ca594c26b1d1e5ff985870087924517c',
  '74e5c6763d1a078f5fdde2382028c072',
  'ae75bfbdab212c5c2cbe03d428fdcb73',
  'ff0ea43cbefb8c4cee444079db1202b0',
  '253e72b9ef071d0f69f5185594ab1e7f',
  'bcb85ea28074ed89e919650e54362a21',
  '253321142818758f15a23b2c30a66d36',
  'd97c6025222e9a7a6cf39439e7c810bb',
  '109a4b35ff63cd0effe59d2dddb05570',
  'd7a6983cb3b21cfa4cd7e4b256674ec5',
  'a817d8067c243799f6f286460d653b81',
  '37125502742cb6eae7637685a947a0f6',
  'b900e68e529ded113d584e87e917eb8f',
  '3aadd7fef7c3ac2ca2fff4f79908fd39',
  '5de8071b68e99a8ad49a4ca29697a02f',
  '67d6451dec8b8d022591407274700d08',
  'd7d17678f2d24130d4f67a2b78b09705',
  '67e878dc92cfb4f86bccb9e729d9d5c3',
  '570e59de1be18171ddda4ab81b154888',
  '4df2155cb2323bcfede0cc59f1a24104',
  '224c24910cba3c24680528bd00c620bb',
  'f31f5106f50b0444183dfd8dd39c2004',
  '85f9fd66b78f4faff7c0e2c558fc9771',
  '2f1dca81e67d527e143b8f2139afdf8a',
  '2fb3119c09a38ebdb628c2697ebb198b',
  '23af33660442e87c74716adf583fb1a2',
  'a6a608beb59649129294c9c7b2f76193',
  'f6748918b70c9691484d6db03fa53d05',
  'e9d2cfd4a070c4b9b92c41332edc6b61',
  '56609ab44e61d567d0e1f7da47a9e66c',
  '2e05b88266df39b1b977753ca7469674',
  '15fd7fd7eff57ba64cc4c6e9549ca1d9',
  '243a3824275ee7d69617206490eece2d',
  '2b068eb1b671acca5cac2cb6cfca2265',
  '252642db22b7e71337461b9aa405d5f1',
  '738874e713cb54bfd305cfac2d7453df',
  'a6d3ba81ddaca1987b184e0bde64e546',
  '7af440c1911d4b0e8fcb6f813924e89d',
  'b8468ae7079b465723c0c59eab7b3789',
  'd76bc6f0fe543e5afab531df3aab8d49',
  '642fd4fa2809b9a1b939f6fab12f6d97',
  '5d803fffe0e7c35f5477dd5450e3c101',
  '844d104957e8c030a10e11d55216ac10',
  'bc1eec9a582b0de33703c86f4b834a58',
  'a0d550473d8a4380e5e6ef51b03158af',
  '04c2ed5619b92e5e31e10835309254d7',
  '49f3bb5cd91c6acf96871edd303baa8b',
  'abab2ae606e4a85908149fd4cb168829',
  'c5aaf6ca0d7612f773c273285a0e303e',
  '52bf0687b5f4b403a1dbf4b85191ab2b',
  'dec01feb1372a521c5295af4e7e557a6',
  '2da395df46b13d351ec4cef03bc20113',
  'ad6a553626d5c1757011ff0f7bb3d4b7',
  '3788a9cbafc944e5afcd7fd12af2e234',
  '8ce22e9a8b0b67f0886c7e3a69b57e34',
  '512eab43c40d082ee024426c7cf06feb',
  '21eccf56e9e7a2d020493e8b80d20746',
  '386aa01aa4e95666d22e70ae1b0c33c4',
  '7304f38df60c273c12395828e06c5bc7',
  'bce5fe43cdef81ff99c7b9d06055112a',
  '9318259544fd83b6b917d88da464b16b',
  '0abead04db99630d732dd8f76275208c',
  '56e73840b16afdaae5126def542f87bb',
  'afedcccd61a78f307fa276af953fe622',
  'dc9a7182f14cc9f944cb00e3b5d44d15',
  'f21544b97318438ed13825bc3c6aaf79',
  '37a984527b81ae934f4c5561cd627d3e',
  'e561bac903e97e7afd5f8ee22cadd68c',
  'af9b61d2069a8e1d2e2a449d86bb80a7',
  '07aeb50651da9fdfc77ecf43608a7070',
  '44855dec4601f919443d7e76b2c0decb',
  'b42ad1e0b3033ae5d88c567de7c7780f',
  'a163d83fc39d86a1a97d72aeaa0111ba',
  '9659bae3fdfb14135a27a0879cafd357',
  'ffaf9cc3070a0bd98b6737747ed23370',
  'c8c34aa334908054b2ddfd2b97b380b1',
  '8de4f6f2a0541e66aa4fbf75387e088b',
  'd8e2596ca0186b42a71fa5de88d33026',
  '056fe0c83fef5eb5107e9f9787d49d5d',
  '3bde4549acf1796ba788de4f013dfadd',
  '2f65f90800a3b6750ac8bfdb9da2b2c1',
  '0b010f940148a6691001f2cedd217b4c',
  'e735c22eb7aa9969e4b3c4f9626ae53f',
  '9a4f90c9e6c4eebf2c863a8f8319e26c',
  'e7d69b0924c0dafe2ea3ad1e1f4b310d',
  'befd42bb4826d0f9504cac90ea22bb6e',
  '23b90a27777276e2440cb049fd8233b5',
  '8a6091ce2732cd697da58b1a7ac00471',
  'a67cfd05c8fabbe3ab92d6eacbde0196',
  '2c0a44502e74cdbc756284bd88e0bb42',
  '245435b614af134b6e922ae0e6cc55a1',
  '34a3ae422eb11b9eeb248f13a95bae4b',
  '7987d0ff9bfed10617a17e9a74ed8897',
  'bd972c5c94c3b775853293e539b3be39',
  '554f888cb5123aacef2f1445da200bef',
  '76ca9ebc70ce6c544d1b987e664811c5',
  '4ccc519bf61e5a12b1d822fee324f930',
  'c105b0af55f592bc270e2047de84e96b',
  '1ccf33a320e1067ebe64b9ec52e41f3a',
  '729d8eb12c1d084d30e88f6dc06d9da5',
  'e9c543102128ad298e24294424691d74',
  '0b8dcb1426b7dd983bb4c85ad831215d',
  '795d0aacd17354d4e1a0caf6afd03f02',
  '211e27f7ff7d87636896726a06bbfd92',
  '7f20756f898849b33af1dd7d9ae8ecf9',
  '4cc1c2647a784f44ca647415d4ae73fa',
  '20ed20c215970b41096780655956fdc5',
  'e577cd1c6d73ff00afecf7d576eba9b4',
  '95eab8b76751bf4a3fa081b9c2224d0e',
  '76e134c9990aeaaa483af350e47801af',
  '1e646049785870becb921b7e543fd5c3',
  '45d96bd333c6cd2c9a4ad9e6546daa3e',
  'd5e76c0422c6a714aca37180dcd934ea',
  '0b2fd7dd71d1167e6c9c200158e1f0c6',
  '7dd151a83eb9d196a3a8e330bd9dc9dc',
  '0a3b341debec454561a6b4c154138eba',
  '24a6eabe9f6c2d78193c9003ff18d11f',
  'dc0949883288a6926894625f9bed72ec',
  '409a8c1cb845d43d4da2c10c392f1f3c',
  '8c87b0875b77030c8953856a5b77abc8',
  '44b5d7747b67d52fe27d30b3db569de5',
  'd67a8755dd8712b010173e1f985f2f88',
  'e1172277ddf46e26badfd33edc4ff706',
  '4844612eebfd4f4c3011250c998d5dea',
  '371c1e44d731e1e181f0dcc9669174e4',
  'c2c46dcb925ff01b0df6f12f154e6b08',
  '7cf26ec7c000c741f2487cef9a59217e',
  'a03f87d2273a00e7f8192d508f73031a',
  '9ae9045d4f38419acb62f0b4d41ea285',
  'db99d54bdd3b12a5442a366cea0798f7',
  '22e87e8d15aeb160136b91a7dc6bf2ca',
  'b5254b7c6d8a10691be8747c11e4dfe7',
  'bbb5c5b5a6db27e2a2f700f945eb6306',
  'b79e3743d66fa5b84d2ea17ff7eb871d',
  '0c3a3a0833ffacaf33e4742aba4f7939',
  'ea0ebaea41b643e65f97e2c14ed22e71',
  'fe1dae4c16aa5fdd2620ff3ff82b6ad1',
  '3c0c8bdc34b8e9303544ce2a5792bae6',
  '91fd4f9d465ae188bd8ace5a979ff274',
  '208a099758f9185d1aa08bc992ba4bc1',
  'ea9e0d599f17a1ab8b59145b0b1c0e91',
  '55cd0f116115e9bafaf6824b8227c25e',
  '34d8bfbea8fefac7505f8e622d6540ce',
  'e14f21f1b60b7fe13c9e2b215f28e38d',
  'ad1f0b4a5f39b5fd2d7757d4a1895530',
  'e300870b1c026033ccb7bfc91653e04c',
  '4fae530f4289b23e0fbefbfeb8239dc6',
  '48fa8d7c6598060d64966941ba5de086',
  'c3eb406c06129ce59f748b3de2f8cddb',
  'deaeb78eb78b5a87f973f8763363f6bd',
  'c669a404b7d0d668307e607aaf00926d',
  '632e55ecc90bc78ab27178340d7dfcdd',
  '639b8a60d30c42865a01a2302251d0ff',
  '43a46f265923028d7bb6b266af0769f2',
  '8e067e2e7caf73dcc26b580659eb6f4b',
  '45ed3f05636334b112b2c4131d75852a',
  '553c6885ac6479b00a567fd3f4b456de',
  'fc971bd90cffd0326e6d00a2935016f2',
  '6f01148e281b0900bbeab5c7d871a4ad',
  '32e7334a0d9a958e152079f842646a49',
  '667195f7a9f4465244390c644102d747',
  '301a7f7c06b03ff134f7034cd408abf8',
  '6f644eac6b1874fb5c27d4a9b51f3762',
  '33d8777d301b478a0cab4d7436dd4339',
  '76ad0d01a23317357329845296a7183d',
  '69796a14773589125320e43a473250b9',
  'fabc865866416181a946ba08d38cd9c9',
  'c79a02ba512d865754f20dab771ab300',
  'dea28f0fdf95d0ef7cac48391c5fb296',
  '910ca560a7535ce8ac023e50d60a2aa9',
  '50b150bf6c2f058c6f17685f39cbaa3f',
  'a0c27009d9c477a051d1af83832e4b3c',
  'e775bef5171eab5d66ab85b1906c2440',
  '3779725f6f54858756127c9c256fe624',
  '31887694d5fa1825c97c8384cdb5f8a3',
  '50ad4336bf5ec7796dc68cf96a0b4bb1',
  '7096c30b433a46306f3d0057c69100a6',
  '69854750c11c0b65ca79062ca90af005',
  'fdf408a6745895bbec53a3a410ffc036',
  'cae3f3094cddc9601d0591ce11c13d0b',
  '598d390ce99811fded2b208f383dafe1',
  'd0a4ae7b807f4a84c8a8b726d9827e5d',
  '6096b962fe679824d1e72ef77913adcd',
  '347dafe4a10774fa53314b68593f439b',
  'e6b100c0fc9d0024350089a6124622ee',
  '266f6bb20cafd0d573f2823a5882ffbd',
  '6b9ad3daaa292e729d099cc7aaba07e4',
  '419d752f9ec3fb6cd0f141b19298147b',
  'ad08b6b5c7fe85e223d32cd53a1512ae',
  'e01022cfcf9dc8f9d9e47000338c3b46',
  'bc6b953a78afc0cd4fa91a1f843ad8c4',
  'b2338964f22579b11a10386b9b052547',
  'e82bebeb37b166569a1ef8fa01ce87ef',
  '16c191ef6ecb2505b6fa977937e32039',
  '19374e46c3d34a34ec747b8c888dfd6a',
  '16eeca5f50b90c9533da0740b14087fb',
  '86584642c927ae61144a62c3d7d23f7e',
  '2b4667543498598d6534c5a9b5370c77',
  '3088233b2e50128c58d9bc2015248932',
  '32d96a1debceebfae14ff03a7db7b920',
  'df5a3e78352a4bd4afcca7f6753e58cb',
  'a0fb883dd638a7ba3a19409eb1fdce6d',
  '17aeca68f12b1d2f8e5c2371670e61a8',
  '20014388114b122117579a4bd6600566',
  '4e892406a6247fde5e423c14134c4c3d',
  'af7ccdafe652beb7121400471fe5b709',
  '78febfe1b0a55a5ae254c6ba9d46da49',
  '13ff12125bc801f36775bedf1bbdafea',
  '38c1fa81b5655b2d645b7ef29f01ad85',
  '8eb4d4074e04462258e44b205ed5e6d9',
  '7a1d79526931b187048b476e280b03af',
  '4d58b91327160c44433b2597860a961f',
  '98d708da413a7c912ff70d24f2b54e8b',
  '9f8ec30bd87c2c12e31659b7ebc8eb09',
  '9f02118746da46f60ae362b811ab4cd5',
  '7847c39d4ae6b06cd5894369b96fbe38',
  '9fc1a485d78ac095ab58adfce6edc64a',
  'c5f527a7c0ef7cb322f4aa2da6eb5246',
  'dad5082eb1457592e7e9dbe371a5b250',
  'ecb82a9b937c8282a122f774af002de6',
  '336408fa2aa4b1adb5d61e997be2e3c9',
  '99ceee2d30a091e1edd9fc66cbb4fc98',
  'c471ad91faba141fafa9d9f51638c9ed',
  '40560166ebcdbc4803b5720049bcb77f',
  'ae51bd72de513b1b2ea8d6e770d7d9df',
  'a9632f3c822fc52647cbead738695237',
  'e90cab72b850eb88eaa9e66de0171b49',
  '13baef365dbc241b74319b167afc47b2',
  'd324793a3516e15b124c3d16af3a7cc5',
  '0a36bf642f39ea205c71dd65cc918963',
  'bca9154425ca94c2ae5f4ff086e41e04',
  '598fdac2cbf9e5a8f6c4122a1773ecaf',
  'd2e5b0c9f66a74ad71c2ad6f6eb63123',
  '2c010140f9560dfeed9b700f50deb6ca',
  'aeafa7d83b8048018f0382395fb09fe5',
  '3738b23bd7bda274e42322373f83d7e1',
  '31ef85f284c819e268997fab32b509e0',
  'cbe97841dfd586b7b9ed8cb6e472e1be',
  'f5f47f4f8c53888d53e5d90f33199377',
  '78dd01d76d1219df4a30e3440d91de32',
  '538ebb8bdc604ac04eedcb7a6e60efb0',
  'b708cadf95e50859c39af7cb577e57cd',
  'c268d9233dcd02a7ce22ae7d80facfa2',
  '84b8f7cd33ca8c72a00f8443425eac37',
  '79c32d43d31fcbf451ebc4b5d89427bd',
  '7fefd43fb47c73504af5feeae7c63e53',
  'a7bac29eb46a360066925fd936007b0d',
  '26d18ef8969fbf88a223afebba1c0af3',
  'af7e4ba269cbcd5abda50718497b23cd',
  '2b63333986fcfc5d1e381de30f5a4179',
  '168941ee829bb2be0c6a89914b9a8eea',
  'c6dc9aa0fd88fd6d3171e2fa8559f527',
  '225df6a977701d1439dea320c25770d3',
  '6c9a3bd12f1d8d2dfdf460be92164a7f',
  '149a114f02abc7bd7085d06614ea770d',
  '4a0334dacc1b33e438f43d97759cb35e',
  '7c239f911572ddb9ad4d50d81af708c1',
  '2c1093822e0eb8109c3de067d814e8c3',
  '90f694a1d20407d93999fbf1c0e02108',
  '7b3ac6c8314425902e4918cefac7e27d',
  'bf8558ec3fa7d82b77706424a3c71160',
  'c38b261d11c6ecdbd10559c00eb0c3a4',
  '91091b314739235ff9cb52915e671f0b',
  '19d38f9d9e5972928b4ddb9104d2d5db',
  '5a9bcff1c953a2dd88595436576964fb',
  '68a7a76a82f211da14b26d3e2836ae10',
  '64691bc3d366757f615ffc92fe9a5872',
  '8099096d2f732738032a9ae4372bd873',
  '2097b9626816c5c9bbeb8ed186ebf474',
  '29b255bbdf90a471af117fdf3fce6fbe',
  'a31db0e1f6ee90db80c3bb093d980fd6',
  'c451a64e00504de2ce6b3429729ba5dc',
  '43474b67bcf10e76cc0e3bb30b90d9bb',
  'c832baa49c8d838ae482905877c7aac4',
  'cd0f4f527e29ebe53669646f4c14f154',
  '58015876471f227b4fd6187126da4032',
  '79d82f29f27c219f355a06a185a91fd9',
  '65b8beb8bf90220b893b3497b5377638',
  '09eb3fe02854a64b69319b5cf54885d2',
  'cf0a1008427d4a2678ced65a5fe991b2',
  '04347d5f4f2175e4b91653528c62ffd9',
  '46c526a300204bf91e2330ecdc03eee7',
  '6d51c79a4e08cdf0c998ed6e2a20a147',
  'f33fa137aef1a4ada7587c954ad0e0f8',
  '4f611f141d060c1582c328ccba2dbd43',
  '1d4abb4e3636e7cf82a644b08c732af5',
  '339df0c2cfb664f6b47d29c57a639e41',
  '3651cd685cb233942797950b6c1b8de1',
  '4833191bc445c17606db5e9b136a0fc8',
  'ebdc3e5cbd3d991ceb24f90bb34a5a65',
  '28beddc9ece813aeb0d165666bddd8fa',
  'dfc059be1578e15e3428d52da5bd96c6',
  '9d448ab4dc3122e85ab85db2255ce356',
  '1e41eb4301c07d455bcb5a6d1eedd2a6',
  '0c910c6386d063a372ddf099d479a453',
  '2ec12978b2b6904066aa56891ee22ca3',
  '136ea632ef1c1ed54e0a47cc63089516',
  '8a987b05764b337c8a95f4b06661f22f',
  '5c54a98efa0cd28e4375ce0cb6beab34',
  '93d1eaabbe3a42b4ef067e3f59df0b70',
  '649db37c2ae81063d970300146c529dc',
  'b2da6a06917e67914866049136219f5d',
  'd4e7605d2c829d747d854496a756ace8',
  '40772b0bbf2aa88a65122d9fea40a4ec',
  'bb95b10a8f499c0d35ead031b865b931',
  '8c19e4cebc2053449aaac612b245e273',
  'e90316051e2138f175f32c1d98f858b1',
  'affbff25b298f6ccd8320363e25c5056',
  '8f5d55f97d334adb79af09dd07484a67',
  '84c4672a3f74f5144f488e8e11049bde',
  '340875e30dddfe20dc6d5539f895c7b7',
  '94178051f52ab27e167d3a0fc699f8e1',
  '6d3e0f598e7f4cafd3a1707c89af99f5',
  'cec17d64520a9bd21fd6f2b46e5636db',
  '02fc8ca4a205e11a07980f02b02192e6',
  'b3ef44ba226b7cee74a14cd5478975d8',
  'bf2eaaa61ccabb0b0b4ec676517a81cc',
  'f25a60bd44961b2a03044c18c4a33bea',
  '2b7280eefc1e6e4b62874ab47ddd7a20',
  '9fd0a48cfaa1572d862758bc289e7888',
  '8ae0c24c6bc3f668352309882547cdc3',
  'f40d7483aceb45a6f43c021dd0014e43',
  'e8ac5f91dd5a17b8f731f4b742602162',
  'd0d0b23a420fafc8bfdf0d425cef4650',
  '595c21d12dfac36e66d1a891938674d7',
  'e854792a81e2a07b43e9de46bcb765a5',
  'c7569278732910ac7efb2ce076d1644e',
  'a551c1ee4edb714e5fdce9d00cce0a57',
  'cd70cefaa8db87bd36c5215e7b5460e9',
  'be44a5cc9673f05fa3d835f922d061ec',
  '055bb3131af30c44984d6aaf6fb8d11f',
  '4111218a1690569c16650a8b5011770a',
  '88059e44970f77898585b01536d81c8b',
  '63fc46d05f70e6208501aa1f8702942e',
  '80b02b2a8e00d2bcf6e2059cadfe48d5',
  'ccde41aef7f94e55823dee8bb30f4f82',
  '90b810dc77f2b369e418bd38d49290ef',
  '20f44927b13303a44279eaf793a19f5f',
  '9fb31c0771bfc9236fcbbb9f85eec354',
  'ff286c9115c0b43d18153a2be446e26d',
  '9e63a8fbb3d5d95e234cfdca832cd647',
  '30a476134fbb5cad8788d59600a2eb00',
  '4faf9b20d625bd7e4c409396605f2eff',
  'f47a1984ec5bd255f78d3a0e8df0aa30',
  '1cc3f5ace392586fd327a62e053e3dea',
  '263b6d3d02a75e3fe87fd8243f7f95b2',
  'b4ce0e0bd0edb0bde9608e2f272a5a0f',
  '658c3343a6dc155da8576ea3a096a48b',
  '715f94c59f696633455defc376a0e8c8',
  'e851e95760bf3b954c5853647e63b4fd',
  '6819539928f86ea2d0ffbecf8d5ffa49',
  'ead5a880d0439fb2702e2e0682eeaae8',
  'df915da8eda8e85e818dcda7fac076f4',
  'b2e62fe47fc0820ab2d24366c791f3d0',
  '26676436be0a34ce7dceb005c0c116d5',
  '6bd5a2c7002c92e34a8643b82bb88ab5',
  '9073a66a130a3bd12281ec24ea52c771',
  '99afe52812ea9ddef954dc14bcbe3704',
  '593d5f052c3ec6be06a3154798a17ff5',
  '5209faa4bcde2e7b89d83226ee11f4f3',
  '489ec3f980e93a3ddcf6c45aa1f39775',
  '2c34690d74d07d2bada98c1767f736e7',
  '33ed73be309fa575ff6e60bfc9841139',
  'b57abc7320e8e1f53bbd0cd82008abc0',
  '4645c8cdf5e3239865d53afbddfdb0d1',
  '7a3a035fa30bdf47de56630be94eb66a',
  '5cfba48fbc97eb0102c2bc62f0f77d71',
  '1df57b5971961c46f2ebcf45073cb520',
  'd87c38e39121b47614a2589d366fe990',
  'e7952dd782d3a809f71f30f9b67479f5',
  '57463d4a5269afc813f5ee90e01e9852',
  '471d6deb95253159e5e1832d6222edbe',
  '0257a12d9b679235af2afcce62a56ce9',
  'c6aeb48cd857cc587b523cca918e6a17',
  '0fd926cf497956bdf2e3e9fae6959a22',
  '0e7bbd973a0b2d079a0009b8546fc535',
  'c0a01557f776334062e8fa0d4821519f',
  '70c16de3567d3582e2b81aed2f8b12a3',
  'ef49485e3f90bc0abb5c1fc875047895',
  '833437318a17887030456c33ac9cb391',
  '5eff900b6e8f56c034682420064de109',
  '3b9d3ec39b4ac706671aa9500b5cc2e3',
  '9e898d3fd0d5aff76c51cd3f51afd1ef',
  '1f3c55c301802f959247ad98f522da58',
  'fda6368a343cadd57e68894b967b17ee',
  '9cf2c80afd93733182375dd8245f7030',
  'b83e3d1e611f2df921921a8f09e5fc7a',
  'aee1760db884ad4297e147e17546639d',
  '6df662ad0841c355c48c4a3c50c30c86',
  'ead6c21dbe09638bab17d018158427ea',
  '4d0f5d1dbd15f79605965a9b16fb4d58',
  'e9bd41eea576a4975feed426082924db',
  'ef2936adfcf7756022b46f1df9cb73e3',
  '85b45c8484228c050ff47319eae3a019',
  '171c43927de9a3545e15992b2a9ceb3d',
  '1309e5e8dc28131af84f7eaf033622b6',
  'ecb4c677a11c7435a75cd214045fdc8b',
  '09554d9058e31af2bc7d40d08ac140e6',
  'f6514eceeee9a15e922222c57231751e',
  '347bc0f45ec9666064766d55d70d1e8b',
  '11c900958b954f8436a8d5cf1d7e70e2',
  'add273383d8c238d4996afdf3b31a32c',
  '36fd55b8785eb1a60469934b2d5b95c5',
  '900bc3dcb50ea0ba66c8b08a215b8594',
  '42c112e03e60129d9bc481f80ab9fe10',
  '906a82006d2d4313cae76305d2ca26a9',
  '9de49c83388199c68713cdc9958dc2bb',
  'fbf3f3bf391d08f3da49a3ece9e6d93d',
  'a10fe0fbfbc7691b28788382cec7fd91',
  'c86e08023d51b0e42a10a1b9d16431a5',
  '13d4acf3fce765094479909a97f5a392',
  '9bfd727b3e016e3c3b2cfffcfb8a4517',
  '8a88f3ba79502b1cfc30868feaf5341a',
  '953897d5af3a6e43c204426de4c9f989',
  'a9b8a144245facbd92198d16ed50c3fe',
  'efb1848acebf5e185c0a7cc92f1a481d',
  '0728f7b3227f3adea24fe9376c1758a2',
  '876370fd9fe06a336304be5c279906a0',
  '12ff0bbf5c775bcab384f581a92434a0',
  'ce462b4d7a07e015ceffd9da1be17a13',
  '7e4fad16490f39e85a3cc031bc9e3331',
  '5d4d5eb4bb35a957bfe6b5c78cb3b72d',
  '5ee21dc5f65a8bfed947dfc514c0573d',
  '32e604d20121dc52779f4a91d90424c2',
  'e299726c382e0dab2bc1aaae93337cd4',
  '676bb1e9fdd36565240b7d26a1c7636f',
  '3b539085d2d7661b60da46d84efc26b2',
  'dbc5f6db34dd051dad7e06a18c0db11d',
  'b14c19c373d15195d6b17c94952481b5',
  'c04f13e6a8512f78a4a2e37c24ae4162',
  '98dfa559b617e32d06ecc8213ff978e4',
  '79c071cf961440ba584506420b77ad6d',
  '2e2e11c03cf3ea1fba98d96af5a3b7a6',
  'f82ef3be8fefbb1449b39fb53b202638',
  'a1644acfc76e44f32e0d480c3534b803',
  'edc9d9343703d5606dc9f8f6ca96d877',
  '95a9d74a0c8f627fd11bf3e89df7ef24',
  'c856200372e1ffeace2d32c711e1b18f',
  'fd21f86c511f0c3e29e324db2867bff0',
  'f39082e83869b9759c9a2a0399315065',
  '2da260735ba8973472ff714671eed3ec',
  'c4697bca11c0bd64f1f4b32543d322ba',
  'e569e54fabdc71f1bb34f73e1842543f',
  '670a2ef562535442cfd7704e6c1ca1b9',
  '75eeaa84720e55db548efabf944e2c48',
  '72d66098063383abc70d1b9d4688f44a',
  '6b51da1ca8a0cc1ee4161d66034aee70',
  '479c361c88e176b374b55266d4f54203',
  'fd483e4bf3b65dfbfe1d233c178852b8',
  '239b92405afb179fc1be4d1de68f510c',
  'cfea027b40ce35814fa663b4ffb6b616',
  'c6d2ea5cf23a016ab8c5ccedba220172',
  '34c1fd3b9b9198e94f51d7cae63d5a0f',
  'a675106cd59ae23b8a81d08b20fb1671',
  'b96778f24e12d55ab6a9c10838e16c16',
  '80d1eca416186cd5fcddd9c0010fe4d0',
  'df7d62b37f2de2bf044ea41281204c1a',
  '70eb2fd528c0f7a3f8dfc61b0f847e2d',
  'f0b78b672fff9f154c881f53cf664dc5',
  '5817f47054f397e159d446f96764fca3',
  '92e4f83ef5467479328ea52efae2a646',
  'a3e84f0a938bf92f80b8e6d065b11e42',
  '56b0e8b1570172abedfe80775d1039ec',
  '811baefb39592db30683d779cc9c7635',
  'd1c623aea8c6568d11bc44557d24ef0a',
  '0cdc44be678ea2c600c80ce73fdc4c75',
  '74c0203173bdfd5b975782a60cd1d543',
  '34fca9a82fce6d70a6f757a496a0dff7',
  '826ba478325412f2637c290cb277abe8',
  '5c568ed293fd8810a26ab99e52a2a804',
  'a3acebed995d432d492922314bed4fab',
  '17a77a550cb9696636280bea6682a5ee',
  '6f2ce3babaf066e08fb14e8f5664a031',
  '39b9f1b067b6c561e3ba500c36b32d9d',
  '2f25f841e378c436fcdc052591a4b880',
  '476eabb0f79d35f90e06a6fd21ca80b9',
  '2ea3d53243ef0900fe918e8726273a85',
  '5a483ee4edda411e00671d2ebef89a72',
  '6546b257a4821bce7b63537c3c5009b4',
  '713c2c27ed80f76f45949fc0b2538429',
  '84cd6997f37c8a1a01171e698fd2a4fc',
  '67045d8b8736bc840f8635a605282b97',
  'bb037bf8378a83571f0631a6b1be3213',
  'c2ce452fd6791cafdeced11b853ecd83',
  'f58e558f969b0e173e46e189b46f7fc6',
  '433b491f2fdd0cef827400317776ef95',
  '436c391faefad7ece0b53d97dcf71c27',
  '96d8f19b76f76a8900b36ba88f722b1a',
  '765752d1a266e8fec56f869714f47222',
  'a27ac2d84aa9358cacb412097e96ee54',
  'cc760824b25d490228089f4ba7267aa1',
  '9efcb1519e06b610145789aa65defbb4',
  '725ad9ca58d5e45490e20035dd8fb31b',
  'dcd5bcfdb86a45a09fe7a3ebbc998822',
  'a633dbc03219a3daf07e8c6a011e0fb1',
  'f67dc4c3c5263e5ed43fd77aba72c874',
  '96461b584abe6e55cfda50761e7a8b0c',
  '6905974948aced0d3eaf9282f72304ba',
  '285e0b59edf6fde8facf8607d714ea44',
  'd9169e876e8d66df5d56a115d04c5341',
  '694ad503f53cb41806e3864044b8dc1a',
  '7a35a7976a6f9503b560457d5e649dee',
  '7e2ccc3f9b87559d630f149100684164',
  '908e8633107e1cf084aaefc3bbb882b1',
  '673080c8163a295119a840d4ba9339eb',
  '4b196420217be05b9b58d7b8acc14086',
  '5dd7dce173acb37a8d1eb4d7b97e8261',
  '8f12f1c9f32885ace821dcfe38cccc9d',
  '4579113f90c4e1e96154eee29aec336e',
  '03427471c6a7a4859aeafe122c73710c',
  '22fcbb5b59bfe45033a614cfc5f72986',
  '6e6e9f6f58fd3dc745d66190f33f5bf8',
  '790e06d81ec5cc4cad09e6bf67d6d6db',
  'cb66c52f58b9923b51e2c709d3056a44',
  'bf2d370aac11ecb60389ea06c3d2911a',
  '04db44e51855c6b2bd42fcc64b6e11b5',
  '8b532771df5aa42baa1705d0b25ed6e3',
  '539e53f42aab3cea808fa62ff4cdb660',
  '1313f70c2ef50e6ec007a449b0a16552',
  '1d2834b15a34c2f5922729061d89b104',
  'a47366c38a74101036131573ef49839d',
  'eca38890036929d5aabef0f3c9d691f4',
  '199a5dc270c49428db738ab53aab6b12',
  'd51dab90d697c17b6a8c24cd54baabef',
  '884e70bc7cf0e2b22207fa95f6f94cbe',
  '73e506c615b2abfae4db8c73e52e992b',
  'c068fdf6c0ffeb7b9edb179bf4d748a1',
  '667f681447449f24e9fb8c1253caa3db',
  'c7b379a365b4d8d04ee8cb1df1da4685',
  '89eac62d5a23c8e762829fb4b38a9e13',
  'c654f155eb60028925c5e39479ddfe05',
  'a268cb2b2ab856bfaa0d8da0412044e3',
  '2bf6bf21e73c93d7728807c94da6393e',
  '57f411d6dd497989f10d79ddb7ce61d1',
  'da6d24730b4538c924765e65a6b47167',
  '5b2bd57649c8788eddc977c1640d20ca',
  '25ea2c87200832e0686fdd854ab6d6b4',
  'd8420670ef8490c41be6b38b8814f0b5',
  'ddabed02d4170c2155ab26886d129bf6',
  '397a2444d3432e5c82480101675f3606',
  '571e25e36e5962ba0994aac9aefce97a',
  '0a92c8952fe708dc7f368f78e1daf03e',
  '67c4d4b7356dd1ccde39b29874ab0481',
  '995404dbc0fc1c2f2389ae3b296ac47d',
  'fcfe22c8095715711310aea2f28bb5ed',
  '18ef25fb25f25c570f2500a6e1402d52',
  '0aa030bcc090f21fb7702f0ce593af12',
  'd4b841707e86d4d9d5c4802e7dce9424',
  '916b4375f10e519bf3cf800010ba2c4c',
  'fe112a105053e37a424d3e8ac364d14d',
  '239e49b5c769b7ecc3e7d62ad5411988',
  'cca62a1f1da6d8fafbc463e7c4f60107',
  'ef4bf8a981f91278e030c36b1ed3e269',
  '1417c6078c593601764be6f56a4ca715',
  '30618ad69c081b06f33aaf7583219629',
  '53854c3b03d1d95c8ebc7b8f93212890',
  '460a6a7272250d503a4c220be98f7202',
  '313b3305e00ce5db751534c1ddf65664',
  'ee130862786e6f23058fdd5b6fd66fc4',
  '5b9d29b2a7869bc2f647906138fff9d6',
  '373470bc0b7d4210f656ec732316fb09',
  'ec9d741c8421bf4939e6c65dc0b9153b',
  'b220a772d6001eda6f9c009ea6fe1e59',
  '83e467e251e0315e69aee1ee4b4450ec',
  '542f4fcf8105c39b0e456469aae33427',
  '5dfb3b0494e179e9eeedece4c45658b5',
  '84776afae95112046cdde4bd0a137694',
  'a0eb6ed59e8da84522945fb2745e49a9',
  'd2d04d9a3ee9e0761a28996ea5914c2c',
  '8bb8a30ddc0255f73c3d801e70632d47',
  '3fde28a975cb34ecfa68e86bf161f9e3',
  '6dbc78b66469b5eba7de357200315a42',
  '56a1579e9748a70c5b6e503da1256ad3',
  'ac770371060e09e068de67c8b6c08c25',
  '4b6c58255495f0ff51af25c9e4273851',
  '2f44b8cfda36ead38c344f03717c06d9',
  '26a11bfae5baa6d2b1d0f371c671bdd7',
  '9dc85b9e54eb8e77740af915ca4cde83',
  '5168fb868086faa2bb007c4ca77a7d22',
  'b9294acc149048a84944921371f50041',
  '0560cf71cf32dc8066231b3fd27e7f08',
  'e247343b43a781da5d36592ff8c69c7e',
  'b7e48e3d9ba9b5ef24d4fa93c5c69b1d',
  '9b0859d15e3680b0c58c43d1d002439e',
  'ecf1e8fce5ac64d5b90515923655c4d7',
  '6004e86c0bc7b61002b665f9c2621b36',
  '7b14d985622f0b56d6a37ce183607614',
  '64385833f9e9d9f209bf924e70d4e3de',
  '46dd196b8385449189e46d7149b14e97',
  '66e7f20db20227d2e7ed116d52ade824',
  'e15fc587460da45b8fb6aaf269c24e3e',
  'f6f32f485e383af56d68f45cbe3b0ea6',
  '16f41d20581d1397139e484c00342969',
  '924748cf2b56f2686839e9893a295d4a',
  '46bb1e650e69aac9276784e29c8477dc',
  'befcb2d4c8bded40ed251a27ab1e2c6c',
  'a44e0cf5f7caae8f68a8ce9dbcc4d2c8',
  '7de779b2e65602d6a08bb22dc98ff163',
  'b198eca3f3f0ab8caa9771e85579590d',
  'b48c483b2c52431baed037f9821ba58a',
  'cdffcb51f2e18c8dfa8968c495168db5',
  '0a29d5638c76a47c662f5f9cbf76795c',
  '8df340d7e8addf955d20a280d854287f',
  '34aa612ed27a9354c5bca0b2eda35b5f',
  '452c73aa0337358695ff2c309e696161',
  'fb1fa945b2d8b521e3cee4212d6e58ba',
  '7b129b28f30f2b657cfb2dbefbc36701',
  'ec4ad2cef383379c1322a1322567d696',
  'f0a0ddd7893af68d728581664db02b38',
  '9a4704966bd9e73fcf963185c3c7d0ed',
  '5d1c57a0a6cb42ec42a748692efe4343',
  '369a88de589b78f1999c4f31dbdc422e',
  '9e1a744133a47e829ab2c8973721ea53',
  '65873da0acb466694d6702c514d258bc',
  'd49f8a9710c3fe156e1d0771a3abcede',
  '44f73ea024039bb12d414d907dd7caf2',
  'd9a97190b0adb845509c0f1ac2f1cd91',
  '46a15150e2ab96046f5a207c171ce0f7',
  'e5d7cd6ae97d25e05b4fcee287d20ea8',
  'd9764d1f441b8f9eb52d72b663c36299',
  '507e9fd25703dd012e7031ce3ea71a3a',
  '09a2d952f1c6cd082783e56c02cd21ee',
  'c5321ade6b59fbea25731764d4504d06',
  '49cc726ca500801402c2d1d864a3341c',
  'd331f905629d0c1cccd27204971ffb6e',
  'a8ee27ed5434ed03ad66bb23dfc2688d',
  '0bd2045a54d146c8194154b61f94af87',
  'f0502858ebf08217e32abca2877eb471',
  'bfa5ad74c6934ee049a7748b996100f8',
  'a6340d3947fd3e55894294c17b1bc1a4',
  '5e4e570893e5ae70e70dbfd2475061b4',
  '8b284cb39024f1dce42d23b205127998',
  '881c32b6d6c47aff05d4f2a6302eb104',
  '2508615dd6a5fe81efd452cf1a1a574d',
  'f12c5852edc4458980fb1b1138d30906',
  '8196ac4f3c04701b17df602a94400ffa',
  'd7c5b034e257703c4ab25090c9755eab',
  '8041ded9be1780da68dc3a8335bf9bc9',
  '47b63617dbaf9998eb963c81e919f527',
  'db5e4ee5ab717ac1c44a8918c0ccc4d8',
  '1d0ce1ff01495367c56feb069f4cf4ce',
  '94a9ed9bdf8ed8a9bbd97b18479374bd',
  '1f6ac368e1f3adbbcb10f3dc1fb2507d',
  '2b21c6bcf0cfe5d0968d7b263e2bdd08',
  'e4e41c923e3202e15bcd3f2dc4c1b298',
  '60e6a803cf690836269be3b2348a2003',
  '9c9e23126cfce4353bdbeb71aa4f81de',
  'c0aa479b7e5569e481e5fcdd523c36e1',
  '091238b5fc1cf507f5b9aa1531d4ec22',
  'b9e34b0b142bbf80d5b7ebfc9a6c7d88',
  '9fd9a612f57c588a62b927a5e892c470',
  'cd8eb3412ca821c807de13acfecea68e',
  'ec2ddd97b70c3e783a71846b05c157d8',
  '8405e42bda1deb9f646897e9391819e7',
  '2d107cae9422c9995fd87503af5c8be5',
  '452d95153316cadad475ad33fb2da313',
  '129a683fb6499a3da4fa76031c892a06',
  '8b0e0c165a763dbf7209defef61840c5',
  '4ca6f670e664232836426a9ebd9f7e15',
  '22fc5cd837e6832c60e85ccb320903e5',
  'faf5baeb67a91c7da8a5f425e5f7db2d',
  '67b809e72b122e444e3806add288e7f5',
  '94c6945149f9f134af970893ba5cae7d',
  'e4c61f16c99de1bcdc5df7625208f003',
  '456852038fd4ab5fa99dc8ab8cd6c442',
  '99ae5020186cda9b16acd4eb5aa1b1b0',
  '06e866e7bf6d5880c04f8512f12c1a11',
  'f6d3c3ba2132c755117c8d1b41a67c25',
  '776510def7230b63c0612457ab7027ee',
  '7d9f12ab3b047e52916e557f86394b73',
  'b40d0f74076c7a93b4b5938b0e4f5b00',
  'd8a0563adc151842db9b0f0ea443b645',
  '3fa7428d758d4ebec99336ed79b061c7',
  '94a6a64aa46084b52a538b05395f15e4',
  '47f751a696109346b834c08e8ca6c596',
  'd01927b91d6fa1747a12a476b654bb08',
  'd72b26b8768453d40179802e1f65ec89',
  'd98482718e4d39b5fe9ce1a3cfe9ece6',
  'd386067cf2bd39d6c3e92290fe1d0f91',
  '2ae08e9cc2269aae00ab5b19dccbc911',
  '3d626397adec88e69821d604149f58e8',
  '05cc80a5f313fa777e594ed5e0eb29c4',
  'cab9b3ab52b66db1dacaf0fce384d41d',
  '32569277ab37950e408360b18dc904bf',
  '7c23a39c5fea37387b8f4a24a5b4cef5',
  'c15f71e658ae51671a6054994fdd1adf',
  '718e2ef75b4df138c78c01b0a04f7b29',
  '8fe7aad62ff119d826d486d4fd835672',
  'd1fa3f10640e6d64dd3e4a48f8e4d393',
  '1883aa456009c0f45c26139119bc8a59',
  'f895bf40f70e09734780dad11960efad',
  '011f755e007eea8d0b64c8f1cc035d12',
  '08893f471d5047cee40e0c0a79c7838e',
  '98d8859b5c3f419911ddf4f78667165d',
  '5eaaf5c485612994b4c73e7945b3438e',
  '187283bf1b74759e6609ec337178ad22',
  '5fedb57fb7b63d7aa9878c53c58eb2c3',
  'aa14b5b1d43d19eb0eb5b92d1560af64',
  '7a676ee2c922aebc0de676292aa10ace',
  '0b9e5af9164c81ec810b8d97a27fa3c1',
  '2a1ef572d21994ab65e201a8a9a8afa1',
  'b00af3239e643cbbd94abf74fc182c32',
  '2e43e0a7698c05ab4ede39e67eeca672',
  'a3189cdcb625995d8395f8e6e9893f2f',
  '20174d1bed676af790fb5119100f06b8',
  '3d5b88088ce7af3e04180c5ac4f6f7a1',
  'f75255743e643d68eff2ba0ea2bdba9d',
  '6ef3fbfd809aac163e873e92ed3d6697',
  '3edf594b7262d927bcda7efbee36706f',
  '52398126ffde00919016af5e59cb226b',
  'bee68adbc75f3d4aff80cf694b443aca',
  '8d6eda7aa5b23bee1da8a9430d6bfc47',
  'eef3698d81539f5a8c0b9e85291f168b',
  'e3ccb9b90e3f40d94f43d861acd0a940',
  '19e0de8e60c120188008940adf61ef46',
  '4da37a783895aa49755f0b5f4916292b',
  'e9d03fac1652f0d4effcdb3812f65f56',
  'e1c6ad67b94006998e5e7a8d9e702f1c',
  '35ec97a964a0837983bfcc691880df32',
  '7716fcf75dadb72f566c89bdf6bbb7bd',
  'b44d4f260413d1d7767ab761290d13ea',
  '8294e2a73408f272b20e59a8f9cb6ade',
  'bfe8aadcd9d89c52c162e019f18d7387',
  '55271622562af7178f921bd7c6e80658',
  '4925c0acc3adbea6835136723a6995fb',
  '190eea5bb5870ec0734644c7c1ec1b24',
  '5db43e0c118fd68f11fb6ce17a61ebc5',
  '0f786f11de9cc0f69b75083471196968',
  'b5187a9d8f1dfcae67d647eda2f1250a',
  '909b181a825c35179f8747477952d26a',
  '974fca14fdb327a09e2bb14218127c25',
  'ced96ad8f8bec59d4d25100fde41dbbc',
  'f978d33c66f6b1286d09aa8e32f35b93',
  '74883b13765e4644e22455828c35de1c',
  '38408b9651ef9f09a0702ab261b40069',
  '39afe56b4fea2441f3cd32293fdbffbc',
  'df5b2af587fa6dd5e0b48e0c4fa23f31',
  '1fa8b0a37aafbfd19c64774ee3190310',
  'f361bcaa6836eda291aafa89708c52f4',
  '297a2f6cf31b1a8c642606c8fa89ea9c',
  '9f21cdc9676ddc8b9fc94b787282065d',
  '2defbdc025965917995460e33fead1a1',
  '67c3cd0c0cd77e0a21b7ff6d2acd9ddb',
  'd534eb4f9143fb0496d1b1a71269b695',
  '7e008c014e5e7fb63e5dc289ed70343e',
  '4ed0d3360af77b164ea20000557942f2',
  '68f0a2845df94d5b03eef13f25519e9f',
  'df74e0de03c9206818da08b1e2f5400e',
  'd17f30cbb2f500fa5f5c369ffdb14ce0',
  '66590da02d7e7ac60084378b52ec3078',
  '89980a008ec577d9d589c979990043ad',
  'af5773b56022e20a6642315a184e895d',
  'be8beafea8a7500bdddfec808aa3694e',
  '429592bbc5bc0f06a66cab1d1fd500e6',
  '0b1b0069809e9a9ab60930915453eeb3',
  '9042189fb490c2cf94b97de31f217bc5',
  'fdd5f75d4633cf6dd4a07ce3c99af871',
  'ff2dd11c2cfdf654a80720bf358bd8e5',
  'c727fe02601a28b2f98dcade6fd1c09e',
  '2634ad4ed55e7c3eff13fb0f46db3868',
  '0c872e23a5f9a1d91fc94634be75be9d',
  'dea37f13c3100be9b83db7d7bef3bde1',
  '2c4c9c242ffa664ca8c02451bd78c332',
  '0bd8efdc82136bb16ff5871f504f57d6',
  '969ff51c0556c930bb4fb239da31457c',
  '221d385315102b116dd208329ea1f427',
  '6dcc31f26a7752f31e7f329b84af05b7',
  '44828cc7ad38e5caef94f3969a375134',
  '8dc48b0d72985dd6f077a54582f15f24',
  'b7aed30a939669d4d88ff4900a531509',
  'c9bf0eabe75eab4e191550c2af22b21c',
  '2968947c84e6bf201bbe71a5d0d2d57f',
  '3b02b7bda61b9bfe0a7ba8854fbd220c',
  '2db7bff8db9982514ffdd122ef1034f9',
  'd2cf136a984712c376487a41e2f00593',
  '2aa4753d0e5f130428e739a9f7a6d17b',
  'fed0efae5a4b2f4c53e1c42352e7da82',
  '926df528fee18efd62757809044aa762',
  'f649c4920101d9d8df8486f2ff56abfb',
  '81e4db84c6a407d1260d7567118f8a4d',
  '13c4b5b19f683ec697fa913688df8090',
  'a6e87ee4fe3104d1d2c008ad556797f0',
  '13c3c9bc5091620cb9dbb00699851354',
  'ce0576918158bf3b1be9815d531cd8da',
  'a0a1d301aef3febf9147e6ed12f717b5',
  '2d2eaf5f6e61c686a912547875ff1ea6',
  '8ab22bf1cdd431d92509598825f98bd2',
  'fc9eee7c531c470dcee8fe53b0abc06c',
  'acce0c8b5ec9b7a7201fa59bb7651695',
  '6aab61277f55e79dacb9b46299deedeb',
  '3ac1529cacc7357c55337b33f4a540c7',
  '0ec2df12d87c19d9ed4b98e461c46450',
  '9e4d0f8605d9e414aaa29021c0357cde',
  'e4566322d2ae158db86ba9254d768575',
  'ee170039b8d6982b4afb4b21b013d045',
  'e7158a95788395b7670cccde404e0017',
  'cb8f5aa7c2eb168de9ed72dd093b6b77',
  'e3dd8c73e1af8805cb2f1ac919010c92',
  'c4ba23394a8dc8c4eefb6619a3654a76',
  '6bf1e01ee3b834204fecb0cb8221d66e',
  'cb1486b7935416d8a39509263fb5e250',
  '15bca552a9e1929dc08c84d9d5e9e98c',
  'edf1092870139bf83b56a49120699735',
  '6e4b2f720e069f47bfe55912ab058601',
  'de12ccee601a423a2f613cdea8aca819',
  'b627880a45cdb4225b67e3c7951b3e74',
  '2a2e7c9ca42f99e77a1514a99d354a2f',
  'e93ce7196545c98567f3b5a6c958e483',
  'de6fbe260a6feb8b6d42381900c0128b',
  '76c0a074deda2669ead50b6a899c589d',
  '60959dcb34aa702704915edb503d8012',
  '6fe982debcb64462d28b08d8290cce5c',
  'b32904e2ac628ebeadc247cea34a1fd0',
  '42214dfb364474fb9cc942212923efc5',
  '72a2645ce92052984ce9cc720b1e0229',
  'b53c84d29e3192be794eb29bd7e3d82d',
  '4ac4be02336631b6b38e40db12ffefa3',
  '4149ba46ce42e35f000f0f3c22d4faa6',
  'c5f924c07c9f7aeb9af72666cddd624c',
  '2de3aa112e3efca4af7ee2516612c066',
  '9a48f7ac902394ec717d95f83db4fac5',
  '658bbe5a45e1d2142bcbf89e1a4f5d46',
  '742a2d1209bbdbc23ab3285ce93e72f0',
  '9b6525c4d948cfd9888857a25080305f',
  'ed9df4eee17d0c45f76d7872a3906cfc',
  '6b7ad229aaf1dd568a437e9fbcfa6d7f',
  'd5f964add7065e8b067350b999f94927',
  '162fd18a7eb753869a7e2d222aecc593',
  'd7f012cd49a45e99d5b9ca47dbb4401f',
  '40bfe390db83743188ee1b322b51c054',
  '5619981b81903df9047cd0672d320c68',
  '1dc035a29f40a7595d9e203353e79a80',
  'ea7273cc373a39a30d3354a2b03f7446',
  'bedcdb051b05649a635e6abc6ff6f93b',
  'd67af43df55ae16248b8db03ac8e9ac2',
  'ebbf3a515b5e7e9770f190da771b76bb',
  '4af42f59523721205346d6c7789a68bb',
  '7bf22aab08ae145b106cf7fe5a7c563f',
  'e7c852e67d041e294f3facd5d9d69b69',
  '31fb3fe038b8431a3738ae47ba2b284a',
  'bde629b56753a4e1bb692762df08ea79',
  '4165ee3e9aa091191690f988c5fe90fa',
  '247c7c49bb749354700d8aa49d0bd827',
  '72a9d4e682180efed979f9a2939a388b',
  '1eab29ce028849659e98171432404a44',
  'e3426c5d60ff3af85a7e589818bd90be',
  'e3b152030fd2b789d22a722cbbad333f',
  '0b575fcbc8772e405029827e4d96fdbc',
  '410ff0a2f8d49a865bb03d668740e92e',
  'b0a9b0cacca8f2044363d71c53d41252',
  '61db698bcd5065dac16f8424b0dac58b',
  '52039eda05dd1dba55de5faf18c7b5e9',
  'b4369f3d3edda74ed21b0da6b976bba6',
  '731ed8e060bb8804b6106992cf92d5b9',
  '47dd09db868859ed8dd4341a3e162a3d',
  'ca3e8f4a4b4f3b108bf18a3ddf79860f',
  '8c46f4486d47549d43b79be21ced8de8',
  '3ae891663e5c2b07035a1b1a7350b969',
  'ac5ed1bc60fc1ee319089f1a9272c403',
  '83645710c590c4a6c145e60969045c4f',
  'eb763d2c43a0eb5d0ede69d712b466fa',
  'f3090ca12e2be42d8bcf6da40573b040',
  '0442553c76d0497e7f02a64396c44679',
  '64c94ede613513c7533f324b42b21b3b',
  '0d36c0a0214c8eaf4a83c6e73afffc95',
  'cc7764ea348c0a59d8687010dc240a5f',
  '8d3b4a0ddead714a02c0a0f826bc59d4',
  'e18026cfb51faaed5edccdb67e51bfe6',
  '4a07561fe94ed0b9650e162564e09bc6',
  '168987750793a67d06a0d19209d517d2',
  'c2428938d69edd29dc5a8d91fc817616',
  '7608edda8ae0f63a2ed653f798ef9565',
  '1f2ee37247dda452e160d47701dbb1cf',
  '7351244b7a97e510bfb92db109e246c7',
  '66c264b1d267b66193dd07af237b5406',
  '125f0ac591a3c92aca489a164d609def',
  '81f0996956b43708a18497e1e52bdd76',
  '9eab990b1ef6d4057ababa301ec2da61',
  '0d218aeeb2a98b0efad03a6e63b160a8',
  'f8e155dd94906df335ac81fbe260c3bb',
  '6c5fe7b48e54f2f7d1d88879a03ca17d',
  '0e989ec7b386fc7f3d26b7245ae0761f',
  '4c82aa6e1654352571f9435a6636b930',
  'a138c951168d9c8769f9ae1e613f6fac',
  'cc6bc09110754a448f260c2b7fd2320c',
  '461be17fbd7ca5cb8ff795b86226ef62',
  'e210c3452e23725537982ebf124b2d31',
  '18afde88903087576b996e71906ca85c',
  'e719980380301f05a5b919c8df5b3f82',
  'c375639a8aad4cfa6753ec66d818c90e',
  '7e188f5c9681425b32fec67b9eceb398',
  'b35ef94589c824001eff98cab6573542',
  'f6201e13394cf1be72e1358ca049eea3',
  'cee9939208dc1118952b661274091deb',
  '2c923a7a06af90d3c6c22144779a08cd',
  '6a8039490728152c2fef02e318dcb48e',
  'c6bb54683efe72d1feeb0bfbe2a8e78c',
  'c9dd5a99f7bee31f2a1014661d838c3f',
  'eccc7dfbe9ddba236beaf4b19d3d8395',
  '45f9ca4eadc83abef5d2aaf151165a77',
  '83d5bca47c7bca0cc1f9c3e9f71d0769',
  '2edbd82960557295a94c2587611816ef',
  '8d2679924ec34d835ec43ff34fdd291d',
  '920e10a06c99153b2f980f1724420729',
  '0f521790df6a12228a2acad500fb53b3',
  'cbac960e8055f9d5d47b3d6153cb1bd0',
  'cdb6a748cc1838b2ae416944d464da9c',
  'efb93e5aaeda4c5e4dd7fb47779adb94',
  '6bf61c45cbb98e03f1de36673dfb59a4',
  '334249c3e00573da05bbd11cfdc76d17',
  '67344ab39bb8105898737a551973a2f3',
  '455036b6f79d087d9f3f5b4f69d23907',
  'e2721e73442b9e549be2d3a28107283e',
  '7c33f0e8238daf24f0c79d026500bf2a',
  '9002d2a44ad9018508c335135abda6ba',
  'd98ef07d8b896ddac61bcbd6debd7d0c',
  'c84b78966b17cc093322403d922b1f20',
  '67d04b24b5ad73e929fa2214acd3f0e9',
  '95cb8edc68018b9b45f61e2c2e8ece4a',
  '9dfcab87522f9ee23eee0b4431f8176a',
  '28ae87b595aa0b0617932b36a278c120',
  'a98aaf0264c15fe311acba4d67ec7068',
  '60f2782395c9466b528d6a04b637b77e',
  '3ae0be4a58a7f4ec90d1170be68dedcf',
  '3c73c7ccdd7008bd210200c87cdf814b',
  '551572566db46842d900e1178902095e',
  '0be1f73d6a7839c3b38bcdc80d90845b',
  '7bd37cd9fed1d9a9c6ec2c81f060fd46',
  '16fb96ded0170281c5fd49eeb432bbd0',
  'd993f18d1d18cc793a04bb55ba33310f',
  '1c3d4a20f696fdc6f3beff3c884618c1',
  '36211a8cbbef9e9525a51c84982dbc0f',
  '8ba15f114691f5f0778623d71adbb0e5',
  '595e5fe22748713e03978bfa7b2dc8b0',
  '84c036442264fc1b6afb4e05ded2a6fa',
  '300e87f3902f07cd3869dd8b5c078898',
  '5f600b81aa54b755eac6c43446e46516',
  'd71c1d246e2b2b250f4fc3eb4f334c09',
  '56b5b66a6b9e9b5de180fc2b549d846b',
  'ff4a670fc05be0527a9a46da53809f22',
  '7445a4320dac6ad40576dc4874d663ba',
  '37314afeb5698c851661f70c1ebbc7ab',
  'ce02d4b3b46e8b2be9e67a2616c4c4c5',
  '304efaba9dcd1c4dbdfff119fae10707',
  '53e36349a40e8a1efb3ec1a4481afff0',
  'db687a77f7ef5f9a4664e5d70e45bf58',
  '0b8f4225c554afd94661bcd20db7c295',
  '17d6e600bdede010e05e3c47e6d4557a',
  'e7b4fea22737edc6ca1ef67d5afeac15',
  'a0605d42252c94c10ac118d9cfbd8bbd',
  '8bf217b90bbc57e7aa01e93c6663a6bc',
  'fcf981918e49d8d2ac22ec5953090639',
  '582357eec32b78f09fd7c64a15da936b',
  'a7d26327a552e611ac8531221e600756',
  '7ab55559196edc533f4caa3cc3be50dd',
  '056049719ad02ea2cf951d2da3afea18',
  '2ca9dc6d28813767b74d54e4502187b1',
  '1f5cf11306e5206657cf1dd51faf1b5d',
  'fe27bebd24b9b79278609980f04ee33c',
  '8e6becb7a1483db749031785118874e2',
  'de829d0de0473969f153c510a21aa22f',
  'd60da42be88ac2c2d5c44be4445d4c20',
  'ef3bed85f7907c626dc985194ea0b450',
  'daa65edab4019e31750a7d1ff44c6b25',
  '0087200fb409882373668e47dcaff210',
  '5054f088629c32a23fa0b22706f9f727',
  '174ab4e7388d184dd3b7d960485d6818',
  '2354094d36e9a3c5141ea5cb9c384a8c',
  '2eb26388bde2f608433aa2eae5172c81',
  '9038009d867a030386b9678cd0aa7660',
  'a82acddbd16b1faa0e7473d2b47baaf2',
  '291aa98634e53bafa39ddb5fdc57e4e4',
  '6313c28f9bc2beb4ca40ed82981d8abe',
  '197126aa1bfce828c4c08cd90930a480',
  '5069ebbb5fc2020d1a243ebb01879e20',
  '49ac7f62fbdef82880389a9f4b2ef4a5',
  '65f74370d907bab7f17ec3798e848492',
  '98c29b6e693f59a427cdb9bc518cbf34',
  '93de0ae77079b89d9c1f852bf5a526f3',
  'ab43bd72244838cb5cc96c51d585a435',
  '30f15d4de9676b75b59be0d84936c51f',
  '997762d7b8e55dd7443a9764cd1be638',
  '3e9a5c39ec3dfd49e8254364078217cf',
  '5b65ee1da0adc69482e8f5d1142abe93',
  '080cf85123a8a17d1a8d36082bc5bec5',
  '81bf432578f2843ec8b5a7bc43efd35b',
  '76d995b2e1ac074abd9f55e83cec37ed',
  '5a9623ac5302916301e746cbf07c4472',
  'cb73bc80a97f8237a5d7513d17db920c',
  'd2f2cc82f12fb1a284bd6fc8ef148ec7',
  '500bf4bb3dc8a23db563dab873feeae5',
  'c7ac4cd61a6ca88374630bb75257d046',
  '72c0f8dc320fe3dbdd8ecd359846e317',
  '05190959bdb30d8fb14114af69296620',
  '13b55112b0836622680ceb8790ad30b2',
  '8bb583dec3a7f721187d603978f900e6',
  'c2f420e05bb61c05d6f4410fbe4fd9b6',
  '73ba24a3d8b9fdc9ccddbe0c04dc1a53',
  '50db5d4ac9f1fe3d70d02c1d2bf37a8a',
  '1e77a326e5f8f6eed1781a4daa5ed5ee',
  '44e72afdd05c52c407ccba41176f72e7',
  'ead530e09a4d2db71ef7ad83bc9362be',
  'f4b28fc6b33b5938eef0c5cfd716dc3c',
  '7290541d281dada74932d1cd19cb1062',
  'a6df935bba008bbc407acf360d7118d3',
  '144372e3b1935b34d239195314f80e52',
  'a7497b8f6deee1c9fe56663f221c9271',
  'c87deec9160f0d372eea7f1e82d19a4c',
  '593406a239691a2282ed947fd387a4dc',
  '3762156db2d68bc11a8dca008c3f7827',
  'd8df1b97ea856af67d76e16849031307',
  'baa1f5639a0421717b64b68f197c5f89',
  '1df7ade496bc0e6fa9d9d748497f00d7',
  '94538422678aca407c10a5e2b900ea91',
  'd56dec836ecea136f7ad3c42ca14f2b7',
  '3ab234af76f340a9b5386ccdb7cfe40e',
  '86e75596317a8b48d4d44b40b1802be6',
  '7f8632f458dc0e7fb10703dd5fe69b53',
  '79203524a3ce7477449e53316bec8f69',
  '943109d56ceb7ab833be5962f3743b7f',
  'dc91af291bf55474e526e38ed5c0b5c1',
  'a51eb46648ab464d1a10f3c63b69277b',
  'd152169637e6ca3c36af5d13305518fa',
  '5bcadf3e5c2e5b61368849bef8187b5e',
  '476344472b4033018f920d73af1f0a66',
  '8f3a584275644e9bf71356051992dadb',
  '7ab54d047a530a4600f5af1cb371b226',
  '8cf37636f6a9ace2648b35af165f2f07',
  'a05ee8c5ed1f8114ff94918232ce390b',
  '34b408c870ee712f8ffb4ac0127ebc83',
  '0bd32707658ab66b0ac7cd4bb96456cf',
  '85e860a29e9ba99180d32f764361ca0a',
  '3134279834dd7665ab0215cb949e1489',
  'b33d7f313252b12fa8a388bddd036a65',
  '487219d07bf0ad77a549987601dd5022',
  'fd404c7a961110e79406fc9e718d69e6',
  'c9f7fda428ad555c78c8917e713aa4d2',
  'f2d37af186f51a7d6f695491c1f116b7',
  '7fab14e68b41872d570fff6442c3dfbf',
  '5be610542587198edad2c18710145842',
  '2d6d55bbfdc02b9fbbf5ea169f58d136',
  '80d1e4fbc1d90898e7c9fdac5ce76d98',
  'e98aad06f1f0c8cd8f26d3d821396498',
  'b02fa75d2964d2475ef007a516d1496a',
  '2283652ba5104f68530ff1897fa85414',
  '092917401cef29831814ecd1adeb4186',
  'c71448fef7eb0194cb63ed6636751694',
  'c00ad29186b6adbf5c8d4efade0b7e68',
  '72f66c67b261f191a53c4e2dc810006a',
  '438abd574015991b92f10ce715a08cc7',
  '9fd275d3fd7ac5afde63f145ed3f0ed1',
  'a10814d77b69846813ac32d42850c6d9',
  '2383fa54d198ccacf51b6aa27e54acb3',
  '275b55ab7e02e4d2f14b101b299a337f',
  '62044408489745dfd8f61f667e6de9f3',
  'dc0313cfa8f92fd090040e40793756bb',
  '2b32938b2e60b6ba89bcde66d00d76bf',
  '9f53ee6ff84239c9d5662f6530fb546e',
  '76296522554cc9aa2ee06efa3bf522bf',
  'daeba01d06b21b51c5a8e1c3c4adbf8f',
  '25d69812cf956c2810336b8e031b47e5',
  'eeacb5a2d7c190dad27c0b873fffeafb',
  'a6107977127ea8835a05f1c2fdbe10fe',
  '5e34f0394fcd587bb7d7ceb3a45df378',
  'c320a34f595ddf2389010c05728c4929',
  '4542cbdab04ca1e2ecf1e102997355d8',
  '584bb05d10967f90fb340c8c722f6160',
  '6ce61f32012178eab18cf6a393d4cee8',
  '9024fc5e249245347444df6eb7b6b304',
  '080bcfb12252c9e5a393a64160eb12f9',
  '384db445dbeda00062b88c26982b670b',
  '6c985e5f50fa858cd8622f14af6d0129',
  '37312933fdcd151d2c1f0f51afc2b4bd',
  '0ce48b02cb710997f556628f3c70cebe',
  '42f896cbc9825237398bca42bf360695',
  'ed79250c1155e7cf87c2cf1cbdb27758',
  '125c1aef9fbd63d32884048ef0cb1c31',
  '69f1282a52f9fb7f0ea4426341904878',
  '43744fcb468d9d1a0287cdcf6bb85d44',
  '172c8adf9e659f55ff9c2db582b40f44',
  'af2c7a4da8beb23df4b3f4daa10dec78',
  'bb109dc368fed95dec0fe272470b0c21',
  '9798e8921ebebba7d4b537fe36df7db4',
  'f0270937750cf241c36629f85c59a989',
  '5869c09c1c92a6b25fbbc0541e855704',
  '95eab737959d9baa98b9c0ad8bd80bf5',
  '70c66144d93fad400b0d4e5d462a385d',
  '5f9e1c358b0ec2de9959a26f9dbc113f',
  'af52b8e526c60122245850445c92f707',
  'ecc32e344b7b45faa4211a0c6fa7a640',
  '55ec9271ff2a70e971a6b46a66023241',
  '349772c216c62b25de0bd9f4e0dc676d',
  '2cc1197c9d33a4fde60915d07618dc60',
  '2cc49aa756dd8b189a60cf6f029d72e3',
  'b7045292e9729030a23871e202775096',
  '0776728d46c0aa21f6236e9013a8e210',
  'c9b35ae05c790c79d89b19c1ade9769c',
  'f545f0a037320699fc18ecba4c7186c7',
  '13e59c6e585aec4e3b0f30807b4e628e',
  '38b7c8611bc56dd049c8ff6ece160c99',
  '15825501158f28cecbb4876fbf12679d',
  'd8da90cf40f1b416df7ac5c765e556b6',
  '593e3d7346684f51e14fa0faa17c66e9',
  '00bffe296ca3ab743ecfdd8e898e4158',
  'fedb56517b78a99d7bde15b1ece8ec58',
  'eeb3917ecc59bed4f9db22fce231739d',
  'e4fd23b354e97cd4b7276d773ad71e94',
  '480b9c90ec83acbb7a48d62e367d4024',
  '9c97b5eeea103052c5f731033c767612',
  '182a41cefe1e61555e89ad8dba6ba399',
  '8ee45e6f1338a4e83eeebecfff0c3c18',
  'fe7c4ca1f421580af5bc5ba352315764',
  'c7e04e3e2a6cbdcf87d11d903bf97658',
  '45f79cd54f50e4888605dcf1fb4c2bb5',
  '3acf211ee1817603739276404b369439',
  '53e4a656abefc2ac75c908dc7b6fe406',
  '8389622bdcb4cb3b576eac61c28b7c8d',
  '2c8a1c5f6befe71bd55594bfd9276fcf',
  'f9bb5741ce3b4f79e833c0c314c121fc',
  '3864e58a6bf2220d57cc11a66c938f2b',
  '21066c519d94af7924a6391da6b65991',
  'db648ed28e5a18b4598050885f7ffde0',
  '7ff8d8ba43c1c3935a2ef17761c932d7',
  '50c73c1dc1509b85f3dd4fd9c9090557',
  'd6d7159ff42dd8a85a6cc2aae58c6df9',
  '947115d0ad90084d29b3731b8fe9da3e',
  '039e2c2d2f491b7160fc87c6d5b6b11c',
  '45462994af3e19cf6019b91babe44dc0',
  '3e89e64e59ef499f345a4e18b6168a24',
  '92fdcb028a8fcac3637a66c7b6e0aca8',
  '9d9663ed7e232859630601344ce4bb50',
  '9e88a5b2020b3687b2be3162fc85fd73',
  'd540e0dd4395a9f6947b26f7253ccecb',
  '954e7587b1accd335c9bbca6e5a71479',
  '9046aae2bdb7a0663ea6cae2a706ed65',
  'cfc972fc5e745a77450ada65f73aa566',
  'e32eb708fba7c3382c71a1cfdf88cc88',
  '7fb275f97244fc3debeb574312005de8',
  '913739ca484a8a860b701db82176d4a0',
  '7de098175e01d1a84418b10e3a3f23a6',
  '3a211a5e38844db6ab5cee8546639932',
  'f12b6f8eb287362ddc2b10b8c2ce5b0c',
  '9e92243540bf46b938d2bac0c9301716',
  '3945e07e0e037598d527e9a18f8477d3',
  '7ecc72bef6bf15f3cfd92e36092f96ac',
  '266acb94da0a3a504e633b5a61e5928f',
  'ddd8ec098cfaa1ac68386f698f9710fd',
  'ad15a339bf07951969f36828cb24b8d5',
  'c5f08a4e6b31a154696c7621f545405f',
  '932f15de19f3e266bbdbba2f1697c623',
  '79a78c3931ff307c4edb65aea1f44ca0',
  'ff36b45921608e343992cc68ca984f8e',
  '515a190fac0c2da2a22b1f3b12a546d7',
  '58b0f08747b074d950f723fa544fe116',
  '4c44f00543e6aff8ce3def4dfbfdbc16',
  '2d8b5de5a56d3ab1b15f51717f39b000',
  '1d678f64ad1f6c6b03f7848efd6f4536',
  '65c768991f823601d86e6e644a1547e8',
  '1b62040683ce2c28cb06c09022d13e27',
  'bc77df921116dea9920a21b4ec94bca6',
  'ea019faca2674f4eea2929fecd76de08',
  '2539e0ffa650d94fbbfd1810ff33b1d7',
  'b66caddf90a5e1e18dfacc87a0d2bfd4',
  '05b11237e1b56301ee785571f85ada17',
  '2cbace81f0bdb38edeb7af1556526936',
  '66e47ee2cd27b1812d4d5d88c98e8fd3',
  '1785668c6f6241ddb73a1db125ce6228',
  '5ddf4fa648385d6d073a8b987f5ce652',
  'fa1f1c072387efa40e6daed06ddd3efe',
  'e881811fe09c10202a3b604c6333bee3',
  '89ae8c245785d48760c73a8e61bb119e',
  'd0b9124e6f895d263466061d387ac982',
  'dbe93603836576c75b230015a8ba79f8',
  '48107f47535d799b2b47ef3d5298c116',
  'd39a90e85b3cfa51f3dfce5946e4d592',
  '965ce729fe663118d5e4071e29ec45bf',
  '2211cc2513cd06f4dcb567e0cbde1039',
  'f5dea04e9032e347692c8475971c5e54',
  'a4c0f216269c169fee2739e8a255c2ec',
  '903fbab94209091693671752045c8107',
  '1cb033a827dd89307a1bb40784791dae',
  '4aef199615aad4bdf098a13566a65a4b',
  'd7a854429740f7cad1d4b7d2522bb9f3',
  '8456bba617471623e27a233f060d7ba4',
  'c9a6951b987a0717ab3b3d5564e0d836',
  'ec4d50066555daecba411074461ceffb',
  '8fc6c6423ad2dc11023cf768d5f68d77',
  '99ac1742651bcad53d25d67a0ed40ef6',
  '588c56e3f91c572e2588ee087ac19a3b',
  '2b1719e53fb7ce94a679b784df3b530f',
  'de36dfe32072d684f3090d4a3ebef442',
  'd808521eef7fb93808209169cee98036',
  '996f32d50ca7789a61c436916580ee61',
  '37b3e701c3cd3800bf423f9eaa991af8',
  'd9d8602aaec9cea4a607b22644876738',
  '481d864aac8bc2de9e7f737af415dac2',
  '36d43ec789a22b2346b00f12f98c89e8',
  'e96e00bbfa9a6a86bf23b8fbe1dfb028',
  'f206e8102e47437d70a1b3c87a264565',
  'cc664b7f9e4fd95472c643ec4f1faf6e',
  '7ea10427c7f7fc081b6165c16ffae2db',
  '4ae3fb96077277304573bda7327f4282',
  '4e3bcf96118dbdc0c8584a84fa686a36',
  '482b111f0e91c29f1d973472ed5bd755',
  'c81c9e762d34504f429be467eb35a86c',
  '4a27cc3f72319e6b937c066b0c91a232',
  'dbb613a680ef5349ee82f522ae9d8530',
  '66f2a4bb1ee1d54de6cc215b570831c0',
  'fc8f812e77fef3ebecc483cebe8338f8',
  '32e84c304c99173895c275522fce6005',
  'a979f6cd1c945a36403df735eabf5015',
  '61b4c7e903677ca9d3cdf6be10f7cffd',
  '3c5ca36fe2452965e7b0a20f83aa3df8',
  'f8f1fbf97ba5dbd6c9b2203e67492b2d',
  '0f7ab3f51379f19f59b0c7898774460f',
  'b3090f9fa84258ed0d70d14c3d51522a',
  '31eb542e58d9d38d3e6c402658c530ef',
  '7011b2fb086e40f3669841b2bbf9629a',
  'a3229f744b8b166d95a1067b0b9bd4e2',
  'd64c5c841f5defe55e1839c509997829',
  'dc3f4e565ba012dd7fd8cdb326fc26d2',
  '24adb268ac2564b23145927178429726',
  '5f937ad81a28e3a5097592d427056380',
  '74bc56c01deea0b4396de997aaa96bc5',
  '0c4bcb9a3fd8ab13faf18a994dbf83af',
  '88ddcec749756a46d9348cd9a514a9c1',
  'fb5bf96c40cae442973117e74e2356a3',
  '22229ae2053adf4bb6a5c5e41fca641f',
  'ae1596d4450819b8054db54717ff0901',
  '7f375142d005c8400fc10a17e953d960',
  '686cd8eaf0cfe9a4aecdc4360365fa09',
  '03840c15a6fc7029138f394a90625774',
  '4c29858765c6dfbccbea4f01a1284bb8',
  'dfa64475a945c638a63a97bb3e2130fb',
  'bdfdd37e14cad0a9c97446bbd18ed471',
  '22502708bfadcbd177bcca7186c273e9',
  '2918ed2d35510aa428a1254bafff1c46',
  '0176509e665f95ec1efac674603f52a6',
  'abbbd40ebeb45b8b799cd462fc553545',
  'd817cb8820bafb78bf8aa86ec76c7cb0',
  '20ea1a378f32d874d81ceb9920522823',
  '414cdd80b8e4580d53ce39d7205b1d4f',
  'a620d8ed2e5eb92035432e7d042707be',
  '85659757ecbd5f46b5f98f798937c107',
  '71dd6b9ea3eb6dd8b5861539d0d20c60',
  '7941649a426c31c248440c5e4b34fb3f',
  'e0d7a920eef8cf59c177aa81fe7c313f',
  'f64eef6f41ffb836f807d114ff59350d',
  '7a69eb20c698d20fd0d6a4a83a3c79b0',
  'fa5ff9f6a58c421d3c0f5d663ec4406e',
  '70361efd008336f55ca0389035bff8d9',
  '4203c4a8c71fab193e73bd6b6fc70902',
  '27d8af4300abf0d220708708afb19bff',
  '816ac2632a8a4c097c89dd8099c8471d',
  'e7f5e223d7c8d62a29da9ea3aab3255f',
  'a0834473eadc211b0187ef1ae610a86b',
  '24b17fee0356fdb012b4fc3261a98250',
  'b9330a9b2049194a62cc26300624e034',
  '6f2789cf1bf935390465eff37f84cbe4',
  '7ffd90e105e5ccf11f991363b697c5c2',
  '597a4aa0683c60bd1bccb13c075e8434',
  '62cf40e5533e665c0a973f5ade5e2066',
  '9d486f3618d88fd7c60ec8e40d5f4f63',
  '4f1d0c860098226f38a367046950ff17',
  'b58ae247d631818e56b6fc100c3716c1',
  '759d14d05ba21a6e92e1e462cd8ec5a9',
  'c8c93bfaf4dfcb5d87850b5988ad6387',
  'dcbbcee122c7a2c9cef7172b6d83816a',
  '65be036890dad6ca9cc4f44fb74e5bd4',
  'e663f136806b132735fb5a923b03151e',
  '16b8c37f1d7867494e66938f956b8d26',
  'eb7bd36f63d580ad8dc265e3a8d3cc6a',
  'e2682fd90203db2cf5ddf0511071af85',
  'f523105ea9e4c906e30aa53b63ee3852',
  '3f458f0da0045f7657a49d0fd73b1cf0',
  '5af97dbd9cf5b8856d4c84758adbc592',
  '26f5de6684cf5f488bc77b04b6cb78e7',
  'fa80c8b18c6c4654852ef733ec4cb790',
  '7ec1019687582d3b95d01297f479e45b',
  '7d07f1458df983a626224595dc705f08',
  '87f014c9da5f7938a0d9be97ed8cf4ea',
  '9e510d2130dcbc794cc9ab80f788d8fa',
  '113ded47d688dfcd6a8afcdfb6e77840',
  'd5c18faeeb1e3fd12ffcb433bf3c1e52',
  '76eb33e3b3db9df6ef968817a1a29936',
  '9bcb6837a469d21cfdec3bddf2f69d03',
  '592891f2c87717692f21e95449fd1e42',
  'cddba60c578ec677f202b4ee383ce753',
  'f7c5b216fe2fbf9f9b4c430ed6ad497e',
  '2b453866f2353e90a839f7d842747e8e',
  '23a64661d3d35df3eaa7dbf16d1e66dc',
  '37a09cb985f9b94c309ae985277ee665',
  'e9484a1acc8862c5adfde35e98722053',
  'b9d1a366792a1efe935fe538c2bd4848',
  'e4784c3bea4a1c2a02063abf32dc5c9c',
  'b230f169b6192e7d84a31c2ecb692d88',
  '49f1813e69dcc5386fd439f87a138147',
  '0718ceda46ef7f71601919dbf0302404',
  'b2364aa453d7a750a3ff63c3baa64c83',
  '5471ac7c034ef55c5e6f280ebda7b0b2',
  '5bdd0802b6a42bba616919d6771a5478',
  '0965049efd86fd0b19a8d6337b951d53',
  '0b4c714ac26f3021a45da647c0894a2f',
  'ebd693fd2a641cd3486b4052cd53fdf3',
  'f44606773ded338a40a665910a0cdcfc',
  'a694830772d4720ba2a41a484650aecc',
  '2beed26bab4e63d93194974e733ede33',
  '133d325e8415e54f625855ddaddf898a',
  '796fee5ee7844b78723e3a0ce4ad6be3',
  'e093a11e5ef8590d1deb7dd0cb4bb53f',
  '9be67ac60e049cbeaffbfa9a3a2b7e7b',
  '0a77d49c30eae3c5084cf0667f080931',
  'f773cc1ea853e0dd61a8809fba224b3f',
  '7b85f1bb0e1ca5cd67aae310b7152fea',
  '71663f0449e4bd48db490bfdc758b43d',
  'e019ea472f876fdf32f719826f2da72f',
  'fe4068b325cb8f5423586e3d206eaa33',
  '639d43c3f97a7d3aad284aaed2042e9b',
  'f520c414f3fb64a55b12f4874deb5086',
  '3f30b19110983c1cd94377f8580516d5',
  '4a08cf0c43ecbb491f2ab1b73b5cd86c',
  '136653e19b0fccf433576d7cfa3c07ad',
  '8ab61addda66561b7af3f1c2a72957ef',
  '57731efe2751b0428e5ed8f3d20a98bf',
  'c11b5c0a6c86276be57c93c23e2c23ec',
  'ae8615516031c10bb255f1f8fba48f3f',
  '33273d2d1e276a844bd068ddd8d77f19',
  '06414d89ceb37c846685b98299fc06e6',
  '604c608137a5a264a86bd1c2bc8ec830',
  '7c5f05d04a7ee245e30e7417e2ad3950',
  '239a81d00fa2fb960a3862359412aab3',
  '6e822fb3eb0ae5c20a1a60bb565d365e',
  'e02a29e595a8141f1660bb53a3df4508',
  'b30b0cde34547da1d1e49740cdf3f2aa',
  'bb5fecbf118c035cd4a5a778974c237e',
  '1c97bb252e1e9154bc5e2eca5da1aaa3',
  'dddc1d187e6d4f0e6fda6ea255d8e8c6',
  '92dd64051539b1862d3ead6363e9a4a8',
  'c7658666b347697a38e424dc6512945b',
  '379305fda2587511a95d7574558742bc',
  '1a99013fd1a79da1c2cfac5fe7772891',
  '7fe14a4229abe87998efc5f9d7cc0c1a',
  'd7157853bdb096449dc9716d628d3d2d',
  '02050e695540cc3380ec2b508e50047c',
  '563636caa6ef270902361c23ff9adaf8',
  '088ddc6d36e0fbddba144d32eba81e38',
  '0f9c9519e8cfa9007e7f71eb5b04e5e0',
  '2779ec9640c5a397a987d03a39e82f7f',
  'c7913cceb214396d04867d34d25e7ecb',
  'b8c62627f1ae9e941590e8ca3c847932',
  '510a497571386239869c7450a016f82a',
  '8f42097634aa8ea4ec812591b5c9201d',
  '26f402254f0e6b195e724abb67e7d6b2',
  'f3c6ebcc96a076195331e3d52d3ad123',
  '10cfd20d7ed54f6c853db55a3a982a26',
  '91b2675f3b00553305ed7b5a191e9f57',
  'ec6cdcaa880fac8f3d97085d3b9a9f01',
  'b2b7f91fd524be97ba55c8bac955555c',
  '6697a4661ab7316074c74933f61a8876',
  '70ae7710e05881a9ab8005dfc53b5a38',
  '09d0778b7f925389132bbaffd8439413',
  '44dfc9f4d3c0053bde38e75a8051172a',
  '670a34ec3ccf4c50abe65c00004aaab0',
  'c84d9da64c898cf4a002129b11a3ec92',
  '3ca8da0f9bf2eeb34f7ee09779165269',
  'ef0213083b4295abda919f8f47ed68be',
  '6e421c9f9b687fe33212031e9f23116b',
  '07f9c7897dc8a02aec275575d6b6c7df',
  'd77089a34545beb62549d171589baf7c',
  'c820cdc6950c0b9bfb1eb69c9fc9edb6',
  '5c06ad5f37db1e1729a52224fbcef824',
  '0601d5490ae89e3e906a52f1f0d5b7ce',
  '3fb01f5411c61b1a8314007a5c851057',
  '622d0ca1a910f9e39f03c533b9e05580',
  '04bfe1713625fda727c4f3556a3d6114',
  'f9fa25d0288828ecde361f9916a67428',
  '60d4762a5d2c14623ee6474156239b51',
  'a4facf996d264757def96e017d9d8e2d',
  '4197451eedfbdd5b8f88ef4fbe4d4ea7',
  '01ef605b45b032d50cbaa8c6defdda84',
  'd52f67ccd04b98192bfe504d0783c580',
  '37f798b787b4de51c8db2b803304520a',
  'cfcf997fbcf76219a7b597233d5f2f3d',
  'ac399fe48f0a0732dbfa82e539241896',
  '7068116be2d906c17448dc61aada54ca',
  '0a87ae291a80c789bb5b0e97191344e6',
  'a041a56c8b3de72c0de7f25064aa9f2e',
  'e871db3e9f64fda930bc252183e991a5',
  '06b5bc6b9670f65aea6adfb2101e474c',
  '9ead827713f6b71545b8e58aa8ecd4f8',
  '4bc5c8905d0aa546e2c1d9d2c4a6b288',
  '1e113c1019d5aec00c77edc0a1f29c62',
  '614f9a897aa502a32b537e950c88991f',
  '7b13d0567f352941c313607c863af524',
  'f463d41f481a82e4a2cef24828721768',
  '0633bcdf8471a958716978af5fd2d0df',
  '056fd688002a7aa6b3a11ee7c5f7b8c5',
  '0b9bf4ed33df2c9fdc7669bcbdcc9f2e',
  '1aa4e526d60eaa0a1123cf23fe034b4d',
  '46f6034b26f8bad134d248ec4a19c666',
  '775c7232981f9b4603c429f133d600ae',
  '8b4afab86684c7226a4a333e9d421ced',
  '636affe51b527c11627d1ebfcc0fac6a',
  '7bbf6043cfd8bdde5ebff9f92a843b99',
  'ab33dcdd5057efb7c544b56a9b4fa1de',
  '2ff7ca108762db488584360a386601e8',
  '3cd396d7669c5036a7a441dbc516202f',
  '728de64ed4802137cfe4e2031ed1536a',
  '289e46747b59576af5488d4f87cf578c',
  'e5cd639c8bbb8fb20c4b791a7927f57d',
  '0bcb6897f774386c1f1b8d60fb1b8800',
  '77df0ab018a3a8fbd1b7f4a12ce80ac9',
  '65180f3de59067e759bcf6193a0682a2',
  'ee461241217c49959f32e2ef3a45ce4b',
  '09753411f0c53c3309852e440a22619d',
  '85c297b42f5639b7883dea13a82869d4',
  '1dd83dcea48d9de757562c6b4d5c0451',
  '02e35c4e5cc33368be72b7e73c50f184',
  '15f0e4700f5708c9ef2738a3802f2884',
  '6b6b32d76cfdeeada1114c6656cded33',
  '0d8aa030daadad02ad9c9c5ec7d0a8f7',
  '777a9632b309743e5adc47e4a724ce3a',
  'daecccfe8c9aa25afff475068ad91de7',
  '2c2bc10d76f2959020f26bb8614a6fa7',
  '6453c32ce92e6e66be28e32c00b5d25f',
  '078af122d73530da3217adfc6a8ff944',
  '111a7341ea4ab233318c6ddb0e130be1',
  '4132f1ebc743dc3debeb510077c9ab6c',
  '3729b717a3b1ba6365eaad8d46d91703',
  'b1a5cf3aaed9a59c9ef37d18384fe287',
  '148f84e2042a1c12bd7533e871e40cd8',
  '200c9638d7397e2f154680d4a9fb5b14',
  'c914dc34ed8997d24a0a7c0276084f97',
  'e4c1cd7fafa6e2e0679065754938c8a1',
  '71177c139068095a9f77e625d47cf328',
  '7f9494a9e584571aee42c8843b1ca44e',
  '95a7ad0ec04d8af04f8366b7a43ed432',
  'bc8b59a94bf5ca7ffe82dd6a28a410f0',
  '4a88cc93d73c3ac7575be6841e1299ea',
  '9424acaecaffec81d224e3c053f87ef9',
  'ee50522df43a4d83efba825e61c9e83b',
  '032764a23d8950c12287b3ae6a325fba',
  'f3ca4b52f27510026fa00274e0e57459',
  'f1414200a9724e075fc77f05749a1302',
  '542b038617ed3a99c37adb9ca8c40dd3',
  '810bcb000ee2a0ed1a223a2e175e8c4e',
  '447ca872b00df989e53aa5f6358b6731',
  '3deb1ee098852b5c16a74a039b53d22f',
  '8c7a93ab5f761d033fb79823be754c70',
  'ce14b34d210fe092f48d913fb22a8211',
  '017d035e6d6a3882250e59d9701ad677',
  '3d241b808e13a401e60d08ebe2bdb87c',
  '0af260908e4ccae70437ed0d0e8bdbd9',
  '11c09cb8453decd2573293b37906f829',
  '979d3e9fe0c6164882ada764e8c12b70',
  '64cda17d0461cb49aeb701863ffeb652',
  'ca59232bc385914c807ac9a4b6629a42',
  'f8a09bcb7dac53d3f488df1cd06deafb',
  '81648b9354e5d797ea6aec7c4e720b12',
  'ea29efb9f082d1d8328572c420e352c5',
  '82b7bb3d5c7570ef47b127d3b5996a0c',
  '560edd3f210c34f5f5d9f241effad782',
  '49caeed4883c7062b357ca44ba55b000',
  '2fd990e2906d8124f10df0aa7f6c6e19',
  'f8bc247eae929f810bbe49c8bfd9b4cd',
  'e2a2c2df37230102b27a4554b7105816',
  'b0029a2456c03272b9657d35004fe5e6',
  'eabf1eef54ce6623310695a579db5fc8',
  '510dd6cf01a87908d8b303c8ace5f4ab',
  'c1310da8a034d5083232ad57cf9ebc26',
  'eacd95bdb72998c6269008e4c4eff301',
  'ddaa6460895b3e820a58abec64a5e19d',
  '5688b5df4a9260140c15d64dff02ffae',
  '938a42018887101fbbdf6a4b06b67285',
  '4121e9039b0dcc3a1de26cbeeadab674',
  '3dad9704a106cdfba107ad940a704861',
  '277ffb0e914c5d2f3ec201308299579f',
  '983280cf0a698672c548c64e4a4d575a',
  '358e21adaf5f7f80306565bb4a0d1fe1',
  '1f3e8b8a321bc5fd9e41338b7acd1a4c',
  '2ad6c37b8f1293c2a218b5c7bd4c060e',
  '954049a674483abe85589f18eaa7ca23',
  '019b45980224569d8aa686f565fbb324',
  '02aef6026c710a42fcdc9862547de264',
  '7ce946440a2357b5ed9dfee7b7b93500',
  '78da9f7a46dd7086df99050c640230b2',
  '478fef4c637f9dc2654cce8ec58c1fbb',
  '43c879e8a4fdda5d3d05b20f97cedee1',
  'b39e6685d046ce329b99643573931280',
  '293eb3e0d0cbd265aabe412ecc4ff0f2',
  'c2a30ec907fc6c7f09865f5db51cb8b5',
  'df180774f0e2c0c4942f9ea949b24f0e',
  'b9758e139eb4d5127941c2aac1924105',
  'cb93826e292e62fc829d84c609b13d42',
  '80e73a9e15ee4f7421e612b3a008fe10',
  'df8ba63d36a1abb7d5bf8a90acebed4c',
  'a3a4a939610cba00be0441c745d10a6e',
  '2037af7b3188c09d192ce0393574ad81',
  '9ef5c47411e5e5fcc1125e08795d29e0',
  '106b16d5332b17972d4cdbbe59595c74',
  '0288a5ab3f3e9359c12a99f78a884753',
  '65e368a29a7e8404a139d756596b7387',
  'e46b4605ffbc7e2ac1d7455318da26db',
  '7463398de3fa6ca6c10395d7d11cbf87',
  '9bcaedf111a9fd4a982489713ddf9825',
  '2fd353df5f9ac76e3464ed7f43c22fb4',
  'd1c1e8277d7a0c1b63f3e2340f240bea',
  'ccf93bf0f9f30a0bf3cba7b3f224a756',
  'c70a44dec6487fc643e23b9555b6ac1f',
  'a0e5e4b9e9749fc3b79857287ef14b99',
  '6273a32d4b9364398d21670cf2a3b8e0',
  '82fab7e688195066e5d0a636ac0863aa',
  '872648ddcfaf667ca08408ae1a3513c3',
  'aa2c4745ff9fac0ce9f14c09fa231503',
  'bc2d7832d1998853ffb7178b288556e9',
  'c5b058c1491363ea87590d5fb7192f0c',
  '84d1131d5ba16761e1e76516fd0056f1',
  'fa70901e2b2dc6ce183a2edbd7029043',
  '74bd6ad9c3e8e169f54b1c834be29f87',
  'cfabaa7674d235fac0ab047ee84cc9fe',
  '385a5f87bb2c3626383510cfe0cec40e',
  '304906670d242600a6ed0492aff48b04',
  'f2b4e1a421ef88b140d070678f8ac74d',
  '19fe008942eeac5c670318469c18418d',
  '636c24c365a4cef97a0ff0ec7b7a8b0f',
  'c86a43de84c555d382ff943c8e6a0e11',
  'e1add6f5e54afc143e7a970457abf9c6',
  '238707f5c5e661a75fe98087ceaa2e14',
  '15229b14e01e79a512c85f539688b7f2',
  '378079e46ffafbc62e10ca0b18c8d38e',
  '86bea9d3a8858c9e6266b27e53888cfe',
  '314165713be2daf624a653f5dc4f08b7',
  '5aefed03e1c9533b53505cf59ca8711d',
  'a516a61d645e2d8c1b3e38f60e979270',
  '208034dcea5b1e8403252f024d1e2eb9',
  '70e8c2fc55b5927b6c903acebbcaf177',
  '6df6e08bf308ebfc79d720bd6d05165a',
  'ce6d41cad30f27dbdc0186f2894ab822',
  '38ca1ce2558e7913cf7e5866a9e82d23',
  'f819c2234275925c3ce9060b2f89f8c2',
  'c7d6113c5af5d6d81a41dc6609bdab0c',
  '376e19893d786ad045372f0b46d14eb6',
  '23cb7bbc86d581c1d2e1278cb9852b14',
  '9b289b03adb10420d6009c447eb390fe',
  '1757705cdcda40c27a6a13437ad5a8e4',
  'b6f60dc4bf0665ef0efbee32e186c635',
  '777a7c15b7795bf1db4d495653b878f4',
  'aabeb185feec5463c5b416555304fa93',
  'ced967249eaf7905b1eb0b213ed0c8a4',
  '3d426948eca2134ebd033976a0eb0ea3',
  '5bdc69519d50c50ba080706e9e794aef',
  '8d0ce470b4a2f1ccdf57f7e8071a6753',
  '6ff1251ea71980763bbe0770f2e38376',
  'ba428e1ca93ab998583f303e55f1a6ed',
  '4d1a11d51a1182b3b75035302d59cdbe',
  'a2d65b9c86c5d89be42678142bfb3292',
  'db532b526e5fa17e5f308328ae62644b',
  '76396dea1db919c24d6d06c8b56dfbee',
  '523be74adcc74ef737c0a26c63e80312',
  '9fbca31169a1098878a86d09a8d982b9',
  '8c7e4ee083d36962fe119a73b567a40f',
  'c7a17669b7a67ac03a6dfdb7732c0835',
  '330440532a86b9803b20834c5964f5c7',
  '08bd565750180e5cb3b75ef827aefe83',
  '79fb30db520e5f7d37eaa2b781152722',
  '575895c6c6264d31e101de7f559dd08f',
  'c1c6f9d1036e9bbb11ab2d169c8bf8f2',
  '1d799e9364679512d4cdc137be71dd26',
  '941ad7b1a660e00c875cb1e53bcd4853',
  'cc15b6f948326d80c6cbb8342b6c7e02',
  '4d0b47bf037de9bb9ae23097a88a434e',
  '800a2cd5b3283512eeaca4e414ffc199',
  'b6fbecab1ff809a626515c59205e16b2',
  '8fba94bbb15827fe84fc4b70a408b0d1',
  'c1b368ec3e9853111f7270cc5df94e48',
  'a58a2d1afff51f18a88fb7a811e80f89',
  '9c751895424b9e2b281ac5da132a796f',
  '62ba74b147a49724ed3b374b40946cc0',
  'e506bd9b242d31ef26a609be9795fdf7',
  '83d3b7ed03d6d82d413a266416b39cf7',
  '36b4f0b53d71da24268616af1e794f38',
  '5014aa5f5cbd964228a78bddcbb12108',
  '73eb0c526483fc95e8c87c8c0e0e3b51',
  '5ad700987ecaf74c3e9480cbd04ba087',
  '90d588f72903031bf0ed6fe3b938db89',
  '3a8b90ac733edd0f9a38ee8f7feb09af',
  'b783e90d27632ee5047c7920c2df46db',
  'c907ac3669f9ace03fcdd1379407ad65',
  '40fdcbedba9f728c026764ec8c202b8c',
  'fb55eb15225650aa406a20689ff8c9f3',
  'd41c79632574837b87734a8535fe714a',
  '375629cfa377ad93ec46cad227c8169a',
  'e8a2e64125d9f206bce1d0113a9646a6',
  'd2dca1b2c63c5b400be6f8b9456e6101',
  '2d6562602b177481c6e4600d6728dba1',
  'fbb21c2b711d61e805a0a1bc0f15435a',
  '5015e9ae4c455108a3a4723810c0134c',
  'e64758863d54c98c4614a3752a9a5d67',
  '4e579975e826b9ad8fd14f3e5244bc32',
  'e353adc1f8db6bf095014c9f60ee9e90',
  '6fd25bb023fb3f2580f143311fa6fd50',
  '1d43465ade0497e226f601e4234dbbf5',
  'ce9b501cb00dbeb7562fa76336f52e44',
  '033f1f57f415191cd336ec0e2ab998e4',
  'bb400f706b9a34f77f62e09a9c2f7158',
  '03a13e94b574c134244104213c51ccd8',
  '7e568bef744428505b8c766d0618c935',
  '9235d7202e8e8f80b3ce67829ef16cff',
  'b9172570cd50dc4d3cf45d556963d138',
  '54e820daf393f289fd9c29ecc5bd6a8e',
  '9e229885058e39c7fa53b88a64061687',
  '693854ca4da8506f3ad558d6131e85c6',
  '205836eacba86d775838a6ac0ead39c0',
  'e044539cdd389abebcea3b9aa052b51f',
  '44940612469adba434c1d3429ab91d92',
  '0ee4ce51fca47b854ee22827a7366dd5',
  '38de64ebde2c1f63166edf80061c6bd0',
  'eee2493aba2d048bc9147bb0cabe7aa1',
  'b4641d6231fa5a31a7aef35ad545ad72',
  'c822dc42754eeac700bd97fc963b76c3',
  '7a714de9c6bbd13c791d6fe4ca0965eb',
  '0c95b5cbb27e27b82c454bc8f2287b3e',
  'bea5072923bad99bb84e9d872f5b2d89',
  'c54641941de45c8fb373007652c3f14e',
  '76e4c76864dba78be104827140ed296f',
  '5ffc8bf81257ea8e1c74778c249e5741',
  '4809f43a1f9ab6cc117f74cfa128b1f9',
  '2fa049b822b37d8758310728b42828e9',
  '1df68c03da4ada24391893ceaf4d5bf3',
  'c254b9198602bd0d66ef814f505f669b',
  '5bdaa9308cb208e5f9c3dc1340e26562',
  'b0614b2607f266d86db60aa301fbc6e3',
  '4ff4c7aaeeb6c2dae9de3e9ccf2520e8',
  '3f1ab204cb596b1c76781f76eb85c46f',
  '6c26d4c7913d5f0bc0aefd20fdb8afed',
  'a0e0d0580b1bc5e4f6434a6cadd5b93b',
  '8ce2799f4352c4ae0dcdc3ff0d563529',
  'aa5f139910f18434aabb4e2276c9c387',
  '5133f9cdb98f58591a54072df1a2b2f9',
  'af6a4f12a789d67d14091d3ede9debda',
  '238a946fa75adf1b46da3e4010ce387c',
  '8ec152a4515da2cb4c710ef9174e0f30',
  '1cc60f74e6ed8d7c403d41de9d4f2266',
  'a7e450116174c9d2de621f1f3193b5bb',
  'bbae059b81072256d767271215bef5a3',
  '56434c2884664602897c73a0cfbda27d',
  'f2eca24b5410d3b83b3da7888e6dbfbd',
  '6fa19f8ee62473738d76c5745266b15f',
  'f203e8186898c36e608e14fd95c9e52e',
  'b3a805c023cebc3a0aab529a14ae145a',
  '0423516ea0c31f02a1bc0eb36dcaef65',
  'fa2a207282b33010115b3dfbf6b0acb9',
  '7afb757e45331a14798b61aec1570e98',
  '3ee12d47db24f7df932efb878ad39468',
  '64240874f5c0e85bbd8edc9f49963d23',
  '6079535c9b699391dea8731f47e98507',
  '4e116abe6cc1e9a9efb0cb80cb2e4e8d',
  '5b6dd7ad4ba2850088999ef55e117e5a',
  'fb9ff584f24a6825f6eac5b34fb46db3',
  'c98d92b132725a987fd556caea0b3fdf',
  '0788479f8a01827ff3aa4b53d2c50340',
  '0582cd308a79d0224102605d06f2f67f',
  '109fb3762566be93890a9692add51879',
  '93f6c1c56bac8b6f48bf984db5235e46',
  '5627467bd0f8beba69170198b2684181',
  '672f85a74e8ca19204390966a1e13493',
  '7dd6c9ac564aa2c423731cf0793b0a72',
  '8c6d5f361d7233ba4d3871b8631187ec',
  'cbbc518ba0b592efd112d2746f32cd87',
  '59438a6151ca235df53fb5ff93ef41bd',
  '8b0c9ba47ba773f6656db2abab686ca4',
  '14bda2da4ec18a5c7ee43445625f17fe',
  '19f56a9af44c4567d482308e3533ed57',
  '8de37e31a127627170e38a400f4fcdc9',
  '92d12fe3248914eb29f4261daea4db1d',
  'b65c4230101295abe460ee3d3148b01d',
  '98bc57b580829a3ae3ab416435f6be1d',
  'bf5b15b60cd28888ed070f6bfbc21e9b',
  'b15091fc3f54b04d11406da46f6230cf',
  '3ee388fa5dd3a0a92762f9ae96da889a',
  '958176d42ce5c167257f99c42121a900',
  'a9434a53d0318c6a68df3088d77e4539',
  'c1a2a7a27df03dc3311b00aab549d1d4',
  'bd2d7de4b2bd348faa89683064b45ec0',
  '4138555595ab877558adc961ec9efdae',
  'ea2bb58bc8026cc1081bf18236425e9a',
  '63bde0da1c8819ab36fbb9e751eb33e5',
  'c01cd42e782145ab83c9fe8337f4ac8b',
  '1edb3b83d6fd6d4ef2b4ffcf9362da67',
  'd539807463818eacccfef8cc0c5f7e06',
  '64af3f068d0871ac61c0b6719bb5b53a',
  '9afbbd32364818c01cb70cc0664c7676',
  '1ac0bc7266b4e40127a707402fdecaf7',
  'd3a289eb4b96ee8f9595b720a1eb3669',
  'b10c3f432b367e22efe0c952fa78e3c8',
  '51bf7f543907b1d931667aaeff25fc3c',
  '55b2bd6171c37cc1f1246a86d15869fe',
  'b2ad3050a0b2b6cb5b09592748b80fd9',
  '1cf8b71f289163f095b0a3c82e458d43',
  '16311e55c1b091a6806d12568968a9d7',
  '694a707453d63f462b7e682173fa9a86',
  'bbf96ff094437f18966469d09bdd356a',
  'b44e26a811bc49a71c10248cd03778da',
  'aa980a4a8f4445335b4599c0493ed543',
  'c1a1b65bd04994300dfd39e3c435a600',
  '87e431c83a28cbe06e93d52c480c4add',
  '7f622fa068b9400dd9ba714549f68514',
  '12888910152e99325f2b404ed302ff86',
  '59c15fae2bff927f1821393ea44a5fe4',
  '6d72a9814588a38d00a546e4b80ee915',
  'a2dbb88271bac0dbf06b331253cb1800',
  '8608366f956627b27a6073b44a4952d7',
  'c111ace90de9ad6decf1ae2c7ffb01ce',
  '765f361bc22cce33dfd767cbb3f09b11',
  '25b221b4e9a915eb6a07db184e4e084f',
  'fe89714c11c875aa7141542f6de23360',
  '3e6a63232d91b330e878cec55aa9109f',
  '940f9e79f1e47f01578838343a400af7',
  'd066ea191b1fbe3d585678bff11c372f',
  '1bd0705ebc537ed18300821a4d715544',
  'd5888532d6961b467f4c5efc325c20ef',
  '7b9d0f0c959fc91e90dc4b5ca0598c15',
  '21cca97f72621aa6e8558d2c2625cfef',
  '9c13d2087a592ea09f92f471621e968c',
  '29d5e3844d7e11ffa008884dc0e62677',
  '9f38bc8009946b4e40f3ab91b2d617bf',
  'cebf3c86fd358b5ee22c9e582d911722',
  'b465f645e1129301d54f36156e25b9dd',
  '9087ce765dd750ff60e270c41cdc6248',
  'e60bce21754a92e9c32811cec3536a32',
  '10bd86f9cd3d412341ee32545da6bc9e',
  '79944c95669e025cb3b94c0922f2660f',
  'e442393ff32fd0c8ac8e6d399fed081c',
  'a708216e85305148e7e655acad889651',
  '76c920b19bbb3782898576ac4c34423f',
  'ed459830512e34075e99e276060ebf48',
  'ec0326661f8aafbf0348162029b50b60',
  '1dae703ac4859484d57da726070c3811',
  '20e0010c01456f706fb838013ec4f087',
  'a639ee5b6657832acc6accba82782f24',
  'd67cf0e2904af6a3183e16857bbe0658',
  'b3e139ef1d7c1267a6ef95e0f220ed05',
  '91c16b8d06561fba242850532a05dd34',
  '4cd79761ba4383a17577a6fc75eb3ed2',
  '884fece8761d18383064ad231954c691',
  '56a9a71f513f968e2f4d6ed9cafd1c67',
  '550aa19706f0a43bc1ff219def3f99c6',
  '47b212ca75c4b096bd2fd895c44d5b7a',
  'b5552d65459e8f376bf15e07afb79bfa',
  '95577f1e401ddd3813ee3a3dcb7c4f83',
  '3ff4619e55c2a84ff11c9716435f35c7',
  '1fc466acdbab70560ab3ad561afa0925',
  '4a9a7ef872c050a6e108f94259b1241b',
  'f913a6be27ab24188879f464f32139e7',
  '7b9d534345330e5c8b8e79872a83c3da',
  '4cb367b3b9bf5994530d7aea55a7d6e4',
  '6fdf3bec22d5c7d2fde74be1276b5950',
  '54f19a21957269e910af9b3b88788325',
  '1c2c369f8811cf98c6e832ce54475e50',
  '9a37719a5417047b13ec9da37e8a7ac7',
  '1a378a1a100144b6698da591d0db965d',
  '0cbc10cade5729569edb8341114b5e7b',
  'd0cc77e8711ae98aa8df16b0ee263432',
  'e2db20cd60b9cb157f3410a5e3cb2980',
  '8a2871187e6c63d43c35df78a14840c2',
  '1450ce2182305dbf566111f399292ff7',
  'af8879164df77267226eaf1e59a18333',
  '2f816c095a63eabee0863ed14bce1c3f',
  '140302809e25c43c7bedc98b26ca7de4',
  '407e111912f5beba8fe48cdcbc9d5dbe',
  'c63a6cf7616654b80e0dfd5f0a631c17',
  '1a814d622f7f8edcc03498a87bf48cbf',
  '309d09f85ae242aaf4ea2b1e636c7eda',
  '2d8af51b0c4325ddb25edae7f9647fc8',
  '9600e2b3684bef7e0c35b46414f9e4f7',
  '699891125a9827cbf4de4c243fe554a2',
  'fef5dc47b6420b9d50730cf42bae1825',
  '2451217c13bf844b6c9b7f8117d0241c',
  'eb6121ced9fd18234d3ea63763ce4e88',
  'a5e24b8f9f740f3e87a920e3c49971c8',
  '6288539bb5dad275ec51f6bf80e86a25',
  '0fc3fbfea71810c2d9e5753e3d022f0f',
  'e58057ca54e07ee921b24ab5bc25724e',
  '2492477c3f5832ac4531d62f1d5a3adc',
  '035b5e7e36b019d87227512933a5399a',
  'c910c0c88f4a012379769e685a18a2e9',
  'd336e1b7b7d2838b9cf717582615ad8f',
  'f9ed35855b036fb72f3c7d37e54fe7c7',
  'f1284ce39cad8ba496ea5c83b587a86d',
  'a28486b9aac89e169b0fd84c066088ba',
  'd865945e8875828538b608947278163d',
  '282f17153f4375aded1f1f89f0ef4918',
  '03f130f61c60d806a788b56c5307270e',
  'c4de3d841164f8f345c7cd7ac6c07bab',
  'd208a895915ee72209b95f2f5c6e5ac8',
  '143e719e1659a3b9009c4e6284f1ec90',
  'a2b94d6f9a8fb328dab6a26c10656faf',
  '6e7a923e34c5cbcc4b3c3bf945c2921a',
  '521053a060965c298d45292cc1cab36f',
  'bdcc16af749218e6ab4da5d066e9ea76',
  '823a7f2e2c3976d9ccb20fb0f3e45b4c',
  'ad18874a9440adc3e1878d660b362b54',
  'c2ee1a6331ffe941ec2c568417e3fd94',
  '3818ee5fc915b7c968cfb62ec4d3736b',
  '74a2acd59cd30d4e4c302c20e0495ecc',
  '5639dd6e3e1fef018652d2f59dc6af93',
  'b7f8985af288d121253a76ad2d06467b',
  'e87693609fa4ad3caa9584adeb17a305',
  '5b9ad861ba8f649662f28fc6a028bc06',
  'b5874fb00adee64d8de5fe1531f51585',
  '342bb437ff3c050056e684fe5d881e08',
  'c45963cbf7d0ad52713fe7f1b5d0fef7',
  'f899155152aa241badf42ff18a34e8ca',
  '975d1a717448b2410eb7721528942a4f',
  '4fa40617f6f68018ee1f4f306fad79ad',
  'c6ed25d2b45759fdbd8666939b273e54',
  'c55869a15de871c129208706b25e1143',
  'ea477c6b46be2625f9fb9c2b40e1305d',
  'bb3b2d8bb7356aa2ef92e45365616fb2',
  '1665d336074d9b0dfa954010b0552ab2',
  'd614d93f644d6ac0073ea2f664bff79e',
  '2ea7e55a310d235ae92a3fe21f7b2b97',
  '16a58df09afd274b53eb1149a1561cba',
  'a099f2655b0248ab59cd52810dbef502',
  '0970683edd5b881baa57a354e4dd740f',
  '46d34341879e568bc9e18d22d0c6e648',
  'eb53dd659e7937a76d2e2218bc31ab21',
  '14164653f4b5d95dcae57d029b58ca2b',
  'b7acfae7ff44c4d838adea8645ae9b6c',
  '83ad1680b4fff6e6264c2731add44853',
  '65431eed6ab14e4a53b7dbc9dfae09c0',
  'a0cbcea5f109a4b9ae2296ff563ccb62',
  'fd8719e5e7b6ad3cc99e7bf105c9cead',
  '5ac5be0584dd9c2b05614c0df6f83cf4',
  '274e6e4cec07013afb9fabe73e435911',
  '65e66b071197dcc5e95cab26765d70b5',
  '946658a8e5e809d9607f31b089095a38',
  '573ade58def633e17fd2eb0bf78f3552',
  '95d114bf76c4fb278da3477ba57d5a7b',
  '0a0edb96268e6978d3ad8222be9c2ef6',
  '06e63fc2d2bd872801c6337f32f43106',
  '8089f8a193a35a37644898dc9cd7582b',
  '63c967b2e9eb9f507c6676096ec9a78c',
  '0c1cb0b6c17a9ba340e1b3d3dcfa0b55',
  'd7e60b982bf098b720a0c67e7c8e8983',
  '953bebb4fd8628adf355a6b140004869',
  'd36ee7dbd78d2a60b0585ddf9fc73afe',
  '5613c520235aae0fdcabc26270a78673',
  '73811ea2d245279c1316e9c418848c0b',
  'e8a5d169cb58561ca36d8df1e20d9c02',
  'b2faf4c7c141120da2d02e988ba3cf2e',
  '2db8db549ddae98a3104d3cc92f62158',
  'b14a1f0837ffb9ddbe6a4668794cbe4e',
  '70514032ae9ed044de4be91dd1f6d41c',
  'c81cd4c928add8b72780989c8a0496b4',
  'b029845e3aca679ca46c788e8625a4b7',
  '899576445b48f6fd50eeb2151cc15401',
  '5d5494b6b543e194ef0c993dd99724e0',
  '836028776782e41eb1541c65a7bd3cbc',
  '6613fb7ae2eb7901705798a43a1528c1',
  '448582d46341daaf8c3edb8c9d39a921',
  '3ec94adb903b9ee679e633d4bfef3811',
  '6030c5bec2b379b7392fa002f922b5ef',
  '268f1c24efa8d406f6164e8f406602b1',
  'b1cce1dc3bf5303abad0829b01fc1ad4',
  'a18270753c171dcdfff4693a89c03b71',
  'de8d7ef3ba0707be307cc2ea6203d31d',
  '387d8b3d0b52db3e6cb38217ea4c415f',
  '393ed2f09edc782623db53c98c0d919b',
  '2d2d325ccfe9af3053c992c3c27a8b83',
  '3cca6cb7d10a89b0bcc0a1e406651abb',
  '7fa6ac8c6951f99b56791efa995a22bc',
  '71bf25491fae491a214de79b10acfda1',
  'c8a7a41d5e8e6070c0c067105786d735',
  'ba7f877074515618705d8c82e7d43bd2',
  'e577bb08c1b437317d7d8447e75a3a4e',
  '8f609d650e0058bde5cddfdfe2d759f8',
  '150e3282449f626a032d52ffd6780f89',
  'c7c2430174ecbd05795413b58816c06f',
  '53ea6636c3d3bb5a43fd628a5d0c37c2',
  '2ddeaec6bd0b4ce7d9c6da702d00087d',
  'a39a920de7be7df600f44600a4ef240e',
  '7c188452152e6e3873c86d12de262f24',
  'cab82b69dd11bdec9993aa53610d5f00',
  '2b473bfcc6db272187063609a5253c66',
  '527e747c4ca5c2c5a582012eb43505b5',
  '8ee0dd3b9815c46520988a11c95e94f6',
  'd8bc55d87a47c8cd93b214396c84eac3',
  'c6436a0c49e85ee93c393685145e22d6',
  '4bfff9525cbf03919cba682e84a18cbc',
  '1e7fe1fda5c39385141fe60d9f99f6a6',
  'c21368bffeb889a1202fa5b565adc141',
  '09fbdcbe580a84713465f0a3d23a950e',
  'baab98c2b7a175afbd11a4bb9d81359f',
  'e27e63866d3ffb2a96042bbb3e36bd7b',
  '7e535afb680349a0c96152f0b79e42fb',
  'a8e9491343a32f29cdb9a5ace21fb364',
  'ef9c61c3a9a2fc32e09ebff2c11d39d9',
  'ac611103d84f717297e7fb33c5690b6c',
  '95e36fece758be636ceaeb87a1fdf8a3',
  '595415d99722b0445112c5cfc2130f29',
  '0dbd0832625da5c0c8d8fa0b3a0944da',
  'ca1ac46f27bd0047400f467ddf7af01c',
  '0dc419086bad925aaa320e20fd65c4f9',
  '34b36a55611ee8d24a1538f07d5fde2e',
  'be7fe61ad12e139ee9665f54d854b72e',
  '9311366cc7a715663cc497e47d52e178',
  'c1e47a99d4a5a281c68ea49273da1abb',
  '103529275f530da9c6c21f938e7b3f39',
  'b5ea18c5393b04cacc5e46bdff286ec3',
  'b064ba70aec1314207e2aecc220937ab',
  '355882b67c31059d5a0f43c73ddcd4a5',
  '8af71a8c35bb5fce75765668d284f555',
  '761af3e4c444c26772b91b47eb74ba27',
  'a111a110ec766b91bf44bedd942d4ffb',
  'cbbb4bef04b6a1b7cd2629cfc5798781',
  'f600e82e9d906b90d84230373763ad1b',
  '6079de8bfa8c89f65fa40748fa05cf9e',
  'cbc03f71b72c947bcbf29b0b1f9bbb0d',
  '76597fa88352b9448356a60225b2dd05',
  '37320b6b1073eaaf280b9b30c6f1da00',
  'cecee547985df21dd7a1b71a23d2bec5',
  'c4d3b53858e022dc41695f72a7dda477',
  'ea03e2cdd01a8d6ed5660b772e918ff6',
  'e7a3630e819fed690df004109beb468e',
  '2b528dc0413ccdd030980a70c7a0c793',
  '02f1b00380c95321a171c0b4b028b521',
  'f73361767945a3095909435cf8d390d3',
  '95040538b9e9a69f3197d7c727ce7118',
  '38c5616d61af42e9b6aa9df6214a1a11',
  '2b393e9da7177a57dd51b048c7f2cb15',
  'bc331602959a4e2689f9092b0efbcfdd',
  'c54f173e8fd4cc60380a259fef184727',
  '8f3d982817d066e204ce5057e85da8c2',
  'e9c8474a03a38bb1ccd00a6c26cb95c8',
  'a1094d42df41b959c391adaab24cf2ae',
  '8bb499d73ec9b09ed26e393587e57d0e',
  '5606e9a8567e09e3320752dcebeae9ad',
  '3e42dd34b1296a52d5aea22f0c97b7f5',
  '838df80d370d791e9c262f3728db3f32',
  '1689d63fe3439a6793cdcbe1ceab49dd',
  'e388b2d7bed36743b177812de9878ea1',
  '6ff7ab3fc1b1f240a5f1b95d3e65dd20',
  'cb529e346045115b538dacc8e9a6440b',
  '008cfe040d8d7980eab699e7162dcdf5',
  '7d50283c9fa09a0268057b692903bfdc',
  '21df9c271a2f9b3086277a2a9565b99f',
  '90d5184da203e8ae91d18c189ae3553a',
  '5c36d25b26c7fa6ac045879901c63f29',
  '51f1c2e5a562f674174107778d6ebc19',
  'fc684b5686ee728f467ea1644a03f94a',
  'd8d3f596915d9398e67f669d1a863c11',
  'a176f45541b47f4feb872c674c41a06f',
  '5bc45471777b0d853682172edfff1aad',
  '6d4f5fcbf9e444ec85959e6eb8229862',
  '2a362bd7e8f1124339905baad9a55e19',
  '915a56827f7879d07616f472cd91a7a6',
  'e7d5ce9156dacc9e6798c419c858080d',
  '86d4e51097881bba4947c60ae54816e9',
  '786e142675036229e3bc1f2e69c09ee3',
  'd5bdcd2a53870b35a0fa153f795112e8',
  'bc1ba63ed54f5c800498fbf16ce66afb',
  'de3dfbbc22da5ba6c4bba9b0118b9584',
  '184317259330d91d114f7addc56b7e5f',
  '8d2a9f8e1f67d447eb493a3c341a7d8b',
  'e1cd3a488a263e179df3e951eb2c05fa',
  'cd283eca2862f02aa373f25fa2d5b2e2',
  '8b28422e72ca5513b0f6e65409137c71',
  'c07d0cebb1f44637a0259ea3bb3195b8',
  '18ad939d06aaf33a5a4026d401e9d088',
  '228bbb6ae6b163256ef5ece60123d3e7',
  'd4ef23476638ec1a9c4b5c11527ff21a',
  '1a82766ad69555671078b7f2dde9e8ad',
  '7cc1a7b8b556f461a277859e1d951b65',
  '6a2028e14348fc08d641c304e03fcf39',
  'b9a08ffef5c027021b9fa1fbcc679801',
  'e8a12ba4a8eb8ba1e37f4a80fafbd5cb',
  '02eea5dff1007d3f50dc3919a1d44b04',
  'ca7d3b6c8e7e4f1e49c4435aba977f70',
  '16e01459565ca4685a76f80ccd41dd82',
  '419aad2566a889af8c0b6aa11c89ec0e',
  '744423525a7f396f2be7cc7a5abf8bba',
  '194b2c5aa03156714de222faed646604',
  'f6f4865799e55cace7a1e23387ce40b6',
  '6a48308af868eaef3a80d30d11b5c26b',
  '8e4a2463e0549954523bc7ceed06c9d1',
  '44bd43c1297b1a95f144abfbe6158891',
  '67a4d1b361b0d564d98e8f8755ab6a80',
  'e394743b1422c6a9c898d015275c73eb',
  'cccab97f708e3360ebec595fb2d7da05',
  'f8a2ce6f66312701c957e12631fbb7f1',
  '2b89127c7d13a188daa9329e23d327ad',
  'b8c628802b0371856e15c911d237607b',
  '6a946899437ca57fb53913e45d7a0065',
  '7f6bfc51aeb3bbc6e4493e97a4bf2d82',
  '5635759a30005373f66920746359f94e',
  'd3df2e780bc5be8a2362853d9ab12de6',
  '2e58cb6eb9fbd3b6bad29710fce4014a',
  '8dc0335224bcfe0218cc1edcc7068822',
  '8d9fd7308248af8b7bb37a122914efb9',
  '66e67fa1d6101f95340811f1bde92e19',
  'c535a93232748e0dbfdf70362305ff71',
  '88797ec181c3f9e306cb4373e950a573',
  '07c9140e1e57c4fa66b3478f4bf6bea5',
  '5afed1d270ec8a22faa62590685c4224',
  'c7955b68aa4c025a802e3d7f61a8546f',
  '8aa29bfa7a6db0c3fb21418d2a69b1f5',
  '3a9b3318cd0cb38ed01385bf6c9d4d4a',
  '8e3c5bfd2c99e5c38b5a92959e286832',
  '78d393efcda07f15d0a369849ee7b5b4',
  'de10e1f3adcf24ef762ce4fd0c303af7',
  '16ad831e7baecf8daad0b8274d771d69',
  '2b64c9536186d4b99ab384af526ad471',
  '1e7d7f64f13f73ecf71a8d264dc5a64a',
  'ed459016ea36b1fe089cf67cf6a986cd',
  '83407d7e23c3e679a9f136c1836dfb21',
  '0fdcfc988ebf287a5a61a7dbe08a3fe4',
  'a4a715a7be86cb0e5c268500accb4b15',
  '91fd8b42f08ef0f3d85856358ae124e8',
  '7d17d29f85ec9469c4a4fbc703daf086',
  'e7ca6d6ddeccaf462133724ecaa37ded',
  'ec3b2ad71e50fcfb854c8948a4f2e170',
  'a45a325b7abaa5623147043fa940c54a',
  'aca3f3125f9935b5ccd25b99bd1e456c',
  '64358e2206e0c1333b515d16bc48dbfc',
  '8c10162df1d2d705647c041b44fcd732',
  '3504b497ea0ccb619a1235e40d0d0818',
  '1bdef9e14ec1e9c64b36aeeecb106c33',
  '553fe89fa4d10410d7ef48145c877655',
  'f006dc7bbd6d527a57ce646bb581c584',
  'e8277be54b17558f037155a36dc5f7c3',
  'e366aa881e9834e4ac14164a174be9c9',
  '8a90ccb0a4cc91b942bc7dc0d8e73ec7',
  '2ec9bfdb242aee970a57bf01e03144e4',
  '0ee91cf5325b5f127fcbfac64d182fe5',
  'be90b3db729667f00ec14c069dcef2cb',
  '8f710c979bddf200334b5eb445c20fa2',
  '67abb98174f09c1a4a8dc8c41416ef19',
  '81aa8deb87711a933d11ad42754f41e2',
  '3ffe2bb65611d9b8f1d78fdcfa82b71b',
  '92eab3bbcb1fe145c7b9e3f02f6c0369',
  'b0f3754e1044feb797d9a2b2a08742b7',
  '609e116926daec213dd6406f776ec42c',
  '7888aa190970318d27996ceb7de2cc80',
  'f4aa4be08f11c411a55e18a241fa5aec',
  '9e1894d0dd3bdeb5d6c0716684250b5f',
  '368856487572c7c850f4bcb059491599',
  '71e59c89cef5d7d358b0fb82476c03e5',
  'b8807b7bf34f925f76297f977f343ad5',
  '2acb16abfdbd7ecc4d967692e34a0351',
  '6f0c8383b19fcbce6c2017bd5f91452b',
  '6438486f866dbfadad433e8b68e093dc',
  'c6648d399cf37a7c1285bf40a97a2125',
  '7e978c67a2fdbe2745aa3cda62620b13',
  '3438f2958a3750a6f7f2a992cfd5c775',
  '7509bcd00ab50556cf5fe11c4b828e4a',
  'cd228c7c37a83e04d507783c28e17eae',
  'ba30a635aab869ddd859dc52d1750827',
  '240ced1c1142d2c5688264de8815a558',
  '9d9d90adb893bd690b0753382aba3e9b',
  'e7ef2b8024b2d67ecf11ea64420fe6fe',
  'c7afc404571745bbb81db0628b51b7ee',
  '9a279020fc38d1a8d4214f583a39ec76',
  '108d668a47abe84981d00053b8286e60',
  '39af3b1eb50d5a8d84f5916916ccfff6',
  '20eb1184741a00c049e9111642fcc42b',
  '8f78425d85be6181e7f897f9257c610d',
  '6ce556aa832d57f40b7ae6623008ccab',
  '6989295da69110c9e32603785a606b6d',
  'bbe2bc1567ddc749da3c10a32ff3b331',
  '2067b9f7785e1b92648f72060a4cb593',
  'f65f83c8ccaba25bc262839fc0d7caa8',
  'f6595989099e90ecd82d6aaa90748a41',
  'cf3892e66c431d1ff6c4dba1b431a0bc',
  'eaff1db4c74aa1cd8f6d9716736754fa',
  'd976051124212c8972ce6a539b27e770',
  'd2b7be3a0f8d4d05f92022ad91023532',
  '3b12df1fb8388e985bd16516342ddbc0',
  '7d4581a9b5eb7eb371675fbdd4f082b6',
  '808607ddd93562a1608042167557f111',
  '40dbb0ef2c6859edffd4fd9e7233533e',
  'f0f2bca8c8eaf038ec40b599bc1ea6ae',
  'fabaab6b523b2620ca2546ed2a2ddcd8',
  'fa16d8880503b3874548be766d8eac47',
  '00f5b6881849bfb698568ef2a9e67f78',
  'aa02a950f7bab8c363bcc0e3e53e1f95',
  '7eddde3065fa6ecea3fe677e2cd36fb9',
  '361844f3d9741c6ff5d02e1432c11d96',
  '55dba92f9602f98d675a4335ed7a3f86',
  'd88342ccf33c204c2540000c52a2871a',
  'a02f9f49d53c0031b933635bf3a4c440',
  '9d7c0a81738a7b7838b724567d8af47d',
  '83acbe8b099acf303de94dbbf1224bb2',
  'e899bba0ced4eb00b374fa3cead84267',
  '59e5606af98f9d33b0da599839058b98',
  'c70c3c1294782a8a53cd592d0a543b11',
  'b8897484a9281e7bf507d59ec4a06c0f',
  'dcced92e64e8c11941244a363c70ebb5',
  'b67934e33cd778b73ef3ab44b2dd6663',
  'c8530c800db623d905174d2caacb134a',
  'd21e651e1a51687a6c9b503f14cdcdba',
  '630b199c3ebd95d666977d8bd03458ee',
  '1ace72df615f7eab8f83a19ea4350e73',
  '6ee4eadc81a4b16abaea4881a4612a84',
  'fe725568aefb4e448ae44219bf40fdf7',
  '94b4477aa5800cb014e6c60441595227',
  '0c5ce6dcb4aa63364bc1b0709d6f29c8',
  '54f5a2e7322e4b4be415423807b72aeb',
  '974e96682753a415f8324d982cecb1ee',
  '1f68de324c10e6c0e7c37e03f1efa06d',
  '393a9a6cf69c66d93e8ba525a14830fc',
  '35eed61d68e09a773e5fbdd9ceedd8a2',
  '0dbbbd683cab864c791288e9e18043df',
  'e983330b90870f605c3a79e6237b6206',
  'ee5cb6873024f3204ed139fbfb5071b9',
  'c26f17506380741f580339732d1fbfe3',
  '8331f92a5f66bf650ab8c96bb3f9560a',
  'ec32712d45664c4a9ddef8d0ae4c4d98',
  '903433ea62aa0a33131c87480bec9bb0',
  '2ddd480370e9987ec3b3ac4c5d1c0151',
  'bf4e4f9f31c4fdf7d9fd5682b218c358',
  'b407e933e92f32652e5b664d09224848',
  'b23d7372d61ea80836aab796e5c0294e',
  'eb8ac61366a6db12bcbb7fb5d8c10852',
  '54d2c480e4a8abf602620439e4d503a9',
  '606f55e1acc786e4113fa3f851bd1626',
  'ecf0c7f08e2d28525b5d64a40eed4c34',
  'f2c3649a9eed4fed9b3a73c55e558c76',
  'c89105613367226fdbd43570409208c6',
  '5328254c4fd66f7ef627f3fdb1387dbb',
  '471c2afe29ae10ebaed14286cbf9c581',
  'c3b7c713c59b7085750873c088a12cd5',
  'dd61416d47fe7834b64d03f8254c57d9',
  '9741e9d9807f14b5b403c405a0a10e35',
  '3729e529823df6552c377d23dc22f3fe',
  '2862b42cae204e4cdb4438abded153c9',
  '4c0e44ba31af27dd623cb7a7f611927e',
  '87ae630077757710ce8b5f156b957e67',
  '10622cd4a2ada49269de64f818a7e8d7',
  '026ddc9b01e97bded5a7955d7bf0c86a',
  'bf8c923164a0fa1bafdc455333a66a6f',
  'b9462d2f45718d42d4d4e544bfbb6607',
  '7388f9f25abf21708127ec0d78cefed1',
  '8a16a21b2267e776cf1b358180c9a590',
  '889a25ac767ce246f6297b0f70270cb7',
  'e196b7d7b5536271ffd7b5160a17d5f5',
  '651eff8282d7e3d739e8cdf578508489',
  '146baaa9eb8a93ca5bb121676aa0e018',
  'cc2642446d340f72e60c98e4a0c917bb',
  '065ba182091a6210cee16dbf260f4bc2',
  '0fc49ca99aae13f7739642173d844e08',
  '4d7c6e42dc806b99ee7db9f8a0cd94a3',
  'f3e2a4f62dc63ee5028ab7e0c8358f6d',
  '5419c2285a0709b33d45c9a95a1a52bb',
  '10f519fd70a9ae15c40d63cb91b87348',
  'e08be9fd07bd181a4d5ff2060ec24acf',
  '0aa33eaec4313f10017da638f905c448',
  '0ef1704d89a420064deb19822b76b95b',
  '713a5263148004d65464133c6b51a58f',
  '631b17cdf13f7a27960183be8a753eff',
  '640c6fa9172023dd9515c42c67ce2d04',
  '834cc88398c08d2600506ec9a391386a',
  '71dd374a71d8bf3d762c5995313810d2',
  'de81dcbecef9684416dd934e7e9c6827',
  '49d56147117db4530444fabd8b760490',
  '4574e8b5a6a97ebc59d9cabf6da75dbe',
  'b2393ff49a553fbae7753db2a9ba2188',
  'b709056dd0302a261eb233c70b211330',
  '61ab7f1f866cb9167e5f91bd9ccdb7ca',
  '4f389ea60b7ed0a83122550ab19a0390',
  '773644242b8805c66ee02956f6ddb1fe',
  'dd159a2ebe9087e8ca52f053e2fc2cdb',
  'c14d6330437d53b6a843fafd57db2c38',
  'b050a24994c07287dc40f6325fbb5d29',
  '1c02b15eab1a26d1caa2879dab554be1',
  '7112bc1a01e580edd0c3592832255037',
  '161bb7a30207b9cbbf7586f9303a6d45',
  'd3c3bd7c1a422f16b501313a88561c4d',
  '727af0602e8a0715c07e8473edacfe9e',
  'a9f03e456e397339a938c6161e50bef8',
  'fa24ee2d926983eeae1c877d4019b962',
  '6e0fb1c55f16a70f14497885fe4bac78',
  'cf3d3e3711dd7a7d9747f39fa0395404',
  '28292e9728d373d31d0696adf3701c95',
  '8911e6135071c4b231aef0c2e4b1240e',
  'dd60f6040e100aece6de77ec175a56e4',
  'c03dde5dd3b51b7aed6a70b3c51efc3c',
  '044a8f5c0c55d2631c96dba5a037c178',
  '64c081d372a7f82507df7e7967f84018',
  '5050296ae46988931db78e61becd8613',
  '7811bf24fee6998d280f1b14bb7269d2',
  '636aed54a2740bb2bf7daced026cfafa',
  '1494a4132b55089a98951de511017bae',
  'afef3a1a324431a6b7e942b3d7dc5653',
  '3979bcf4144b50037c3a74cda4b8c00c',
  'cdfb6ea2f8e6e0c2abc5fd5c5e9e1d30',
  '662211e79f45b3460016bf0a6df95a08',
  'b17e073bea07c5c8fd7148b73a882d25',
  '6670bcd6170e8879e8a7ca7bd39c3bd7',
  'ef443907666575be7b297d62ab20a85e',
  '4411c84b6ffee1028eb2e4548eab4ad8',
  'dd6fa8cf04c0c91ad7a262e56992b460',
  '8d7f4e97929fb738b3b5a1458b304810',
  '707c439b9ddc1c7a152fffbd14ac1d36',
  'c8dbbb5b5b0997fc8e1edc6783948b68',
  'b140c368ac59b98d6ef62faa7343e880',
  'd3542b48037c448e818999b2c7527c77',
  'c217f2bc679ff057381b43ebfb512fc5',
  '066205009b87c51d42d479190fb75dc7',
  'c0ba9027100a1171d89e017cfe73f5b6',
  '4acca5c68dff4fc7bb4bcf9b1e7ccf27',
  'e135b9176ffc3d4127ee8590653ac26d',
  '8baeb9f5589e7cb0dc83d62520e132f8',
  '3c674fd2917e531fa667a1e3784fd274',
  '674df3db27d1b827e878ec3ae57d15a0',
  '5a2ebf797fcff54d8201bac05af6f9ad',
  'ec141a92ddbeaae863bd502f85aca84c',
  '5d44136cde79a09b31647d027c987138',
  'd9bd5ec815882d6352eb3fe5cb3762ca',
  '98c8047b68314eef4d711bb2facffd66',
  'ad7acafae07c18e8d0f4da376cc60f4e',
  '53cb7e063feab7207273157f2025bd1e',
  'ddc4fd8880d1d5be1d410cf8b361b6a7',
  '51c0ad4900f24c982c6740bf86eadee7',
  '5ce1a839c90cca6d59d24e7db7060d18',
  '4c3ece046a5cd4a2dfe6fa99da3d9b8b',
  '6c730aad6184f25e4ffb01e518ebd458',
  '6ab3a6d9c0a0f20129fc2c10083c58bf',
  'ffc25160806069504c93655cfb515a77',
  'e71aa39cb42acca5d2a43dffa972cafa',
  '5563b4883ae242ef7f23b6d71653cdbd',
  '1fbf18416493104d4e0dbec930632e14',
  'eb09e815cfcf89afa7bbd1ffccd8ec86',
  '612d39a0668eba5ae58c0c6539b5f84b',
  '6e541da9d118d9c75bf200175e3d7644',
  '9c68ba14d4b01c452b11a6c7c7e28b1b',
  '2feba0b46e501a91cb49f541a9246f93',
  '5ea3f797f9556ac2ec6f62d6cbdbb1a9',
  '23c3ebe8f51aa1412617873add8f360b',
  '482a7fe031208714714ec607c93bb3aa',
  '46dc86289182d9dcbfb3f30ace11b591',
  '3b55d43564dd0533cf81b0eac57ef57f',
  '5c3e534d133d129cc556c45ffd0a163d',
  '6f5d41a78ac1cc38998f341ace26e9ac',
  '2164cc4b6175417a75ad5a1f951b9645',
  '40fedce966cd4fff8bd4a0fd90a502c6',
  '57676b670bcf733ac606e4c88fd642f6',
  'a7551cbe69e97bdf03ba99f5dc57e844',
  '88833f6e44483b28eb14e6e2d66fc0f2',
  '5c9524abd4fc62816bb6745f98168646',
  '3d0154d9a03a5886f6fcaa616e503790',
  '4bf4a28b22626c99e95fb778d75639b2',
  'af47b47b0c2e160e3c1e9056b0dfa5ae',
  'b5cab12f55d204f4587c7b8d23ae139c',
  '873251996f27b031fc1f244269407066',
  '0b3b9f371cecc09c4ea89653a7e31f37',
  'c454387f3792cf053c392baa4a5f8151',
  '1e99bef3077cad802083f8ea72486176',
  'f3b27c6a14960ba848c7a9657ae3ec3a',
  '7a3b47ae3b8181d4227aaf77d42e9870',
  '3d3694d8c75d8a5d3083c863117f4d88',
  'a03cd04f8f29b89cb3f4ababe800ab84',
  '29b59f85df778ccaecd408a4ec943bc4',
  'fd6ab0ed520f1553b4bed9ac16ef9248',
  '31582a267a1f8673a4738b0c9467867e',
  '16eb46854c629ada79c59edaf1b5b34e',
  '530ff68d7ea170e2a5db079861f18e09',
  '3784fe6a756ae9571c42996b22220847',
  'b78802f1bd7503a55a3d1dba2e1f71b7',
  '1d581a0a0e41db75be20de94d58d7e90',
  '533d4931b3434a035b55e11cb87b4363',
  '8785b7cee069bbcc9a54a3cdce4d7b4e',
  '09ebf84c772879ebf701a007fc0db932',
  '7138cd86a1373b83a857a977e085adcf',
  '5331aac0e2feaf0c2807ff1030c986e7',
  '1646c32c10dfb70328f1f1e6a5bf8411',
  '3983e5e42a558de9a87b2f764f218e12',
  'cd5db7cfee6abf3d9ec08e40e0850f53',
  '10aeb438b13d368387d2ca50ee68ae92',
  'b8c90df40d55d188463c8cc625e24c28',
  'b785cd9321005cabe598e572bd5953d9',
  '4a927f5039c66bd2dbee5838adf017e1',
  '5295a6f33bc24160fe9bf7791b0b5c35',
  'c833b7db1df347084852ddecc4937697',
  'c7116d57f235d72b5124439de3f25a45',
  '583a520f3315b294823f1b83a3e8bdd9',
  '8adb2ab2199c0cefd88a3b836f6b6b6e',
  'ee651c98d23f902cc061b9c25494a6bf',
  '2c91b527a4e055de802454e3a0a07d20',
  '5d49ccc4b046268786b9aef7d8d70fdc',
  'b988e841eb15c2be8fb83a1fecaef90c',
  'bde882503d6cb9338286ab63495dfd30',
  'c9383003aed5131c7f4b21d583d3bee5',
  '8bf8b32622aba19bbc8002e662ae2a08',
  '389413c828fae219cb8fbf9fe39b793d',
  '684982617ddca94a6b25790861a16fb5',
  'ea2852edf1d081cd7abb14b0d391b29a',
  '6a978c445e16fb557e7669c36256ab15',
  '11c305796673d0852ec4380475d4241a',
  '789b8b4422cc91a5a06e5f866a214a2d',
  '6fc149351a30444a8b7a27dabf1be87c',
  '4f6a257551916b15983c197bb36f7d95',
  'c9d887bcae63234701a61c47dc182ba1',
  'c0c5076d80ed8f40657adfff26944c1b',
  '116ea435fad571170f16ffc856fc1f87',
  'c270258fee9f0c42a5c2562206817395',
  '0845f4628a6b9bfc42c27d28c0aada61',
  '379c9558db2717a45a119642c1b17a9c',
  '9bf945b4de97a77e0c784758bc6cdda9',
  'bfff0e1b24774b0caf3e219e6b4ba650',
  '0e62acaba581eea96860c6abacf9ee66',
  '94aac388cd1d7df1dff8c4e17893790d',
  '41cfed1a93f2dac2c2e8b0750e39ce1e',
  '3c84d2619ad85a2be3cedb5920bbde76',
  'c18118540acbcdb7b7128773f4dfe3c5',
  '1002ef4abdaefdf755979c0d62b5c9fe',
  'ea68cc5b6c072367606639c7e57647b8',
  '66f8b81983e0b8436d62d7b5836fc4f4',
  '24e00b2a9ccddd4d102979c9c75b4f1c',
  '50d338bda253a0ee4b5f70a1a2dbb05c',
  '3bc593faa6e8778067cda4aa61800256',
  '7c9ed2b46658e9ec9f7ccb698ec5de03',
  'ff3cb3d916ea57de986e8884318d38a5',
  '9fdd86904347e16f46dccb0e04b89b1d',
  '28bd7868e66750e22630af5250143d08',
  'b05f77cc07c30f801c16adf3068cf4cb',
  '86561effc003817685f5b4cc616440e5',
  '2419faa38a53b5aa2ea5801cac50b1a3',
  '49044fad991085ec7c5a0f92c00f6440',
  '6671f003931cf97ed80410d7f2290083',
  'c4110ac261a602bcd7ca3b14400acb71',
  'cd933ca8453fb33ace9229b69ee10e79',
  'eae6aedb0b6e570c6e7f025017255bd9',
  '4b72c1ad256b6dee857c095c65c409ed',
  '6f55ecf6b1512667ea06f150e1dfd197',
  'f89c07674dde557a53cc35ceda67e974',
  'b72ad177b1014bccf7b55e1920b22f25',
  'dc05b463f2360e262f5fdff50a123df4',
  '443ee034b70e2fb473333229ac1a1578',
  'c4784e6e08df9120fb83921b4bb48613',
  'def1a2acaa196d41a18021c887321436',
  'd5ca132f6f27bcb8d9d73fc175561c5e',
  'b7fbf41332603ab472ee0cbbcfadf2ad',
  '18e48068fa3bcd3902ec681df65c3910',
  '6a056d35cccb328241bad8f8707439a3',
  '8a42f9c601656829017630e19dd584cc',
  'd473dae00c8065e5cef3f275d58d0501',
  '170d87874c0d889de83aa71e75651089',
  '8a6d7bb686e15ed41a2558ac668a4b14',
  '141c9bb93a4e3ead43b351d65472f62f',
  '6c2af8bd5236c6ad57f50a5bae0cffc6',
  'bda72032211b16f02a55a9f8b6ffc16a',
  'cf8d53fbaa343cf967266b3c735d7e0a',
  '078823ca827f1572a225c25c8eedd8e6',
  'f3bf297652cd97e9841f3345c20313af',
  '33e52fd0b3a3f7d2f744461d6b0350ac',
  '6830e4556afd8786140410ff34ff3bc1',
  'a6a331ec2f549af0d53d3e77dded5af0',
  '8f28fbf11144da77c4a7050929b9c0c8',
  '96a1f76ded18f030eb1408d9748485db',
  '54b451c63e1f1f920164928321d21f05',
  'f72af9dad94cfc498585d4da57962281',
  '4c9486233d2e73319066ed301a60bcb2',
  '3b5738eba9ad80117dcaf668baae570a',
  'ba3fd7a3636fe448a667f014aa97d261',
  '53990fc478a905ef27f46ff0d79ac7d1',
  '86a6907921f8a1f90ee64a90d5d02c95',
  '9346f6b68168afaae229465ed6aeb081',
  'bbd38deec09b4707e37182fb15c7407f',
  '0dc15463fa11c11689e8cc2d7c292394',
  '200cbb2fe7bc9807cc2603817d130fe3',
  '9a22b507a0197bc389cd94a65e02ff4c',
  'c79d8e1934cf7de1de60c44598af2815',
  'c1ae024e13ab77efaa810be4500e9cfc',
  'd49f08e33b6e5e38f2a4be0da51a7407',
  '6ab9a674dd8382a4bbc31a39a98a1ef5',
  '356dea0662d51511f669d635b4306be0',
  '298da79a45adf92a6e25fc1282154c24',
  'a67715d6e2fe0ee06ba760edb143f31a',
  '3ba69005c10dd0eee614f4331a7e7cd7',
  'ea68fc1e843ed345f6dc56f63799415e',
  '73e92ffe61a2ab1e5d535aaec5a79d60',
  '83f163a2fce1ad1f30b7aa5f3b29d24f',
  '16428bfe12d59727aa25e8a9ce501a2e',
  'bbb2c367747139ec138f11fca02a74b9',
  'a0dcccb299881693ec8e995ebb9efe42',
  '45b68c19836a9435409f6eb9d3d2bdb7',
  '7f6c4e471211c55fc9c1c3cf702b6770',
  '854aa8581f7c044050de8f4ab9e086b9',
  'ef46388ef67c8206f0af9873a376ec5a',
  'b928df883b136e9bb17578d126d237d2',
  '180ea3740ca9490282b902a5f53930aa',
  '6842ad6dafd3f5b1fac6f131d11be85b',
  'e5edff4ad2a1389d18574fcfa4b7c8ab',
  '790858aa4992fa366242064574677832',
  '4767d809b9a5834705dc4a6bb8be8c3b',
  'b3963c5cf99879a05da39b19fd455a9c',
  '1bf169d018fad3831f7b5aa57d6dacca',
  '3fffe9e9c172631f7d94fe0b7afa2606',
  'ee442055e8006c2d878fddc7f2cd5cff',
  'e6daf810d915f1c1f91a17c46a389cad',
  '5eb42dbdefdf44fc750133d66cc1c0bf',
  'f4228c72b9edee8c23a689438a6dd30f',
  '7fa06d09140e6d528aee7835c86e9975',
  '546496a607e745013a9f55bdfbbd7232',
  '05a7f77767d747e3400ffac6749659b2',
  'e69b6e28e3e301fe2fea6125fce22407',
  '26204f6f57db15edf6ec819ca23400b0',
  '6f68178159fe57e91d677942d86337d2',
  'e6695f6129e985952b660a98dd610894',
  '844cf742704ac411af81c47ce9054805',
  'b220722587e59b3efcb81ea812bdfc28',
  'e3ced25b7c8a84d73268103515a0e9c8',
  'e6845b9ebecfb4979b121d634152f475',
  '54d070af80d05d26405b85fcc21fe128',
  '1334fb7a68e47590e7c800e31aa0992c',
  '5e39a197405686cd485cea04461bfacb',
  '58487d8dec40e831f1c098b43d377997',
  'f3db4c626abbc31c911ae57d7489040e',
  'ecd391dd41e640b254da24f41732617d',
  '138069bbee2b6aad2f07bec35457bc81',
  'b46fa5ec036d34a74da8653636c4a263',
  'e56a27b3a01f151787c415950688375c',
  '20c52d3d2b864825f51e964f8c1c73e1',
  '37e1339a97f3e51d4939de8a5174c434',
  'e96827456b4fac60f9276acd39692d0c',
  '33a0e999f442a39c9a41a08fd6ec0676',
  'e33aeb687274835aad3c5f1d5a3d30bb',
  '4af1ff825ae07d06ee4f460ad4bf946b',
  '5a5537bb3a5cf596a6a44b9b8315d232',
  '5e725b12c6576337132859c1ba3632ec',
  '5408bae137429b6ceb5a3ef0e03b54ee',
  '3a4fe347d156b292e9a6d3556e1324ec',
  '26441f98abf27ea2170e2a7096b7d8d5',
  '496d22ecc8ad7d953a22f6e865681503',
  '3b7d055324fac613f2377dd07b383e4c',
  '48492e7053b6483c28bbc56257dbe9b9',
  '3003c79620e4a10d1a231b2df6d591e7',
  '65fa2b7bbefb681065d620aae1849e18',
  '3531d2b9ef0b6ac75663e01969e4a6ce',
  'f0945f6bf74e39cb0ba298515085f4ec',
  '5d7de70703d841ef104ea0cdedeb832d',
  '2dbcce56da4cd241118d75b88bab029a',
  '2643707acc9a11c50232bc2afb587711',
  '09b3e9ce51f611a5c60e1f5506098ec9',
  '1b95484f07586560956e1f4f434a080e',
  '8a1593445080377c78ea35a42e8f4ab3',
  '3ca3a4d7e28959433280314fe44bb20e',
  'dc070eaf7dbd999e1b44a6c8fdd8b475',
  '0fdcd47cba6c80c286aad3c5dbf7c2e9',
  '5580bb8138daf4fa04674cf795e63fa0',
  'ce6240cc47d7db1484794ea685f7af11',
  'fe5b884d30afce7ca5d5f785107336f0',
  '4ecc0e0658a307a6148b34155600a068',
  '9598291f2515444ca0247694555ff1d9',
  'd9b4ba7797c98d60d4b31845df5a2fee',
  '59c57d918b637fa32a8cf9ced179244a',
  '811557c4c77dc137ad137f943e33de7e',
  '6337c88422eebfa440517513be04e387',
  'a15f0dbe73dadb55d1cd788401bc57e2',
  '9a03b129e135b580c3329ce53a361a44',
  'e25966cc2a07e13bb1aecf2fea596d0c',
  '70f47f746a823acb62eff1004a56314c',
  '05508c78e94869910497b8cb36f1a41c',
  '1dc298fbf0a1520b5ea95d14a851b084',
  '68e8a4ffab145a3505ffe8c41578a9b2',
  'cb3516256a21da9e35d1df0f13f0a773',
  '8788216f1d4b063c3e2a5edadcc462a1',
  '65efa87d77c27903b7d6ddfe601460ef',
  'ec8704284d72a1f0ac90aa6c4b1d5986',
  'd19303e7c7dadc8438cd1993e6f4ff30',
  '8e3c7b798eed0d82d6673b808c6c1c30',
  '43b9c9329eb7b0e2f8773bdc432012da',
  'd132b4f5d42fbd9e7bbcb5789647d7b2',
  '9f24ce10fd30d238dfdd6cb9af779ee8',
  'af590c7a52c7b8127ca4a88a1993b168',
  '7a2838814c0d97313f6adb5768cb9f04',
  '621932e6ca154d78d235b5ae2b9819a3',
  '38a3a5fb3c80925fbbf2f79b0e4c2830',
  'a80584e080dcc6a5e9c3a5461d720a1b',
  '0070419487978a0638dc985b404f56de',
  '9b93813dbc45cb7be375b54877e34e45',
  '43651dd57399412121e1a79b90b1a836',
  'f60baf675c7e3d96a492d63eefa5b217',
  '334e5464ed91f236212e4e99e20a94a6',
  '591247e36426abe0be5c94b2d4a4118e',
  '298d44b6055decb7345c371acfcf4c75',
  '609ab527d86ea27d870bd5a81cf3248f',
  'b06b86b4254e1b4cb63c3b18e93250ab',
  'f439b96442b45205d375d44ba4954fb7',
  'c4f6f5de55639f7e4f97e240845c798a',
  '43122927e8a9fa4dca983f5b54ae9b23',
  '57d7045809433f9b43bde1f7ffbcd3e3',
  'e1fc1eaeb8fd080a2b170274246faaef',
  'ca75746066c93462b24d814e2ce6a16d',
  '51a49b44a23029addda3440473d02127',
  'cee6ab1343f0ae3e93ec9630367fe4fd',
  '735fadbee82865a7feb7c23838726859',
  '7a4dcd9c4be38ad6179d0d1447c3d145',
  'e5ec2a4aacd69ea78c4334b8dac8f464',
  '1590bf32c5f849fd752915e8b40307bc',
  '90b87ab9ba6683c37f0d8c2d27495099',
  '3405d1e654ae38ea6bb0cd253ee9eaa5',
  'b1e651c2f6d1e232a5370f31ef90bbaa',
  'b5aa25f6d3dab5d94fe6e409ff1df56e',
  'd73629b6e11263151828ad891ed74d1c',
  'e56e4ca0e8c1079ce10a96836397a77a',
  '8b85f29ac8045c7324a9afce20323074',
  '16482bb368e6915092547e590964e6c5',
  '6c9fcad84de5d11a59e00b190647f996',
  '158c00f5f7834996a0354d6185d1dab7',
  '0ee30288903cc7f851bb7a5d01f9b91a',
  '932c4bf1ea614398b75eb011582fa269',
  '2c99bf11aa344fa79cef20066b43efc4',
  'f2908851a7b96d8f32479bb7e907baf6',
  '456b9f1c507b9ff7a73364b6432ce006',
  'd37d9ea368614b48c6821c77fdf106d2',
  '032b5117a833eed6f7dc7ed00f36d0e1',
  '158c48bf96f89da7a1fff639d9d9c01f',
  '2ae0bb526ca10ad61c6f1ecce35b38da',
  'f8b2d9423cf8e6852f40b7132b35a4c5',
  '3f28c501f6f7f7b99777657ee45d14bc',
  '949fae58780611824d2e29e006fce16e',
  'a7290f27df78ecf7672f2274aa2657b5',
  'b351a2a7820e787fa1f5129d78e2c805',
  '0fecb89fa45e714ff5794a4d2598a55c',
  'd12f9fc2e344218508dac36587905bc9',
  'beab483bbda9e4a2f00bb1c7ff1e0a22',
  '679d93f00c0365b08f4d8ef10417ab41',
  '2eccc686f967cadeb092b082687a5568',
  'a03f29a6db251e6ac7afe3936970d3d5',
  'ea9d3cc659c607cd6c4529b68845bc49',
  '56976e8aee02966db967b73a1ac6661e',
  'af3b3e8b55922240270dc0328f515f22',
  '5b7f668fcc7a946aa3b07a60bb234bbb',
  '20477b1e1c4afb0310c128ab3c9f8843',
  'c2fe1f884b4088dd47de51c4e09ad999',
  '2609c9149b87b7ebf0c95fedfbd652a9',
  'c84442b7bea8b454e84bcb4e04da172e',
  '00df0c932115ce2c3c7aba964275c85f',
  'efa56aece9aad8850883d398cf476680',
  '5abcac27bbb76724aa3c185b2cfe5344',
  '1ebb638c6bff974251135173cbef6e6f',
  '1eb2b0763fd8d37bbb57ec57ea1917ef',
  'a93086ee2f5e242d04fe46a582bbb3dd',
  'f2d2c6197e2ef28d3caa0ad9c7b4a51f',
  'c4174fc262156a4475f3370c0aec03d6',
  '8ae455ad79acaa5f2259d312e2e22dbe',
  '0e135470c3af9e08305d4c2e688fbbe4',
  '3bbec1e840da023e9308887ca7d25575',
  '581df96c48b44bc731f0d621da50e87f',
  'ebd50ef26239582b987e872f1c7b8e79',
  '76248497f252ab9961a732628860a010',
  '0fdba4a945b2ecca2573d0e571a5be8e',
  '5e33877fcdceeb8215bd8fcfc573ef93',
  '52f9dad2d3c180e4e0899f9e6ae97921',
  'c4552fe72567e9a6a64d9e78bbcf8599',
  'd4e9e8efac9cf9bb367a3e2eb2048e8a',
  '4e5e2d3fb9dc2957e1af61c2d7ceb2bc',
  '9bd8621b0b90bdb87f7cfa317a3c9c2b',
  '074805bd34d1781f9a3f1a008066552b',
  'b92cac1ea3a46a73d1c77859cc083384',
  'db27b9f4885bd0f83225a86a91465ed6',
  '4842a53fc2b9ccff27c633f8feefe7d7',
  '367c0539cd9ca58bbd9bd73539f74f54',
  '789b49b77df5840450b291ac99330237',
  '2b625c643f8a9858f6070276c807961e',
  'c9d83d6f6ba031058d3b7742d83f571d',
  'a7f973c11193b3e6b4c214c90e50a559',
  'f4332a89c3c89dad0fdb0084116c6442',
  '8010f7cf4783a8d10b8f57da558f94a9',
  '560fce88bd327a19725ab12cf1ea438b',
  '53b91549708b4a93e48fc4dc078cc544',
  'f8651b08c450779167f8fc15d1a86efb',
  'bc3041de6fbf6264af389e656fb8ed05',
  '17d4626ef76d65b9cfecdea2639f27ad',
  'dda9620d6b51c4a8980f4dc598bad336',
  '0d211e558adddec6413b1dc14f5a0444',
  'c8e40905ae3777fd6a590cc587597361',
  'd95ac6924d867f1d8bbfb78366e3d580',
  '193f3e0b80221c0bf1a2de609a480bf6',
  '2ec62b057f35ee3cee8c31e0c16087ce',
  '2b5e303e2582f12ef89a2e4c929c62fe',
  'ec804439e1a4b5283842d25d40755e21',
  '30234144ca4de53357bdb5c025658140',
  'e0f609c940595e252ea0e429fc9012ef',
  '460aa8b36a61c7b3108aca9e298612a7',
  '6aa3a019de8b776fc2224c12a8bb3b0f',
  '765111956fa0fef7272c5efeb2fa48b6',
  '8c4595892480514fd23bcaa8b911102a',
  '383788e86beb86b15546a3fbf6c8b0ce',
  '87d8eb67dc2dee8ebe51650c2849fc7a',
  '178ddcb38b91a21ea6192c1b89027b62',
  'c7987e7e012849893554ce243433225c',
  '4c318b2a3806f66b35002e69134b9150',
  'f01c095a9bd8b1b67d696edf32efd6ac',
  '14b2f0531537b3461239447d67f1e7d2',
  'd08eba96c6274383cca95d0ef1e68607',
  '1804a2e192ccc2ecb908f62db14d071b',
  'fc91830580887a12f553b4db355e5f96',
  'ef9d80a3d65e448819aa24e121f68daa',
  '8c6385d22d1d4dfb3f21fa0e23a8682c',
  '3a81c4335920e404a399b523f4f50789',
  '30fcd05306bb08325cacb046b89f66af',
  'f4033e6e0096d0c511281bd00029bb8d',
  'a9c11b2f84cb0196e84a539f18926504',
  '73b5d0eb6179a667f45fabe35f7ac287',
  '42e1761290c94628f2fc2dcd790c1ad4',
  'd59f5664687a5ffd46d94cfaf27364be',
  'ce08eb5b01a9b879893095b43e1f822f',
  'b60c1cbc11931bf0658b4cb1734c1692',
  '1b79f646283008b797090eb7bfff6641',
  'e088ca11a8cd45c21e0be860ba119354',
  '82448760e1f088fa77f794a6fcfe02e6',
  'd1115d50b9fb9ec4caa48c63c5ff2001',
  '5e5606b6e9b13b93af66b2a16a7f251b',
  'f76d523dd04f39e012fa46bfddebc86d',
  '18170b4d85615e51ba9321023f411d23',
  '11ce72f7a6300b4fa8fc05c532df1475',
  '0261989b48cb19b8b234b5d7df1f1e96',
  '9478a64a36ef8ecc0b1364f9faa0d415',
  '63b84584c3acd333c3a31143f4cfd58c',
  '997bf8f20197ed8f5144bdceb895afd5',
  'f3aa19daa53d025a3428279d7e562c65',
  'a2d7e48d6ec73f30a6ddaa9a42bbad82',
  '5c499fac89eb8aa5005a82d3a1d71cba',
  'bc092fa9fe4c8764d454576770924175',
  'e0f6ca4f0467b3f1ca029dc015be8ba3',
  'cf173262348dfe46e1672645f74f13ca',
  '4cff1714bad3c1bd9718c47bb57bf9d0',
  '9a0fc1a63c583155421e29f0403bf60f',
  '3d284410967573b9ec620ee4397f63e8',
  '0c97bc543809ac73d1106990008c7c03',
  '04d9def1d181fd3acf3b2dc0850b541f',
  'bad317c31c3ff1cc290a937653d56d5a',
  '792fef25636918472a173d12cf9db7be',
  'dbfbe47b92a985478ed8d49649d9fd0b',
  'c90fa0ae0c76288609b0c77107d2e32b',
  'a7d0a9b7b1890ec80529060d1ce4a0ce',
  '0f33606cd378e61ef4f21c04e1545b5a',
  '31124d30d11570bd6c37bfdfb60e7e22',
  '4deec8335c3f56f57565b1c8a665e0d4',
  '8c68a8442e4856fed70e4ac99050478b',
  '56d766096bfe45f82198a110d48471ce',
  'be65f3c4b0c991e7367c650fefaf000e',
  'e753a96bedd156ff3c8ab64bea22f5a7',
  'c7be9755a49d754b63c730182b02df1d',
  'c9ef67441a626b9add89db5954c3af27',
  'a306898bcec9124eb13127f32d9c0997',
  '71145489da936c43685c9b5d6da62872',
  '42c6ead7ed3c87ea13486f683b336634',
  'ff6f5236f008d16e27bf49eebb8b3f63',
  'e1f1eb0e34f4bac0293e30eaeaabe03d',
  '8f995d5f2cec3f63de7594e6945ad57d',
  '80807abf6caa76a563325a49b0889287',
  '5c5271bf9327599a0b1ab8ac098aca4b',
  'f9fe804d5fd458ead12530698e06babf',
  '5cad19307d789a31b947ea0737bcd0f8',
  'd03822ae0b5e8808101c8559bd49fc20',
  'bf969f120e43737395d2810df06a0dab',
  '209f88faa622d085f03abe616fba24c8',
  '8f104ce27c84f8fa84982051d30c1f7f',
  '57f0cde134ad93790e98dfc55c920ab7',
  'fc3b18eb04eed751e9e99d21043ede13',
  '47f63fca900008452c4ef27527bd6461',
  'fbed87ea4cc3783abf9415a4b7ba91c7',
  'b0a184ac2bb5f686679ee246983eaff8',
  '2a277fcc91ad425c426d10222b448a58',
  '90b65edd4baeb415885b1753ebda086a',
  '37785a6c62e8bbb65ef0dd49439d1356',
  'ac15fe990b979e2cdac7c8f42aa6911b',
  '3c2ec95ec9e4680cc6752617e00ff581',
  'abd3a33b7b7af43e5b49ac9a02b8db00',
  '7d4be2704c02a4579566e46d81964850',
  '4732ab069053d4096f1398264c87c925',
  'a721e218a21584c5688c59ab2633b18f',
  'f0f0e427f622ea75e3cf7db55e9a77e8',
  'b84ea94cb5f0ffc4789402d64a30c8dc',
  '5ee38b5f3e6c5a853c34599ff3b77f41',
  'd7936597d9b1cadb3c960b13ac7d7f32',
  '18da9a84207440dc5dedc10fae0474f7',
  'a073585331c8ee2030b04e636db9a991',
  'a1e3f9aa61d8a25672dd9125010a04ba',
  'b559858341b670c83dc20de42c5190b6',
  'e2ee03ad4fa195c7a006c13fb8d61434',
  '021bc743ab3e81168fc6eb3bb33368ac',
  '42e7b5c31253145ea34ca642314b6a88',
  '2dbb8fd36fd211c137a97f59b177f8bb',
  '3938be4181ffe88c1581faa1e07f76db',
  'd9cd9df3d93b89e115ac0010f86700a4',
  '105697976868ef4ebd114cb61696dd3c',
  '7151c86349597e01da37c46807b6215f',
  '26e4184ec9b5bdf979a7a8edbfa25719',
  '854d1bb02714ca3629fddb7bcf214ab7',
  '08da4acfaa88974cd54c4547ec4f2211',
  '8bd31087c72151539517da0c0cade8ee',
  '895894ad542d017d654a9787a53a5408',
  'aec1568bbfbc834645759f32a8bc0ea0',
  '34e7c8a59c14ecf926e9606f61d609b0',
  '74580bc8c55d8dae7f0c81f622132710',
  'd6a54e5b8fb3f50213627ae83dd763ee',
  '845c65f6a84ef7ee5849d6b5024fb882',
  '7ebc5e97b05c101ba14b0df5daf7c03a',
  'bdac4803a97397df13aee69168b04007',
  'a25faa1631db57b51a8703f33f9662da',
  '7af527cc31e4808884237cb224ce1ea6',
  'e50719a56e5784a61ac1b15dd7d8742a',
  'b73eff6ad8d67596d3865f1e1c836387',
  '91d8dc8735f57221e5b413023520c8f7',
  '87801cf908bcc52afffbc16654d1eb30',
  '074d9bfbb5150df88043ab2ef7e9a200',
  '3c8ecb79969363c267d2b9ae9a43bae9',
  '0daa5e875ea24b42e94c4df3290031ee',
  'acd1ae56dc6b23944cc2657a890e7de6',
  'f380ec2e6154545490093e5f82c58635',
  '5e5b00cd4213726fa9c51293e2f8a9ed',
  '284b85c4daa405f2e311ad392943ba3f',
  'ba4c9ae0577142be3df7ca9c8b75bb46',
  '6d173403b653e1e0d5dd472025cdf57a',
  'b4c4fad2bd7287d5b962eca6f7219b0b',
  'd1c8181ca633ad1655a615eb6ee17d79',
  'd362c91594f6e312c0280bb793d6a8c6',
  'd9eb372d26cf782e00e89b46f191cd0e',
  '1f12e76ad03f9aa19e30f355e2096303',
  'a3f44b49a5bc01acce609a3a29094c9b',
  'e65a3603f11cbedc3f5350b101460486',
  'fbed1c4337c6e51ebe4f4863f123c4cd',
  '65fd8171d26602680abccbb2427df9c8',
  'b8219e61bbcd9329279293a24f408838',
  'b742f45de3662895c7f33868c20d7a7b',
  '7503b5b3c41720ff7a7caf5a6e34ff70',
  '4ede1b09c3060f13cb34ec9e7ba8969c',
  'd27f109687b3a73aea86714ea6242a25',
  '81fddcf8eef13b4bb3e82c71370f0320',
  'e06ee9840300a49e63f1b2981c327cc6',
  '2bc0e95da0af3e7ae7d5f0cc3f06928a',
  '9b3fb0f3e4f703448c4b108a5b0ff990',
  'c664b6117aadce631fed8e566a0e28da',
  '5968bba75580a6fb106e69e3439ff888',
  '2e8b6ab6e707cf052a04839e5cc1b7b7',
  '5740a915a71b620ff666cc7b0ff48cc9',
  'ec99551b57096b810e4da2a92694fec9',
  'c77a45482308d8ad6440c71e28ad90f1',
  '7a17960ad2b35d49e4d2deb7bab9a81d',
  '9ae2a445abb5d6042784b1e6c35305bc',
  '5c9ffd5561aed6594f6a2959e2e44e56',
  'facbbe0917106245d4644a98fb9d3077',
  'e9980239e2c81cbd4728a1e510077f20',
  '9e953b626093c237fd288776ac8e4a29',
  '57aa0ba8ef1ca9bf98b9891e869814b0',
  '5537ec7379a6e446471dd74de0d5c4f2',
  'f5ac7847bf655d088b2b227bd444e73a',
  'c562b830c304e3f07f4bf8535a8f6f98',
  '5cc9026ef2d2ddbdd733484ed7e8137c',
  '127db9b1718406c6d35ec1145e3be47d',
  '5fc294204efe8cb09a8a5c7e301fafc8',
  '340c5bc29b902b84e8875612f229cb7d',
  '1d3466f0b56665594824185fffa4d1e4',
  '3e5160230962c9fbbc6a643ee08fd354',
  '5b48c33c951c8ac7a78c56a9a2865b8d',
  'bab0524d5b2d5657d4b4ade8900e696a',
  '17f187540e5fdb0652977b45f194d7b1',
  '17f603b406eabbdc76b58cd1cbd51b63',
  'afa815fddc762850ad9409d08713de8c',
  '10647ff22c803bf1b3a5a09d36ad1645',
  '4d5f500927dfbfb637eae931fa27df85',
  '7de8879bf21d8c14b8ae54e132b20e21',
  '45582ee93398d82d459fcc7a4ffaf8e0',
  'bf8ccc4bc0117b82f300af9400d73f92',
  '71d80b9e5be7bf0233f639a32e1c4514',
  '40683c3670300e496c8370969d8b0f9f',
  '6923a4d953d46c47af035c007d62a142',
  '1b87b3e8a2161365cc7056868b2404fd',
  '2a1bd0852b53e558ca33bb50af6c5a6d',
  'fda2fe35d40f22bccae2bbf328aee8fb',
  'f9584df15efbc137e0e3b4c7f80fbe1a',
  '7aec58ba6aee9c750497a660a6d443ab',
  '12f46312d12a5b13969c2b243e10535b',
  'cb473e91692ea85966697296431980d6',
  '3b2e98619d094f050074ffa8d2b4b31c',
  '335cbf198005a050c49532cf1ad7e90a',
  'ea356e8b394b4d43285c17e39ef555ff',
  '97c1d24473b43c771a73e4f9b2125339',
  '4eb754e8453e22323d285900cb06b777',
  '5e68dd25a3aff3c09eccce002f56b30f',
  '7e9fc5dd42cd885c3d1827fce1e2acec',
  '5620c73109e2e97e1442b5e13588349f',
  '4829ffe1b3f9f29f80dbae18f75ff151',
  'e6c14afe1be4730954c7004875c099d4',
  '5e2d8bcaba13c0eab2dc06808ad5174f',
  '68e79da7fad990bf5d39882f90f3f317',
  'edca5b50fb22d8649237f041a5e8a943',
  '5cb5d0b1dfd2ed3bd13d1bdc80ac94cb',
  '3a7caf002c690a838cb75e828caf7fd3',
  '90648bddb54503edf8cbeb4b63bcbdcb',
  '1956879f0e9dbf1441d20831cd0e4d18',
  '188180879b3c4bde96b29b51650921d6',
  'eba7fe7558a54907bc9dad14a6053338',
  '400afbc62494df7445f0609c41ab6eae',
  '053c4078ee0b714010d57c3a05edd0e1',
  '6746083d77f26e02855a20847c3c2914',
  'beca5764a080b0075afe0543ac4f15e8',
  'c1bc4530865bf13bd0662c6c65acc30d',
  'c290eccb892117d8442edb5908fcd436',
  'dc3533133f0716f3c7bf44efda424198',
  '8e8f3bbe3ff0cdc671ee533d67956316',
  'a2f8e9ea1c49ac960319ff9dca3cf757',
  '76efed70daceadc6df9c4f8996564e8c',
  '04aa97ef6ff9b5ecd4da4d18be131f9e',
  '438350c9f1bc02a3bf84b86a95d2e39b',
  '7633af5ccd0279aaacb7d76d397a6c89',
  '49cc11e49cf2ab654042308fcdc00bed',
  'f451e87ea9054ca90c1c7b2e6d3256a1',
  '5c64de3ade0ab0d1b88ea413b0750155',
  '62d75bb580efa3238cb8b62f7dacaea5',
  '93bd4ae0d26c267b9ce7e679f0867bd2',
  'e40d7b5c2e9dfdc90ee4a2bfcf9cf6ab',
  'f6b02fedd3936295ebb22c9294205127',
  '670aa8bce7efb996ec559980e9f9494c',
  'ebe93d8462e670ef103afeb0b2bc12fa',
  'de64fb99bb2b556eb731eeeec5aa970c',
  '05ee74581cb5b908041aca1ddeea94f5',
  '6a2da79c1c04a6867cfe3c4ab6d9eef5',
  '60b08a7a644e63f5bf19d47efae262b9',
  'fdbb8136a2eac9a7b5d5d58c26fe4105',
  '94313cff7b9fd457dcc63ee78c48baa4',
  'a6e3d4719ab7e36f56feb9da8427d978',
  '8a20d117bacb2ffb29ecf89c901ba5ca',
  '42b898cf61111dbdf997e7461fd02641',
  '90a9006d227a853b4fb228535ba13cf2',
  'c06d66352efb4f32ba7912afa4bf34f2',
  '4b2706b5502bdad5ddd3b93413220daf',
  '2a6a9696a154a118576de32829012497',
  '82ed06ebc8f438990cd784a26154d4dd',
  '278a1c4b085b5b1ff3fec54d744c1518',
  '355f39fea9f4962580ef3ceebab08f68',
  'bb9370900e25568fa8e465bf6d69c1e5',
  '9759aeaafb0b65e5fa4be90e4b3211e0',
  'dc5829caf5a21e8844b88d860533b325',
  'e6150fdafb0309cb41d2a246690e5bcf',
  '1c03baa54a35f315c0334e7cf7c26004',
  '3599aed1279f834572afed28d0330fed',
  '5d92312b80ddd299ed2064ba90710e52',
  'f74d5dcdab1ebb66f4e0faa3ef2d01ef',
  '88a3d3a042cfe3c393af44c8d66d319d',
  '4dc18982c1c310ae7eed8db52f99bd45',
  '4ab74c04fbb8e622979a382dd1275747',
  '8fb5d83d60bfd019f7d4431e94fb0483',
  'e85b969003d8225afeff9f586757dedd',
  '22a982753fd84e2b701ce0aecc0529a7',
  '0e7338ec488b6fee0d81d97e6f8a874c',
  '6c4681e9f72903277beac53f2603cb2c',
  '8859c13cf6432c26a46b25ff449680be',
  'da859394cfe303cbe019e4d73dd7167b',
  'e3dc069f206c58823ff7a4f463611926',
  'f118684e1da97253261916069aab9c9f',
  '80d57edb137e9b3d9627134df8a85512',
  '8eb9ebb34f258d851c003159b123814e',
  '54af8149ef5017cfc14a9e17a2801b24',
  'dd50115f94a4b24ebdaddda3ebcb5ece',
  '50656807642bfcc0397cee51accb65b7',
  '6f5ed41e5398f8f24c6e32c3c69e6bba',
  'e1b09c9af55927a5bd36458eff37d09e',
  'ad9a6389dea3df24a34e8d3c866d0fe4',
  'dfc20d67bb708f87e6900b89b49fd99e',
  'f0193ae160f393697e03e549a9fe4a32',
  'c6fbad7afbfe368835f6a7eb9cd6e682',
  'cf2cbab8c05ee8586a4d68f4b05a874c',
  'a4d3ddcfea5960939169fb2a7c46dca5',
  '64980f9574dd099f22ac1a2132b27dcb',
  '80cfb54365067687837628afc82cdd06',
  '895b250f2148136eb633023321d343ac',
  'bb8ccb7a2f0162795e32a5112d0a1378',
  '8a91b61ce82f87e17646b4ff3b496117',
  '93e6d9e04e9a47430a08bb19d332adbf',
  '304ee5177f4bac4d2038f371ae1bf642',
  '4044fc61e7f6acbf46679a0941c51be1',
  '6b17215da5c40183ac3952c36e8dd763',
  'dedb97c5f3ee26343dbe73cdd6ceb638',
  'f2fd22c02e61a86d48b688303a48718c',
  '0b9dfd2f53084d0a549139685f08d271',
  '57d55a5a085cc077d3237e6d83dc9d4a',
  '333bb9b81d1d967ca2df47ab24b05cfc',
  '83dfaefc6d6683c0bcecf163ca01a3ac',
  'a51bd2b9a0b12672c29b59006034b444',
  '10ecaa801a914866677b2e1c1d3c6deb',
  '36bc27620f5f75b76a5b137a1a216c24',
  '36447b1dffa11162c46b028f6dde92d4',
  'ebbff9bdb84e23801d9dbdc2d0bca1d3',
  '4f6d7f314b1710b81567556f97057b8b',
  '1db8c2c0621b3b2369de65aee64fab78',
  'f164a9d316712b01723b83361da84b10',
  '86ea75667b61eb7f0a77c0363a2426fa',
  'ea5eec0d307dc9b95c702cc05ac9ebf3',
  'f199083985825f07c74d93c09b44db2c',
  '85260e6136532b7f2b2db1a1100fdb37',
  'c9a0143cd28ba6a2c9fd720c4b21611e',
  '431938953f23ff87a6abcf86ffaca8a8',
  'de9177eccd28d8a709e581541dea6c94',
  'a3c20df8a020c38309f45b94556632f9',
  'c6de071ff5aa1b2daefb0ddd59f1f101',
  '21ea434865c986731d573d9082a3a5f3',
  'd653907b39584e6fda84abd8e588d7e2',
  '09b51eb41712848e5d0279374a8353df',
  '461de5fc91ea9451f262721f335e8893',
  '087853d46d3faba9235fcdec31cdc218',
  '961398f90966a2127df5b7dc75810510',
  '47cb9a855874f3ba496b0eace9727cfa',
  '3c85ba6958dc5d69d546300673702d02',
  'd99ced80c3ca9b8e0a34d2f09d7af85c',
  'f3b8859236c76b7f6c092f11e1753449',
  '29c10dbefdc463c6035d85f97d05e788',
  '22692a24540912d7097456f7c92ac0aa',
  'b51356ec1c645dbcb2473e79e8cb67ba',
  '587d36a9772c97c35718b16b3cbe379c',
  '38cc97b203895493c50ea0b77bfd9b37',
  '9d350895d30b7e22f9d6358f80aee618',
  '03651860a1bd57b8a3f9644de1b9b41b',
  '0e47ff9f952db2bb5924fb9c62121dcd',
  '776b75754e845be2e25f40837c70a00b',
  '27b11f4ac45bca8d12165173c5a9d75a',
  '5d835a5bcbf1e6bb16df00bbc7dacd37',
  '2ef1e12281388c101566dcabcefccc46',
  'adfe462f77daa52274cd470fd76c8f77',
  'a36493e4797ac8f1d4ee9e71ee66e379',
  '22ad6821b2635cdf6f6d0fbf334bdf83',
  '8d201dfb98bf09e741c1ce23f3a749a2',
  '60cf2323f6ab7f11f42a4f83b6e0cbdc',
  '644923388c5fb8a5203b56ebd38d2865',
  '08fa7d2478a440e74d9eb606aa4353ca',
  'b4f1dd74989f5e1be9f5872056992ce5',
  '90a1f260e052cc37ef8995ac5946defd',
  '3ea97967caef77d355db688be65fdea3',
  'e3c1b821d27d7bf685309080efa6a85f',
  'd7f579a02b7f597403608ee5d1f48dbe',
  '2adee09ef823e30164fcf053e874d0e7',
  '0f8986d1a148348dbb0aa5ad06609cb3',
  '74d7dbe0fdf012e5dc133fa3b435f06a',
  'b8aece8cb78e616514e6a7ff26a5a65c',
  'a2d72fae69042c8676b6171df8ee775c',
  '559879838675a8ae88cfb1d1abd0e44e',
  'b84c9b8c04be885a9bb7dd5b71f3efc7',
  'f5e898f8ac76fc1b0dae07921a555794',
  '6e7922284a365b78c6d57b8e4d0fc72a',
  '8c1394c9821df9f9354fbf33ddb829a6',
  'a9d0c94a7a5724dd7d10ecc7ab7513b3',
  '2e2c39fd01968faa86ddc1a63b51094d',
  '87009f022f4424110c76c64d84dd7272',
  'c3b4042732e9058b9edbeaf2fe131048',
  'c2d9c8235a0b37cce5769de18d24270e',
  'cc0901744badf9f1e839a3c54a97dbe6',
  '87867afd1e9756181bfaaddd2f42a34e',
  'df579f1dd9718fbb7d82139aa2cf4fc7',
  '35aeddb061227861daa7561f8bff68f9',
  'fa780882d28c4797a08d9bad7dbbbe7c',
  'a8f815c7c1e81883eda0e031191a0991',
  'd48e07dbcdc5a9ce1e014482a5593dd1',
  '57edae818c18ad47ec2e8959fee87ca4',
  '873c71ab27082324990ffe41f40f445f',
  '288b6a7bf62a279c7fdce9b2011b874c',
  '7a164dac0836a17e03bf72060f8abdbb',
  '15d1e26434aefa9208c88a0e07975adf',
  '02f91ce2f6edc366e92d53fe1229e7a8',
  'fb201884e5d9d15e6a20fb97a7ba8587',
  '64523c302bffb0a58d11455b999324f3',
  '20d3a5fa55d7df5c0e49c354ae238a24',
  'e9bbbb38ef1f6f045bfbfbcef2a4d1d8',
  '8900549cd1a95cac7849f73f813ad161',
  '86b2dd28f465bc613defeb76e4180eb6',
  'f3f4af1cffd63c805a380e48a640e143',
  '8392f578e945e460cbf46dd4e84e0575',
  '556a41612a2ecd71315b1cd0f0e28767',
  '4f28204c057034c6cf6766cc27b59ca7',
  '470ef4dcce40c4052605cb003f233a9e',
  'fa223df15362e9303774f2bd8828127a',
  'e4350ac5bd7ffdaf5accff30b56d09bf',
  'f2d2dabd2ded634268a5b11513dd7a88',
  '0fa420bbac390b7918efcdbfc0c457a9',
  '88c88b487348d35692864d19bde06534',
  '25c459ae882390882668aa551570ec4c',
  '573ca9097ddaec04c5638580c9cb686a',
  'e5c33bac077edcb2bfc9defc2ee2d36d',
  '7430aae67f72ee720e81c296d9417feb',
  '88cb71fe121054568d5218ae07ae81d2',
  'dfa5566d0f032687bdd183b7312ab491',
  '16b59b0b5d51b46691ce87d85e82ab6b',
  'd6460e740b49ba8b9c1034f4b8e72a1b',
  '86f96afe657aebef2d4f1237d47923f2',
  '9e1c7771b5dfd77b81f41b6b3815ecd1',
  'e01f80a3b231ba02aac363de66a8d357',
  '1d40f2d12a02c678a05e308a55d3a84c',
  'b81e7f627c0dea1f3ba3c0b472599628',
  'eac4cf64d7e66aa9ec1d46da18d8d119',
  '5bf31cdb25e1bb792c0bceacb05c057a',
  '6bade1263ce7b03e194052386e681514',
  '4797524c27ac20c0b44825a7a52c0f55',
  '687f900c0a9a1c7489a244fd71cf5d7e',
  'ab4f17db54d0eea498f8977a976a0771',
  'e149800ebac4962b1c395cb95e6a5305',
  '1e6d4de5deb61b1c7ae5570d104f3f2a',
  '0cfcdf4a2929611d8228bf61d9aadb8d',
  '1f3ad4399f968cec8ca0834bdeda37cb',
  'a3b424108d97ecffebffa1cba594a21e',
  'f6557f8ba20b2845c96e8ca52ffb7c97',
  'b43518c07358c2050833a764cfce3c62',
  '90f70c163d5396f3a373154c96b7c76d',
  '882bdcf8d3a7fe802c2c6acea0a71d57',
  '06e874cf6edee4ee33f56d9a83bda4fb',
  'e250b381888af58e38a5a61ec4679f72',
  '79d27f0f77a7533ce634e3e33d76f04a',
  '2ddc2d0ede3ef2e5ff39e9cca58c9e38',
  '97ba1627d65dac19f71a44797eac713c',
  '1ba34e08b930ba5f87167c1f47c9aaf8',
  '62eab4e7c92d2b5aa34a747848680757',
  'f563c4a02575e1fb4df9fd9d5f956b89',
  '88fb3ebf3b227a72f2578a3653ea72e6',
  '425528c2ec2601f0941aeb9bcc0ffc16',
  '3e35bcb1ed9a8630373eed2334627157',
  '1c866045c15e7b50735150d0441a5102',
  '4cc73b45aebaf8df4d459c99fe37fd00',
  'bf4640f20e3a9747e2f34595106521f6',
  'e011d86f2e4bfd5fd4571567cc715b6a',
  '3fa8cd7e060babd5058f17014f73f946',
  '046253c1b5636fa44db1242ab63cf3b2',
  '8305125343970e5a035c5acde188f2f5',
  '51cb5584de2794c7f956d92d381336ee',
  'f47d84371f82fe4c9424c11ceef980cd',
  '51a0200f8abc2650aeae20c83065f590',
  'b566c882b63f7f4629d7b138a0b876da',
  '6ebe00bdde4c8e85e14f3f9a947f3b4c',
  'dab946ba2eaefdd183cf5059562a8031',
  'ea84a08396997d09440e030f89d58661',
  '66dfe43af78396bed1876b30a0fc774e',
  'bdfa62fec238e9dab8a3608ed3ab37e8',
  '647cc672805ca2239271b5faed8c2c9b',
  '2432569c28f47c5494585c2a792935f5',
  '2bb288664a5a8ba58009796ebb5304e8',
  'fd9ca26143eab02f73777e0ac4deeadc',
  '9629098800aa49d2216c8e34c84533c4',
  '66851aefed8697d4a6977c016b257bda',
  '4fc7d221e0837fc10c280badd2b049bd',
  '091b1e67f5651db060581436cbb68144',
  '1225b4bc7f47f602c3e3458e79c64e99',
  '87a80178996ba5de06884209bb4b7d17',
  'ca39f5997095f46a49aa3934bb209e1d',
  'e42f5bc1baaeaf8112170b3ce8437991',
  'f8ca7d96c4073c44deae1854ba44a9d4',
  'beb12f9e0e64f5340d3a788a619d3b46',
  '77d23a17a4d3265820ecf2211e0a3009',
  'b242e14b07412ec9844e774c188a457f',
  '11dc65a0efc17f8957bd963edfca1b22',
  '217b5f22456f0c2f44f8c61f4b3d3f28',
  'beedb10bbc60af752c6d7abb3f8d4b21',
  '86023d2d2b92bb7411f9b50530b0b03a',
  '1a56f4f751907a2ff0c0b5b91a5a52e4',
  '91ce33031227333a7ed645e3c09f5f53',
  'fff4ea0c8f36db66d8fe032599e489bb',
  '97ebe9024490dd24b866fb6917ec714e',
  'cf272d04f4194e2a908853361616c3c9',
  'bfa1d59cc09ed140349029c48b69fb32',
  'ed07dd2a523a3624834646511849b890',
  'd2bbc48529a4221e29029e98bab887f1',
  'bdf8b0440295df4add11faaccf690cc2',
  '9885dc406ad847074d192708c720acd1',
  '9d39e2fcac380c73b317a63e070522f2',
  '5a7ec4df4e9c786687135b339fcf46d5',
  'f77edb04517ec56ba142f5a1b49c8da6',
  '9c6a59f40152c6d26bbc6ed5e80238ef',
  '109c038550b2d65c91d1b090a5f69f00',
  '0fc2edf953d4aa2b55ac5b4e83a0854a',
  'a8f8ba88f8a5178f62e07b7267dbbb26',
  'dc3cea7e17bd930bc227ac96acdf223c',
  '7694adb521fe8d87b977ac0fe36dc12c',
  '76112748dfd5842acb4124a3930ff647',
  '4967f2572f7dd63897b5a460d54e1930',
  '66c8fe223c255cf6122516724259d3a2',
  'dcfcb89e2867278d6526c4684032649d',
  'ed841fa04b289724a1c840aa2871ed12',
  '0433316bc252e0205f19c39136319afe',
  'c19eacf188e49b5c75157cb7233ca1f8',
  'b25fce8d10d9e2d39934da00571cb193',
  '3d1855f3912b8f5c78f3d0015cb6dec6',
  '7e5b3e818dfa85898916a61b939d40d1',
  '467258e6ade5ecac4621a97aa9904b2e',
  '5af32c816f0c398dc437d6b111088b45',
  'f72784653ccdaae402b47eec8fc782c1',
  'c692443ed73247bf85559b0465dba94f',
  '62ad34018f4c94b003b067d56bc09296',
  'de82efdedc9498fe85a692113c93f931',
  '26bb0c8a2561638ce7e124bd1a2dea25',
  'aebd44e98adc5212b5f3a6c41e818284',
  'fff6eeca3589127f399eb7f8e70b0889',
  '4dc1b496133e278843dcdcf94e97ec88',
  'e8e22eef229bc815c46ae90f3f1e678e',
  'edd5d6a6f159edcd95b39bbff2fc267d',
  '8708ea6fe5b747e2d12aa8da8e606001',
  '35dea57fbf5bca6d9e561bb2afe6f4d5',
  '0b8d240ede9d6106bd3e8ce371320c72',
  '7a3094aabcd08695210fdf88b246cda1',
  'ce3489752394f0490328279d7c6e743b',
  '1e5a2a70d911d34a47158f2628757c7f',
  '4155f25d27da9b1404ec048a09ead9bf',
  'f58798a2fee25961711bc39ad98ab71d',
  'cd58657d6efe45a21e016dcd9566f369',
  '4ff845b4ef889bc649fcf2fed617fae2',
  '11c3b660f9c85a4380ff04588bc61cfd',
  'a480d679db7743fdc0a4071970a1c85e',
  '11770eeed79813a5405a4ef1eb98b4f8',
  '1ba54d2a79cc5b750cc4b71db5472ac8',
  'bd54d91455d84383c6cf8fd292b58260',
  'bc52d5f3b98828d47143813034369d38',
  '59b3ad6ddbaa1b640039e62516441a54',
  '76aca1fa9ed14b5548fb63b6a21b0c63',
  'b84855ddf9d83e99f94b6cc5e70dc770',
  '21521582120aa14190f3c8a440d749a3',
  '33eb51fbb856bba48a9b7d77280da194',
  '04df5f39ee0a972f2d963e309ad028f5',
  '0b474c2e39550e8a5791f3c6c635e917',
  '2d9558506d5228f75fd057cdc66e8e98',
  'c7c12ae1971b692923faa77a4a6de2b8',
  '37dbe44cabccd31ecbf8d9c71ac69fa5',
  '6d151e82d1a103c539c112d63384a6bd',
  '33e69fbdf3f0f912d4fba7c715851f9a',
  'c56427eecad58221a86308fc37a36593',
  'c7c28cbe4d6e4599a7dab1c074351d59',
  '079a872e78dfa0378aaf53ba9a1a0a73',
  '7a53de9d5f4a699490b6dced900a9d71',
  '8c30db1ad47cb66b99f6c9f458ee8607',
  '78c2b14080b498d1dd591ddf87a99088',
  '5e24cca363f3d17565b99d552c465e3e',
  'ce3be716de8716b1a8d079831743f2b5',
  '8e42268c96a75aa2ffc71b102dc2a6f0',
  '5452302d1054b55dc526adeaa111c8e5',
  '87bae08cb3193f8db62ce6ddb31d3cce',
  '144905902cb295152cc0bfa9bd2d9029',
  'ffb1a48b0db240968ec5f4443f60a412',
  '578b31ccc1a7e60d10d1e53ffc7b86fc',
  '7c7a1537bd94861d7816e54c37ffb1a7',
  '09dba3c26daf0f44a70f709fdf227f59',
  'e01b673165c3db3a9d0fe3abe6f9b90e',
  '36338e8adc37035ae7592354e5d23898',
  'c0b766b0c9ec70af5433e8cddd713898',
  '1454968a8eec0fde1166a6ff5f5e42ee',
  '208fdda55255aeaeb46e7e02cdaa07b3',
  'c633a3497e15fb000e726a3306153205',
  '48d6a1f7c308f17baf1660d5df7a887f',
  '5dd3d356ecdb5b1adb1cf679ead6b957',
  '78ceceed807effd1d0de1332b6390995',
  '9db2b672e0f492ec0201d7a80b66feb7',
  'd5ab5519e04aa9a4adc4081452a38616',
  '49d4c648db29ae81225b0833da81ee8c',
  '81366e6bfa9795b52dd93b938b347f5b',
  '04af2309b5e5c63e328d4e93bd8586e8',
  '8a6f260c60bb60c8a58dd6806e96abc8',
  'cc4ba76f1a5f4974fc0857270c5ea297',
  '12396b2d2a0bfde42fe06f9d1bf44af3',
  '0d45a78c1b31d135308d333d4e6deeff',
  '28599e36d34aa5a06a4dd56583004885',
  '389b059ee539935520883ff1af6ba13a',
  '8d38e3d4ed40d7966da0525d99f057de',
  'a58200acf34d86672b372e55a7616a3d',
  '74ee327e367c38eb78075192f3bb44c9',
  '00a05fa99ff0e26e942fa700d8ab07fe',
  'f51d905480c06df264ff091d494405e8',
  '3f873a6b71363cf43af2ecb630bba6cb',
  '97dbc03fb54159e21815d19f08fac58e',
  'd682ea42fdc379d408cf37bd49fdd0ff',
  'dad1a9e78ee7c2a4c025387ca0efa878',
  '06477892e3339b4099468e497cd08fad',
  'e3280f0b8405429c1bed2073fa7da3e8',
  '43a56175628619bf35354a103ebc123b',
  '2a156afb0ea30abd20f7d274361adc5c',
  'c062b97150d5f1539cb9aca634999d33',
  'e306e1e18be15989e9d9be9a908e5252',
  'aacf8a458747ef54fb78b97031af3d65',
  'f924a987c04fbf17ed85a017f79d6403',
  '868157a5eaac7995e349772704c9a88f',
  '9426d28e7c61a2de967be20d31fc4b9f',
  '569f8a8223611354d35c82460840f3ac',
  '51ba806e04f378c3271636ed0c277de5',
  '24ce469d05b3f137d769c301aadfade9',
  '0be7f064826b47790365f753c5e2e629',
  'ae9a2eb4cb0c4a724ba13bba163bd0fb',
  'f6d2010336694bb21d3fbb0a7abff5bd',
  'd7393286fbeae09c4621e21f79d7ec05',
  'd965558cde15f54a06337b34c3d9fa65',
  'e090fae312250b38fe47550fbd84bdbe',
  '22d52d13978cd9233187f2504ff9db12',
  'b6b440a1cde90f2d1966cc91cdde3294',
  'c50ce632ebd131d258b1daea1abe5df6',
  '128c99c4430a755f39f565309171bd47',
  '3faf6bb86f9d66d927fb58d5fd23ed3e',
  '9654a3ee30a74a406ff7f0b1c1b3549f',
  'c15dd557bd6de338256b89b5ff1bef72',
  'c488629ca56c1dc53381ec516567ca00',
  'cf324733129274327b3099e68548cb0f',
  '6f80d14f3b1c1e75b555fe16a4722954',
  'f5dd83ec9b47f283af3eed4d02bf007c',
  'ca4f6e570ba7472351fbee2b0e7bc5c9',
  '9111f544545c35e6185424add3425b98',
  '50f51968e373fbf34c75f3d92225d67a',
  'd14089d244f66f45d3411c36c96255f7',
  '274b79fa96abb1057ec433efb75c672d',
  'b85aa3f21706228f2db61bd3a62a8d9a',
  '70acdcb289485e05cf82c64c7de01133',
  '964cf6d8349eb31fd9172e951ac649dd',
  '98403e3fefb7165e6ebc45fe922209a2',
  '942a31fb6ed8c8514fc0ee9f479f8957',
  '82e201db21aa6e272ec23f455c795f93',
  '2eee6d5a48f0f896e20265db5baf5a10',
  '7293feebf83641e62b865cf064e1b223',
  '484f947bd1fe990df88331de126152ab',
  '1db9caf066b0a5ab86cb1ccd46a653d8',
  'da686cce04fd78c43a213d89522a5fee',
  '6e58b4b9f560101a5cde9cd98fa72b62',
  '3df80ea5ecd822f9f3d08233653ade4a',
  '8f1d8f913a0516897ae5aaf2566a96a9',
  '922a62da58a9869d5625f7d9462f7ffc',
  '7485c4673d44f62e867977985986c25d',
  'b56fbdaadfe8784d8f45efae1dace1b5',
  '937fe14ea6a5061f123b3e775890368d',
  'e262ba656723986ff78445329642e4a2',
  '39c1063d845ef78d8ef6d6bdb9efa5b1',
  'bc93c37f2b20f9c8f6478b21570d8abe',
  '722c7578595ea068d7e94c2a05c216bd',
  '5718d6d5c66480d700fb21b75444189b',
  '0f61b50a7f729a7d3dfc13af7a4d7cca',
  '52e0d50394106948f7ece79c3ad00cea',
  '1277ee84eb9e0fc1aa3cf977d7b78cb7',
  '8427a6b9c0d55d1e07be00e06ae51166',
  '1cbbcd47321785b331353e74ab4ed600',
  'd62ad41d02aefffd987240f970c4609d',
  '2cdc0b796576728ee0b80dfacb6acacd',
  '945fe97cd2b04b8b4ed808842447eae0',
  '572d607aadf371348442ad7183704c22',
  '8f7842b112e49bce864dc53d793ebf6c',
  'e509340a1d3d9ea8b868d26ef3deb4cc',
  'c7a6f0adf184be89c40f1efa48492c07',
  'e0715f798542e333371b834bf00a6d9a',
  'c3533527026c608f1ae55f6748b97e2b',
  '2d0ed0849489b68d69f1ad354c708475',
  'c0d47362fd8cb7c3f42cf13fb86d7d21',
  '870bd4d6ee24d73e11dbc4a0ebf52959',
  'f991e8a3a84190876b1ad7582e8f8882',
  'd1bfd3844e4998a9084a6e039383ef8e',
  '03a3a2ddb93dcc078eac65e52ac350a2',
  'e3f1c248f9f08b581d00f473a433eac4',
  '517c725cc63057ab83c5d78a90e1bc42',
  '88e1e78a6975a9af32009c622729c573',
  '8b53f2da2390c3269839694bef0df79b',
  '1d7bfbeb57e5dff0dd5ad64e5040508c',
  '4fb033f9d076bbf8c6f10d19057363a3',
  '6a4d9a1a91f39efb6beb42d3d40612d1',
  'ae4b864a8fcf730789147d3bcb422f8b',
  '9b1063f51c8ebdbe32760fd5fc527c7e',
  '0df638c04a5863db092be026f320bb02',
  'de7eadd5e48234cea3b412d155a1741e',
  '43c978b676b12550e5ee57e635d4e018',
  '09343763beb63de382d40666a241abf7',
  '4affd2f28ee72c268687af7b36242e0d',
  'cf603d2829fa4abf48f4dddb75a1531a',
  'ab0658bb3062ebbbc90dd0f65ab0b41b',
  '6f8202d2d19fa2260a877779d6c3b9cc',
  '20471aef3138049c9b7ca4a18e611605',
  '624cc6bb0736393f0dec62e38ead0d13',
  '4506e1fb3dd016bd73b7cc4400a8312f',
  'dbfcbebb0b01172a6601fdf0f4470e46',
  '9c7de40d30e67b8c8d826e571b35915f',
  'd10287804bafa707f7558f2069731545',
  'f5408f2a815c7360d3a01468e23fdbee',
  '5008c0aa9a7a77af29b0130a9b575847',
  'dec1b4dbb6e4867b0af8785d42159c90',
  '67f04a104f7f4592dd9caf75137b24ed',
  'e75d8d6e551710adf26aae15a5745a4e',
  'd22f19408c811648baaf4ee5e60292ee',
  '0a5d62e0a510b7041a91b3dac37f309d',
  'efc7b75af2b8ec3db89d6fdf8aca3543',
  '63e0530204075740732fcd1d1a654960',
  '2fa8f9612ab9cece81e8256022e68a7a',
  '5520b5c31a47c3656fccb30629ffb50d',
  '57325edb6e3c62affa556a5202ea0b24',
  'ab644d1d755926bd6bc904856df18a93',
  '380fc39d9392d30ebb2a6f29b73f5098',
  '5cbb5bd6fd9c3125a6853e36fdbc91f8',
  '10620df1ba6ed1475d73811751c17715',
  'c3d42e002341136295a210b31fffd691',
  '3deee0246187a742e290ca96549210fb',
  '062843aa0eaaeebbbb2e94649a8aa30b',
  '8a575aab475a68e2543e850b39ca70c5',
  'b1226c6a783054c9b9618c9085eb98cb',
  '341ff1996995558512953ddcf9c05759',
  'fae8f523a1feff23e9b3374ae0f8eefc',
  '83a6ef134ef37db70cbd224a1170b047',
  '7ebb078550be8d7013787b93ad69868b',
  'cad9c0cd5fc709f5ca1eff5d5bfe2171',
  '52df955c538df19e930091be561d4452',
  '106eef8020fa5087eed1dfd00b9e0975',
  '0e98dd3db0e507329df25acccf96e810',
  '73e5d46d5acad673adaf40d8634cefed',
  '2a7a9bbc90a433b3b8627b2240cdee3b',
  '6a36fc4fb78dbc5dd71b706197b7deec',
  '47faa45a9729349e78e8f8643a5f5015',
  '75329b4585b954643e27532e8bfd67c9',
  '1bae77a15f95f0053b0c85a4e53fee81',
  'fe7e816e43aaab0091abd0193e7b6b68',
  '24e39e1dd17cd5fc213c40f3254aae47',
  '0fa88222f2be4ad784e3c7c1dd521eec',
  '24f567f3d7d4ac0bc67d9f5ec4ac10e8',
  '741433d3e32f7344901100167ed454bf',
  'c9f16af637323bd60dc78326fd204759',
  '5d9301f8debcf334479dcc845e5982e7',
  'afb43659e7364eefc7ef5373afc8ec1d',
  'ffc5ff12746247bbcd2e84c8a334083c',
  'ff0d6c2b010a80ffcf136f6646818477',
  '307f57bafe530c1328dc1b517970b9b6',
  '1a80ed3765a01d396b4fd9655a2ced8a',
  'e941eff3ea117a2a5d322d8ad35c36cf',
  'cb0ea7a521c7c909e42443d02302d6f4',
  '68a3ac8159bb73bae4c591faf248d476',
  'efa20f38e268466f4d438b4d843ac214',
  '0a50bff8b48bd61f379d5f64c4ea73ec',
  '43c9d37e3b7f3e0cdb8ea3dddf938c32',
  '5f466dd12a89fc8471e61f51f2f4470f',
  '33926fea28fce477cd346556f447f64d',
  '3c86b992d7e03264055f1fb187c37ce1',
  '6eeea00bb7f1635d01d80c418d233df9',
  '136253cdd3774dc1e647929c7963dd15',
  'ce1ba05aa49b894df72388f5e1bdeccd',
  '84be63241084731374d840f03c12be95',
  '018cbe1198534903a60b38ae54d2c494',
  '5e6e6d018e9b047a96ac4ecaddc3a4ee',
  '11ad83e47f4d935037e65566c93b8ac3',
  '05ac9fa9b0c5ad7b40df5d2513c849ea',
  '5087e18f97785ea7e0951c7967d1e9aa',
  '0b82f36f52b2e8d5b4828d2656e739c7',
  'aafa66b4ec46f5058266914680c47b8f',
  '677368ce57f8fd5e8d25bf0a7f3e3d10',
  '7b521bdce369ac1986edd84b4fbc1037',
  'c29fec5d5ac1bb3f658e995b6d32a6b7',
  'babb25825186feff742ba4c88419aa0c',
  '9d7bedc61ed4e719b2bcdac7fedc75f9',
  'b3e351f1f63e5acc1fff3b075e8dd439',
  '04965da5604864df78e41277d4ec1e12',
  'ab24f5e054da3ac6ce957d5f42045ef2',
  '7d38d5f4f1e75923bd9ba658420dfb66',
  '5fbccbc8c0cc4ab184d11ddfa1dd3a32',
  '4d60b7186e55a3a9d8badddcaff7c91b',
  '09da58ff6050c6776b234372c55a26de',
  'fc85cd9f5b5978fd659ed399aa9ea6be',
  '728bc33a28747f7aef7d605936072640',
  'c428f865efc9c9384bc93299e1c8b9d5',
  'b1e4ee88b9b616a976e3ad3a922da5bb',
  'fc18770cad2ea957c64e1e1d356ab1fd',
  '97c1872b4a1b8453b748c3f115ba718c',
  'aa30f64b14d0acc3f88fcf9ed1f855c9',
  '4f1cdbc94aecfd3ca92dd337da460cfd',
  '9724295337f81c202cc968b8e2937daf',
  '9feb2deef45c8f1d7c254190723e00f2',
  '4f1f2e28f331d26fff90239247264c4c',
  'e7846025d81da80e8fe069fb575366c6',
  'd320d61e28f64187f9275bcf81a5c185',
  '9496604eb0f7b8489f26072c4972faf7',
  '947a56136f197e5f0b63e6f478701e62',
  '250d595257999bd43898a047ba0d0829',
  '8d0b3dad513f0174cba7b9985de751f7',
  'f66dade0f9030a820cb4bbe1509f3566',
  '464d81ae00ef8ad0bfd72007656cd3ae',
  'b874c4e166515f2e27debcf576d90d66',
  'f29d922e9ded3f7737757bd6211ed700',
  '8c05f3d406d4a2e241ba2ac4c13fb4b1',
  'e196471f89655690f732b176898300e4',
  '8ae1e3bf4f06ceb0aa65550245ae4a75',
  'd884cac843ce92520992d2cf60f50077',
  '2c03553b89ce576c4cda82ea4b7df973',
  '0cac1b39003fcbd91ba13bd4b288b094',
  '6ff36a9dc7d5a84c3d8544c959c0564d',
  'ec1618fc2408a3b6a6e7d3ff3fb9130a',
  '17c89b222df4f98a1ac2cf4ce1675c13',
  '214f70bfbcc145414fc3f89d9534780e',
  'b6de2ed4eb0e1ba0f5be69a65bfd5672',
  '2b84032374faaa1d166588948fb9cb77',
  '9ae8452470d730b62f81f50d8d2f08e8',
  '6f8cfbc287d48450955859fe0a937e61',
  '1ed8fb5f0245fc93ffabd652e4953a27',
  '5360943448f01308b5e661ed20c3d118',
  '8c874ffee9a4525bf4bcc04a9fda7275',
  'e78d8175c5c14a91ea761de233e25faa',
  'f92613ea3922e338645fb4a923312eaf',
  '7709012a8bf0644708c878046424af19',
  '829e5afdb023bfa942f140b8e48e51ba',
  'e11485479752a4fc31d363e80daeec87',
  '65dc5c6b96e03e6d79d17047163be09e',
  '040100aadd41835ce74ccd2c3c8c5eef',
  'c7a5912e939eaafa8b7bad06da4a5a94',
  'bd6ce056676a4892807c28addb2aee26',
  '9d35916bbe5ea5709cacc2c8bc94bad4',
  '6a98b3afb514ba42aecc07f1530576bb',
  '2295f430c284af264c0d6a667798c9ee',
  '8780af51739a4897aadc90535b457ff3',
  '5d1611bf56f7c3b61fc1d1bf6f6a6a89',
  '50d5445e31d379b8979108b4110ddf82',
  '5b39b11aeee71ddf7da75dd4a482f5d0',
  '03948e52881825a8a745ea1db6e4ba0f',
  '292db0615fabb9213d908c465d750836',
  '6eda54bebea9ffb8fbe42622448623e6',
  '3ac241c3f1e0914affdd3a9cbc29cf3b',
  'a1f7e0b788c4e27a99fddf754e073e69',
  '7eeceff10d17b0a91e64ff45d6311fc1',
  'c29cf3ceab34e40fb37039a76a8d7b1f',
  '68deac30a25eafcfd1dc998c8a5cadc4',
  'f709a08050bbc8e85f6a2645fb7cf183',
  'b4de7321094b5f3d6cbfa75766790d2e',
  '6dfe98efa63cf53df7b0fa5bb5efcec4',
  '5e8af0ffff4a9591c51af254280284ec',
  '76e4736e2d64d36e2d52cb5d77def176',
  'c421461f155db90f3b7343c75d766b45',
  '7de9fbd5f2c2bd05b8e51f06e2b63872',
  '762903e2c7e1758a2bb9a6f5870b2a51',
  '99c6344da7c9d0ffd7616e729014cdba',
  '58e7b751e680154f602127d452a42ca9',
  '04f434dd35629ce24ea225b180a48759',
  '0a13c1586d19127ab9dc744c0de7e6d1',
  'aa4f73c0e2814ee9136127e664a842bf',
  '9b58c50e14d7a98fd3f42589fcf86aa6',
  'd6a6ae21e04c09feae90295cb5992a24',
  '6c79301a9f552498fe281ef8abcefb94',
  '66f9ea4ad3b19d3bba9a09bd3a43a9b4',
  '090a6b0dc67b4e90fcf454c3efa2ac4a',
  '5b28abb1db9fdee309dd36f20ec6ed41',
  'e4904b17a771755520742c3163306bab',
  '35a5e7bf23cf0adf9943a21725a3427b',
  'd4d9ad0f029197438ecb22b7eb06c0dc',
  'f722051ead96d97ab4e54c02c95f7ba5',
  '362304ba2b36237df116cbbb62cf1cb9',
  'bde3d92afac9f29f74f05101273ad0ed',
  'd04ca193cedd768c399d6c0bc95b7603',
  'd3fc071aaffc2ff4fc1997cdd314a062',
  'bb57d63c5d02d8e6dc2f6054fb55a18c',
  '7dae48757f11bec9450f1de2ab4e3090',
  'dc75b190d19b7b5ce34d04432c596250',
  '52493f225c0d9a4b1ae946ab0f00a864',
  'd2386413b2f32916861f73dabce411d6',
  'bd4a95f525ea3ef809254de836651fc3',
  'a767b28fcf8853381423f29d2abdbe12',
  'eebbaca6911275208b448550d73921e5',
  '59ff0655613fbbe7da7879ebdad98be6',
  '5b17657ae9135a4fd8ac2eaf3db4b2a9',
  '7c7e8243de74731ce202506c33dda4a2',
  'df4ed255fdcffcebf97820ba138ccd75',
  '11161b62452f837b1f5d854a5a3d4710',
  'a198d2709e5267c199cb3d43e21ec85b',
  '8f075205627a336207b95cce66d5bc24',
  'c25faf0c7f1d90cb1e2f2f41cb507703',
  '2dca5464fe7a36b4af26047b3dc59253',
  '462bb6348297a377c23926443905f440',
  '734007602b12d9aa5addbbebbb74ba24',
  '2744cf27e715244bf414c3a0abe97728',
  'd11c5a3156a65804cbca34a47b51abf1',
  '9dc554fb9452eb4d19e12efb1ebd816b',
  'bc2474710d50ebc38c526721c1c668b5',
  '18e94e1515826e12b9c20205b8d55e81',
  '41da17da39336f8b6cc948165e6f7dd9',
  '09ccaf809b61e519f7b5b46c339dd003',
  '35247559dbff2545aa1555decb6f3b95',
  '5d967959a9fc52c0b88295069b0cda12',
  '823efaef5f2224a845a8e6cb2a0ce07a',
  '3e9d68ca21015e4bf0a9fe32a2f392ac',
  'f3b1fe233e3c71781e6bc89436c955a2',
  'b3132dacb2699416ec9bad8e17739aec',
  '4a33442f433c350470b1a33baf4d4367',
  'd73ed26479e9c3afaa41c62590c10113',
  'fdc37a6f52238ce8c93af675c26944da',
  'f7676f259a161fbc989ae2b50756fcb3',
  '193f3b1021e907368548938ff1fec15c',
  '52d65557c8134f2547cf5793a1f564ff',
  'a06f99e3dcbfd9f605cde483fddef24b',
  '7493cb50ee6b865436c3c9e8dd013eb3',
  '75ad131c13ca2bc8315b907a9da16fdb',
  '62ae8b25485b69762c86a636a5c2333a',
  '02ffc7e26e941b5a7ff1899f2eb6e9ce',
  '0411e5f1720fa49291f460f07eed86c1',
  '7c2faba8aab898313c123ed5ad7b9db7',
  'd10366e1e96437124a210e35b6653488',
  'ee3debc966dc3b5ec6249d1270cc1d7c',
  '470b68af9f9ee5e50d443a670dbdcf24',
  'a6450b3f2622380f27b38249089a8771',
  '2def626ab99e77118ecf10f0e85114e0',
  '036b5cc0ca3740cbde93199142321f25',
  '3546a370e76dd84d9c51612635a16935',
  '9b897e6088be26cafe1531d0ce3f7e41',
  '1ab31571e0a88bd198c5270e37338e38',
  'e62769a7c53a8b0966cfe9799fa660d9',
  'ca77fdb6237e48882b071545a1914d7c',
  '2e070eb047c94edeef0ecd6ad93afeee',
  '9518dd3c9d0a0873e3b2c95fd371652d',
  'dad970656fb42be293fa5ff4499afb59',
  'b4f37cba2e1238751d0a6982aaeda0b1',
  '022fed33b6b419084c91b914d170735d',
  '802bb51183dd0d2e2b741359641bdec4',
  '4e9fce79c3aadd1184cd54f64d8d1f80',
  '1ee944624503422c11927667df0f6c38',
  '25291cacd46e32379608962eb7e65019',
  '6f15133b63c0f62004a0618f0eb44d48',
  '58b7083bead63de700abdabef5e2dbae',
  '7e29236321f5c27ce0b8d6e9c3402826',
  '53abc9a15b8c46579a5b88f2c92a04f4',
  'd737523855a1ec00f115f01cef2efb7f',
  '6ac1cb2500d10095a864497f36760712',
  '9f482e7b7723c8c2d43eb1869108b59b',
  '30c93c55ce21c45933b7979712e585f0',
  'ac428a9205b9398d24c0493821c620e8',
  '858dc5417b36142465d5b58c3a3e4d14',
  'c2f24fec8f0e773917b0af970151482a',
  'afc8f48438d2f614e483b12e9ea8fde0',
  '2800846d3c003d3c37dddcc5d88c7251',
  '2ab9851590ced4633af951daf602be8c',
  '61d3d7a633d558d5ca74f514973d46db',
  'c1db13d9840f7af397405fcbcfd3623d',
  '60e8f7b361068a476d2b1d75c0333c3e',
  '47afe0a2feb98e2e2c8bdbeea061d93a',
  'a37a22f989c1e5b6be04d3f50be2ede1',
  '62f1bd92289fa969aa3f522557261630',
  'f3837eb7bac5937832b9d7ab9057a362',
  '8d382b7ca70e215157b00922bd9d2042',
  'dfe7aaf9340d061ef9572d8ea0244fc3',
  'd1a03071477c2554c50f688b2d69a830',
  '3ee951e24faba5e69997cb1d4b661194',
  'fa0b2568fdc1adaffacef395e666cff2',
  '7c4731065086667a3573e4cfc5ac49ae',
  '2e57bcb7447503f0edb02910bcff1926',
  'af757fad86a7446cb60d43c6119a30aa',
  'db803e758ecb22205c2ad9b82e8e23d9',
  'ee621022a3154d682ab2a9770d5a620e',
  'c286c18b21594dd07f7b2823aeba816b',
  '1b5815fc4b22493c3c2a334d2b2afe7a',
  'caf1dae7b49b4b92fbd2432c01c2cd76',
  '07d0d34b618d1a11ead720b5ecd6c04a',
  '34cdf0a341bda72a8737de06087f7df8',
  'c08548c5fa3528200af142b7d16e85b5',
  '627af456dcfd9788d4407c15f4bf19e3',
  '0b8e376b911598f48b4d075a3ee2fbd1',
  '413f9469f3d1d65096399a1aaa10647f',
  '339218692eeeb2d5ab8ebc0631fae68a',
  '9cafe77e003de2a6811a169aa8686775',
  '3971f113a2426cf2b82fc7417b6355bf',
  '87d6a59d824f8e59a6368988e251063a',
  'c30f9be827e8fd45b1b566a437fed388',
  '6d965311e30f73b0c2f9f4fd1c9ef8e2',
  '5047793e125b57b55b410159c44c04b0',
  '1fbc5ecad3d079840963677f7d32fac8',
  '8cf97e127551ee113b3ebbb71c37ddac',
  '8b6ea1d7a9eb7886cd213af5a5575211',
  '79eec3ad0d1f06bd780603b11260b7a9',
  'f08eb875170b9f8ac7a99cfa8b8c7f0a',
  'c4bd0db544d07b4bfb8a5bb7446048af',
  'dbab028b35b077c1745db1bc555601d6',
  'dd6f410ac8a1dd7615fdeefe62975779',
  '414cb8e9092fa061ba94d5ef41297f74',
  '145cdbecefd1057c9454cb3be54fa28e',
  'e9f7675af8a1cde93dd158bc8bfde6dd',
  '951f24ba409dc42d5d0df65a13556903',
  '24db7878b7fb13affe2de9b0fd71cd3a',
  '2fe56d532477f706f3d4fae6d6f0eab5',
  '6e4eafe43472ef9407e3f16e8811afcf',
  '1a2f43dbf130326ff1c7bd35b272f757',
  '3f19534006c1948d3748723ff470934c',
  '69398ef296675829e23d776618ee9387',
  'ec4a19b84b0ab2fef69b26bf0f1eed7a',
  '2a102276fa5b842e402ae849d49a1e07',
  '7cba943653e8c467e270191f0248c691',
  '21dfd3061c743f6f6bc898a54619aa1d',
  'e0477205a6dc16f27be942232406cce9',
  '29bb9595d6df9bf3d609fabf3503f05f',
  'f14ac314fc1ec9fccad8fbb004d02493',
  '9b475b963c725e3d14ebe579557a682d',
  '118b46ce39d639794827b78446a4776d',
  'a1c6a5016f1863f208b029c6ede70557',
  'e5b5b94f4397c8934b08a09c87a6adfa',
  '151ef3626b8589b9e234a6cd39b92dcf',
  '2512165f85dad14da66233aaa3653887',
  '39e1d55a7b34faa5b94f537707d3da2c',
  '6bdda3e6ce2e31fd0486e9525cd658a8',
  '4b304504479a493aac018cd810d8660f',
  '14c5f62b7ce0ad524bc662cee59aae10',
  'eba8a413feb716fbc74dc233cff319a3',
  'b630e3f66978840ee9c5a6ca29418ab4',
  '34dad87d9ae4abf3d986573605bd3464',
  '5bd98ee1e8e8407cd8d0265aa3a20339',
  '0fc9c083f92fa9921f95cec841e31d48',
  'b7028d207895c7ab60db56b52eeaf988',
  '543a294d3d27ed376e0eedd54451c706',
  '422911a2d64cd07688f35059d60d393d',
  'e5b25c73e8cb12092d0dbdcc97c150f1',
  '14a04e1fbb4d378bf4d28e36a87046f3',
  'f983e3703d3822206f3c677408f69646',
  '6478830fd1edd843a677078af063deb8',
  'b360b4d0c4360b9b1a7e0a446596b61c',
  'f1483cec9075d255c46990a2e29283e4',
  '421682f36e726bda5033aa7b809bb2fb',
  '97ccf2fa2678739cabb2c54a67045b94',
  '112174a36bde83265baa0ec3dd03a37b',
  'e6129dc730b40f1a2bda38a282df6a6d',
  'b0092a61509b87243142ea3a479b25cd',
  '3947a0a8b7080cad2da8bfe76b24171c',
  '2b5a176ecd3905eca542569b7843b899',
  '5df6094dd48eb84bcfdb2878307f8178',
  '0e7e010c8c30d83322de00ef740d9881',
  '8aed31a6f83132b337f9134e74a8538b',
  '033027b3f5bf1a755c8a2480ad26eb36',
  '70b1ee651b5e95d85b01da0c6c200e74',
  'ea17e08c79b7425dbc09177b73bc61fe',
  '5be2cbb073cc1321617d0f86a3e9e8a1',
  '9f9e030e536a46527cfc8d9e27ca78d9',
  'e79660fcb74ac102e24db02a63b50869',
  '389043520da7e1b10698dcb4018fb3a9',
  'e7cfa4c6ce2be2f7f1d9e6de0df2ffff',
  '4d69bf375227c39d374a27cd0ce5882d',
  'ca0dc55123d43b8e70b62b7de87e253d',
  'b30933ce22971d64a27bca97d1e3d966',
  '0a8ef85641cbf6fe1b635177551e5848',
  '8796d66d23c64126c8231aafb79f1f89',
  '1f7bea141de4be8af238cf9bd9ecc3ab',
  'f83c117db176fb0190eaf936cb962ede',
  '60defc4a0ee6736c80e005bccbaddfa6',
  '91882272febda203adf89444d171779e',
  '83fff70c38f90965ef5d61297db8a5fb',
  '3c8aa8b2d38b4a34e9a7b580a0d556d6',
  'f0dceb14be83c956a445c526b66abfbd',
  'ec9ddc086aa08aed47c8d81d3ee94791',
  '3f7002bd9cd9e8f18ba0b082ee32873c',
  '7b4d0b7b6c6042843fba5d156279c8bc',
  '816966cf3fad8b5c26b142cb2b5ff26f',
  '00c1a462240b24a541deff2ab8861ad7',
  'cb49f371cbc273ff94c22303d64882ea',
  'fd87c721e9504edbbba2108718d411f1',
  '738d16eeb8b0f5d4cb05c5b1f80a1192',
  'a7facaa13e05bb0ab415ce3d786f7103',
  '8ca9c9df75ea9aad2171f725570a9ae6',
  '43cf4d9bef7efa8b786793e15eaec999',
  'b29220320b88fa4364832466d2cb5063',
  '5b4d797693cd5a64cbb3a4594b2d61a3',
  '33dedd1c6681cd6283bb77f4f9690967',
  'd2b4ec420058995acce6d5eb8364352c',
  '4aba41709190b44d133e28e937fc9e8c',
  '1890b93256afb7371b09a43ca27f67f4',
  '7b2662254911b3c03ca7c691627f4cc8',
  '3233b23ccf342c033a6a7d1e81924cf8',
  '9999e7e2b30003ceee1baecc3016e2c7',
  '434bba1a5ac647b9d6b961b63ad68d26',
  'b105a749a88d42d24b670ff9247839f8',
  '2e5894c60dc1cb1dbb0215d16a3d27b5',
  '23a60fc6b9d9dd1859e774f1408cbe9a',
  '56ad5bf7b869402010006f5d1bcf3d79',
  '57249e09a163cce12d959a08caa93750',
  '76aa942b6fe2dd6ae30d3a1df1288667',
  '2c55b57b759482d9b88858d422c95903',
  '6986f96ce9ea34bd503ace209d8e9b48',
  'b3682561cd95d60179862f7dab3a947d',
  'aa5d4d7ec40117fd1ce379e0633d5843',
  '81152962fa62e7b83086d230c48f07fc',
  'f5b7aab310b3b28d05afa9eaf22b1917',
  'e0253df79b2c2b79116ac27dbeee0cc4',
  'a27e8e867e0106104d5ee009e0ae0533',
  '8448b76a592abc3d065374f5b1e5d89a',
  '194b80d49391e44e3c0930b7623e832f',
  '46e6f19652782ae9823d8dbdd26c6beb',
  '42599cc72544b841e1e655387f504e76',
  '404a20a474a9fddfb04b106f8b8c5d3e',
  '0b29e7cd011dfe50473385add097b0a8',
  '86c06bd9a3937297e0bd7eee65af704d',
  '5c877d88db7b088a1f36896ea737f17f',
  '3fda736894cc481f75a03c04c2772bdc',
  '82f13e68b5e213dcb4f9acb4686b565b',
  'dc2fb92a6b4e99f8495021f09cf1a446',
  '197682437903e1e6d909427010a87e19',
  'c2b11b51d834b02437c31b491cf9aa88',
  '8f0d18ef247942db3cc226acac9fafb2',
  '5794c13e45117ad1d1a2d55831c6e99e',
  'a1839233db669eeec33766d067f91298',
  '3accd064e4fe999580b568ec27c29d28',
  '582b80df37a7f0c1c282c81d10c3b7d4',
  '1bebdd5b880d6f61b098317c60ff0c0e'
]);
function isThiralTNPolitics5000Question(q){
  return THIRAL_TN_POLITICS_5000_HASHES.has(crypto.createHash('md5').update(String(q||'')).digest('hex'));
}

function canonicalSubject(raw){ return SUBJECT_ALIASES[String(raw||'').trim()] || String(raw||'').trim(); }
function subjectCandidates(raw){
  const s=String(raw||'').trim();
  if(!s) return [];
  const canonical=canonicalSubject(s);
  const aliases=Object.entries(SUBJECT_ALIASES)
    .filter(([label,key]) => key===canonical)
    .map(([label])=>label);
  return [...new Set([canonical,s,...aliases].filter(Boolean))];
}
function subtopicCandidates(raw){
  const s=String(raw||'').trim();
  if(!s) return [];
  const a=[s, GROUP4_SUBTOPIC_ALIASES[s] || ''];
  return [...new Set(a.filter(Boolean))];
}

function newSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function setSessionCookie(res, id) {
  res.cookie('thiral_session', id, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 20 * 60 * 1000,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie('thiral_session', { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' });
}

/* ===== ONE-STUDENT / ONE-DEVICE ACCOUNT BINDING =====
   Student credentials alone are not enough to move an account to another
   browser/device. The first successful student registration/login binds the
   account to a random httpOnly device cookie. A different device is rejected
   server-side. Admin accounts are intentionally excluded from this rule.
*/
const DEVICE_COOKIE_NAME = 'thiral_device';

function deviceBindingSecret(){
  return String(
    process.env.THIRAL_DEVICE_BINDING_SECRET ||
    process.env.THIRAL_API_KEY ||
    process.env.DATABASE_URL ||
    'thiral-device-binding-dev-only'
  );
}

function newDeviceId(){
  return crypto.randomBytes(32).toString('hex');
}

function hashDeviceId(deviceId){
  return crypto.createHmac('sha256', deviceBindingSecret())
    .update(String(deviceId || ''))
    .digest('hex');
}

function getOrCreateDeviceId(req, res){
  const existing=String(req.cookies?.[DEVICE_COOKIE_NAME] || '').trim();
  if(existing) return { id:existing, isNew:false };
  const id=newDeviceId();
  res.cookie(DEVICE_COOKIE_NAME,id,{
    httpOnly:true,
    secure:isProd,
    sameSite:'strict',
    maxAge:365*24*60*60*1000,
    path:'/'
  });
  return { id, isNew:true };
}

function setDeviceCookie(res, deviceId){
  res.cookie(DEVICE_COOKIE_NAME,String(deviceId||''),{
    httpOnly:true,
    secure:isProd,
    sameSite:'strict',
    maxAge:365*24*60*60*1000,
    path:'/'
  });
}

async function enforceStudentDeviceBinding({req,res,user}){
  if(!user || user.role !== 'STUDENT') return {ok:true};

  const device=String(req.cookies?.[DEVICE_COOKIE_NAME] || '').trim();
  if(!device){
    const created=newDeviceId();
    const boundHash=hashDeviceId(created);
    const bound=await pool.query(
      `UPDATE users
          SET login_device_hash=$1
        WHERE id=$2 AND role='STUDENT' AND login_device_hash IS NULL
      RETURNING id`,
      [boundHash,user.id]
    );
    if(bound.rowCount){
      setDeviceCookie(res,created);
      return {ok:true};
    }
    return {ok:false};
  }

  const current=await pool.query(
    `SELECT login_device_hash FROM users WHERE id=$1 AND role='STUDENT' LIMIT 1`,
    [user.id]
  );
  const stored=String(current.rows[0]?.login_device_hash || '').trim();

  if(!stored){
    const boundHash=hashDeviceId(device);
    await pool.query(
      `UPDATE users SET login_device_hash=$1
       WHERE id=$2 AND role='STUDENT' AND login_device_hash IS NULL`,
      [boundHash,user.id]
    );
    return {ok:true};
  }

  if(stored !== hashDeviceId(device)) return {ok:false};
  return {ok:true};
}

async function getUserFromSession(req) {
  const sid = req.cookies?.thiral_session;
  if (!sid) return null;
  const q = await pool.query(
    `SELECT u.id,u.student_id,u.name,u.email,u.phone,u.dob,u.gender,u.role,u.is_active,u.must_change_password,s.expires_at
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.id=$1 AND s.expires_at > now() AND u.is_active=true`, [sid]
  );
  return q.rows[0] || null;
}

async function requireAuth(req, res, next) {
  try {
    const user = await getUserFromSession(req);
    if (!user) return sendError(res, 401, 'ACCESS DENIED: Login required.');
    req.user = user;
    next();
  } catch (e) {
    console.error(e);
    return sendError(res, 500, 'Authentication service error.');
  }
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, async () => {
    if (req.user.role !== 'ADMIN') {
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',userId:req.user.id,email:req.user.email,details:`Attempted ${req.method} ${req.originalUrl}`,sendAlert:true});
      return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    }
    next();
  });
}

async function requirePasswordReady(req, res, next) {
  // A student's password is permanent until the student explicitly changes it
  // or completes the password-reset flow. Never force a password change merely
  // because a session expired or because an admin previously set the password.
  return requireAuth(req, res, next);
}

async function ensureAdmin() {
  const adminId = (process.env.ADMIN_ID || '').trim();
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  if (!adminId || !adminPassword) {
    console.warn('ADMIN_ID / ADMIN_PASSWORD not set. Admin login cannot be seeded automatically.');
    return;
  }
  const hash = await argon2.hash(adminPassword);
  const existing = await pool.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [adminId]);
  if (existing.rowCount) {
    await pool.query(
      `UPDATE users SET role='ADMIN', is_active=true, must_change_password=false, password_hash=$1, email=$2 WHERE id=$3`,
      [hash, adminId, existing.rows[0].id]
    );
    console.log(`Admin account ready: ${adminId}`);
  } else {
    let studentId = 'ADMIN-0001';

    const idCheck = await pool.query(
      'SELECT 1 FROM users WHERE student_id=$1 LIMIT 1',
      [studentId]
    );

    if (idCheck.rowCount) {
      const suffix = crypto.randomBytes(4).toString('hex').toUpperCase();
      studentId = `ADMIN-${suffix}`;
    }

    await pool.query(
      `INSERT INTO users(student_id,name,email,password_hash,role,is_active,must_change_password)
       VALUES($1,$2,$3,$4,'ADMIN',true,false)`,
      [studentId, 'Thiral Administrator', adminId, hash]
    );

    console.log(`Admin account created: ${adminId} (${studentId})`);
  }
}

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'Thiral V167 Secure Temporary Password', database: 'ok', time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, service: 'Thiral V167 Secure Temporary Password', database: 'error' });
  }
});

const api = express.Router();
api.use(apiLimiter);

api.get('/auth/me', async (req, res) => {
  try {
    const user = await getUserFromSession(req);
    res.json({ user: user || null });
  } catch (e) { sendError(res, 500, 'Authentication service error.'); }
});

async function isLoginTemporarilyBlocked(email, ip){
  const q=await pool.query(`
    SELECT count(*)::int AS n
    FROM security_events
    WHERE event_type='FAILED_LOGIN'
      AND created_at>=now()-interval '15 minutes'
      AND (lower(coalesce(email,''))=lower($1) OR ip=$2)`,[email,ip]);
  return Number(q.rows[0]?.n||0) >= 8;
}

api.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) return sendError(res, 400, 'ID/email and password are required.');
    const loginIp=clientIp(req);
    if(await isLoginTemporarilyBlocked(email,loginIp)){
      await logSecurityEvent({req,eventType:'LOGIN_BLOCKED',email,details:'Temporary login block after repeated failed attempts',sendAlert:true});
      return sendError(res,429,'Too many failed login attempts. Please try again later.');
    }
    const q = await pool.query(
      `SELECT id,student_id,name,email,password_hash,phone,dob,gender,role,is_active,must_change_password FROM users WHERE lower(email)=lower($1) LIMIT 1`, [email]
    );
    const u = q.rows[0];
    if (!u || !u.is_active) {
      await logSecurityEvent({req,eventType:'FAILED_LOGIN',email,details:'Unknown or inactive account',sendAlert:true});
      return sendError(res, 401, 'Invalid ID/email or password.');
    }
    const ok = await argon2.verify(u.password_hash, password);
    if (!ok) {
      await logSecurityEvent({req,eventType:'FAILED_LOGIN',userId:u.id,email:u.email,details:'Invalid password',sendAlert:true});
      return sendError(res, 401, 'Invalid ID/email or password.');
    }

    const sid = newSessionId();
    await pool.query(`DELETE FROM sessions WHERE expires_at <= now()`);
    await pool.query(`INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')`, [sid, u.id]);
    await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [u.id]);
    await pool.query(`INSERT INTO activity_events(user_id,event_type,metadata) VALUES($1,'LOGIN',$2)`, [u.id, JSON.stringify({ role: u.role })]);
    if(u.role==='ADMIN') await logSecurityEvent({req,eventType:'ADMIN_LOGIN_SUCCESS',userId:u.id,email:u.email,details:'Admin login successful',sendAlert:true});
    setSessionCookie(res, sid);
    delete u.password_hash;
    res.json({ user: u });
  } catch (e) {
    console.error(e);
    sendError(res, 500, 'Login service error.');
  }
});


/*
 * Registration date normalization.
 * The frontend may send DOB as DD/MM/YYYY (for example 21/07/1991),
 * while PostgreSQL DATE expects ISO YYYY-MM-DD.
 * Existing database rows are not changed.
 */
function normalizeRegistrationDate(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;

  // Already ISO: YYYY-MM-DD
  let m = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) {
    const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) {
      throw new Error('Invalid date of birth.');
    }
    return value;
  }

  // Common Indian form: DD/MM/YYYY
  m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) {
    // Also accept DD-MM-YYYY without changing the frontend.
    m = value.match(/^(\d{2})-(\d{2})-(\d{4})$/);
  }

  if (m) {
    const d = Number(m[1]), mo = Number(m[2]), y = Number(m[3]);
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) {
      throw new Error('Invalid date of birth.');
    }
    return `${String(y).padStart(4, '0')}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
  }

  throw new Error('Invalid date of birth. Use DD/MM/YYYY.');
}

api.post('/auth/register', authLimiter, async (req, res) => {
  let client;
  try {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const phone = String(req.body?.phone || '').trim();
    const dob = normalizeRegistrationDate(req.body?.dob);
    const gender = String(req.body?.gender || '').trim();

    if (!name || !email || password.length < 8) {
      return sendError(res, 400, 'Name, valid email and password (minimum 8 characters) are required.');
    }

    /*
       Registration-safe student number allocation.
       This version does NOT depend on a custom PostgreSQL function or sequence.
       It uses a transaction-scoped advisory lock so two simultaneous
       registrations cannot receive the same THR number.
       Existing rows are only read; nothing is deleted or rewritten.
    */
    client = await pool.connect();
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [741926]);

    const exists = await client.query(
      'SELECT 1 FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [email]
    );
    if (exists.rowCount) {
      await client.query('ROLLBACK');
      return sendError(res, 409, 'This email is already registered.');
    }

    const numberQ = await client.query(`
      SELECT COALESCE(
        MAX((substring(student_id FROM '^THR-([0-9]+)$'))::BIGINT),
        0
      ) + 1 AS next_number
      FROM users
      WHERE student_id ~ '^THR-[0-9]+$'
    `);

    const nextNumber = Number(numberQ.rows[0]?.next_number || 1);
    if (!Number.isSafeInteger(nextNumber) || nextNumber < 1) {
      await client.query('ROLLBACK');
      return sendError(res, 500, 'Unable to allocate a new student ID safely.');
    }

    const studentId = `THR-${String(nextNumber).padStart(6, '0')}`;
    const hash = await argon2.hash(password);
    const registrationDeviceId=newDeviceId();
    const registrationDeviceHash=hashDeviceId(registrationDeviceId);

    const ins = await client.query(
      `INSERT INTO users(student_id,name,email,password_hash,phone,dob,gender,role,is_active,login_device_hash)
       VALUES($1,$2,$3,$4,$5,$6,$7,'STUDENT',true,$8)
       RETURNING id,student_id,name,email,phone,dob,gender,role,is_active,created_at,last_login_at`,
      [studentId, name, email, hash, phone, dob, gender, registrationDeviceHash]
    );

    const u = ins.rows[0];
    const sid = newSessionId();
    await client.query(
      `INSERT INTO sessions(id,user_id,expires_at)
       VALUES($1,$2,now()+interval '30 minutes')`,
      [sid, u.id]
    );

    await client.query('COMMIT');
    setSessionCookie(res, sid);
    setDeviceCookie(res, registrationDeviceId);
    return res.json({ user: u });
  } catch (e) {
    if (client) {
      try { await client.query('ROLLBACK'); } catch (_) {}
    }

    console.error('Registration service error:', {
      code: e?.code || null,
      message: e?.message || String(e),
      detail: e?.detail || null,
      constraint: e?.constraint || null,
      table: e?.table || null,
      column: e?.column || null
    });

    if (e?.code === '23505') {
      return sendError(res, 409, 'Email or student ID already exists.');
    }
    return sendError(res, 500, 'Registration service error.');
  } finally {
    if (client) client.release();
  }
});


/* =========================================================
   THIRAL V162 SECURE OTP
   Password reset uses:
   Render -> HTTPS -> Google Apps Script -> Gmail
   No SMTP connection is required on Render.
   ========================================================= */

function otpConfigReady(){
  return Boolean(
    String(process.env.THIRAL_APPS_SCRIPT_URL || '').trim() &&
    String(process.env.THIRAL_API_KEY || '').trim()
  );
}

function hashOtp(value){
  const pepper = String(process.env.OTP_PEPPER || '').trim();
  return crypto
    .createHash('sha256')
    .update(pepper + ':' + String(value))
    .digest('hex');
}

function newOtp(){
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function newResetToken(){
  return crypto.randomBytes(32).toString('hex');
}

async function sendOtpThroughAppsScript(to, otp){
  const url = String(process.env.THIRAL_APPS_SCRIPT_URL || '').trim();
  const apiKey = String(process.env.THIRAL_API_KEY || '').trim();

  if(!url || !apiKey) throw new Error('OTP bridge configuration is missing.');

  const response = await fetch(url, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    redirect:'follow',
    body:JSON.stringify({
      api_key:apiKey,
      to:String(to || '').trim().toLowerCase(),
      otp:String(otp || '')
    })
  });

  const text = await response.text();
  let data = {};
  try { data = JSON.parse(text); } catch (_) {}

  if(!response.ok || data.ok !== true){
    const err = new Error('OTP email delivery failed.');
    err.status = response.status;
    err.bridgeMessage = String(data.message || '').slice(0,200);
    throw err;
  }
  return true;
}

function otpPublicMessage(){
  return 'If the registered email exists, an OTP has been sent.';
}

api.post('/auth/forgot-password/request', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();

    if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
      return sendError(res,400,'Valid email is required.');
    }

    if(!otpConfigReady()){
      console.error('[OTP] Bridge configuration missing.');
      return sendError(res,503,'OTP service is not configured.');
    }

    const q = await pool.query(
      `SELECT id,email,is_active,role
       FROM users
       WHERE lower(email)=lower($1)
       LIMIT 1`,
      [email]
    );

    /*
      Do not reveal whether an email is registered.
      Only active STUDENT accounts can use student password reset.
    */
    const user = q.rows[0];
    if(!user || !user.is_active || user.role !== 'STUDENT'){
      return res.json({ok:true,message:otpPublicMessage()});
    }

    const recent = await pool.query(
      `SELECT id
       FROM password_reset_otps
       WHERE user_id=$1
         AND created_at > now() - interval '60 seconds'
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );

    if(recent.rowCount){
      return sendError(res,429,'Please wait before requesting another OTP.');
    }

    const otp = newOtp();
    const otpHash = hashOtp(otp);

    await pool.query(
      `UPDATE password_reset_otps
       SET used_at=now()
       WHERE user_id=$1 AND used_at IS NULL`,
      [user.id]
    );

    const ins = await pool.query(
      `INSERT INTO password_reset_otps
       (user_id,email,otp_hash,expires_at,attempts,used_at)
       VALUES($1,$2,$3,now()+interval '10 minutes',0,NULL)
       RETURNING id`,
      [user.id,user.email,otpHash]
    );

    try{
      await sendOtpThroughAppsScript(user.email,otp);
      console.log('[OTP] Apps Script mail sent successfully.');
    }catch(mailErr){
      await pool.query(
        `UPDATE password_reset_otps SET used_at=now() WHERE id=$1`,
        [ins.rows[0].id]
      );
      console.error('[OTP] Apps Script mail failed:', {
        status:mailErr?.status || null,
        message:mailErr?.message || String(mailErr),
        bridgeMessage:mailErr?.bridgeMessage || null
      });
      return sendError(res,502,'OTP email delivery failed.');
    }

    return res.json({ok:true,message:otpPublicMessage()});
  }catch(e){
    console.error('[OTP] Request error:',e);
    return sendError(res,500,'OTP service error.');
  }
});

api.post('/auth/forgot-password/verify', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();
    const otp = String(req.body?.otp || '').trim();

    if(!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(otp)){
      return sendError(res,400,'Email and 6-digit OTP are required.');
    }

    const q = await pool.query(
      `SELECT o.id,o.user_id,o.otp_hash,o.expires_at,o.attempts,
              u.email,u.is_active,u.role
       FROM password_reset_otps o
       JOIN users u ON u.id=o.user_id
       WHERE lower(u.email)=lower($1)
         AND o.used_at IS NULL
       ORDER BY o.created_at DESC
       LIMIT 1`,
      [email]
    );

    if(!q.rowCount) return sendError(res,400,'Invalid or expired OTP.');

    const row = q.rows[0];

    if(!row.is_active || row.role !== 'STUDENT'){
      return sendError(res,400,'Invalid or expired OTP.');
    }

    if(new Date(row.expires_at).getTime() <= Date.now()){
      return sendError(res,400,'OTP has expired.');
    }

    if(Number(row.attempts) >= 5){
      return sendError(res,429,'Too many incorrect OTP attempts.');
    }

    const suppliedHash = hashOtp(otp);

    if(!crypto.timingSafeEqual(
      Buffer.from(suppliedHash,'utf8'),
      Buffer.from(String(row.otp_hash),'utf8')
    )){
      await pool.query(
        `UPDATE password_reset_otps
         SET attempts=attempts+1
         WHERE id=$1`,
        [row.id]
      );
      return sendError(res,400,'Invalid or expired OTP.');
    }

    const resetToken = newResetToken();
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    await pool.query(
      `UPDATE password_reset_otps
       SET verified_at=now(),reset_token_hash=$1
       WHERE id=$2`,
      [resetTokenHash,row.id]
    );

    return res.json({ok:true,reset_token:resetToken});
  }catch(e){
    console.error('[OTP] Verify error:',e);
    return sendError(res,500,'OTP verification service error.');
  }
});

api.post('/auth/forgot-password/reset', authLimiter, async (req,res)=>{
  try{
    const email = String(req.body?.email || '').trim().toLowerCase();
    const resetToken = String(req.body?.reset_token || '').trim();
    const newPassword = String(req.body?.password || '');

    if(!email || !resetToken || newPassword.length < 8){
      return sendError(res,400,'Email, reset token and password (minimum 8 characters) are required.');
    }

    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    const q = await pool.query(
      `SELECT o.id,o.user_id,o.reset_token_hash,o.verified_at,
              u.email,u.is_active,u.role
       FROM password_reset_otps o
       JOIN users u ON u.id=o.user_id
       WHERE lower(u.email)=lower($1)
         AND o.reset_token_hash=$2
         AND o.used_at IS NULL
         AND o.verified_at IS NOT NULL
         AND o.expires_at > now()
       ORDER BY o.created_at DESC
       LIMIT 1`,
      [email,tokenHash]
    );

    if(!q.rowCount) return sendError(res,400,'Invalid or expired password reset token.');

    const row = q.rows[0];

    if(!row.is_active || row.role !== 'STUDENT'){
      return sendError(res,400,'Invalid password reset request.');
    }

    const passwordHash = await argon2.hash(newPassword);

    await pool.query('BEGIN');
    try{
      await pool.query(
        `UPDATE users SET password_hash=$1,login_device_hash=NULL WHERE id=$2`,
        [passwordHash,row.user_id]
      );

      await pool.query(
        `UPDATE password_reset_otps
         SET used_at=now(),reset_token_hash=NULL
         WHERE id=$1`,
        [row.id]
      );

      /* Password reset invalidates all existing sessions for this student. */
      await pool.query(
        `DELETE FROM sessions WHERE user_id=$1`,
        [row.user_id]
      );

      await pool.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'PASSWORD_RESET',$2)`,
        [row.user_id,JSON.stringify({method:'OTP'})]
      );

      await pool.query('COMMIT');
    }catch(e){
      await pool.query('ROLLBACK');
      throw e;
    }

    return res.json({ok:true,message:'Password reset successfully.'});
  }catch(e){
    console.error('[OTP] Password reset error:',e);
    return sendError(res,500,'Password reset service error.');
  }
});



api.post('/auth/change-password', requireAuth, async (req,res)=>{
  const client = await pool.connect();
  try{
    if(req.user.role !== 'STUDENT'){
      return sendError(res,403,'Only student accounts can change this password.');
    }

    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');
    const confirmPassword = String(req.body?.confirm_password || '');

    if(!currentPassword || !newPassword || !confirmPassword){
      return sendError(res,400,'Current password, new password and confirm password are required.');
    }
    if(newPassword.length < 8){
      return sendError(res,400,'New Password must be at least 8 characters.');
    }
    if(newPassword !== confirmPassword){
      return sendError(res,400,'New Password and Confirm Password must match.');
    }
    if(newPassword === currentPassword){
      return sendError(res,400,'New Password must be different from the temporary password.');
    }

    const q = await client.query(
      `SELECT id,password_hash,must_change_password,is_active,role
       FROM users WHERE id=$1 LIMIT 1 FOR UPDATE`,
      [req.user.id]
    );

    if(!q.rowCount || !q.rows[0].is_active || q.rows[0].role !== 'STUDENT'){
      return sendError(res,401,'Invalid password change request.');
    }

    const validCurrent = await argon2.verify(q.rows[0].password_hash,currentPassword);
    if(!validCurrent){
      return sendError(res,401,'Current password is incorrect.');
    }

    const passwordHash = await argon2.hash(newPassword);
    await client.query('BEGIN');
    await client.query(
      `UPDATE users
       SET password_hash=$1,must_change_password=false,login_device_hash=NULL
       WHERE id=$2`,
      [passwordHash,req.user.id]
    );
    await client.query(
      `INSERT INTO activity_events(user_id,event_type,metadata)
       VALUES($1,'PASSWORD_CHANGED',$2)`,
      [req.user.id,JSON.stringify({method:q.rows[0].must_change_password ? 'FORCED_FIRST_LOGIN' : 'SELF_SERVICE'})]
    );
    await client.query('COMMIT');

    return res.json({ok:true,message:'Password changed successfully.'});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('[PASSWORD] Change error:',e);
    return sendError(res,500,'Password change service error.');
  }finally{
    client.release();
  }
});

api.patch('/admin/students/:studentId/password', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    const temporaryPassword = String(req.body?.temporary_password || '');

    if(!studentId || temporaryPassword.length < 8){
      return sendError(res,400,'Student ID and a temporary password of at least 8 characters are required.');
    }

    const q = await client.query(
      `SELECT id,student_id,role,is_active
       FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount) return sendError(res,404,'Student not found.');

    const target = q.rows[0];
    if(target.role !== 'STUDENT') return sendError(res,400,'Only STUDENT accounts can be changed here.');
    if(!target.is_active) return sendError(res,400,'Student account is inactive. Reactivate it before setting a temporary password.');

    const passwordHash = await argon2.hash(temporaryPassword);

    await client.query('BEGIN');
    await client.query(
      `UPDATE users
       SET password_hash=$1,must_change_password=false,login_device_hash=NULL
       WHERE id=$2`,
      [passwordHash,target.id]
    );
    await client.query(`DELETE FROM sessions WHERE user_id=$1`,[target.id]);
    await client.query(
      `INSERT INTO activity_events(user_id,event_type,metadata)
       VALUES($1,'TEMP_PASSWORD_SET',$2)`,
      [req.user.id,JSON.stringify({target_student_id:target.student_id})]
    );
    await client.query('COMMIT');

    return res.json({
      ok:true,
      student_id:target.student_id,
      must_change_password:false,
      message:'Student password updated successfully. The student can continue using this password until they explicitly change or reset it.'
    });
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('[ADMIN] Temporary password error:',e);
    return sendError(res,500,'Temporary password service error.');
  }finally{
    client.release();
  }
});

api.post('/auth/heartbeat', requireAuth, async (req,res)=>{
  try{
    const sid = req.cookies?.thiral_session;
    if(!sid) return sendError(res,401,'Login required.');
    await pool.query(
      `UPDATE sessions SET expires_at=now()+interval '30 minutes' WHERE id=$1`,
      [sid]
    );
    res.json({ok:true,expires_at:new Date(Date.now()+30*60*1000).toISOString()});
  }catch(e){
    console.error('[HEARTBEAT] error:',e);
    sendError(res,500,'Session heartbeat service error.');
  }
});

api.post('/auth/logout', async (req, res) => {
  try {
    const sid = req.cookies?.thiral_session;
    if (sid) await pool.query('DELETE FROM sessions WHERE id=$1', [sid]);
  } catch (e) { console.error(e); }
  clearSessionCookie(res);
  res.json({ ok: true });
});

api.get('/questions', requirePasswordReady, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const rawSubject = String(req.query.subject || '').trim();
    const subject = canonicalSubject(rawSubject);
    const subjectCandidatesList = subjectCandidates(rawSubject);
    const language = String(req.query.language || 'ta').trim();
    const subtopic = String(req.query.subtopic || '').trim();
    const historyMode = String(req.query.historyMode || '').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit || '20',10) || 20,1),200);
    const offset = Math.max(parseInt(req.query.offset || '0',10) || 0,0);
    if (!exam || !subject || !['ta','en'].includes(language)) return sendError(res,400,'Invalid question request.');

    const where = ['exam=$1','subject = ANY($2::text[])','language=$3','is_active=true'];
    const params = [exam, subjectCandidatesList, language];
    let n = 4;
    const subCandidates = subtopicCandidates(subtopic);
    if (subtopic === THIRAL_TN_POLITICS_5000_SUBTOPIC) {
      /* Exact batch filter. This keeps the 5,000 uploaded rows together
         without changing their stored subtopic values. */
      where.push(`md5(question) = ANY($${n}::text[])`);
      params.push([...THIRAL_TN_POLITICS_5000_HASHES]);
      n++;
    } else if (subCandidates.length === 1) {
      where.push(`subtopic=$${n++}`); params.push(subCandidates[0]);
    } else if (subCandidates.length > 1) {
      where.push(`subtopic = ANY($${n}::text[])`); params.push(subCandidates); n++;
    }

    /* Question Bank continuation: exclude only questions already used
       in this user's Question Bank mode. Normal Practice/Mock are unchanged. */
    if (historyMode === 'bank') {
      where.push(`NOT EXISTS (
        SELECT 1 FROM question_history h
        WHERE h.user_id = ${n}
          AND h.question_id = questions.id
          AND h.mode = 'bank'
      )`);
      params.push(req.user.id);
      n++;
    }

    const countQ = await pool.query(`SELECT count(*)::int AS total FROM questions WHERE ${where.join(' AND ')}`, params);
    const total = Number(countQ.rows[0]?.total || 0);

    const dataParams = [...params, limit, offset];
    const q = await pool.query(
      `SELECT id,exam,subject,subtopic,language,question,options,explanation,
              COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
       FROM questions
       WHERE ${where.join(' AND ')}
       ORDER BY id LIMIT $${n} OFFSET $${n+1}`, dataParams
    );

    const nextOffset = offset + q.rows.length;
    res.json({
      questions:q.rows,
      pagination:{limit,offset,returned:q.rows.length,total,hasMore:nextOffset<total,nextOffset}
    });
  } catch(e) { console.error(e); sendError(res,500,'Question service error.'); }
});

/* ===== FAST PRACTICE API =====
   Existing /questions API is intentionally left unchanged.
   Practice gets only the requested number of fresh questions.
*/
api.get('/practice/questions', requirePasswordReady, async (req, res) => {
  try {
    const exam = String(req.query.exam || '').trim();
    const rawSubject = String(req.query.subject || '').trim();
    const subject = canonicalSubject(rawSubject);
    const subjectCandidatesList = subjectCandidates(rawSubject);
    const language = String(req.query.language || 'ta').trim();
    const subtopic = String(req.query.subtopic || '').trim();
    const limit = Math.min(
      Math.max(parseInt(req.query.limit || '10', 10) || 10, 1),
      200
    );

    if (!exam || !subject || !['ta', 'en'].includes(language)) {
      return sendError(res, 400, 'Invalid question request.');
    }

    const params = [req.user.id, exam, subjectCandidatesList, language];
    let n = 5;

    let where = `
      q.exam = $2
      AND q.subject = ANY($3::text[])
      AND q.language = $4
      AND q.is_active = true
    `;

    const subCandidates = subtopicCandidates(subtopic);
    if (subCandidates.length === 1) {
      where += ` AND q.subtopic = $${n}`;
      params.push(subCandidates[0]);
      n++;
    } else if (subCandidates.length > 1) {
      where += ` AND q.subtopic = ANY($${n}::text[])`;
      params.push(subCandidates);
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
        `???? ????????? ???????? ????? ????????? ${result.rows.length} ??????? ?????.`
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

api.post('/attempts', requirePasswordReady, async (req,res)=>{
  try {
    const {exam,subject,mode,language,questionIds}=req.body||{};
    if(!exam || !subject || !['practice','mock','bank'].includes(mode) || !['ta','en','mixed'].includes(language) || !Array.isArray(questionIds) || !questionIds.length) return sendError(res,400,'Invalid attempt.');
    const ids=[...new Set(questionIds.map(Number).filter(Number.isInteger))];
    if(!ids.length || ids.length>5000) return sendError(res,400,'Invalid question list.');
    const q = language==='mixed'
      ? await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND is_active=true`,[ids,exam])
      : await pool.query(`SELECT id FROM questions WHERE id=ANY($1::bigint[]) AND exam=$2 AND language=$3 AND is_active=true`,[ids,exam,language]);
    const valid=new Set(q.rows.map(x=>String(x.id)));
    const clean=ids.filter(id=>valid.has(String(id)));
    if(clean.length!==ids.length) return sendError(res,400,'Some questions are not valid for this exam/language.');
    const ins=await pool.query(`INSERT INTO attempts(user_id,exam,subject,mode,language,question_ids) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,[req.user.id,exam,subject,mode,language,clean]);

    /* Normal Practice/Mock questions are reserved immediately.
       Question Bank is different: a question becomes 'used' only when
       the student actually finishes/logs out of that bank session. */
    if (mode !== 'bank') {
      await pool.query(
        `INSERT INTO question_history(user_id, question_id, mode)
         SELECT $1, x, $2
         FROM unnest($3::bigint[]) AS x
         ON CONFLICT (user_id, question_id, mode)
         DO NOTHING`,
        [req.user.id, mode, clean]
      );
    }

    res.json({id:ins.rows[0].id});
  }catch(e){console.error(e);sendError(res,500,'Attempt service error.');}
});

api.post('/attempts/:id/check-answer', requirePasswordReady, async (req,res)=>{
  try {
    const attemptId=Number(req.params.id);
    const questionId=Number(req.body?.questionId);
    const answer=Number(req.body?.answer);

    if(!Number.isInteger(attemptId) || !Number.isInteger(questionId) || !Number.isInteger(answer)) {
      return sendError(res,400,'Invalid answer data.');
    }

    const attemptResult=await pool.query(
      `SELECT id,status,question_ids
       FROM attempts
       WHERE id=$1 AND user_id=$2
       LIMIT 1`,
      [attemptId,req.user.id]
    );

    if(!attemptResult.rowCount) {
      return sendError(res,404,'Attempt not found.');
    }

    const attempt=attemptResult.rows[0];

    if(attempt.status==='SUBMITTED') {
      return sendError(res,409,'Attempt already submitted.');
    }

    const questionIds=Array.isArray(attempt.question_ids)
      ? attempt.question_ids.map(Number)
      : [];

    if(!questionIds.includes(questionId)) {
      return sendError(res,400,'Question does not belong to this attempt.');
    }

    const questionResult=await pool.query(
      `SELECT correct_option,explanation
       FROM questions
       WHERE id=$1 AND is_active=true
       LIMIT 1`,
      [questionId]
    );

    if(!questionResult.rowCount) {
      return sendError(res,404,'Question not found.');
    }

    const question=questionResult.rows[0];
    const isCorrect=Number(answer)===Number(question.correct_option);

    return res.json({
      correct:isCorrect,
      correct_option:Number(question.correct_option),
      explanation:question.explanation || ''
    });
  } catch(e) {
    console.error('Check answer error:',e);
    return sendError(res,500,'Answer checking service error.');
  }
});

api.post('/attempts/:id/submit', requirePasswordReady, async (req,res)=>{
  try {
    const id=Number(req.params.id);
    const a=await pool.query(`SELECT * FROM attempts WHERE id=$1 AND user_id=$2 LIMIT 1`,[id,req.user.id]);
    if(!a.rowCount) return sendError(res,404,'Attempt not found.');
    const attempt=a.rows[0];
    if(attempt.status==='SUBMITTED') return res.json({score:attempt.score,correct:attempt.correct_count,total:attempt.total_count});
    const answers=req.body?.answers && typeof req.body.answers==='object' ? req.body.answers : {};
    const allIds=Array.isArray(attempt.question_ids) ? attempt.question_ids.map(Number) : [];
    /* For Question Bank, only questions actually reached/answered in this
       session count toward the Review percentage and become permanently used.
       Unseen questions remain available next time. */
    const usedIds = attempt.mode === 'bank'
      ? allIds.filter(qid => Object.prototype.hasOwnProperty.call(answers,String(qid)) && Number.isInteger(Number(answers[String(qid)])))
      : allIds;

    const qs=usedIds.length
      ? await pool.query(`SELECT id,correct_option FROM questions WHERE id=ANY($1::bigint[])`,[usedIds])
      : {rows:[]};

    let correct=0;
    for(const q of qs.rows){
      const raw=answers[String(q.id)] ?? answers[q.id];
      const idx=Number(raw);
      if(Number.isInteger(idx) && idx>=0 && idx===Number(q.correct_option)) correct++;
    }

    const total=usedIds.length;
    const unanswered=usedIds.filter(qid => Number(answers[String(qid)])===-1).length;
    const score=total ? Number(((correct*100)/total).toFixed(2)) : 0;

    if (attempt.mode === 'bank' && usedIds.length) {
      await pool.query(
        `INSERT INTO question_history(user_id, question_id, mode)
         SELECT $1, x, 'bank'
         FROM unnest($2::bigint[]) AS x
         ON CONFLICT (user_id, question_id, mode) DO NOTHING`,
        [req.user.id, usedIds]
      );
    }

    await pool.query(`UPDATE attempts SET status='SUBMITTED',score=$1,correct_count=$2,total_count=$3,submitted_at=now() WHERE id=$4`,[score,correct,total,id]);
    await pool.query(`INSERT INTO activity_events(user_id,event_type,metadata) VALUES($1,'ATTEMPT_SUBMITTED',$2)`,[req.user.id,JSON.stringify({attempt_id:id,mode:attempt.mode,exam:attempt.exam,score,used_questions:total,unanswered})]);
    res.json({score,correct,total,unanswered,usedQuestionIds:usedIds});
  }catch(e){console.error(e);sendError(res,500,'Grading service error.');}
});

api.get('/results', requirePasswordReady, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT id,exam,subject,mode,language,score,correct_count,total_count,started_at,submitted_at FROM attempts WHERE user_id=$1 AND status='SUBMITTED' ORDER BY started_at DESC LIMIT 100`,[req.user.id]);
    res.json({results:q.rows});
  }catch(e){console.error(e);sendError(res,500,'Results service error.');}
});

/* Group 4 UI topic map used only for Admin result filtering/export. Existing question rows keep their original subtopic values. */
const GROUP4_RESULT_TOPICS = {
  'தமிழ்': ['எழுத்து வகைகள்','சொல் வகைகள்','வேற்றுமை','வினைச்சொல்','புணர்ச்சி','ஒருபொருட்பன்மொழி','எதிர்ச்சொல்','இணைச்சொல்','மரபுத்தொடர்','கலைச்சொல்','சங்க இலக்கியம்','பதினெண்கீழ்க்கணக்கு','காப்பியங்கள்','பக்தி இலக்கியம்','நவீன இலக்கியம்','அறத்துப்பால்','பொருட்பால்','இன்பத்துப்பால்','குறள் பொருள்','குறள் சார்ந்த கருத்துகள்'],
  'இந்திய வரலாறு': ['பண்டைய இந்தியா','இடைக்கால இந்தியா','நவீன இந்தியா','சுதந்திரப் போராட்டம்'],
  'தமிழ்நாடு வரலாறு': ['சங்க காலம்','சோழர்','பாண்டியர்','பல்லவர்','நாயக்கர்'],
  'இந்திய அரசியல்': ['அரசியலமைப்பு','அடிப்படை உரிமைகள்','பாராளுமன்றம்','மாநில அரசு','உள்ளாட்சி'],
  'புவியியல்': ['இந்தியா','தமிழ்நாடு','ஆறுகள்','மலைகள்','வளங்கள்'],
  'அறிவியல்': ['இயற்பியல்','வேதியியல்','உயிரியல்','சுற்றுச்சூழல்'],
  'பொருளாதாரம்': ['அடிப்படை பொருளாதாரம்','இந்திய பொருளாதாரம்','தமிழ்நாடு பொருளாதாரம்'],
  'அடிப்படை கணிதம்': ['எண்கள்','பின்னங்கள்','சதவீதம்','விகிதம்','சராசரி'],
  'அளவியல்': ['பரப்பளவு','சுற்றளவு','கனஅளவு','அலகுகள்'],
  'வணிகக் கணிதம்': ['இலாபம் மற்றும் நட்டம்','வட்டி','காலம் மற்றும் வேலை','வேகம் மற்றும் தூரம்'],
  'தர்க்கத் திறன்': ['எண் தொடர்','எழுத்துத் தொடர்','ஒப்புமை','வகைப்படுத்தல்','குறியீடு']
};
function group4TopicForSubtopic(v){
  const s=String(v||'').trim();
  const tamil = GROUP4_SUBTOPIC_ALIASES[s] || s;
  for(const [topic,subs] of Object.entries(GROUP4_RESULT_TOPICS)){ if(subs.includes(s) || subs.includes(tamil)) return topic; }
  return '';
}

/* Admin: exam-wise overall results. Student identity is included for result reporting. */
api.get('/admin/exam-results', requireAdmin, async (req,res)=>{
  try{
    const exam = String(req.query.exam || '').trim();
    const type = String(req.query.type || '').trim().toLowerCase();
    const subjectFilter = String(req.query.subject || '').trim();
    const from = String(req.query.from || '').trim();
    const to = String(req.query.to || '').trim();
    const requestedSubtopic = String(req.query.subtopic || '').trim();
    const requestedSubtopics = String(req.query.subtopics || '').split('|').map(x=>x.trim()).filter(Boolean);
    const requestedSubtopicCandidates = [...new Set([...requestedSubtopics, ...requestedSubtopics.map(x=>GROUP4_SUBTOPIC_ALIASES[x]||'')].filter(Boolean))];
    const requestedSubtopicCandidatesSingle = requestedSubtopic ? [...new Set([requestedSubtopic, GROUP4_SUBTOPIC_ALIASES[requestedSubtopic]||''].filter(Boolean))] : [];
    const minPct = req.query.min_pct === undefined || req.query.min_pct === '' ? 0 : Number(req.query.min_pct);
    const maxPct = req.query.max_pct === undefined || req.query.max_pct === '' ? 100 : Number(req.query.max_pct);
    const page = Math.max(parseInt(req.query.page || '1',10) || 1,1);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '100',10) || 100,1),200);
    if(!Number.isFinite(minPct) || !Number.isFinite(maxPct) || minPct<0 || maxPct>100 || minPct>maxPct){
      return sendError(res,400,'Invalid percentage range.');
    }

    const where=[`a.status='SUBMITTED'`];
    const params=[];
    const add=(sql,val)=>{params.push(val);where.push(sql.replace('?', '$'+params.length));};
    if(exam) add(`a.exam=?` ,exam);
    if(subjectFilter){
      const subjectList = subjectCandidates(subjectFilter);
      where.push(`a.subject = ANY($${params.length+1}::text[])`);
      params.push(subjectList);
    }
    if(from) add(`a.submitted_at::date >= ?::date`,from);
    if(to) add(`a.submitted_at::date <= ?::date`,to);
    if(requestedSubtopic){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidatesSingle);
    } else if(requestedSubtopics.length){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidates);
    }
    where.push(`COALESCE(a.score,0) >= $${params.length+1}`); params.push(minPct);
    where.push(`COALESCE(a.score,0) <= $${params.length+1}`); params.push(maxPct);

    const typeSql=`CASE
      WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam'
      WHEN a.mode='mock' THEN 'Mock Test'
      WHEN a.mode='bank' THEN 'Question Bank'
      WHEN a.total_count=10 THEN '10 Questions'
      WHEN a.total_count=20 THEN '20 Questions'
      WHEN a.total_count=50 THEN '50 Questions'
      ELSE 'Practice'
    END`;
    if(type && ['model','mock','practice','bank','10','20','50','100'].includes(type)){
      const typeExpr=type==='model' ? `lower(a.exam) LIKE '%model%'` : type==='mock' ? `a.mode='mock'` : type==='bank' ? `a.mode='bank'` : type==='10' ? `a.total_count=10` : type==='20' ? `a.total_count=20` : type==='50' ? `a.total_count=50` : type==='100' ? `a.total_count=100` : `(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50,100))`;
      where.push(typeExpr);
    }

    const whereSql=where.join(' AND ');
    const base=`FROM attempts a WHERE ${whereSql}`;
    const countQ=await pool.query(`SELECT count(*)::int AS total, count(DISTINCT a.user_id)::int AS participants, COALESCE(sum(a.total_count),0)::bigint AS total_questions, COALESCE(avg(a.score),0)::numeric(10,2) AS average_pct, COALESCE(max(a.score),0)::numeric(10,2) AS highest_pct, COALESCE(min(a.score),0)::numeric(10,2) AS lowest_pct ${base}`,params);
    const offset=(page-1)*limit;
    const pageParams=params.slice();
    pageParams.push(limit,offset);
    const rowsQ=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS marks,COALESCE(a.total_count,0)::int AS total_marks,COALESCE(a.score,0)::numeric(10,2) AS percentage,COALESCE((SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic) FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid),'') AS subtopics FROM attempts a JOIN users u ON u.id=a.user_id WHERE ${whereSql} ORDER BY COALESCE(a.submitted_at,a.started_at) DESC,a.id DESC LIMIT $${pageParams.length-1} OFFSET $${pageParams.length}`,pageParams);

    const rows=rowsQ.rows.map(r=>({ ...r, topic:[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ') }));
    const c=countQ.rows[0]||{};
    const examsQ=await pool.query(`SELECT DISTINCT a.exam FROM attempts a WHERE a.status='SUBMITTED' ORDER BY a.exam`);
    res.json({ok:true,rows,total:Number(c.total||0),limit,page,exams:examsQ.rows.map(x=>x.exam).filter(Boolean),summary:{participants:Number(c.participants||0),attempts:Number(c.total||0),total_questions:Number(c.total_questions||0),average_pct:Number(c.average_pct||0),highest_pct:Number(c.highest_pct||0),lowest_pct:Number(c.lowest_pct||0)}});
  }catch(e){console.error('[ADMIN EXAM RESULTS]',e);sendError(res,500,'Exam results service error.');}
});

api.get('/admin/exam-results/export', requireAdmin, async (req,res)=>{
  try{
    const exam=String(req.query.exam||'').trim();
    const type=String(req.query.type||'').trim().toLowerCase();
    const subjectFilter=String(req.query.subject||'').trim();
    const from=String(req.query.from||'').trim();
    const to=String(req.query.to||'').trim();
    const requestedSubtopic=String(req.query.subtopic||'').trim();
    const requestedSubtopics=String(req.query.subtopics||'').split('|').map(x=>x.trim()).filter(Boolean);
    const requestedSubtopicCandidates=[...new Set([...requestedSubtopics,...requestedSubtopics.map(x=>GROUP4_SUBTOPIC_ALIASES[x]||'')].filter(Boolean))];
    const requestedSubtopicCandidatesSingle=requestedSubtopic?[...new Set([requestedSubtopic,GROUP4_SUBTOPIC_ALIASES[requestedSubtopic]||''].filter(Boolean))]:[];
    const minPct=req.query.min_pct===''||req.query.min_pct===undefined?0:Number(req.query.min_pct);
    const maxPct=req.query.max_pct===''||req.query.max_pct===undefined?100:Number(req.query.max_pct);
    if(!Number.isFinite(minPct)||!Number.isFinite(maxPct)||minPct<0||maxPct>100||minPct>maxPct)return sendError(res,400,'Invalid percentage range.');

    const where=[`a.status='SUBMITTED'`],params=[];
    const add=(sql,val)=>{params.push(val);where.push(sql.replace('?', '$'+params.length));};
    if(exam)add(`a.exam=?`,exam);
    if(subjectFilter){
      const subjectList=subjectCandidates(subjectFilter);
      where.push(`a.subject = ANY($${params.length+1}::text[])`);
      params.push(subjectList);
    }
    if(from)add(`a.submitted_at::date >= ?::date`,from);
    if(to)add(`a.submitted_at::date <= ?::date`,to);
    if(requestedSubtopic){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidatesSingle);
    } else if(requestedSubtopics.length){
      where.push(`EXISTS (SELECT 1 FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic = ANY($${params.length+1}::text[]))`);
      params.push(requestedSubtopicCandidates);
    }
    where.push(`COALESCE(a.score,0) >= $${params.length+1}`);params.push(minPct);
    where.push(`COALESCE(a.score,0) <= $${params.length+1}`);params.push(maxPct);
    if(type && ['model','mock','practice','bank','10','20','50','100'].includes(type)){
      where.push(type==='model'?`lower(a.exam) LIKE '%model%'`:type==='mock'?`a.mode='mock'`:type==='bank'?`a.mode='bank'`:type==='10'?`a.total_count=10`:type==='20'?`a.total_count=20`:type==='50'?`a.total_count=50`:type==='100'?`a.total_count=100`:`(a.mode='practice' AND lower(a.exam) NOT LIKE '%model%' AND a.total_count NOT IN (10,20,50,100))`);
    }

    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' WHEN a.total_count=100 THEN '100 Questions' ELSE 'Practice' END`;
    const q=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS marks,COALESCE(a.total_count,0)::int AS total_marks,COALESCE(a.score,0)::numeric(10,2) AS percentage,COALESCE((SELECT string_agg(DISTINCT qq.subtopic, ' | ' ORDER BY qq.subtopic) FROM unnest(a.question_ids) AS aqid JOIN questions qq ON qq.id=aqid),'') AS subtopics FROM attempts a JOIN users u ON u.id=a.user_id WHERE ${where.join(' AND ')} ORDER BY COALESCE(a.submitted_at,a.started_at) DESC,a.id DESC`,params);

    const escXml=v=>String(v??'')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&apos;');
    const colName=n=>{
      let s=''; n=Number(n)+1;
      while(n){ const r=(n-1)%26; s=String.fromCharCode(65+r)+s; n=Math.floor((n-1)/26); }
      return s;
    };
    const inlineCell=(ref,value,style)=>{
      const text=escXml(value);
      return `<c r="${ref}" t="inlineStr"${style?` s="${style}"`:''}><is><t xml:space="preserve">${text}</t></is></c>`;
    };
    const numCell=(ref,value,style)=>`<c r="${ref}" t="n"${style?` s="${style}"`:''}><v>${Number(value)||0}</v></c>`;
    const sheetXml=(rows)=>{
      const headers=['Name','Email','Exam','Exam Type','Topic','Subtopics','Date','Questions','Marks','Total Marks','Percentage'];
      const out=[];
      out.push('<row r="1">'+headers.map((h,i)=>inlineCell(`${colName(i)}1`,h,1)).join('')+'</row>');
      rows.forEach((r,ri)=>{
        const rowNo=ri+2;
        const topic=[...new Set(String(r.subtopics||'').split(' | ').map(group4TopicForSubtopic).filter(Boolean))].join(' | ');
        const vals=[r.name,r.email,r.exam,r.exam_type,topic,r.subtopics,r.date];
        const cells=[];
        vals.forEach((v,i)=>cells.push(inlineCell(`${colName(i)}${rowNo}`,v)));
        cells.push(numCell(`H${rowNo}`,r.questions));
        cells.push(numCell(`I${rowNo}`,r.marks));
        cells.push(numCell(`J${rowNo}`,r.total_marks));
        cells.push(numCell(`K${rowNo}`,r.percentage));
        out.push(`<row r="${rowNo}">${cells.join('')}</row>`);
      });
      return `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"/></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols><col min="1" max="1" width="24"/><col min="2" max="2" width="32"/><col min="3" max="4" width="18"/><col min="5" max="6" width="28"/><col min="7" max="7" width="20"/><col min="8" max="11" width="14"/></cols><sheetData>${out.join('')}</sheetData><autoFilter ref="A1:K${Math.max(1,rows.length+1)}"/></worksheet>`;
    };

    const safeSheetName=(name,used)=>{
      let n=String(name||'Exam').replace(/[\\\/\?\*\[\]:]/g,' ').trim()||'Exam';
      n=n.slice(0,31);
      const base=n; let i=2;
      while(used.has(n)){const suffix=` (${i++})`;n=base.slice(0,31-suffix.length)+suffix;}
      used.add(n);return n;
    };

    const groups=new Map();
    for(const r of q.rows){const key=String(r.exam||'Unknown Exam');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
    if(!groups.size)groups.set('No Results',[]);

    const sheets=[]; const rels=[]; const content=[]; const usedNames=new Set();
    let idx=1;
    for(const [examName,rows] of groups.entries()){
      const sheetName=safeSheetName(examName,usedNames);
      sheets.push(`<sheet name="${escXml(sheetName)}" sheetId="${idx}" r:id="rId${idx}"/>`);
      rels.push(`<Relationship Id="rId${idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${idx}.xml"/>`);
      content.push(`<Override PartName="/xl/worksheets/sheet${idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`);
      idx++;
    }

    const files=[
      {name:'[Content_Types].xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${content.join('')}</Types>`},
      {name:'_rels/.rels',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
      {name:'xl/workbook.xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets>${sheets.join('')}</sheets></workbook>`},
      {name:'xl/_rels/workbook.xml.rels',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels.join('')}<Relationship Id="rId${idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
      {name:'xl/styles.xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Arial"/></font><font><b/><sz val="10"/><name val="Arial"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0"/></cellXfs></styleSheet>`}
    ];
    idx=1;
    for(const [examName,rows] of groups.entries()){
      files.push({name:`xl/worksheets/sheet${idx}.xml`,data:sheetXml(rows)});idx++;
    }

    const crcTable=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
    const crc32=buf=>{let c=0xFFFFFFFF;for(const b of buf)c=crcTable[(c^b)&255]^(c>>>8);return (c^0xFFFFFFFF)>>>0;};
    const zipParts=[];const central=[];let offset=0;
    const now=new Date();const dosTime=(now.getHours()<<11)|(now.getMinutes()<<5)|Math.floor(now.getSeconds()/2);const dosDate=((now.getFullYear()-1980)<<9)|((now.getMonth()+1)<<5)|now.getDate();
    for(const f of files){
      const nameBuf=Buffer.from(f.name,'utf8'), dataBuf=Buffer.from(f.data,'utf8'), crc=crc32(dataBuf);
      const local=Buffer.alloc(30+nameBuf.length);local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0,6);local.writeUInt16LE(0,8);local.writeUInt16LE(dosTime,10);local.writeUInt16LE(dosDate,12);local.writeUInt32LE(crc,14);local.writeUInt32LE(dataBuf.length,18);local.writeUInt32LE(dataBuf.length,22);local.writeUInt16LE(nameBuf.length,26);local.writeUInt16LE(0,28);nameBuf.copy(local,30);zipParts.push(local,dataBuf);
      const c=Buffer.alloc(46+nameBuf.length);c.writeUInt32LE(0x02014b50,0);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(0,8);c.writeUInt16LE(0,10);c.writeUInt16LE(dosTime,12);c.writeUInt16LE(dosDate,14);c.writeUInt32LE(crc,16);c.writeUInt32LE(dataBuf.length,20);c.writeUInt32LE(dataBuf.length,24);c.writeUInt16LE(nameBuf.length,28);c.writeUInt16LE(0,30);c.writeUInt16LE(0,32);c.writeUInt16LE(0,34);c.writeUInt16LE(0,36);c.writeUInt32LE(0,38);c.writeUInt32LE(offset,42);nameBuf.copy(c,46);central.push(c);offset+=local.length+dataBuf.length;
    }
    const centralBuf=Buffer.concat(central);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,4);end.writeUInt16LE(0,6);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(centralBuf.length,12);end.writeUInt32LE(offset,16);end.writeUInt16LE(0,20);
    const xlsx=Buffer.concat([...zipParts,centralBuf,end]);
    const filename='thiral_exam_results_'+new Date().toISOString().slice(0,10)+'.xlsx';
    res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
    res.setHeader('Content-Length',String(xlsx.length));
    res.end(xlsx);
  }catch(e){console.error('[ADMIN EXAM EXPORT]',e);sendError(res,500,'Exam export service error.');}
});

api.get('/admin/exam-results/:attemptId', requireAdmin, async (req,res)=>{
  try{
    const id=Number(req.params.attemptId);
    if(!Number.isInteger(id) || id<1) return sendError(res,400,'Invalid attempt ID.');
    const typeSql=`CASE WHEN lower(a.exam) LIKE '%model%' THEN 'Model Exam' WHEN a.mode='mock' THEN 'Mock Test' WHEN a.mode='bank' THEN 'Question Bank' WHEN a.total_count=10 THEN '10 Questions' WHEN a.total_count=20 THEN '20 Questions' WHEN a.total_count=50 THEN '50 Questions' WHEN a.total_count=100 THEN '100 Questions' ELSE 'Practice' END`;
    const q=await pool.query(`SELECT a.id AS attempt_id,u.name,u.email,a.exam,${typeSql} AS exam_type,to_char(COALESCE(a.submitted_at,a.started_at),'DD-MM-YYYY HH24:MI') AS date,COALESCE(a.total_count,0)::int AS questions,COALESCE(a.correct_count,0)::int AS correct,COALESCE(a.score,0)::numeric(10,2) AS percentage FROM attempts a JOIN users u ON u.id=a.user_id WHERE a.id=$1 AND a.status='SUBMITTED' LIMIT 1`,[id]);
    if(!q.rowCount) return sendError(res,404,'Result not found.');
    const r=q.rows[0];
    const subsQ=await pool.query(`SELECT DISTINCT qq.subtopic FROM unnest((SELECT question_ids FROM attempts WHERE id=$1)) AS aqid JOIN questions qq ON qq.id=aqid WHERE qq.subtopic IS NOT NULL ORDER BY qq.subtopic`,[id]);
    const subtopics=subsQ.rows.map(x=>x.subtopic).filter(Boolean);
    const topic=[...new Set(subtopics.map(group4TopicForSubtopic).filter(Boolean))].join(' | ');
    const eventQ=await pool.query(`SELECT metadata FROM activity_events WHERE event_type='ATTEMPT_SUBMITTED' AND metadata->>'attempt_id'=$1 ORDER BY id DESC LIMIT 1`,[String(id)]);
    const unanswered=eventQ.rowCount ? Math.max(0,Number(eventQ.rows[0].metadata?.unanswered||0)) : 0;
    const wrong=Math.max(0,Number(r.questions)-Number(r.correct)-unanswered);
    res.json({ok:true,result:{...r,wrong,unanswered,topic,subtopics:subtopics.join(' | ')}});
  }catch(e){console.error('[ADMIN EXAM RESULT DETAIL]',e);sendError(res,500,'Exam result detail service error.');}
});


api.get('/admin/security/events', requireAdmin, async (req,res)=>{
  try{
    const limit=Math.min(Math.max(Number(req.query.limit)||100,1),200);
    const q=await pool.query(`
      SELECT id,event_type,created_at,email,ip,user_agent,details
      FROM security_events
      ORDER BY id DESC
      LIMIT $1`,[limit]);
    const s=await pool.query(`
      SELECT
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='FAILED_LOGIN')::int AS failed_logins,
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='ADMIN_LOGIN_SUCCESS')::int AS successful_admin_logins,
        count(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_type='UNAUTHORIZED_ADMIN_ACCESS')::int AS unauthorized_admin_access
      FROM security_events`);
    res.json({events:q.rows,stats:s.rows[0]||{}});
  }catch(e){console.error('Security events error:',e);sendError(res,500,'Security monitor error.');}
});

api.get('/admin/usage-monitor', requireAdmin, async (req,res)=>{
  try{
    const summary = await pool.query(`
      SELECT
        (SELECT count(DISTINCT s.user_id)::int
           FROM sessions s
           JOIN users u ON u.id=s.user_id
          WHERE s.expires_at > now()
            AND u.role='STUDENT'
            AND u.is_active=true) AS active_now,
        (SELECT count(*)::int
           FROM users u
          WHERE u.role='STUDENT'
            AND u.is_active=true
            AND u.last_login_at >= current_date) AS active_today,
        (SELECT count(*)::int
           FROM users u
          WHERE u.role='STUDENT'
            AND u.is_active=true
            AND u.last_login_at >= now()-interval '24 hours') AS active_24h,
        (SELECT count(*)::int
           FROM attempts a
           JOIN users u ON u.id=a.user_id
          WHERE u.role='STUDENT'
            AND a.mode='practice'
            AND a.started_at >= now()-interval '24 hours') AS practice_sessions_24h,
        (SELECT count(*)::int
           FROM attempts a
           JOIN users u ON u.id=a.user_id
          WHERE u.role='STUDENT'
            AND a.mode='mock'
            AND a.started_at >= now()-interval '24 hours') AS mock_tests_24h
    `);

    const online = await pool.query(`
      SELECT DISTINCT ON (u.id)
        u.student_id,u.name,u.email,u.last_login_at,s.expires_at
      FROM sessions s
      JOIN users u ON u.id=s.user_id
      WHERE s.expires_at > now()
        AND u.role='STUDENT'
        AND u.is_active=true
      ORDER BY u.id,s.expires_at DESC
    `);

    const last24 = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        u.last_login_at,
        count(DISTINCT a.id)::int AS activity_count,
        max(a.started_at) AS last_activity_at
      FROM users u
      LEFT JOIN attempts a
        ON a.user_id=u.id
       AND a.started_at >= now()-interval '24 hours'
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND (
          u.last_login_at >= now()-interval '24 hours'
          OR a.id IS NOT NULL
        )
      GROUP BY u.id,u.student_id,u.name,u.email,u.last_login_at
      ORDER BY COALESCE(u.last_login_at,'1970-01-01'::timestamptz) DESC,
               COALESCE(max(a.started_at),'1970-01-01'::timestamptz) DESC
    `);

    const practice = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        count(a.id)::int AS session_count,
        min(a.started_at) AS first_started_at,
        max(a.started_at) AS last_started_at,
        count(*) FILTER (WHERE a.status='SUBMITTED')::int AS completed_count
      FROM attempts a
      JOIN users u ON u.id=a.user_id
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND a.mode='practice'
        AND a.started_at >= now()-interval '24 hours'
      GROUP BY u.id,u.student_id,u.name,u.email
      ORDER BY count(a.id) DESC,max(a.started_at) DESC
    `);

    const mock = await pool.query(`
      SELECT
        u.student_id,u.name,u.email,
        count(a.id)::int AS test_count,
        min(a.started_at) AS first_started_at,
        max(a.started_at) AS last_started_at,
        count(*) FILTER (WHERE a.status='SUBMITTED')::int AS completed_count,
        count(*) FILTER (WHERE a.status='SUBMITTED' AND a.score IS NOT NULL)::int AS scored_count
      FROM attempts a
      JOIN users u ON u.id=a.user_id
      WHERE u.role='STUDENT'
        AND u.is_active=true
        AND a.mode='mock'
        AND a.started_at >= now()-interval '24 hours'
      GROUP BY u.id,u.student_id,u.name,u.email
      ORDER BY count(a.id) DESC,max(a.started_at) DESC
    `);

    res.json({
      ok:true,
      active_now:Number(summary.rows[0]?.active_now||0),
      active_today:Number(summary.rows[0]?.active_today||0),
      active_24h:Number(summary.rows[0]?.active_24h||0),
      practice_sessions_24h:Number(summary.rows[0]?.practice_sessions_24h||0),
      mock_tests_24h:Number(summary.rows[0]?.mock_tests_24h||0),
      online_students:online.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        last_login_at:x.last_login_at,
        session_expires_at:x.expires_at
      })),
      last24_students:last24.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        last_login_at:x.last_login_at,
        activity_count:Number(x.activity_count||0),
        last_activity_at:x.last_activity_at
      })),
      practice_students:practice.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        session_count:Number(x.session_count||0),
        completed_count:Number(x.completed_count||0),
        first_started_at:x.first_started_at,
        last_started_at:x.last_started_at
      })),
      mock_students:mock.rows.map(x=>({
        student_id:x.student_id,
        name:x.name,
        email:x.email,
        test_count:Number(x.test_count||0),
        completed_count:Number(x.completed_count||0),
        scored_count:Number(x.scored_count||0),
        first_started_at:x.first_started_at,
        last_started_at:x.last_started_at
      }))
    });
  }catch(e){
    console.error('[ADMIN USAGE] error:',e);
    sendError(res,500,'Usage monitor service error.');
  }
});
api.get('/admin/summary', requireAdmin, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT
      count(*)::int AS total,
      count(*) FILTER (WHERE created_at::date=current_date)::int AS today,
      count(*) FILTER (WHERE date_trunc('month',created_at)=date_trunc('month',now()))::int AS month,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='ஆண்')::int AS male,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='பெண்')::int AS female,
      count(*) FILTER (WHERE trim(COALESCE(gender,''))='மூன்றாம் பாலினம்')::int AS third,
      max(last_login_at) AS last_login
      FROM users WHERE role='STUDENT' AND is_active=true`);
    res.json({students:{total:q.rows[0].total,today:q.rows[0].today,month:q.rows[0].month,male:q.rows[0].male,female:q.rows[0].female,third:q.rows[0].third,lastLogin:q.rows[0].last_login||null}});
  }catch(e){console.error(e);sendError(res,500,'Admin summary error.');}
});

api.get('/admin/students', requireAdmin, async (req,res)=>{
  try{
    const q=await pool.query(`SELECT student_id,name,email,phone,gender,dob,created_at,last_login_at,is_active,must_change_password FROM users WHERE role='STUDENT' ORDER BY is_active DESC, created_at DESC LIMIT 5000`);
    res.json({students:q.rows});
  }catch(e){console.error(e);sendError(res,500,'Admin students error.');}
});

api.delete('/admin/students/:studentId', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    if(!studentId) return sendError(res,400,'Student ID is required.');

    await client.query('BEGIN');

    const q = await client.query(
      `SELECT id,student_id,role FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,404,'Student not found.');
    }

    const target = q.rows[0];
    if(target.role !== 'STUDENT'){
      await client.query('ROLLBACK');
      return sendError(res,400,'Only STUDENT accounts can be deleted here.');
    }
    if(target.id === req.user.id){
      await client.query('ROLLBACK');
      return sendError(res,400,'The logged-in Admin account cannot be deleted here.');
    }

    /* Delete only this student's account and student-owned records.
       Questions and Question Bank are never touched by this operation. */
    await client.query(`DELETE FROM sessions WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM question_history WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM password_reset_otps WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM attempts WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM activity_events WHERE user_id=$1`, [target.id]);
    await client.query(`DELETE FROM users WHERE id=$1 AND role='STUDENT'`, [target.id]);

    await client.query('COMMIT');
    res.json({ok:true,student_id:target.student_id});
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){ }
    console.error('[ADMIN] Student delete error:',e);
    sendError(res,500,'Student delete service error.');
  }finally{
    client.release();
  }
});

api.patch('/admin/students/:studentId/status', requireAdmin, async (req,res)=>{
  const client = await pool.connect();
  try{
    const studentId = String(req.params.studentId || '').trim();
    const requestedActive = req.body?.is_active;

    if(!studentId || typeof requestedActive !== 'boolean'){
      return sendError(res,400,'Student ID and is_active are required.');
    }

    await client.query('BEGIN');

    const q = await client.query(
      `SELECT id,student_id,role,is_active FROM users WHERE student_id=$1 LIMIT 1 FOR UPDATE`,
      [studentId]
    );

    if(!q.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,404,'Student not found.');
    }

    const target = q.rows[0];

    if(target.role !== 'STUDENT'){
      await client.query('ROLLBACK');
      return sendError(res,400,'Only STUDENT accounts can be changed here.');
    }

    if(target.id === req.user.id){
      await client.query('ROLLBACK');
      return sendError(res,400,'The logged-in Admin account cannot be changed here.');
    }

    await client.query(
      `UPDATE users SET is_active=$1 WHERE id=$2`,
      [requestedActive, target.id]
    );

    /* Deactivation immediately invalidates every active session for that student.
       Results, attempts, questions and other historical data are intentionally kept. */
    if(!requestedActive){
      await client.query(`DELETE FROM sessions WHERE user_id=$1`, [target.id]);
      await client.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'ACCOUNT_DEACTIVATED',$2)`,
        [req.user.id, JSON.stringify({target_student_id:target.student_id})]
      );
    }else{
      await client.query(
        `INSERT INTO activity_events(user_id,event_type,metadata)
         VALUES($1,'ACCOUNT_REACTIVATED',$2)`,
        [req.user.id, JSON.stringify({target_student_id:target.student_id})]
      );
    }

    await client.query('COMMIT');

    res.json({
      ok:true,
      student_id:target.student_id,
      is_active:requestedActive
    });
  }catch(e){
    try{ await client.query('ROLLBACK'); }catch(_){}
    console.error('Student status change error:',e);
    sendError(res,500,'Student status change service error.');
  }finally{
    client.release();
  }
});

api.get('/group4/question-status', requirePasswordReady, async (req,res)=>{
  try{
    const rows=await pool.query(`
      SELECT subject,language,count(*)::int AS total,
             count(*) FILTER (WHERE is_active=true)::int AS active
      FROM questions
      WHERE exam='group4'
      GROUP BY subject,language
      ORDER BY subject,language`);
    res.json({exam:'group4',rows:rows.rows});
  }catch(e){ console.error(e); sendError(res,500,'Question status service error.'); }
});

/* Security invariant: every /api/admin/* request must have a valid ADMIN session.
   Keep this server-side; hiding the Admin screen in HTML is not a security boundary. */
app.use('/api/admin', async (req, res, next) => {
  try {
    const user = await getUserFromSession(req);
    if (!user) {
      const ip=clientIp(req);
      const recent=await pool.query(`SELECT count(*)::int AS n FROM security_events WHERE event_type='UNAUTHORIZED_ADMIN_ACCESS' AND ip=$1 AND created_at>=now()-interval '15 minutes'`,[ip]);
      const alert=Number(recent.rows[0]?.n||0)===0;
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',details:`Blocked ${req.method} ${req.originalUrl}`,sendAlert:alert});
      return sendError(res, 401, 'ACCESS DENIED: Login required.');
    }
    if (user.role !== 'ADMIN') {
      await logSecurityEvent({req,eventType:'UNAUTHORIZED_ADMIN_ACCESS',userId:user.id,email:user.email,details:`Non-admin user attempted ${req.method} ${req.originalUrl}`,sendAlert:true});
      return sendError(res, 403, 'ACCESS DENIED: Admin authorization required.');
    }
    req.user = user;
    res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma','no-cache');
    res.setHeader('Vary','Cookie, Origin');
    next();
  } catch (e) {
    console.error('Admin authorization error:', e);
    return sendError(res, 500, 'Authentication service error.');
  }
});


/* ===== GROUP 4 MOCK ROTATION API =====
   Final Group 4 Mock selector.
   - Exactly 200 questions when the database has at least 200 unique unused rows.
   - Q1-Q100 Tamil; Q101-Q200 = 75 GS + 25 Aptitude.
   - Excludes this student's previous Mock history by both question ID and content.
   - Removes duplicate content even when duplicate DB rows have different IDs/options order.
   - Prefers Moderate/Hard/Very Hard questions and strongly penalizes short direct-fact items.
   - Never deletes or rewrites question-bank rows.
   - Practice 10/20/50/100 routes are not changed here.
*/
api.get('/mock/questions', requirePasswordReady, async (req,res)=>{
  const exam=String(req.query.exam||'').trim();
  const requestedLanguage=String(req.query.language||'ta').trim();
  if(exam!=='group4' || !['ta','en'].includes(requestedLanguage)){
    return sendError(res,400,'Invalid Group 4 Mock request.');
  }

  const client=await pool.connect();
  try{
    await client.query('BEGIN');

    /* Prevent two simultaneous Mock starts for the same student from taking
       overlapping fresh pools. */
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext($1))`,
      [`thiral-group4-mock:${req.user.id}`]
    );

    const specs=[
      {name:'tamil',candidates:['tamil','தமிழ்'],language:'ta'},
      {name:'gs',candidates:['பொது அறிவு','General Knowledge','general knowledge','பொது அறிவு / General Studies','General Studies','general studies'],language:requestedLanguage},
      {name:'apt',candidates:['apt','திறனறிவு / Aptitude','Aptitude','aptitude'],language:requestedLanguage}
    ];

    const all=[];
    for(const spec of specs){
      const r=await client.query(
        `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
           FROM questions
          WHERE exam=$1
            AND subject=ANY($2::text[])
            AND language=$3
            AND is_active=true
            AND NOT EXISTS (
              SELECT 1 FROM question_history h
               WHERE h.user_id=$4
                 AND h.question_id=questions.id
                 AND h.mode='mock'
            )
          ORDER BY id
          LIMIT 3000`,
        [exam,spec.candidates,spec.language,req.user.id]
      );
      all.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
    }

    /* Ensure the 5,000-question Tamil Nadu politics batch is available to the
       Mock selector. It occupies part of the existing 75-question GS quota,
       so the 200-question Group 4 structure is unchanged. */
    if(requestedLanguage==='ta'){
      const politicsCandidates=['பொது அறிவு','General Knowledge','general knowledge','பொது அறிவு / General Studies','General Studies','general studies'];
      const pr=await client.query(
        `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
           FROM questions
          WHERE exam=$1
            AND subject=ANY($2::text[])
            AND language='ta'
            AND is_active=true
            AND md5(question)=ANY($3::text[])
            AND NOT EXISTS (
              SELECT 1 FROM question_history h
               WHERE h.user_id=$4
                 AND h.question_id=questions.id
                 AND h.mode='mock'
            )
          ORDER BY id
          LIMIT 5000`,
        [exam,politicsCandidates,[...THIRAL_TN_POLITICS_5000_HASHES],req.user.id]
      );
      all.push(...pr.rows.map(q=>({...q,_mockSubject:'gs'})));
    }

    const normalizeText=(v)=>String(v??'')
      .normalize('NFKC')
      .replace(/[“”‘’]/g,'"')
      .replace(/[^\p{L}\p{N}]+/gu,' ')
      .replace(/\s+/g,' ')
      .trim()
      .toLowerCase();

    /* Content key intentionally sorts options, so changing A/B/C/D order does
       not create a fake new question. */
    const contentKey=(q)=>{
      const qKey=normalizeText(q.question);
      const opts=Array.isArray(q.options)
        ? q.options.map(normalizeText).filter(Boolean).sort()
        : [];
      return qKey+'|'+opts.join('|');
    };
    const questionOnlyKey=(q)=>normalizeText(q.question);

    const oldHistory=await client.query(
      `SELECT q.question,q.options
         FROM question_history h
         JOIN questions q ON q.id=h.question_id
        WHERE h.user_id=$1 AND h.mode='mock'`,
      [req.user.id]
    );

    const blockedContent=new Set();
    const blockedQuestion=new Set();
    for(const q of oldHistory.rows){
      blockedContent.add(contentKey(q));
      blockedQuestion.add(questionOnlyKey(q));
    }

    /* Remove duplicates in the current fresh pool and also block previous
       Mock content even when it exists under another database ID. */
    const seenContent=new Set(blockedContent);
    const seenQuestion=new Set(blockedQuestion);
    const unique=[];
    for(const q of all){
      const ck=contentKey(q);
      const qk=questionOnlyKey(q);
      if(!qk || seenContent.has(ck) || seenQuestion.has(qk)) continue;
      seenContent.add(ck);
      seenQuestion.add(qk);
      unique.push(q);
    }

    const shuffle=(rows)=>{
      const a=rows.slice();
      for(let i=a.length-1;i>0;i--){
        const j=Math.floor(Math.random()*(i+1));
        [a[i],a[j]]=[a[j],a[i]];
      }
      return a;
    };

    /* Difficulty is not inferred from the number of options. That was the
       previous problem: four options do not magically make a Taj Mahal fact
       question difficult. Explicit DB difficulty wins, but obvious direct-fact
       questions are capped at Moderate unless their wording has real complexity. */
    const difficultyInfo=(q)=>{
      const raw=String(q.difficulty||'').trim().toLowerCase();
      const text=normalizeText(q.question);
      const words=text.split(' ').filter(Boolean).length;
      const directFact=/^(who|where|when|what is|what was|which is|which was|identify|name the|who was|where was|when was)\b/.test(text)
        || /^(யார்|எவர்|எங்கு|எப்போது|எது|எவை|எந்த|அடையாளம் காண்க|பெயரிடுக)\b/.test(text);
      const complex=/statement|statements|assertion|reason|cause|effect|match|matching|pair|sequence|arrange|order|select the correct|which of the following|கூற்று|கூற்றுகள்|காரணம்|விளைவு|பொருத்துக|வரிசை|சரியான இணை|பின்வருவனவற்றில் எவை|கீழ்கண்டவற்றுள்/.test(text);
      const quantitative=/percentage|ratio|average|profit|loss|interest|discount|time and work|speed|distance|mixture|age|probability|data interpretation|series|equation|fraction|சதவீதம்|விகிதம்|சராசரி|இலாபம்|நட்டம்|வட்டி|தள்ளுபடி|வேலை|வேகம்|தூரம்|கலவை|வயது|நிகழ்தகவு|தரவு|வரிசை|சமன்பாடு|பின்னம்/.test(text);
      const long=words>=24 || text.length>=125;
      const optionText=Array.isArray(q.options)?q.options.map(normalizeText).join(' '):'';
      const richOptions=optionText.split(' ').filter(Boolean).length>=18;

      let score=0;
      if(complex) score+=3;
      if(quantitative) score+=3;
      if(long) score+=2;
      if(richOptions) score+=1;
      if(directFact && !complex && !quantitative && words<18) score-=3;

      let bucket=null;
      if(/very\s*hard|veryhard|மிக\s*கடினம்|மிகக்கடினம்/.test(raw)) bucket=3;
      else if(/\bhard\b|கடினம்/.test(raw)) bucket=2;
      else if(/moderate|medium|normal|மிதமானது|சாதாரணம்/.test(raw)) bucket=1;
      else if(/easy|basic|எளிது|அடிப்படை/.test(raw)) bucket=0;

      if(bucket===3 && score<2 && directFact) bucket=1;
      if(bucket===2 && score<1 && directFact) bucket=1;
      if(bucket===null){
        bucket=score>=5?3:score>=3?2:score>=1?1:0;
      }

      /* A ranking score is also kept, so when a preferred bucket is short the
         strongest available questions fill the remaining slots. */
      const rank=(bucket*20)+(score*5)+(complex?3:0)+(quantitative?3:0)+(long?2:0);
      return {bucket,rank};
    };

    const selectBest=(rows,count,quotas)=>{
      const meta=rows.map(q=>({q,info:difficultyInfo(q)}));
      const chosen=[];
      const used=new Set();

      const takeBucket=(bucket,n)=>{
        if(n<=0) return;
        meta.filter(x=>x.info.bucket===bucket)
          .sort((a,b)=>b.info.rank-a.info.rank || Math.random()-.5)
          .some(x=>{
            if(chosen.length>=count || used.has(String(x.q.id))) return false;
            chosen.push(x.q); used.add(String(x.q.id));
            return chosen.filter(y=>difficultyInfo(y).bucket===bucket).length>=n;
          });
      };

      /* Preferred distribution: Moderate 20%, Hard 60%, Very Hard 20%.
         If the DB has fewer genuinely difficult questions, fill from the next
         strongest unused questions instead of returning a broken Mock. */
      takeBucket(3,quotas[3]||0);
      takeBucket(2,quotas[2]||0);
      takeBucket(1,quotas[1]||0);

      if(chosen.length<count){
        meta.sort((a,b)=>b.info.rank-a.info.rank || Math.random()-.5);
        for(const x of meta){
          if(chosen.length>=count) break;
          const id=String(x.q.id);
          if(used.has(id)) continue;
          chosen.push(x.q); used.add(id);
        }
      }
      return chosen.slice(0,count);
    };

    let tamilRows=unique.filter(q=>q._mockSubject==='tamil');
    let gsRows=unique.filter(q=>q._mockSubject==='gs');
    let aptRows=unique.filter(q=>q._mockSubject==='apt');

    /* If this student has already consumed the fresh pool, do not leave the
       Mock screen empty. Reuse old Mock questions only after the fresh pool
       for that subject is exhausted. The current Mock still avoids duplicate
       content until its unique pool is exhausted. */
    const need={tamil:100,gs:75,apt:25};
    const freshCount={tamil:tamilRows.length,gs:gsRows.length,apt:aptRows.length};
    if(freshCount.tamil<100 || freshCount.gs<75 || freshCount.apt<25){
      const recycleAll=[];
      for(const spec of specs){
        const r=await client.query(
          `SELECT id,exam,subject,subtopic,language,question,options,explanation,
                  COALESCE(to_jsonb(questions)->>'difficulty',to_jsonb(questions)->>'level','') AS difficulty
             FROM questions
            WHERE exam=$1
              AND subject=ANY($2::text[])
              AND language=$3
              AND is_active=true
            ORDER BY id
            LIMIT 5000`,
          [exam,spec.candidates,spec.language]
        );
        recycleAll.push(...r.rows.map(q=>({...q,_mockSubject:spec.name})));
      }

      const addRecycled=(name,current,required)=>{
        if(current.length>=required) return current;
        const localSeen=new Set(current.map(contentKey));
        for(const q of recycleAll){
          if(q._mockSubject!==name) continue;
          const ck=contentKey(q);
          if(!ck || localSeen.has(ck)) continue;
          localSeen.add(ck);
          current.push(q);
          if(current.length>=required) break;
        }
        return current;
      };

      tamilRows=addRecycled('tamil',tamilRows,100);
      gsRows=addRecycled('gs',gsRows,75);
      aptRows=addRecycled('apt',aptRows,25);
    }

    /* A Mock must contain 200 slots. If a subject has fewer than its required
       number of unique questions even after recycling, cycle only after that
       subject's unique pool is exhausted. This prevents an empty Mock while
       preserving uniqueness for as long as the database permits. */
    const cycleTo=(rows,count)=>{
      if(!rows.length) return [];
      const out=[];
      for(let i=0;i<count;i++) out.push(rows[i%rows.length]);
      return out;
    };

    const tamilSelected=selectBest(tamilRows,Math.min(100,tamilRows.length),{1:20,2:60,3:20});

    const tnPoliticsRows=requestedLanguage==='ta'
      ? gsRows.filter(q=>isThiralTNPolitics5000Question(q.question))
      : [];
    const politicsTarget=Math.min(20,tnPoliticsRows.length);
    const politicsSelected=politicsTarget
      ? selectBest(tnPoliticsRows,politicsTarget,{1:4,2:12,3:4})
      : [];
    const politicsKeys=new Set(politicsSelected.map(contentKey));
    const gsGeneralRows=gsRows.filter(q=>!politicsKeys.has(contentKey(q)));
    const gsGeneralTarget=Math.max(0,75-politicsSelected.length);
    const gsGeneralSelected=selectBest(gsGeneralRows,Math.min(gsGeneralTarget,gsGeneralRows.length),{1:11,2:33,3:11});
    const gsSelected=[...politicsSelected,...gsGeneralSelected];

    const aptSelected=selectBest(aptRows,Math.min(25,aptRows.length),{1:5,2:15,3:5});

    const tamilFinal=tamilSelected.length>=100?tamilSelected:cycleTo(tamilRows,100);
    const gsFinal=gsSelected.length>=75?gsSelected:cycleTo(gsRows,75);
    const aptFinal=aptSelected.length>=25?aptSelected:cycleTo(aptRows,25);

    if(!tamilFinal.length || !gsFinal.length || !aptFinal.length){
      await client.query('ROLLBACK');
      return sendError(res,409,
        `Mock-க்கு தேவையான கேள்விகள் இல்லை. தமிழ்: ${tamilRows.length}, GS: ${gsRows.length}, Aptitude: ${aptRows.length}.` 
      );
    }

    /* Aptitude gets a second diversity pass across subtopics, without allowing
       a weaker question to displace a much stronger one unnecessarily. */
    const aptBySub=new Map();
    for(const q of aptSelected){
      const k=normalizeText(q.subtopic)||'__no_subtopic__';
      if(!aptBySub.has(k)) aptBySub.set(k,[]);
      aptBySub.get(k).push(q);
    }
    const aptTopics=shuffle(Array.from(aptBySub.keys()));
    const aptMixed=[];
    let more=true;
    while(more){
      more=false;
      for(const k of aptTopics){
        const arr=aptBySub.get(k);
        if(arr&&arr.length){aptMixed.push(arr.shift());more=true;}
      }
    }

    const selected=[
      ...shuffle(tamilFinal).slice(0,100),
      ...shuffle([...gsFinal.slice(0,75),...aptMixed.slice(0,25)])
    ];

    if(selected.length!==200){
      await client.query('ROLLBACK');
      return sendError(res,500,'Mock Test-க்கு 200 கேள்விகளை உருவாக்க முடியவில்லை.');
    }

    const clean=selected.map(q=>Number(q.id));
    const ins=await client.query(
      `INSERT INTO attempts(user_id,exam,subject,mode,language,question_ids)
       VALUES($1,$2,'mixed','mock','mixed',$3)
       RETURNING id`,
      [req.user.id,exam,clean]
    );

    await client.query(
      `INSERT INTO question_history(user_id,question_id,mode)
       SELECT $1,x,'mock'
         FROM unnest($2::bigint[]) AS x
       ON CONFLICT(user_id,question_id,mode) DO NOTHING`,
      [req.user.id,clean]
    );

    await client.query('COMMIT');

    res.json({
      attemptId:ins.rows[0].id,
      questions:selected,
      count:200,
      recycled:0
    });
  }catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('Group 4 Mock selection error:',e);
    sendError(res,500,'Mock question service error.');
  }finally{
    client.release();
  }
});


/* ===== MODEL EXAM ADMIN SAVE ===== */
async function ensureModelExamTables(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exams (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      exam_date DATE NOT NULL,
      exam_time TIME NOT NULL,
      duration_minutes INTEGER NOT NULL DEFAULT 180,
      access_window_hours INTEGER NOT NULL DEFAULT 24,
      status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','active','closed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_questions (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES model_exams(exam_id) ON DELETE RESTRICT,
      question_no INTEGER NOT NULL,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      correct_option CHAR(1) NOT NULL CHECK (correct_option IN ('A','B','C','D')),
      explanation TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(exam_id, question_no)
    )
  `);

  /* Existing Supabase/Render databases may already contain an older
     model_exams table created before exam_time was introduced.
     CREATE TABLE IF NOT EXISTS does not alter an existing table, so the
     migration below adds only missing columns and preserves existing rows. */
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS exam_time TIME`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS start_time TIME`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS duration_minutes INTEGER NOT NULL DEFAULT 180`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS access_window_hours INTEGER NOT NULL DEFAULT 24`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'draft'`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()`);
  await pool.query(`ALTER TABLE model_exams ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`);

  /* Older Supabase installations may already have model_exam_questions with a
     different/partial schema. Add only missing columns; never delete or rewrite
     existing question rows. Nullable is intentional for migration safety. */
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS exam_id TEXT`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS question_no INTEGER`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS question TEXT`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS options JSONB`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS correct_option CHAR(1)`);
  /* Older Model Exam schema used correct_answer instead of correct_option.
     Keep both columns populated so the existing Supabase table remains compatible. */
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS correct_answer CHAR(1)`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS explanation TEXT NULL`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS subject TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS topic TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS language CHAR(2) NOT NULL DEFAULT 'ta'`);
  await pool.query(`ALTER TABLE model_exam_questions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()`);
  await pool.query(`CREATE INDEX IF NOT EXISTS model_exam_questions_exam_idx ON model_exam_questions(exam_id, question_no)`);
}

function parseModelExamQuestionPaper(raw){
  const text=String(raw||'').replace(/\r\n/g,'\n').replace(/\r/g,'\n').trim();
  if(!text) throw new Error('Question Paper is empty.');
  const starts=[...text.matchAll(/^Q\s*([0-9]{1,4})\s*$/gmi)];
  if(!starts.length) throw new Error('Q001 / Q002 போன்ற question numbering கிடைக்கவில்லை.');
  const blocks=[];
  for(let i=0;i<starts.length;i++){
    const no=Number(starts[i][1]);
    const start=starts[i].index + starts[i][0].length;
    const end=i+1<starts.length ? starts[i+1].index : text.length;
    const block=text.slice(start,end).trim();
    const qm=block.match(/^Question\s*:\s*([\s\S]*?)(?=^A\.\s)/mi);
    const am=block.match(/^A\.\s*(.*?)\s*$(?=[\s\S]*^B\.\s)/mi);
    const bm=block.match(/^B\.\s*(.*?)\s*$(?=[\s\S]*^C\.\s)/mi);
    const cm=block.match(/^C\.\s*(.*?)\s*$(?=[\s\S]*^D\.\s)/mi);
    const dm=block.match(/^D\.\s*([\s\S]*?)(?=^Correct\s+Answer\s*:|^Explanation\s*:|$)/mi);
    const corr=block.match(/^Correct\s+Answer\s*:\s*([ABCD])\b/im);
    const exp=block.match(/^Explanation\s*:\s*([\s\S]*)$/im);
    if(!qm || !am || !bm || !cm || !dm || !corr){
      throw new Error(`Q${String(no).padStart(3,'0')} format incomplete. Question, A-D and Correct Answer தேவை.`);
    }
    const question=qm[1].trim();
    const options=[am[1],bm[1],cm[1],dm[1]].map(x=>String(x||'').trim());
    if(!question || options.some(x=>!x)) throw new Error(`Q${String(no).padStart(3,'0')} question/options காலியாக உள்ளது.`);
    blocks.push({questionNo:no,question,options,correctOption:corr[1].toUpperCase(),explanation:exp?exp[1].trim():null});
  }
  const nums=blocks.map(x=>x.questionNo);
  const unique=new Set(nums);
  if(unique.size!==blocks.length) throw new Error('Question number duplicate உள்ளது.');
  blocks.sort((a,b)=>a.questionNo-b.questionNo);
  return blocks;
}

api.post('/admin/model-exam/save', requireAdmin, async (req,res)=>{
  let client;
  try{
    const examId=String(req.body?.examId||'').trim();
    const title=String(req.body?.title||'').trim();
    const examDate=String(req.body?.examDate||'').trim();
    const examTime=String(req.body?.examTime||'').trim();
    const duration=Number(req.body?.durationMinutes||180);
    const questionText=String(req.body?.questionText||'');
    if(!examId || !title || !examDate || !examTime) return sendError(res,400,'Model Exam ID, title, date and start time are required.');
    if(duration!==180) return sendError(res,400,'Model Exam duration must be 180 minutes.');
    if(examId.length>100) return sendError(res,400,'Exam ID is too long.');
    const questions=parseModelExamQuestionPaper(questionText);
    if(questions.length>200) return sendError(res,400,'ஒரு Model Exam-ல் அதிகபட்சம் 200 questions மட்டுமே சேமிக்கலாம்.');

    client=await pool.connect();
    await client.query('BEGIN');
    const exists=await client.query('SELECT 1 FROM model_exams WHERE exam_id=$1 LIMIT 1',[examId]);
    if(exists.rowCount){
      await client.query('ROLLBACK');
      return sendError(res,409,'இந்த Model Exam ID ஏற்கனவே உள்ளது. Existing exam overwrite செய்யப்படாது.');
    }
    /* Existing databases may use start_time instead of exam_time.
       Keep both populated when both columns exist, so old Supabase schemas
       remain compatible without changing or deleting existing data. */
    await client.query(`INSERT INTO model_exams(exam_id,title,exam_date,exam_time,start_time,duration_minutes,access_window_hours,status)
      VALUES($1,$2,$3,$4,$4,$5,24,'active')`,[examId,title,examDate,examTime,duration]);
    for(const q of questions){
      await client.query(`INSERT INTO model_exam_questions
        (exam_id,question_no,question,options,correct_option,correct_answer,explanation,subject,topic,language)
        VALUES($1,$2,$3,$4::jsonb,$5,$5,$6,$7,$8,$9)`,
        [examId,q.questionNo,q.question,JSON.stringify(q.options),q.correctOption,q.explanation||'',title,'','ta']);
    }
    await client.query('COMMIT');
    res.status(201).json({saved:true,questionCount:questions.length,exam:{examId,title,examDate,examTime,durationMinutes:duration,status:'active'}});
  }catch(e){
    if(client){try{await client.query('ROLLBACK');}catch(_){} }
    console.error('[MODEL EXAM] save error:',e);
    sendError(res,400,e?.message||'Model Exam save error.');
  }finally{ if(client) client.release(); }
});


/* ===== MODEL EXAM STUDENT ENGINE ===== */
async function ensureModelExamStudentTables(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_attempts (
      id BIGSERIAL PRIMARY KEY,
      exam_id TEXT NOT NULL REFERENCES model_exams(exam_id) ON DELETE RESTRICT,
      user_id BIGINT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      submitted_at TIMESTAMPTZ NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'in_progress'
        CHECK(status IN ('in_progress','submitted','expired')),
      question_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      total_questions INTEGER NOT NULL DEFAULT 0,
      attempted INTEGER NOT NULL DEFAULT 0,
      not_attempted INTEGER NOT NULL DEFAULT 0,
      marks NUMERIC(10,2) NOT NULL DEFAULT 0,
      percentage NUMERIC(6,2) NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_answers (
      id BIGSERIAL PRIMARY KEY,
      attempt_id BIGINT NOT NULL REFERENCES model_exam_attempts(id) ON DELETE CASCADE,
      question_id BIGINT NOT NULL REFERENCES model_exam_questions(id) ON DELETE RESTRICT,
      answer CHAR(1) NULL CHECK(answer IS NULL OR answer IN ('A','B','C','D')),
      answered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(attempt_id,question_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS model_exam_results (
      id BIGSERIAL PRIMARY KEY,
      attempt_id BIGINT NOT NULL UNIQUE REFERENCES model_exam_attempts(id) ON DELETE RESTRICT,
      exam_id TEXT NOT NULL,
      user_id BIGINT NOT NULL,
      total_questions INTEGER NOT NULL,
      attempted INTEGER NOT NULL,
      not_attempted INTEGER NOT NULL,
      marks NUMERIC(10,2) NOT NULL,
      percentage NUMERIC(6,2) NOT NULL,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS model_exam_attempts_user_idx ON model_exam_attempts(user_id,exam_id,started_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS model_exam_answers_attempt_idx ON model_exam_answers(attempt_id)`);
}

function modelExamStartExpr(){
  return `(e.exam_date::text || ' ' || COALESCE(e.exam_time,e.start_time)::text)::timestamp AT TIME ZONE 'Asia/Kolkata'`;
}

async function getAvailableModelExam(){
  const startExpr=modelExamStartExpr();
  const q=await pool.query(`
    SELECT e.exam_id,e.title,e.exam_date,COALESCE(e.exam_time,e.start_time) AS start_time,
           e.duration_minutes,e.access_window_hours,e.status,
           ${startExpr} AS start_at,
           COUNT(q.id)::int AS question_count
    FROM model_exams e
    LEFT JOIN model_exam_questions q ON q.exam_id=e.exam_id
    WHERE e.is_active=true AND e.status IN ('active','draft')
      AND now() >= ${startExpr}
      AND now() < ${startExpr} + (e.access_window_hours || ' hours')::interval
    GROUP BY e.id
    ORDER BY ${startExpr} DESC,e.created_at DESC
    LIMIT 1`);
  return q.rows[0] || null;
}

/* Student dashboard checks whether a Model Exam is currently accessible. */
api.get('/model-exams/available', requirePasswordReady, async (req,res)=>{
  try{
    const exam=await getAvailableModelExam();
    if(!exam) return res.json({available:false});
    res.json({available:true,exam:{
      examId:exam.exam_id,title:exam.title,examDate:exam.exam_date,startTime:exam.start_time,
      durationMinutes:Number(exam.duration_minutes),accessWindowHours:Number(exam.access_window_hours),
      questionCount:Number(exam.question_count)
    }});
  }catch(e){
    console.error('[MODEL EXAM] availability error:',e);
    sendError(res,500,'Model Exam availability service error.');
  }
});

function publicModelExamQuestion(row){
  return {id:Number(row.id),questionNo:Number(row.question_no),question:row.question,options:row.options};
}

api.post('/model-exams/start', requirePasswordReady, async (req,res)=>{
  const client=await pool.connect();
  try{
    const exam=await getAvailableModelExam();
    if(!exam) return sendError(res,403,'தற்போது Model Exam கிடைக்கவில்லை.');
    if(Number(exam.question_count)<1) return sendError(res,409,'Model Exam-ல் கேள்விகள் இல்லை.');

    /* One in-progress attempt per student/exam. */
    const existing=await pool.query(`
      SELECT id,started_at,status FROM model_exam_attempts
      WHERE user_id=$1 AND exam_id=$2 AND status='in_progress'
      ORDER BY id DESC LIMIT 1`,[req.user.id,exam.exam_id]);
    if(existing.rowCount){
      const a=existing.rows[0];
      const age=(Date.now()-new Date(a.started_at).getTime())/60000;
      if(age < Number(exam.duration_minutes)){
        const qs=await pool.query(`
          SELECT id,question_no,question,options FROM model_exam_questions
          WHERE exam_id=$1 ORDER BY question_no`,[exam.exam_id]);
        const answers=await pool.query(`SELECT question_id,answer FROM model_exam_answers WHERE attempt_id=$1`,[a.id]);
        return res.json({ok:true,attemptId:Number(a.id),resumed:true,startedAt:a.started_at,durationMinutes:Number(exam.duration_minutes),exam:{examId:exam.exam_id,title:exam.title,questionCount:qs.rowCount},questions:qs.rows.map(publicModelExamQuestion),answers:answers.rows});
      }
      await pool.query(`UPDATE model_exam_attempts SET status='expired' WHERE id=$1`,[a.id]);
    }

    const qs=await client.query(`SELECT id,question_no,question,options FROM model_exam_questions WHERE exam_id=$1 ORDER BY question_no`,[exam.exam_id]);
    if(!qs.rowCount) return sendError(res,409,'Model Exam questions are not available.');
    const ids=qs.rows.map(r=>Number(r.id));
    await client.query('BEGIN');
    const ins=await client.query(`
      INSERT INTO model_exam_attempts(exam_id,user_id,started_at,status,question_ids,total_questions)
      VALUES($1,$2,now(),'in_progress',$3::jsonb,$4)
      RETURNING id,started_at`,[exam.exam_id,req.user.id,JSON.stringify(ids),ids.length]);
    await client.query('COMMIT');
    res.status(201).json({ok:true,attemptId:Number(ins.rows[0].id),resumed:false,startedAt:ins.rows[0].started_at,durationMinutes:Number(exam.duration_minutes),exam:{examId:exam.exam_id,title:exam.title,questionCount:qs.rowCount},questions:qs.rows.map(publicModelExamQuestion),answers:[]});
  }catch(e){
    try{await client.query('ROLLBACK');}catch(_){ }
    console.error('[MODEL EXAM] start error:',e);
    sendError(res,500,'Model Exam start service error.');
  }finally{client.release();}
});

async function getModelExamAttemptForUser(attemptId,userId){
  const q=await pool.query(`
    SELECT a.*,e.title,e.duration_minutes,e.exam_id
    FROM model_exam_attempts a JOIN model_exams e ON e.exam_id=a.exam_id
    WHERE a.id=$1 AND a.user_id=$2 LIMIT 1`,[attemptId,userId]);
  return q.rows[0]||null;
}

function attemptExpired(a){
  return (Date.now()-new Date(a.started_at).getTime()) >= Number(a.duration_minutes||180)*60000;
}

api.post('/model-exams/attempt/:attemptId/answer', requirePasswordReady, async (req,res)=>{
  try{
    const attemptId=Number(req.params.attemptId), questionId=Number(req.body?.questionId);
    const answer=String(req.body?.answer||'').trim().toUpperCase();
    if(!Number.isInteger(attemptId)||!Number.isInteger(questionId)||!['A','B','C','D'].includes(answer)) return sendError(res,400,'Invalid Model Exam answer.');
    const a=await getModelExamAttemptForUser(attemptId,req.user.id);
    if(!a) return sendError(res,404,'Model Exam attempt not found.');
    if(a.status!=='in_progress') return sendError(res,409,'Model Exam attempt is already closed.');
    if(attemptExpired(a)){
      await pool.query(`UPDATE model_exam_attempts SET status='expired' WHERE id=$1`,[attemptId]);
      return sendError(res,409,'Model Exam நேரம் முடிந்துவிட்டது.');
    }
    const allowed=Array.isArray(a.question_ids)?a.question_ids.map(Number):[];
    if(!allowed.includes(questionId)) return sendError(res,403,'Question does not belong to this attempt.');
    await pool.query(`
      INSERT INTO model_exam_answers(attempt_id,question_id,answer,answered_at)
      VALUES($1,$2,$3,now())
      ON CONFLICT(attempt_id,question_id) DO UPDATE SET answer=EXCLUDED.answer,answered_at=now()`,[attemptId,questionId,answer]);
    res.json({ok:true,saved:true});
  }catch(e){
    console.error('[MODEL EXAM] answer error:',e);
    sendError(res,500,'Model Exam answer service error.');
  }
});

api.post('/model-exams/attempt/:attemptId/submit', requirePasswordReady, async (req,res)=>{
  const client=await pool.connect();
  try{
    const attemptId=Number(req.params.attemptId);
    if(!Number.isInteger(attemptId)) return sendError(res,400,'Invalid attempt ID.');

    const a=await getModelExamAttemptForUser(attemptId,req.user.id);
    if(!a) return sendError(res,404,'Model Exam attempt not found.');

    if(a.status!=='in_progress'){
      const existing=await client.query(`
        SELECT total_questions,attempted,not_attempted,marks,percentage
        FROM model_exam_results
        WHERE attempt_id=$1
        ORDER BY id DESC LIMIT 1`,[attemptId]);
      if(existing.rowCount){
        return res.json({ok:true,result:existing.rows[0],alreadySubmitted:true});
      }
      return sendError(res,409,'Model Exam attempt is closed.');
    }

    const expired=attemptExpired(a);
    await client.query('BEGIN');

    if(expired){
      await client.query(
        `UPDATE model_exam_attempts SET status='expired',submitted_at=now() WHERE id=$1`,
        [attemptId]
      );
    }

    const rows=await client.query(`
      SELECT q.id,q.correct_option,q.correct_answer,a.answer
      FROM model_exam_questions q
      LEFT JOIN model_exam_answers a
        ON a.question_id=q.id AND a.attempt_id=$1
      WHERE q.exam_id=$2
      ORDER BY q.question_no`,[attemptId,a.exam_id]);

    const total=rows.rowCount;
    const attempted=rows.rows.filter(r=>r.answer!==null && r.answer!=='').length;
    const correct=rows.rows.filter(r=>
      r.answer &&
      String(r.answer).toUpperCase()===
      String(r.correct_option ?? r.correct_answer ?? '').toUpperCase()
    ).length;
    const notAttempted=Math.max(0,total-attempted);
    const pct=total ? Number(((correct/total)*100).toFixed(2)) : 0;
    const finalStatus=expired?'expired':'submitted';

    await client.query(`
      UPDATE model_exam_attempts
      SET submitted_at=now(),
          status=$1,
          total_questions=$2,
          attempted=$3,
          not_attempted=$4,
          marks=$5,
          percentage=$6
      WHERE id=$7`,
      [finalStatus,total,attempted,notAttempted,correct,pct,attemptId]
    );

    /*
      Do not depend on ON CONFLICT(attempt_id).
      Older databases may not have a unique constraint on attempt_id.
      Update an existing result; otherwise insert a new one.
    */
    const existing=await client.query(`
      SELECT id
      FROM model_exam_results
      WHERE attempt_id=$1
      ORDER BY id DESC
      LIMIT 1
      FOR UPDATE`,[attemptId]);

    if(existing.rowCount){
      await client.query(`
        UPDATE model_exam_results
        SET exam_id=$1,
            user_id=$2,
            total_questions=$3,
            attempted=$4,
            not_attempted=$5,
            marks=$6,
            percentage=$7,
            submitted_at=now()
        WHERE id=$8`,
        [a.exam_id,req.user.id,total,attempted,notAttempted,correct,pct,existing.rows[0].id]
      );
    }else{
      await client.query(`
        INSERT INTO model_exam_results
          (attempt_id,exam_id,user_id,total_questions,attempted,not_attempted,marks,percentage,submitted_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())`,
        [attemptId,a.exam_id,req.user.id,total,attempted,notAttempted,correct,pct]
      );
    }

    await client.query('COMMIT');

    res.json({
      ok:true,
      result:{
        total_questions:total,
        attempted,
        not_attempted:notAttempted,
        marks:correct,
        percentage:pct
      }
    });
  }catch(e){
    try{await client.query('ROLLBACK');}catch(_){}
    console.error('[MODEL EXAM] submit error:',e);
    sendError(res,500,'Model Exam submit service error.');
  }finally{
    client.release();
  }
});

/* ===== MODEL EXAM SUBMIT FINAL MIGRATION =====
   Non-destructive: only adds missing columns required by the submit/result flow.
*/
async function ensureModelExamSubmitSchema(){
  await pool.query(`
    ALTER TABLE model_exam_attempts
      ADD COLUMN IF NOT EXISTS total_questions INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS attempted INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS not_attempted INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS marks NUMERIC(10,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS percentage NUMERIC(6,2) NOT NULL DEFAULT 0
  `);
  await pool.query(`
    ALTER TABLE model_exam_answers
      ADD COLUMN IF NOT EXISTS answer CHAR(1) NULL,
      ADD COLUMN IF NOT EXISTS answered_at TIMESTAMPTZ NOT NULL DEFAULT now()
  `);
  await pool.query(`
    ALTER TABLE model_exam_results
      ADD COLUMN IF NOT EXISTS attempt_id BIGINT,
      ADD COLUMN IF NOT EXISTS exam_id TEXT,
      ADD COLUMN IF NOT EXISTS user_id BIGINT,
      ADD COLUMN IF NOT EXISTS total_questions INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS attempted INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS not_attempted INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS marks NUMERIC(10,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS percentage NUMERIC(6,2) NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
  `);
}

/* ===== IMPORTANT NEWS ===== */
async function ensureImportantNewsTable(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS important_news (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','published')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      published_at TIMESTAMPTZ NULL
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS important_news_status_idx
    ON important_news(status, created_at DESC)
  `);
}

api.post('/admin/important-news', requireAdmin, async (req,res)=>{
  try{
    const title=String(req.body?.title||'').trim();
    const content=String(req.body?.content||'').trim();
    const status=String(req.body?.status||'draft').trim().toLowerCase();
    if(!title || !content) return sendError(res,400,'Title and content are required.');
    if(!['draft','published'].includes(status)) return sendError(res,400,'Invalid news status.');
    const {rows}=await pool.query(`
      INSERT INTO important_news(title,content,status,published_at)
      VALUES($1,$2,$3,CASE WHEN $3='published' THEN now() ELSE NULL END)
      RETURNING id,title,content,status,created_at,updated_at,published_at`,
      [title,content,status]
    );
    res.status(201).json({news:rows[0]});
  }catch(e){
    console.error('[IMPORTANT NEWS] save error:',e);
    sendError(res,500,'Important News save error.');
  }
});

api.delete('/admin/important-news/current', requireAdmin, async (req,res)=>{
  try{
    const {rows}=await pool.query(`
      SELECT id,title
      FROM important_news
      WHERE status='published'
      ORDER BY published_at DESC NULLS LAST, created_at DESC
      LIMIT 1
    `);
    if(!rows.length) return sendError(res,404,'No published Important News found.');
    const item=rows[0];
    await pool.query(`DELETE FROM important_news WHERE id=$1`,[item.id]);
    res.json({deleted:true,news:item});
  }catch(e){
    console.error('[IMPORTANT NEWS] delete current error:',e);
    sendError(res,500,'Important News delete error.');
  }
});

api.get('/admin/important-news', requireAdmin, async (req,res)=>{
  try{
    const {rows}=await pool.query(`
      SELECT id,title,content,status,created_at,updated_at,published_at
      FROM important_news ORDER BY created_at DESC LIMIT 100`);
    res.json({news:rows});
  }catch(e){
    console.error('[IMPORTANT NEWS] admin list error:',e);
    sendError(res,500,'Important News list error.');
  }
});

/* Public read only: only published announcements are exposed. */
api.get('/important-news', async (req,res)=>{
  try{
    const {rows}=await pool.query(`
      SELECT id,title,content,published_at,created_at
      FROM important_news
      WHERE status='published'
      ORDER BY published_at DESC NULLS LAST, created_at DESC
      LIMIT 20`);
    res.json({news:rows});
  }catch(e){
    console.error('[IMPORTANT NEWS] public list error:',e);
    sendError(res,500,'Important News service error.');
  }
});

app.use('/api', api);

app.use(express.static(path.join(__dirname,'frontend'), { index:'index.html' }));

app.get('/{*splat}', (req,res)=>{
  res.sendFile(path.join(__dirname,'frontend','index.html'));
});

/* Create the history table/index without touching existing question data. */


async function ensureSecurityEventsTable(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS security_events (
      id BIGSERIAL PRIMARY KEY,
      event_type VARCHAR(80) NOT NULL,
      user_id BIGINT NULL,
      email TEXT NULL,
      ip TEXT NULL,
      user_agent TEXT NULL,
      details TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_security_events_ip_created ON security_events(ip,created_at DESC)`);
}

async function ensureMustChangePasswordColumn(){
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false
  `);
}


async function ensureLoginDeviceBindingColumn(){
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS login_device_hash TEXT NULL
  `);
}

async function ensurePasswordResetTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_otps (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      email TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      verified_at TIMESTAMPTZ NULL,
      reset_token_hash TEXT NULL,
      used_at TIMESTAMPTZ NULL
    )
  `);

  await pool.query(`
    ALTER TABLE password_reset_otps
    ADD COLUMN IF NOT EXISTS email TEXT
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_user_created
    ON password_reset_otps(user_id, created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_otps_token
    ON password_reset_otps(reset_token_hash)
  `);
}

async function ensureQuestionHistory() {
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
}


/*
   No database schema change is required for registration.
   Student IDs are allocated inside the registration transaction using a
   PostgreSQL advisory transaction lock. Existing users, questions,
   attempts, results and admin data are not deleted or rewritten.
*/

/* Backfill Last Login for older accounts from the server-side LOGIN audit trail.
   This does not touch passwords, registrations, results or attempts. */
async function backfillLastLoginFromAudit(){
  await pool.query(`
    UPDATE users u
       SET last_login_at = x.last_login
      FROM (
        SELECT user_id, MAX(created_at) AS last_login
          FROM activity_events
         WHERE event_type='LOGIN'
         GROUP BY user_id
      ) x
     WHERE u.id=x.user_id
       AND (u.last_login_at IS NULL OR u.last_login_at < x.last_login)
  `);
}

async function start(){
  try{
    await pool.query('SELECT 1');
    await ensureSecurityEventsTable();
    await ensureMustChangePasswordColumn();
    await ensureLoginDeviceBindingColumn();
    await ensurePasswordResetTables();
    await ensureQuestionHistory();
    await ensureImportantNewsTable();
    await ensureModelExamTables();
    await ensureModelExamStudentTables();
    await ensureModelExamSubmitSchema();
    await backfillLastLoginFromAudit();
    await ensureAdmin();
    app.listen(PORT,'0.0.0.0',()=>console.log(`Thiral V171 Secure Temporary Password + Gender Summary + Detailed Usage Monitor listening on port ${PORT}`));
  }catch(e){
    console.error('Startup failed:',e);
    process.exit(1);
  }
}

start();
