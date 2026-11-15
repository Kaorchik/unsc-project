const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL environment variable is required");
if (!process.env.ADMIN_PASSWORD) console.warn("Set ADMIN_PASSWORD in Layero secrets before public use.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const app = express();
const PORT = Number(process.env.PORT || 3000);
app.set("trust proxy", 1);
app.use(express.json({limit:"100kb"}));
app.use(session({
  name:"unsc.sid",
  secret:process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:"auto",maxAge:12*60*60*1000}
}));
app.use(express.static(__dirname));

const delegations = [
 ["france","Франция","🇫🇷"],["uk","Великобритания","🇬🇧"],["usa","США","🇺🇸"],
 ["russia","Россия","🇷🇺"],["china","Китай","🇨🇳"],["brazil","Бразилия","🇧🇷"],
 ["japan","Япония","🇯🇵"],["turkey","Турция","🇹🇷"],["nordania","Нордания","🏳️"]
];

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS delegations(
      id TEXT PRIMARY KEY,name TEXT NOT NULL,flag TEXT NOT NULL,
      password_salt TEXT,password_hash TEXT,active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS announcements(
      id BIGSERIAL PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS documents(
      id BIGSERIAL PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS resolutions(
      id BIGSERIAL PRIMARY KEY,title TEXT NOT NULL,text TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS votes(
      id BIGSERIAL PRIMARY KEY,resolution_id BIGINT NOT NULL REFERENCES resolutions(id) ON DELETE CASCADE,
      delegation_id TEXT NOT NULL REFERENCES delegations(id),choice TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(resolution_id,delegation_id)
    );
    CREATE TABLE IF NOT EXISTS private_messages(
      id BIGSERIAL PRIMARY KEY,sender_id TEXT NOT NULL REFERENCES delegations(id),
      recipient_id TEXT NOT NULL REFERENCES delegations(id),body TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS uk_strategy(
      id TEXT PRIMARY KEY DEFAULT 'uk',body TEXT NOT NULL DEFAULT '',updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  for (const d of delegations) {
    await pool.query(
      "INSERT INTO delegations(id,name,flag) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING", d
    );
  }
}
function requireDelegate(req,res,next){if(req.session.role!=="delegate")return res.status(401).json({error:"Требуется вход"});next();}
function requireAdmin(req,res,next){if(req.session.role!=="admin")return res.status(403).json({error:"Нет доступа"});next();}
function allowedChat(id){return id==="usa"||id==="turkey";}
function hashPassword(password,salt){return crypto.pbkdf2Sync(password,salt,150000,32,"sha256").toString("hex");}
function safeEqual(a,b){const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y);}

app.post("/api/login",async(req,res)=>{
  try{
    const password=String(req.body.password||"");
    const delegationId=String(req.body.delegation_id||"");
    if(!/^[a-z]+$/.test(delegationId))return res.status(400).json({error:"Сначала выберите делегацию"});
    const {rows}=await pool.query("SELECT id,name,flag,password_salt,password_hash FROM delegations WHERE id=$1 AND active=TRUE AND password_hash IS NOT NULL",[delegationId]);
    const found=rows.find(d=>safeEqual(hashPassword(password,d.password_salt),d.password_hash));
    if(!found)return res.status(401).json({error:"Неверный пароль"});
    req.session.role="delegate";req.session.delegationId=found.id;
    res.json({delegate:{id:found.id,name:found.name,flag:found.flag}});
  }catch(e){console.error(e);res.status(500).json({error:"Ошибка сервера"});}
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/content",requireDelegate,async(req,res)=>{
  try{
    const [news,docs,rs]=await Promise.all([
      pool.query("SELECT id,title,body,created_at FROM announcements ORDER BY id DESC"),
      pool.query("SELECT id,title,body,created_at FROM documents ORDER BY id DESC"),
      pool.query("SELECT id,title,text,status FROM resolutions ORDER BY id DESC")
    ]);
    res.json({news:news.rows,documents:docs.rows,resolutions:rs.rows});
  }catch(e){console.error(e);res.status(500).json({error:"Не удалось загрузить материалы"});}
});
// UK-only diplomatic strategy. Only the authenticated UK delegation can read or edit it.
app.get("/api/uk/strategy",requireDelegate,async(req,res)=>{
  if(req.session.delegationId!=="uk")return res.status(403).json({error:"Доступ разрешён только делегации Великобритании"});
  try{
    const {rows}=await pool.query("SELECT body,updated_at FROM uk_strategy WHERE id='uk'");
    res.json(rows[0]||{body:"",updated_at:null});
  }catch(e){console.error(e);res.status(500).json({error:"Не удалось загрузить стратегию"});}
});
app.put("/api/uk/strategy",requireDelegate,async(req,res)=>{
  if(req.session.delegationId!=="uk")return res.status(403).json({error:"Доступ разрешён только делегации Великобритании"});
  const body=String(req.body.body||"");
  if(body.length>12000)return res.status(400).json({error:"Текст слишком длинный"});
  try{
    await pool.query("INSERT INTO uk_strategy(id,body,updated_at) VALUES('uk',$1,NOW()) ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body,updated_at=NOW()",[body]);
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"Не удалось сохранить стратегию"});}
});

app.post("/api/vote",requireDelegate,async(req,res)=>{
  try{
    const {resolution_id,choice}=req.body;
    if(!["for","against","abstain"].includes(choice))return res.status(400).json({error:"Некорректный вариант"});
    const r=await pool.query("SELECT id FROM resolutions WHERE id=$1 AND status='open'",[resolution_id]);
    if(!r.rowCount)return res.status(400).json({error:"Голосование не открыто"});
    await pool.query("INSERT INTO votes(resolution_id,delegation_id,choice) VALUES($1,$2,$3)",[r.rows[0].id,req.session.delegationId,choice]);
    res.json({ok:true});
  }catch(e){
    if(e.code==="23505")return res.status(409).json({error:"Голос этой делегации уже учтён"});
    console.error(e);res.status(500).json({error:"Не удалось принять голос"});
  }
});

// Private channel: server-side access is restricted to USA and Turkey.
app.get("/api/chat",requireDelegate,async(req,res)=>{
  const id=req.session.delegationId;
  if(!allowedChat(id))return res.status(403).json({error:"Доступ запрещён"});
  try{
    const {rows}=await pool.query(
      "SELECT sender_id,recipient_id,body,created_at FROM private_messages WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1) ORDER BY id DESC LIMIT 100",
      ["usa","turkey"]
    );
    res.json({messages:rows.reverse()});
  }catch(e){console.error(e);res.status(500).json({error:"Не удалось загрузить сообщения"});}
});
app.post("/api/chat",requireDelegate,async(req,res)=>{
  const id=req.session.delegationId;
  if(!allowedChat(id))return res.status(403).json({error:"Доступ запрещён"});
  const body=String(req.body.body||"").trim();
  if(!body||body.length>2000)return res.status(400).json({error:"Сообщение должно быть от 1 до 2000 символов"});
  try{
    const recipient=id==="usa"?"turkey":"usa";
    await pool.query("INSERT INTO private_messages(sender_id,recipient_id,body) VALUES($1,$2,$3)",[id,recipient,body]);
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"Не удалось отправить сообщение"});}
});

app.post("/api/admin/login",(req,res)=>{
  if(!process.env.ADMIN_PASSWORD||!safeEqual(req.body.password||"",process.env.ADMIN_PASSWORD))return res.status(401).json({error:"Неверный пароль администратора"});
  req.session.role="admin";req.session.delegationId=null;res.json({ok:true});
});
app.get("/api/admin/delegations",requireAdmin,async(req,res)=>{
  const {rows}=await pool.query("SELECT id,name,flag FROM delegations ORDER BY id");res.json({delegates:rows});
});
app.post("/api/admin/passwords",requireAdmin,async(req,res)=>{
  const list=Array.isArray(req.body.delegates)?req.body.delegates:[];
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    for(const d of list){
      if(!/^[a-z]+$/.test(d.id)||typeof d.password!=="string"||d.password.length<8)throw new Error("Пароль должен быть не короче 8 символов");
      const salt=crypto.randomBytes(16).toString("hex");
      await client.query("UPDATE delegations SET password_salt=$1,password_hash=$2 WHERE id=$3",[salt,hashPassword(d.password,salt),d.id]);
    }
    await client.query("COMMIT");res.json({ok:true});
  }catch(e){await client.query("ROLLBACK");res.status(400).json({error:e.message});}
  finally{client.release();}
});
app.post("/api/admin/announcement",requireAdmin,async(req,res)=>{
  const {title,body}=req.body;if(!title||!body)return res.status(400).json({error:"Заполните заголовок и текст"});
  const x=await pool.query("INSERT INTO announcements(title,body) VALUES($1,$2) RETURNING id",[title,body]);res.json({id:x.rows[0].id});
});
app.post("/api/admin/document",requireAdmin,async(req,res)=>{
  const {title,body}=req.body;if(!title||!body)return res.status(400).json({error:"Заполните название и текст"});
  const x=await pool.query("INSERT INTO documents(title,body) VALUES($1,$2) RETURNING id",[title,body]);res.json({id:x.rows[0].id});
});
app.post("/api/admin/resolution",requireAdmin,async(req,res)=>{
  const {title,text}=req.body;if(!title||!text)return res.status(400).json({error:"Заполните название и текст"});
  const x=await pool.query("INSERT INTO resolutions(title,text) VALUES($1,$2) RETURNING id",[title,text]);res.json({id:x.rows[0].id});
});
app.post("/api/admin/resolution-status",requireAdmin,async(req,res)=>{
  const {id,status}=req.body;if(!["draft","open","closed"].includes(status))return res.status(400).json({error:"Некорректный статус"});
  await pool.query("UPDATE resolutions SET status=$1 WHERE id=$2",[status,id]);res.json({ok:true});
});
app.get("/api/admin/results",requireAdmin,async(req,res)=>{
  const {rows}=await pool.query("SELECT choice,COUNT(*)::int AS count FROM votes WHERE resolution_id=$1 GROUP BY choice",[req.query.id]);res.json({results:rows});
});
app.get("/health",async(req,res)=>{
  try{await pool.query("SELECT 1");res.json({ok:true,service:"UNSC Simulation 2026",database:"connected"});}
  catch{res.status(503).json({ok:false,database:"disconnected"});}
});

initDb().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log(`UNSC app listening on ${PORT}`)))
.catch(e=>{console.error("Database initialization failed",e);process.exit(1);});
