/**
 * درمان‌گر — ثبت‌نام و ورود با نام کاربری و گذرواژه؛ بدون وابستگی به SMS.
 */
const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const SERVICES = [
  { id: "home-nursing", name: "پرستاری در منزل", description: "انواع تزریقات، خدمات بخیه، پانسمان و درمان زخم و مراقبت از سالمند" },
  { id: "physiotherapy", name: "فیزیوتراپی", description: "خدمات فیزیوتراپی توسط ارائه‌دهنده تأییدشده" },
  { id: "massage", name: "ماساژدرمانی", description: "خدمات ماساژ توسط ارائه‌دهنده تأییدشده" }
];
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {status, headers:{...HEADERS,...extra}});
const clean = (v,n) => typeof v === "string" ? v.trim().slice(0,n) : "";
const uuid = () => crypto.randomUUID();
const phoneNorm = v => clean(v,32).replace(/[()\s-]/g,"");
const phoneValid = v => /^\+?[0-9]{10,15}$/.test(v);
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), c=>c.charCodeAt(0));
async function sign(payload, secret) {
  const data = new TextEncoder().encode(payload);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC",key,data));
}
async function makeToken(claims, secret) {
  const payload=b64(new TextEncoder().encode(JSON.stringify(claims)));
  return payload+"."+await sign(payload,secret);
}
async function verifyToken(token, secret) {
  if (!token || !secret || !token.includes(".")) return null;
  const [payload,sig]=token.split(".");
  if (!payload || !sig || !(await sign(payload,secret)).length) return null;
  const expected=await sign(payload,secret);
  if (expected !== sig) return null;
  try {
    const claims=JSON.parse(new TextDecoder().decode(unb64(payload)));
    if (!claims.sub || !claims.exp || claims.exp < Math.floor(Date.now()/1000)) return null;
    return claims;
  } catch { return null; }
}
async function bodyJson(req) { try { return await req.json(); } catch { return null; } }
async function hashPassword(password,salt,iterations=310000) {
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations,hash:"SHA-256"},material,256);
  return b64(bits);
}

async function dispatchPushToUsers(env, userIds, notification) {
  if (!env.PUSH_DISPATCH_URL || !env.PUSH_DISPATCH_TOKEN || !userIds?.length) return;
  const unique=[...new Set(userIds)].slice(0,500), placeholders=unique.map(()=>"?").join(",");
  const rows=await env.DB.prepare(`SELECT endpoint,p256dh,auth FROM push_subscriptions WHERE disabled_at IS NULL AND user_id IN (${placeholders})`).bind(...unique).all();
  if (!rows.results?.length) return;
  try { await fetch(env.PUSH_DISPATCH_URL,{method:"POST",headers:{"content-type":"application/json","authorization":`Bearer ${env.PUSH_DISPATCH_TOKEN}`},body:JSON.stringify({subscriptions:rows.results,notification})}); } catch {}
}
async function getSession(req, env) {
  const auth=req.headers.get("authorization")||"";
  const bearer=auth.startsWith("Bearer ")?auth.slice(7):"";
  const cookie=(req.headers.get("cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("dg_session="))?.slice(11);
  const claims=await verifyToken(bearer||cookie, env.SESSION_SECRET);
  if (!claims || !env.DB) return null;
  const row=await env.DB.prepare("SELECT id, role, phone, username, is_active FROM users WHERE id=?").bind(claims.sub).first();
  if (!row || !row.is_active) return null;
  return row;
}
function sessionCookie(token, maxAge=86400) {
  return `dg_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
export default {
 async fetch(request,env) {
  const url=new URL(request.url);
  if (request.method==="OPTIONS") return new Response(null,{status:204,headers:{"access-control-allow-methods":"GET,POST,OPTIONS","access-control-allow-headers":"content-type,authorization","access-control-max-age":"86400"}});
  if(url.pathname==="/api/health"&&request.method==="GET") return json({ok:true,service:"darmangar-api",stage:"username-password-pilot",production_ready:false,auth:"username-password",sms_otp:false});
  if(url.pathname==="/api/services"&&request.method==="GET") return json({services:SERVICES});
  if(!env.DB && url.pathname.startsWith("/api/")) return json({error:"database_not_configured",message:"پایگاه داده تنظیم نشده است."},503);

  // Public account registration: username + password. Passwords are PBKDF2 hashes, never stored in plaintext.
  if(url.pathname==="/api/auth/register"&&request.method==="POST") {
    const body=await bodyJson(request); if(!body) return json({error:"invalid_json"},400);
    const username=clean(body.username,32).toLowerCase(), password=typeof body.password==="string"?body.password:"", role=body.role;
    if(!/^[a-z0-9_]{4,32}$/.test(username)) return json({error:"invalid_username",message:"نام کاربری باید ۴ تا ۳۲ حرف انگلیسی کوچک، عدد یا زیرخط باشد."},400);
    if(password.length<10 || password.length>128 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) return json({error:"weak_password",message:"رمز عبور باید حداقل ۱۰ نویسه و شامل حرف و عدد باشد."},400);
    if(!['requester','provider'].includes(role)) return json({error:"invalid_role",message:"نوع حساب معتبر نیست."},400);
    if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32) return json({error:"server_not_configured",message:"تنظیم امن سرور کامل نیست."},503);
    const existing=await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(username).first();
    if(existing) return json({error:"username_taken",message:"این نام کاربری قبلاً انتخاب شده است."},409);
    const id=uuid(), salt=uuid(), iterations=310000, passwordHash=await hashPassword(password,salt,iterations);
    await env.DB.prepare("INSERT INTO users (id,role,username,password_hash,password_salt,password_iterations,phone) VALUES (?,?,?,?,?,?,NULL)").bind(id,role,username,passwordHash,salt,iterations).run();
    const token=await makeToken({sub:id,exp:Math.floor(Date.now()/1000)+86400},env.SESSION_SECRET);
    return json({ok:true,user:{id,role,username,phone:null},token,expires_in:86400},201,{"set-cookie":sessionCookie(token)});
  }
  if(url.pathname==="/api/auth/login"&&request.method==="POST") {
    const body=await bodyJson(request); if(!body) return json({error:"invalid_json"},400);
    const username=clean(body.username,32).toLowerCase(), password=typeof body.password==="string"?body.password:"";
    if(!/^[a-z0-9_]{4,32}$/.test(username)||!password||password.length>128) return json({error:"invalid_credentials",message:"نام کاربری یا رمز عبور نادرست است."},401);
    const row=await env.DB.prepare("SELECT id,role,username,phone,is_active,password_hash,password_salt,password_iterations,login_failed_attempts,login_locked_until FROM users WHERE username=?").bind(username).first();
    if(!row||!row.password_hash) return json({error:"invalid_credentials",message:"نام کاربری یا رمز عبور نادرست است."},401);
    if(row.login_locked_until&&Date.parse(row.login_locked_until)>Date.now()) return json({error:"login_locked",message:"به‌دلیل تلاش ناموفق، ورود برای مدتی قفل شده است."},429);
    const candidate=await hashPassword(password,row.password_salt,Number(row.password_iterations)||310000);
    if(candidate!==row.password_hash){const fails=Number(row.login_failed_attempts||0)+1,locked=fails>=5?new Date(Date.now()+15*60*1000).toISOString():null;await env.DB.prepare("UPDATE users SET login_failed_attempts=?,login_locked_until=? WHERE id=?").bind(fails,locked,row.id).run();return json({error:"invalid_credentials",message:fails>=5?"۵ تلاش ناموفق؛ ورود برای ۱۵ دقیقه قفل شد.":"نام کاربری یا رمز عبور نادرست است."},401)}
    if(!row.is_active) return json({error:"account_disabled",message:"این حساب غیرفعال است."},403);
    await env.DB.prepare("UPDATE users SET login_failed_attempts=0,login_locked_until=NULL WHERE id=?").bind(row.id).run();
    const token=await makeToken({sub:row.id,exp:Math.floor(Date.now()/1000)+86400},env.SESSION_SECRET);
    return json({ok:true,user:{id:row.id,role:row.role,username:row.username,phone:row.phone},token,expires_in:86400},200,{"set-cookie":sessionCookie(token)});
  }

  if(url.pathname==="/api/auth/logout"&&request.method==="POST") return json({ok:true,message:"نشست محلی پاک شد."},200,{"set-cookie":sessionCookie("",0)});
  if(url.pathname==="/api/me"&&request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    return json({user:{id:user.id,role:user.role,username:user.username,phone:user.phone}});
  }

  // Web Push subscription management. Actual delivery uses a configured, trusted dispatcher adapter.
  if(url.pathname==="/api/push/config"&&request.method==="GET") return json({publicKey:env.VAPID_PUBLIC_KEY||"",supported:true});
  if(url.pathname==="/api/push/status"&&request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    const row=await env.DB.prepare("SELECT COUNT(*) AS count FROM push_subscriptions WHERE user_id=? AND disabled_at IS NULL").bind(user.id).first();
    return json({ok:true,enabled:Number(row?.count||0)>0,subscriptions:Number(row?.count||0),deliveryConfigured:!!env.PUSH_DISPATCH_URL});
  }
  if(url.pathname==="/api/push/subscribe"&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    const body=await bodyJson(request);
    const sub=body?.subscription;
    if(!sub || typeof sub.endpoint!=="string" || !sub.endpoint.startsWith("https://") || !sub.keys || typeof sub.keys.p256dh!=="string" || typeof sub.keys.auth!=="string" || sub.endpoint.length>2048 || sub.keys.p256dh.length>200 || sub.keys.auth.length>100)
      return json({error:"invalid_subscription",message:"اطلاعات اعلان معتبر نیست."},400);
    await env.DB.prepare(`INSERT INTO push_subscriptions (id,user_id,endpoint,p256dh,auth,user_agent,disabled_at)
      VALUES (?,?,?,?,?,?,NULL) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth=excluded.auth,user_agent=excluded.user_agent,last_seen_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),disabled_at=NULL`)
      .bind(uuid(),user.id,sub.endpoint,sub.keys.p256dh,sub.keys.auth,clean(request.headers.get("user-agent"),300)).run();
    return json({ok:true,message:"این دستگاه برای دریافت اعلان ثبت شد."});
  }
  if(url.pathname==="/api/push/unsubscribe"&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    const body=await bodyJson(request); const endpoint=clean(body?.endpoint,2048);
    if(!endpoint.startsWith("https://")) return json({error:"invalid_endpoint"},400);
    await env.DB.prepare("UPDATE push_subscriptions SET disabled_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE user_id=? AND endpoint=?").bind(user.id,endpoint).run();
    return json({ok:true,message:"اعلان این دستگاه غیرفعال شد."});
  }
  if(url.pathname==="/api/push/test"&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    if(!env.PUSH_DISPATCH_URL || !env.PUSH_DISPATCH_TOKEN) return json({error:"push_delivery_not_configured",message:"ثبت دستگاه انجام می‌شود، اما سرویس ارسال اعلان هنوز در سرور تنظیم نشده است."},503);
    const subs=await env.DB.prepare("SELECT endpoint,p256dh,auth FROM push_subscriptions WHERE user_id=? AND disabled_at IS NULL").bind(user.id).all();
    if(!subs.results?.length) return json({error:"no_subscription",message:"ابتدا اعلان‌های این دستگاه را فعال کنید."},400);
    let response;
    try {
      response=await fetch(env.PUSH_DISPATCH_URL,{method:"POST",headers:{"content-type":"application/json","authorization":`Bearer ${env.PUSH_DISPATCH_TOKEN}`},body:JSON.stringify({subscriptions:subs.results,notification:{title:"درمان‌گر",body:"اعلان آزمایشی فعال است.",url:"/"}})});
    } catch { return json({error:"push_dispatch_failed",message:"ارتباط با سرویس ارسال اعلان برقرار نشد."},502); }
    if(!response.ok) return json({error:"push_dispatch_failed",message:"سرویس ارسال اعلان پاسخ موفق نداد."},502);
    return json({ok:true,message:"درخواست اعلان آزمایشی ارسال شد."});
  }


  // Create a service request. Address and requester contact are never returned to providers.
  if(url.pathname==="/api/requests"&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    if(user.role!=="requester") return json({error:"forbidden"},403);
    const body=await bodyJson(request); if(!body) return json({error:"invalid_json"},400);
    const serviceId=clean(body.service_id,60);
    const description=clean(body.description,1200);
    const city=clean(body.city,80)||"تبریز";
    const address=clean(body.address_text,500);
    const desiredRaw=clean(body.desired_at,40);
    const desiredDate=new Date(desiredRaw);
    if(!serviceId||description.length<5||!address||!desiredRaw||Number.isNaN(desiredDate.getTime()))
      return json({error:"invalid_request",message:"خدمت، شرح، نشانی و زمان موردنظر را کامل وارد کنید."},400);
    if(desiredDate.getTime()<Date.now()+5*60_000)
      return json({error:"invalid_desired_time",message:"زمان مراجعه باید دست‌کم پنج دقیقه در آینده باشد."},400);
    const service=await env.DB.prepare("SELECT id FROM service_catalog WHERE id=? AND is_active=1").bind(serviceId).first();
    if(!service) return json({error:"invalid_service",message:"این خدمت فعال نیست."},400);
    const id=uuid();
    try {
      await env.DB.prepare("INSERT INTO service_requests (id,requester_user_id,service_id,description,city,address_text,desired_at) VALUES (?,?,?,?,?,?,?)")
        .bind(id,user.id,serviceId,description,city,address,desiredDate.toISOString()).run();
      const matched=await env.DB.prepare(`SELECT DISTINCT u.id FROM users u JOIN provider_services ps ON ps.provider_user_id=u.id
        WHERE u.role='provider' AND u.is_active=1 AND ps.service_id=? AND ps.approval_status='approved'`).bind(serviceId).all();
      const serviceLabel=serviceId==='home-nursing'?'پرستاری در منزل':serviceId==='physiotherapy'?'فیزیوتراپی':'ماساژدرمانی';
      await dispatchPushToUsers(env,(matched.results||[]).map(x=>x.id),{title:"درمان‌گر · درخواست جدید",body:`درخواست جدید ${serviceLabel} در ${city}. برای مشاهده وارد اپ شوید.`,url:"/"});
      return json({ok:true,request:{id,service_id:serviceId,description,city,desired_at:desiredDate.toISOString(),status:"open"},message:"درخواست ثبت شد."},201);
    } catch {
      return json({error:"request_not_saved",message:"ثبت درخواست انجام نشد."},500);
    }
  }

  // Provider board: only approved providers with an approved matching service see requests.
  // Crucially, no requester phone, name, precise address, or user id is returned.
  if(url.pathname==="/api/provider/requests"&&request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized"},401);
    if(user.role!=="provider") return json({error:"forbidden"},403);
    const profile=await env.DB.prepare("SELECT verification_status FROM provider_profiles WHERE user_id=?").bind(user.id).first();
    if(!profile||profile.verification_status!=="approved") return json({error:"provider_not_approved"},403);
    const rows=await env.DB.prepare(
      `SELECT r.id,r.service_id,s.name AS service_name,r.description,r.city,r.desired_at,r.created_at
       FROM service_requests r JOIN service_catalog s ON s.id=r.service_id
       JOIN provider_services ps ON ps.service_id=r.service_id AND ps.provider_user_id=? AND ps.approval_status='approved'
       WHERE r.status='open' AND r.desired_at >= datetime('now','-15 minutes')
       AND r.offer_count < 5
       AND NOT EXISTS (SELECT 1 FROM offers o WHERE o.request_id=r.id AND o.provider_user_id=?)
       ORDER BY r.desired_at ASC LIMIT 100`
    ).bind(user.id,user.id).all();
    return json({requests:rows.results||[],privacy_note:"شماره تماس، نام، شناسه و نشانی دقیق درخواست‌کننده در این فهرست نمایش داده نمی‌شود."});
  }

  // Private request list: only the signed-in requester can see their own requests.
  if(url.pathname==="/api/requests/mine"&&request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized"},401);
    if(user.role!=="requester") return json({error:"forbidden"},403);
    const rows=await env.DB.prepare(
      "SELECT r.id,r.service_id,s.name AS service_name,r.description,r.city,r.desired_at,r.status,r.offer_count,r.created_at FROM service_requests r JOIN service_catalog s ON s.id=r.service_id WHERE r.requester_user_id=? ORDER BY r.created_at DESC LIMIT 100"
    ).bind(user.id).all();
    return json({requests:rows.results||[]});
  }

  // A requester can see only their own offers. Provider private phone numbers are
  // omitted unless that exact offer has been accepted by the requester.
  const offersMatch=url.pathname.match(/^\/api\/requests\/([^/]+)\/offers$/);
  if(offersMatch&&request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized"},401);
    if(user.role!=="requester") return json({error:"forbidden"},403);
    const requestId=offersMatch[1];
    const own=await env.DB.prepare("SELECT id,status,requester_user_id FROM service_requests WHERE id=?").bind(requestId).first();
    if(!own) return json({error:"not_found"},404);
    if(own.requester_user_id!==user.id) return json({error:"forbidden"},403);
    const rows=await env.DB.prepare(
      `SELECT o.id AS offer_id,o.price_toman,o.can_arrive,o.arrival_at,o.note,o.status AS offer_status,
       u.display_name,p.avatar_url,p.profession,p.bio,
       CASE WHEN o.status='accepted' AND r.status IN ('selected','in_progress','completed') THEN u.phone ELSE NULL END AS contact_phone
       FROM offers o JOIN users u ON u.id=o.provider_user_id
       JOIN provider_profiles p ON p.user_id=u.id JOIN service_requests r ON r.id=o.request_id
       WHERE o.request_id=? ORDER BY o.created_at ASC LIMIT 5`
    ).bind(requestId).all();
    return json({request:{id:own.id,status:own.status},offers:rows.results||[],privacy_note:"شماره تماس فقط برای ارائه‌دهنده انتخاب‌شده نمایش داده می‌شود."});
  }

  // Offer submission: only verified providers with approved service can submit.
  if(offersMatch&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized"},401);
    if(user.role!=="provider") return json({error:"forbidden"},403);
    const requestId=offersMatch[1], body=await bodyJson(request);
    if(!body) return json({error:"invalid_json"},400);
    const price=Number(body.price_toman);
    if(!Number.isSafeInteger(price)||price<0||price>1000000000) return json({error:"invalid_price"},400);
    const canArrive=body.can_arrive===true;
    const arrivalAt=canArrive?clean(body.arrival_at,40):null;
    if(canArrive&&!arrivalAt) return json({error:"arrival_time_required"},400);
    const note=clean(body.note,500)||null;
    const id=uuid();
    try {
      await env.DB.prepare("INSERT INTO offers (id,request_id,provider_user_id,price_toman,can_arrive,arrival_at,note) VALUES (?,?,?,?,?,?,?)")
        .bind(id,requestId,user.id,price,canArrive?1:0,arrivalAt,note).run();
      return json({ok:true,offer_id:id},201);
    } catch(e) {
      const message=String(e?.message||"");
      if(message.includes("offer_limit_reached")) return json({error:"offer_limit_reached",message:"برای این درخواست پنج پیشنهاد ثبت شده است."},409);
      if(message.includes("provider_not_approved")) return json({error:"provider_not_approved"},403);
      if(message.includes("provider_service_not_approved")) return json({error:"provider_service_not_approved"},403);
      if(message.includes("request_not_open")) return json({error:"request_not_open"},409);
      if(message.includes("UNIQUE constraint failed")) return json({error:"offer_already_submitted"},409);
      return json({error:"offer_not_saved"},500);
    }
  }

  // Choose one offer: only the requester who owns the request can choose.
  const chooseMatch=url.pathname.match(/^\/api\/requests\/([^/]+)\/choose-offer$/);
  if(chooseMatch&&request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized"},401);
    if(user.role!=="requester") return json({error:"forbidden"},403);
    const body=await bodyJson(request);
    const offerId=clean(body?.offer_id,80);
    if(!offerId) return json({error:"offer_id_required"},400);
    const reqId=chooseMatch[1];
    const own=await env.DB.prepare("SELECT id,status,requester_user_id FROM service_requests WHERE id=?").bind(reqId).first();
    if(!own) return json({error:"not_found"},404);
    if(own.requester_user_id!==user.id) return json({error:"forbidden"},403);
    if(own.status!=="open") return json({error:"request_not_open"},409);
    const offer=await env.DB.prepare("SELECT id,request_id,status FROM offers WHERE id=? AND request_id=?").bind(offerId,reqId).first();
    if(!offer||offer.status!=="submitted") return json({error:"offer_not_available"},404);
    // Batch is used to keep the request/offer transition together in D1.
    await env.DB.batch([
      env.DB.prepare("UPDATE offers SET status='declined' WHERE request_id=? AND status='submitted'").bind(reqId),
      env.DB.prepare("UPDATE offers SET status='accepted' WHERE id=? AND request_id=?").bind(offerId,reqId),
      env.DB.prepare("UPDATE service_requests SET status='selected',updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND requester_user_id=? AND status='open'").bind(reqId,user.id)
    ]);
    const chosen=await env.DB.prepare("SELECT u.phone FROM offers o JOIN users u ON u.id=o.provider_user_id WHERE o.id=? AND o.status='accepted'").bind(offerId).first();
    if(!chosen) return json({error:"selection_failed"},409);
    return json({ok:true,message:"ارائه‌دهنده انتخاب شد.",contact_phone:chosen.phone});
  }


  // Private chat: available only after the requester has selected an offer.
  const chatMatch=url.pathname.match(/^\/api\/requests\/([^/]+)\/chat$/);
  if(chatMatch && request.method==="GET") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    const requestId=chatMatch[1];
    const reqRow=await env.DB.prepare("SELECT id,status,requester_user_id FROM service_requests WHERE id=?").bind(requestId).first();
    if(!reqRow) return json({error:"not_found"},404);
    if(!["selected","in_progress","completed"].includes(reqRow.status)) return json({error:"chat_not_open",message:"گفت‌وگو پس از انتخاب ارائه‌دهنده فعال می‌شود."},409);
    const accepted=await env.DB.prepare(
      "SELECT o.provider_user_id,u.display_name FROM offers o JOIN users u ON u.id=o.provider_user_id WHERE o.request_id=? AND o.status='accepted' LIMIT 1"
    ).bind(requestId).first();
    if(!accepted) return json({error:"selected_provider_not_found"},409);
    if(user.id!==reqRow.requester_user_id && user.id!==accepted.provider_user_id) return json({error:"forbidden",message:"شما عضو این گفت‌وگو نیستید."},403);
    const convId=uuid();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO conversations (id,request_id,requester_user_id,provider_user_id) VALUES (?,?,?,?)"
    ).bind(convId,requestId,reqRow.requester_user_id,accepted.provider_user_id).run();
    const conv=await env.DB.prepare("SELECT id,created_at,updated_at FROM conversations WHERE request_id=?").bind(requestId).first();
    const requester=await env.DB.prepare("SELECT display_name FROM users WHERE id=?").bind(reqRow.requester_user_id).first();
    const rows=await env.DB.prepare(
      "SELECT m.id,m.sender_user_id,m.message_text,m.created_at,m.read_at,u.display_name AS sender_name FROM chat_messages m JOIN users u ON u.id=m.sender_user_id WHERE m.conversation_id=? ORDER BY m.created_at ASC LIMIT 100"
    ).bind(conv.id).all();
    await env.DB.prepare("UPDATE chat_messages SET read_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE conversation_id=? AND sender_user_id<>? AND read_at IS NULL").bind(conv.id,user.id).run();
    return json({conversation:{id:conv.id,request_id:requestId,requester_name:requester?.display_name||"درخواست‌کننده",provider_name:accepted.display_name||"ارائه‌دهنده"},messages:rows.results||[],privacy_note:"شماره تماس درخواست‌کننده در گفت‌وگو نمایش داده نمی‌شود؛ فقط اعضای همین درخواست به پیام‌ها دسترسی دارند."});
  }
  const chatSendMatch=url.pathname.match(/^\/api\/requests\/([^/]+)\/chat\/messages$/);
  if(chatSendMatch && request.method==="POST") {
    const user=await getSession(request,env);
    if(!user) return json({error:"unauthorized",message:"ابتدا وارد شوید."},401);
    const requestId=chatSendMatch[1], body=await bodyJson(request);
    const message=clean(body?.message,2000);
    if(message.length<1) return json({error:"empty_message",message:"متن پیام را وارد کنید."},400);
    const reqRow=await env.DB.prepare("SELECT id,status,requester_user_id FROM service_requests WHERE id=?").bind(requestId).first();
    if(!reqRow) return json({error:"not_found"},404);
    if(!["selected","in_progress","completed"].includes(reqRow.status)) return json({error:"chat_not_open",message:"گفت‌وگو پس از انتخاب ارائه‌دهنده فعال می‌شود."},409);
    const accepted=await env.DB.prepare("SELECT provider_user_id FROM offers WHERE request_id=? AND status='accepted' LIMIT 1").bind(requestId).first();
    if(!accepted || (user.id!==reqRow.requester_user_id && user.id!==accepted.provider_user_id)) return json({error:"forbidden",message:"شما عضو این گفت‌وگو نیستید."},403);
    const conv=await env.DB.prepare("SELECT id FROM conversations WHERE request_id=? AND requester_user_id=? AND provider_user_id=?").bind(requestId,reqRow.requester_user_id,accepted.provider_user_id).first();
    if(!conv) return json({error:"chat_not_initialized",message:"ابتدا صفحه گفت‌وگو را باز کنید."},409);
    const id=uuid();
    await env.DB.prepare("INSERT INTO chat_messages (id,conversation_id,sender_user_id,message_text) VALUES (?,?,?,?)").bind(id,conv.id,user.id,message).run();
    const saved=await env.DB.prepare("SELECT id,sender_user_id,message_text,created_at FROM chat_messages WHERE id=?").bind(id).first();
    await env.DB.prepare("UPDATE conversations SET updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").bind(conv.id).run();
    return json({ok:true,message:saved},201);
  }

  if(url.pathname==="/api/feedback"&&request.method==="POST") {
    const body=await bodyJson(request); if(!body) return json({error:"invalid_json"},400);
    const allowed=new Set(["suggestion","complaint","bug","thanks"]);
    const category=clean(body.category,20), message=clean(body.message,1500), phone=phoneNorm(body.contact_phone)||null;
    if(!allowed.has(category)) return json({error:"invalid_category",message:"نوع پیام معتبر نیست."},400);
    if(message.length<3) return json({error:"message_too_short",message:"متن پیام باید دست‌کم ۳ نویسه باشد."},400);
    if(phone&&!phoneValid(phone)) return json({error:"invalid_phone",message:"شماره تماس معتبر نیست."},400);
    const user=await getSession(request,env);
    try {
      await env.DB.prepare("INSERT INTO feedback (id,user_id,category,message,contact_phone) VALUES (?,?,?,?,?)").bind(uuid(),user?.id||null,category,message,phone).run();
      return json({ok:true,message:"پیام ثبت شد."},201);
    } catch { return json({error:"storage_failed",message:"ذخیره پیام انجام نشد."},500); }
  }
  return json({error:"not_found"},404);
 }
};
