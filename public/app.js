(() => {
"use strict";
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
let user = null, authMode = {requester:"login",provider:"login"}, currentRequest = null;
const notice = (msg, kind="") => { const n=$("#notice"); n.textContent=msg; n.className="notice "+kind; n.hidden=false; window.scrollTo({top:0,behavior:"smooth"}); };
const clearNotice=()=>{$("#notice").hidden=true;};
async function api(path, opts={}) {
  const headers={"content-type":"application/json",...(opts.headers||{})};
  const token=localStorage.getItem("dg_token"); if(token) headers.authorization="Bearer "+token;
  const res=await fetch(path,{...opts,headers,credentials:"same-origin"});
  let data={}; try{data=await res.json()}catch{}
  if(!res.ok) throw new Error(data.message || ({unauthorized:"ابتدا وارد شوید.",provider_not_approved:"حساب ارائه‌دهنده هنوز تأیید نشده است.",provider_service_not_approved:"خدمت انتخابی شما تأیید نشده است.",offer_limit_reached:"ظرفیت پنج پیشنهاد تکمیل شده است.",request_not_open:"این درخواست دیگر باز نیست.",offer_already_submitted:"قبلاً برای این درخواست پیشنهاد داده‌اید."}[data.error]) || "انجام عملیات ناموفق بود.");
  return data;
}
function show(id){$$(".view").forEach(x=>x.hidden=true);$("#"+id).hidden=false;clearNotice();}
function home(){user=null;show("home");}
$$("[data-show]").forEach(b=>b.addEventListener("click",()=>show(b.dataset.show)));
$$("[data-home]").forEach(b=>b.addEventListener("click",home));
$$("[data-mode]").forEach(b=>b.addEventListener("click",()=>{const role=b.dataset.role;authMode[role]=b.dataset.mode;$$(`[data-mode][data-role="${role}"]`).forEach(x=>x.classList.toggle("active",x===b));}));
$$("[data-auth]").forEach(form=>form.addEventListener("submit",async e=>{
 e.preventDefault();const role=form.dataset.role,fd=new FormData(form),body={username:String(fd.get("username")).toLowerCase(),password:fd.get("password"),role};
 try{const result=await api(authMode[role]==="register"?"/api/auth/register":"/api/auth/login",{method:"POST",body:JSON.stringify(authMode[role]==="register"?body:{username:body.username,password:body.password})});
 localStorage.setItem("dg_token",result.token);user=result.user;if(user.role!==role)throw new Error("نوع حساب واردشده با این بخش مطابقت ندارد.");
 await enterApp();
 }catch(err){notice(err.message,"error");}
}));
async function enterApp(){if(!user){const me=await api("/api/me");user=me.user;}if(user.role==="requester"){show("requester-app");await loadServices();await loadMine();}else{show("provider-app");await loadBoard();}}
async function loadServices(){try{const d=await api("/api/services"),sel=$("#services");sel.innerHTML='<option value="">انتخاب کنید</option>';(d.services||[]).forEach(s=>{const o=document.createElement("option");o.value=s.id;o.textContent=s.name;sel.append(o);});}catch(e){notice(e.message,"error");}}
$("#new-request").addEventListener("submit",async e=>{e.preventDefault();const f=new FormData(e.currentTarget),date=new Date(f.get("desired_at"));if(!Number.isFinite(date.getTime()))return notice("زمان مراجعه را درست وارد کنید.","error");const body={service_id:f.get("service_id"),desired_at:date.toISOString(),city:f.get("city"),address_text:f.get("address_text"),description:f.get("description")};try{await api("/api/requests",{method:"POST",body:JSON.stringify(body)});e.currentTarget.reset();e.currentTarget.city.value="تبریز";notice("درخواست شما ثبت شد.","success");await loadMine();}catch(err){notice(err.message,"error");}});
$("#reload-mine").onclick=loadMine;
async function loadMine(){try{const d=await api("/api/requests/mine");const box=$("#mine");box.innerHTML="";if(!d.requests?.length){box.textContent="هنوز درخواستی ثبت نکرده‌اید.";return;}d.requests.forEach(r=>{const el=document.createElement("div");el.className="item";el.innerHTML=`<h4>${esc(r.service_name||r.service_id)}</h4><p>${esc(r.description)}</p><p>زمان: ${esc(fmt(r.desired_at))} · وضعیت: ${esc(r.status)} · پیشنهادها: ${Number(r.offer_count||0)} از ۵</p><button class="secondary">مشاهده پیشنهادها</button>`;el.querySelector("button").onclick=()=>loadOffers(r.id);box.append(el);});}catch(e){notice(e.message,"error");}}
async function loadOffers(id){try{currentRequest=id;const d=await api(`/api/requests/${encodeURIComponent(id)}/offers`),box=$("#offers");box.innerHTML="";$("#offers-panel").hidden=false;if(!d.offers?.length){box.textContent="هنوز پیشنهادی دریافت نشده است.";return;}d.offers.forEach(o=>{const el=document.createElement("div");el.className="item";el.innerHTML=`<h4>${esc(o.display_name||"ارائه‌دهنده خدمات")}</h4><p>مبلغ: ${Number(o.price_toman).toLocaleString("fa-IR")} تومان</p><p>امکان حضور در زمان درخواستی: ${o.can_arrive?"بله":"خیر"}</p><p>${esc(o.note||"")}</p>${o.status==="accepted"?"<p>این پیشنهاد انتخاب شده است.</p>":o.offer_status==="submitted"?'<button class="primary">انتخاب این ارائه‌دهنده</button>':""}`;const btn=el.querySelector("button");if(btn)btn.onclick=async()=>{if(!confirm("این ارائه‌دهنده را انتخاب می‌کنید؟"))return;try{await api(`/api/requests/${encodeURIComponent(id)}/choose-offer`,{method:"POST",body:JSON.stringify({offer_id:o.offer_id})});notice("ارائه‌دهنده انتخاب شد.","success");await loadOffers(id);await loadMine();}catch(e){notice(e.message,"error");}};box.append(el);});}catch(e){notice(e.message,"error");}}
$("#hide-offers").onclick=()=>$("#offers-panel").hidden=true;
$("#reload-board").onclick=loadBoard;
async function loadBoard(){try{const d=await api("/api/provider/requests"),box=$("#board");box.innerHTML="";if(!d.requests?.length){box.textContent="در حال حاضر درخواست واجد شرایطی برای خدمات تأییدشده شما وجود ندارد.";return;}d.requests.forEach(r=>{const el=document.createElement("div");el.className="item";el.innerHTML=`<h4>${esc(r.service_name||r.service_id)}</h4><p>شهر: ${esc(r.city)}</p><p>زمان موردنظر متقاضی: ${esc(fmt(r.desired_at))}</p><p>${esc(r.description)}</p><label>مبلغ پیشنهادی (تومان)<input type="number" min="0" max="1000000000" step="1000" class="price" required></label><label>یادداشت (اختیاری)<textarea class="note" maxlength="500"></textarea></label><button class="primary">ثبت پیشنهاد برای زمان درخواستی</button>`;el.querySelector("button").onclick=async()=>{const price=Number(el.querySelector(".price").value);if(!Number.isSafeInteger(price)||price<0)return notice("مبلغ پیشنهادی را وارد کنید.","error");try{await api(`/api/requests/${encodeURIComponent(r.id)}/offers`,{method:"POST",body:JSON.stringify({price_toman:price,can_arrive:true,arrival_at:r.desired_at,note:el.querySelector(".note").value})});notice("پیشنهاد شما ثبت شد.","success");await loadBoard();}catch(e){notice(e.message,"error");}};box.append(el);});}catch(e){notice(e.message,"error");}}
$$("[data-logout]").forEach(b=>b.onclick=async()=>{try{await api("/api/auth/logout",{method:"POST",body:"{}"});}catch{}localStorage.removeItem("dg_token");home();});
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function fmt(v){if(!v)return "—";const d=new Date(v);return Number.isNaN(d.getTime())?v:d.toLocaleString("fa-IR");}
(async()=>{if(localStorage.getItem("dg_token")){try{await enterApp();}catch(e){localStorage.removeItem("dg_token");home();notice(e.message,"error");}}})();
})();
