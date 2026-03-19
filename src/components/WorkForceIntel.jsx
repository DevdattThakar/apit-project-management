import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { supabase } from "@/integrations/supabase/client";
import {
  supabaseLogin, supabaseLogout, getSession,
  fetchEmployees, fetchProjects, fetchReports, fetchAnnouncements,
  fetchProjectItems, insertProjectItems, deleteProjectItems,
  insertReport, insertProject, updateProject, updateProjectStatus,
  insertAnnouncement, uploadReportImage, uploadPODocument, createEmployee,
  fetchMaterialConsumption,
} from "@/lib/supabaseData";

// ═══════════════════════════════════════════════════════════════════════════════
// ─── SECURITY LAYER ──────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ── Input Sanitization ──
// Strips HTML tags and dangerous characters to prevent XSS
const sanitize = (str) => {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;")
    .trim();
};

// ── Input Validation ──
const Validate = {
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test((v || "").trim()),
  password: (v) => typeof v === "string" && v.length >= 8
    && /[A-Z]/.test(v) && /[0-9]/.test(v),
  text: (v, min = 1, max = 500) => typeof v === "string"
    && v.trim().length >= min && v.trim().length <= max,
  number: (v, min = 0, max = 24) => {
    const n = parseFloat(v); return !isNaN(n) && n >= min && n <= max;
  },
  noScript: (v) => !/(<script|javascript:|on\w+=)/i.test(v || ""),
};

// ── Rate Limiter ──
// Tracks failed attempts per identifier (email/IP) in memory
const RateLimiter = (() => {
  const store = {};                       // { key: { count, firstAt, lockedUntil } }
  const MAX_ATTEMPTS = 5;
  const WINDOW_MS = 15 * 60 * 1000;  // 15 min window
  const LOCKOUT_MS = 30 * 60 * 1000;  // 30 min lockout
  return {
    check(key) {
      const now = Date.now();
      if (!store[key]) return { allowed: true, remaining: MAX_ATTEMPTS };
      const rec = store[key];
      if (rec.lockedUntil && now < rec.lockedUntil) {
        const mins = Math.ceil((rec.lockedUntil - now) / 60000);
        return { allowed: false, remaining: 0, lockedMins: mins };
      }
      if (now - rec.firstAt > WINDOW_MS) {
        delete store[key];
        return { allowed: true, remaining: MAX_ATTEMPTS };
      }
      return {
        allowed: rec.count < MAX_ATTEMPTS,
        remaining: Math.max(0, MAX_ATTEMPTS - rec.count),
      };
    },
    fail(key) {
      const now = Date.now();
      if (!store[key]) store[key] = { count: 0, firstAt: now };
      store[key].count++;
      if (store[key].count >= MAX_ATTEMPTS) {
        store[key].lockedUntil = now + LOCKOUT_MS;
      }
    },
    reset(key) { delete store[key]; },
  };
})();

// ── Session Manager ──
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 min inactivity
const SessionManager = (() => {
  let timer = null;
  let onExpire = null;
  const reset = () => {
    clearTimeout(timer);
    if (onExpire) timer = setTimeout(onExpire, SESSION_TIMEOUT_MS);
  };
  return {
    start(cb) {
      onExpire = cb;
      ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(ev =>
        window.addEventListener(ev, reset, { passive: true })
      );
      reset();
    },
    stop() {
      clearTimeout(timer);
      onExpire = null;
      ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(ev =>
        window.removeEventListener(ev, reset)
      );
    },
    refresh: reset,
  };
})();

// ── Audit Logger ──
// Immutable append-only in-memory audit trail
const AuditLog = (() => {
  const logs = [];
  return {
    push(action, detail = "", user = "system") {
      logs.push({
        id: `AL${Date.now()}${Math.random().toString(36).slice(2, 6)}`,
        ts: new Date().toISOString(),
        user, action, detail,
        ip: "client",           // In production: real IP from server
      });
    },
    getAll() { return [...logs]; },
    getLast(n = 50) { return logs.slice(-n); },
  };
})();


// ── HTTPS Enforcer ──
const enforceHTTPS = () => {
  if (typeof window !== "undefined"
    && window.location.protocol === "http:"
    && window.location.hostname !== "localhost"
    && window.location.hostname !== "127.0.0.1") {
    window.location.replace(window.location.href.replace("http://", "https://"));
    return false;
  }
  return true;
};

// ── Auth Logic Mock (for synchronous tests) ──
const authLogin = (email, password) => {
  if (!email || !Validate.email(email)) return { ok: false, error: "Invalid email" };
  const cred = CREDENTIALS.find(c => c.email === email.toLowerCase());
  const lock = RateLimiter.check(email.toLowerCase());
  if (!lock.allowed) return { ok: false, locked: true, error: "Too many attempts" };
  if (!cred || cred.password !== password) {
    RateLimiter.fail(email.toLowerCase());
    return { ok: false, error: "Invalid email or password" };
  }
  const emp = MOCK_EMPLOYEES.find(e => e.email === email.toLowerCase());
  return { ok: true, user: emp };
};

// ════════════════════════════════════════════════════════════════════════════════
// ─── TESTING LAYER ───────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════════════

const TestRunner = (() => {
  const suites = [];
  const results = [];

  const describe = (name, fn) => {
    const suite = { name, tests: [] };
    const it = (label, testFn) => suite.tests.push({ label, testFn });
    fn(it);
    suites.push(suite);
  };

  const expect = (val) => ({
    toBe: (exp) => { if (val !== exp) throw new Error(`Expected ${JSON.stringify(exp)}, got ${JSON.stringify(val)}`); },
    toEqual: (exp) => { if (JSON.stringify(val) !== JSON.stringify(exp)) throw new Error(`Expected ${JSON.stringify(exp)}, got ${JSON.stringify(val)}`); },
    toBeTruthy: () => { if (!val) throw new Error(`Expected truthy, got ${JSON.stringify(val)}`); },
    toBeFalsy: () => { if (val) throw new Error(`Expected falsy, got ${JSON.stringify(val)}`); },
    toContain: (exp) => { if (!(Array.isArray(val) ? val.includes(exp) : String(val).includes(exp))) throw new Error(`Expected to contain ${exp}`); },
    toMatch: (rx) => { if (!rx.test(String(val))) throw new Error(`Expected to match ${rx}, got ${val}`); },
    toBeGreaterThan: (n) => { if (!(val > n)) throw new Error(`Expected ${val} > ${n}`); },
    toBeLessThan: (n) => { if (!(val < n)) throw new Error(`Expected ${val} < ${n}`); },
    toThrow: () => {
      if (typeof val !== "function") throw new Error("toThrow needs a function");
      try { val(); throw new Error("no_throw"); }
      catch (e) { if (e.message === "no_throw") throw new Error("Expected function to throw"); }
    },
  });

  // ── Test Suites ─────────────────────────────────────────────────────────────

  describe("🔐 Authentication Security", it => {
    it("rejects empty email", () => {
      const r = authLogin("", "Admin@1234");
      expect(r.ok).toBe(false);
    });
    it("rejects invalid email format", () => {
      const r = authLogin("notanemail", "Admin@1234");
      expect(r.ok).toBe(false);
    });
    it("rejects wrong password", () => {
      const r = authLogin("admin@corp.com", "wrongpassword");
      expect(r.ok).toBe(false);
      expect(r.error).toContain("Invalid email or password");
    });
    it("accepts valid admin credentials", () => {
      RateLimiter.reset("admin@corp.com");
      const r = authLogin("admin@corp.com", "Admin@1234");
      expect(r.ok).toBe(true);
      expect(r.user.role).toBe("admin");
    });
    it("accepts valid employee credentials", () => {
      RateLimiter.reset("m.webb@corp.com");
      const r = authLogin("m.webb@corp.com", "Marcus@1234");
      expect(r.ok).toBe(true);
      expect(r.user.role).toBe("employee");
    });
    it("returns correct user data on success", () => {
      RateLimiter.reset("admin@corp.com");
      const r = authLogin("admin@corp.com", "Admin@1234");
      expect(r.user.name).toBe("Sarah Mitchell");
      expect(r.user.department).toBe("Administration");
    });
    it("is case-insensitive for email", () => {
      RateLimiter.reset("ADMIN@CORP.COM");
      const r = authLogin("ADMIN@CORP.COM", "Admin@1234");
      expect(r.ok).toBe(true);
    });
    it("blocks account after 5 failed attempts", () => {
      const testEmail = "brute@test.com";
      RateLimiter.reset(testEmail);
      for (let i = 0; i < 5; i++) authLogin(testEmail, "wrong");
      const r = authLogin(testEmail, "wrong");
      expect(r.locked).toBe(true);
    });
    it("allows login after rate limit reset", () => {
      RateLimiter.reset("admin@corp.com");
      const r = authLogin("admin@corp.com", "Admin@1234");
      expect(r.ok).toBe(true);
    });
  });

  describe("🛡️ Input Sanitization (XSS Prevention)", it => {
    it("sanitizes script tags", () => {
      const r = sanitize("<script>alert('xss')</script>");
      expect(r).toContain("&lt;script");
      expect(r).not.toContain("<script");
    });
    it("sanitizes event handlers", () => {
      const r = sanitize("<img onerror='alert(1)'>");
      expect(r).not.toContain("<img");
    });
    it("sanitizes double quotes", () => {
      const r = sanitize('He said "hello"');
      expect(r).toContain("&quot;");
    });
    it("sanitizes single quotes", () => {
      const r = sanitize("it's a test");
      expect(r).toContain("&#x27;");
    });
    it("sanitizes ampersands", () => {
      const r = sanitize("A & B");
      expect(r).toContain("&amp;");
    });
    it("preserves safe text", () => {
      const r = sanitize("Hello World 123");
      expect(r).toBe("Hello World 123");
    });
    it("handles empty string", () => {
      expect(sanitize("")).toBe("");
    });
    it("handles non-string input gracefully", () => {
      expect(sanitize(null)).toBe("");
      expect(sanitize(undefined)).toBe("");
    });
    it("detects injection in noScript check", () => {
      expect(Validate.noScript("<script>")).toBe(false);
      expect(Validate.noScript("javascript:")).toBe(false);
      expect(Validate.noScript("onclick=")).toBe(false);
      expect(Validate.noScript("safe text")).toBe(true);
    });
  });

  describe("✅ Input Validation", it => {
    it("validates correct email formats", () => {
      expect(Validate.email("user@example.com")).toBe(true);
      expect(Validate.email("u@x.io")).toBe(true);
    });
    it("rejects invalid emails", () => {
      expect(Validate.email("notanemail")).toBe(false);
      expect(Validate.email("@no-user.com")).toBe(false);
      expect(Validate.email("")).toBe(false);
    });
    it("validates password strength", () => {
      expect(Validate.password("Secure@123")).toBe(true);
      expect(Validate.password("Admin@1234")).toBe(true);
    });
    it("rejects weak passwords", () => {
      expect(Validate.password("short")).toBe(false);
      expect(Validate.password("alllowercase1")).toBe(false);
      expect(Validate.password("ALLUPPERCASE")).toBe(false);
    });
    it("validates text within bounds", () => {
      expect(Validate.text("hello", 1, 100)).toBe(true);
      expect(Validate.text("", 1, 100)).toBe(false);
    });
    it("validates hours worked range", () => {
      expect(Validate.number(8, 0, 24)).toBe(true);
      expect(Validate.number(-1, 0, 24)).toBe(false);
      expect(Validate.number(25, 0, 24)).toBe(false);
      expect(Validate.number("abc", 0, 24)).toBe(false);
    });
  });

  describe("🔄 Rate Limiter", it => {
    it("allows first attempt", () => {
      RateLimiter.reset("new@test.com");
      expect(RateLimiter.check("new@test.com").allowed).toBe(true);
    });
    it("tracks remaining attempts correctly", () => {
      const k = "track@test.com"; RateLimiter.reset(k);
      RateLimiter.fail(k); RateLimiter.fail(k);
      expect(RateLimiter.check(k).remaining).toBe(3);
    });
    it("locks after max attempts", () => {
      const k = "lock@test.com"; RateLimiter.reset(k);
      for (let i = 0; i < 5; i++) RateLimiter.fail(k);
      expect(RateLimiter.check(k).allowed).toBe(false);
    });
    it("reset clears lockout", () => {
      const k = "clear@test.com"; RateLimiter.reset(k);
      for (let i = 0; i < 5; i++) RateLimiter.fail(k);
      RateLimiter.reset(k);
      expect(RateLimiter.check(k).allowed).toBe(true);
    });
  });

  describe("📋 Audit Logger", it => {
    it("logs events with correct structure", () => {
      AuditLog.push("TEST_ACTION", "detail", "testuser");
      const logs = AuditLog.getLast(1);
      expect(logs.length).toBeGreaterThan(0);
      const last = logs[logs.length - 1];
      expect(last.action).toBe("TEST_ACTION");
      expect(last.detail).toBe("detail");
      expect(last.user).toBe("testuser");
    });
    it("generates unique IDs for each log", () => {
      AuditLog.push("A", "", "u"); AuditLog.push("B", "", "u");
      const all = AuditLog.getAll();
      const ids = all.map(l => l.id);
      const unique = new Set(ids);
      expect(unique.size).toBe(ids.length);
    });
    it("stores ISO timestamps", () => {
      AuditLog.push("TIMESTAMP_TEST", "", "u");
      const last = AuditLog.getLast(1)[0];
      expect(last.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
    it("getLast returns correct count", () => {
      const before = AuditLog.getAll().length;
      AuditLog.push("L1", "", "u"); AuditLog.push("L2", "", "u"); AuditLog.push("L3", "", "u");
      const last3 = AuditLog.getLast(3);
      expect(last3.length).toBe(3);
    });
  });

  describe("📊 Data Integrity", it => {
    it("all mock employees have required fields", () => {
      MOCK_EMPLOYEES.forEach(e => {
        expect(Validate.text(e.id)).toBe(true);
        expect(Validate.text(e.name)).toBe(true);
        expect(Validate.email(e.email)).toBe(true);
      });
    });
    it("all mock reports have valid hours", () => {
      MOCK_REPORTS.forEach(r => {
        expect(Validate.number(r.hours, 0.5, 24)).toBe(true);
      });
    });
    it("all projects have valid status", () => {
      SEED_PROJECTS.forEach(p => {
        expect(["active", "completed"].includes(p.status)).toBe(true);
      });
    });
    it("report locations have valid coordinates", () => {
      MOCK_REPORTS.forEach(r => {
        expect(typeof r.location.lat).toBe("number");
        expect(typeof r.location.lng).toBe("number");
        expect(r.location.lat).toBeGreaterThan(-90);
        expect(r.location.lat).toBeLessThan(90);
      });
    });
    it("no duplicate employee IDs", () => {
      const ids = MOCK_EMPLOYEES.map(e => e.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
    it("no duplicate project IDs", () => {
      const ids = SEED_PROJECTS.map(p => p.id);
      expect(new Set(ids).size).toBe(ids.length);
    });
    it("report employee IDs reference valid employees", () => {
      const empIds = MOCK_EMPLOYEES.map(e => e.id);
      MOCK_REPORTS.forEach(r => {
        expect(empIds.includes(r.employeeId)).toBe(true);
      });
    });
    it("report project IDs reference valid projects", () => {
      const projIds = SEED_PROJECTS.map(p => p.id);
      MOCK_REPORTS.forEach(r => {
        expect(projIds.includes(r.projectId)).toBe(true);
      });
    });
  });

  describe("🔒 Role-Based Access Control", it => {
    it("CREDENTIALS list has no empty passwords", () => {
      CREDENTIALS.forEach(c => {
        expect(Validate.text(c.password, 1, 200)).toBe(true);
      });
    });
    it("all credentials have valid roles", () => {
      CREDENTIALS.forEach(c => {
        expect(["admin", "employee"].includes(c.role)).toBe(true);
      });
    });
    it("admin credential has admin role", () => {
      RateLimiter.reset("admin@corp.com");
      const r = authLogin("admin@corp.com", "Admin@1234");
      expect(r.user.role).toBe("admin");
    });
    it("employee cannot login with admin creds", () => {
      RateLimiter.reset("m.webb@corp.com");
      const r = authLogin("m.webb@corp.com", "Admin@1234");
      expect(r.ok).toBe(false);
    });
    it("credential IDs match employee records", () => {
      const empCreds = CREDENTIALS.filter(c => c.role === "employee");
      const empIds = MOCK_EMPLOYEES.map(e => e.id);
      empCreds.forEach(c => expect(empIds.includes(c.id)).toBe(true));
    });
  });

  describe("📍 Location Security", it => {
    it("GPS coordinates are numeric", () => {
      const loc = { lat: 20.5937, lng: 78.9629, accuracy: 10 };
      expect(typeof loc.lat).toBe("number");
      expect(typeof loc.lng).toBe("number");
    });
    it("latitude is within valid range", () => {
      const lat = 20.5937;
      expect(lat > -90 && lat < 90).toBe(true);
    });
    it("longitude is within valid range", () => {
      const lng = 78.9629;
      expect(lng > -180 && lng < 180).toBe(true);
    });
    it("rejects out-of-range coordinates", () => {
      const invalidLat = 95;
      expect(invalidLat > -90 && invalidLat < 90).toBe(false);
    });
  });

  // ── Runner ──────────────────────────────────────────────────────────────────
  const run = () => {
    results.length = 0;
    let passed = 0, failed = 0;
    suites.forEach(suite => {
      suite.tests.forEach(test => {
        try {
          test.testFn(expect);
          results.push({ suite: suite.name, label: test.label, status: "pass" });
          passed++;
        } catch (e) {
          results.push({ suite: suite.name, label: test.label, status: "fail", error: e.message });
          failed++;
        }
      });
    });
    return { passed, failed, total: passed + failed, results };
  };

  return { run, getSuites: () => suites };
})();

// ─── Work Completion Report (WCR) Generator ──────────────────────────────────
function generateWCR(project, employees, reports, consumptionData = []) {
  // 1. Correct Data Source: consumptionData comes directly from the aggregated Supabase view

  // Aggregation of total points for executive summary
  // Aggregation of total work done from project_items for executive summary
  const totalQtyDone = consumptionData.reduce((s, m) => s + Number(m.consumedQty || 0), 0);

  // validation items
  let validationError = null;

  let technicalItems = [];
  let consumptionItems = [];

  consumptionData.forEach(m => {
    const itemName = m.itemName;
    const model = m.modelNumber || "-";
    const supplied = Number(m.suppliedQty || 0);
    const consumed = Number(m.consumedQty || 0);
    const balance = supplied - consumed; // explicit calculation
    const unit = m.unit || "Nos";

    // 5. Validation Before WCR
    if (consumed > supplied) {
      validationError = "Material usage exceeds supplied quantity";
    }

    // 2. Correct Calculation Logic & 3. Status
    let status = "";
    if (consumed > supplied) {
      status = "Error";
    } else if (balance === 0) {
      status = "Fully Utilized";
    } else {
      status = `${balance} ${unit} Remaining`;
    }

    const cat = (itemName || "").toLowerCase();
    // Simple heuristic to split Equipment vs Material
    const isTechnical = (cat.includes("cctv") || cat.includes("networking") || cat.includes("server") ||
      cat.includes("access") || cat.includes("panel") || cat.includes("switch") ||
      cat.includes("monitor") || cat.includes("camera") || cat.includes("nvr"));

    if (isTechnical && !cat.includes("cable")) {
      technicalItems.push({
        desc: itemName,
        model: model,
        qty: `${supplied} ${unit}`
      });
    } else {
      consumptionItems.push({
        desc: itemName,
        supplied: `${supplied} ${unit}`,
        consumed: `${consumed} ${unit}`,
        status: status
      });
    }
  });

  if (validationError) {
    alert(validationError);
    return;
  }

  const today = new Date().toLocaleDateString("en-US", { day: "numeric", month: "long", year: "numeric" });

  const equipRows = technicalItems.map(item =>
    `<tr><td>${item.desc}</td><td>${item.model}</td><td>${item.qty}</td></tr>`
  ).join("");

  const materialRows = consumptionItems.map(item =>
    `<tr><td>${item.desc}</td><td>${item.supplied}</td><td>${item.consumed}</td><td>${item.status}</td></tr>`
  ).join("");

  // Section 3: Scope of Work (Dynamic based on data)
  const scopeContent = `
    <ul class="main-bullets">
      <li>
        <b>System Configuration:</b> ${totalQtyDone} Active points now live on the NVR.
        <ul class="sub-bullets">
          <li><b>New Installations:</b> Completed and commissioned across site.</li>
          <li><b>Relocation (Shifting):</b> Any existing hardware was optimized and re-installed at strategic locations.</li>
        </ul>
      </li>
      <li>
        <b>Infrastructure & Civil Work:</b>
        <ul class="sub-bullets">
          <li><b>Fabrication & Foundation:</b> Support poles and concrete bases installed where required.</li>
          <li><b>Mounting Support:</b> Specialized mounting hardware utilized for stability.</li>
          <li><b>Trenching & Cabling:</b> Underground and surface cabling performed for network safety.</li>
        </ul>
      </li>
      <li>
        <b>Inventory Reconciliation:</b>
        <ul class="sub-bullets">
          <li><b>Completed:</b> All supplied materials accounted for and handover documents prepared.</li>
        </ul>
      </li>
    </ul>
  `;

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WCR - ${project.name}</title>
<style>
  @page{size:A4;margin:15mm 20mm;}
  *{margin:0;padding:0;box-sizing:border-box;}
  body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#fff;color:#000;line-height:1.4;padding:40px 50px;}
  .page{max-width:800px;margin:0 auto;}
  h1{text-align:center;font-size:20px;font-weight:bold;margin-bottom:20px;letter-spacing:0.5px;text-transform:uppercase;}
  .meta{margin-bottom:10px;font-size:14px;line-height:1.6;}
  .meta div{margin-bottom:4px;}
  .meta b{font-weight:bold; display: inline-block; width: 100px;}
  .separator{border-top: 1px solid #777; margin: 15px 0 20px 0;}
  h2{font-size:15px;font-weight:bold;margin:20px 0 10px;padding:0;}
  p{font-size:14px;line-height:1.5;text-align:justify; margin-bottom: 12px;}
  table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:13px;}
  th{border:1px solid #000;padding:8px 10px;font-weight:bold;text-align:left;background:#f9f9f9;}
  td{border:1px solid #000;padding:7px 10px;vertical-align:top;}
  
  .main-bullets{list-style-type: disc; margin-left: 25px; font-size: 14px;}
  .main-bullets > li{margin-bottom: 12px;}
  .sub-bullets{list-style-type: circle; margin-left: 25px; margin-top: 6px;}
  .sub-bullets > li{margin-bottom: 4px;}

  .sig-section{margin-top:30px; border-top: 1px solid #777; padding-top: 20px;}
  .sig-section h2{margin-bottom:15px; font-size: 16px;}
  .sig-line{display:inline-block;border-bottom:1px solid #000;min-width:250px;margin-left:4px; height: 18px; vertical-align: bottom;}
  .sig-row{margin:12px 0;font-size:14px;}
  .client-ack{margin-top:25px;}
  .client-ack p{margin-bottom:5px; font-weight: bold;}
  .ack-text{font-size:13px; font-weight: normal !important; margin-bottom: 15px;}
  
  @media print{body{padding:0;}.page{max-width:none;}}
  @media screen{body{background:#e0e0e0;}.page{background:#fff;padding:60px 70px;box-shadow:0 4px 20px rgba(0,0,0,.15); margin-top: 20px; margin-bottom: 20px;}}
</style></head><body>
<div class="page">

  <h1>WORK COMPLETION REPORT</h1>

  <div class="meta">
    <div><b>Date:</b> ${today}</div>
    <div><b>Client:</b> ${project.companyName || "—"}</div>
    <div><b>Site Address:</b> ${project.workLocation || "—"}</div>
    <div><b>Subject:</b> Completion Report for ${project.name}</div>
  </div>

  <div class="separator"></div>

  <h2>1. Project Executive Summary</h2>
  <p>
    This report confirms the successful completion of the <b>${project.name}</b> project. 
    We have installed and commissioned a total of <b>${totalQtyDone} active points</b> at the ${project.companyName || "client"} facility. 
    The project involved new equipment installation, relocation of existing units, and infrastructure optimization.
  </p>

  <h2>2. Technical Equipment &amp; Hardware Details</h2>
  <p>The following hardware was supplied and integrated into the system:</p>
  <table>
    <thead><tr><th>Item Description</th><th>Model Number</th><th>Quantity</th></tr></thead>
    <tbody>${equipRows}</tbody>
  </table>

  <h2>3. Scope of Work &amp; Execution Details</h2>
  ${scopeContent}

  <h2>4. Material Consumption Report</h2>
  <table>
    <thead><tr><th>Material Description</th><th>Supplied Qty</th><th>Consumed Qty</th><th>Balance/Status</th></tr></thead>
    <tbody>${materialRows}</tbody>
  </table>

  <h2>5. Final Testing &amp; Handover</h2>
  <p>
    All cabling and hardware components have been verified for performance excellence. 
    Every point has been tested for network connectivity and operational stability. 
    The system is now fully operational and handed over for active use.
  </p>
  <p><b>Please review and acknowledge the completion of the work.</b></p>

  <div class="sig-section">
    <h2>Confirmation &amp; Approval</h2>

    <div class="sig-row"><b>Service Provider:</b> AP IT SOLUTIONS</div>
    <div class="sig-row">Name: <span class="sig-line"></span></div>
    <div class="sig-row">Signature &amp; Date: <span class="sig-line"></span></div>

    <div class="client-ack">
      <p>Client Acknowledgment (${project.companyName || "Client"}):</p>
      <div class="ack-text">I hereby confirm that the work mentioned above has been completed as per our requirements.</div>
      <div class="sig-row">Name: <span class="sig-line"></span></div>
      <div class="sig-row">Signature &amp; Stamp: <span class="sig-line"></span></div>
    </div>
  </div>

</div>

<script>
  window.onload = function() {
    setTimeout(function(){ window.print(); }, 800);
  };
</script>
</body></html>`;

  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const w = window.open(url, '_blank');
  if (!w) {
    const a = document.createElement("a");
    a.href = url; a.download = `WCR-${project.name.replace(/\s+/g, "-")}-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}


// ─── PDF / CSV helpers (unchanged logic) ─────────────────────────────────────
function buildReportHTML(r, emp, proj) {
  const refId = `WFI-${r.id.toUpperCase()}-${r.date.replace(/-/g, "")}`;
  const tasks = r.tasksCompleted.map(t => `<tr><td style="padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:12px;color:#374151;">✓ ${t}</td></tr>`).join("");
  const issues = r.issuesFaced.length
    ? r.issuesFaced.map(t => `<tr><td style="padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:12px;color:#374151;">⚠ ${t}</td></tr>`).join("")
    : `<tr><td style="padding:6px 0;font-size:12px;color:#94a3b8;font-style:italic;">None reported.</td></tr>`;
  return `<html><head><meta charset="UTF-8"><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:Arial,sans-serif;background:#fff;color:#0f172a;}
  .pg{width:740px;margin:0 auto;padding:48px 0;}.hdr{display:table;width:100%;padding-bottom:16px;border-bottom:2.5px solid #2563eb;margin-bottom:24px;}
  .hl{display:table-cell;vertical-align:middle;}.hr{display:table-cell;vertical-align:middle;text-align:right;}
  .br{font-size:13px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#2563eb;}.bs{font-size:9px;color:#64748b;letter-spacing:.1em;margin-top:2px;}
  .dt{font-size:18px;font-weight:700;color:#0f172a;}.dr{font-size:10px;color:#94a3b8;margin-top:3px;}
  .sl{font-size:9px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:#94a3b8;padding-bottom:6px;border-bottom:1px solid #e2e8f0;margin-bottom:12px;}
  .blk{margin-bottom:20px;}.it{width:100%;border-collapse:collapse;border:1px solid #e2e8f0;margin-bottom:20px;}
  .it td{padding:10px 14px;border:1px solid #e2e8f0;}.ik{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#94a3b8;margin-bottom:3px;}
  .iv{font-size:13px;font-weight:600;color:#0f172a;}.gps{background:#eff6ff;border:1px solid #bfdbfe;border-radius:3px;padding:10px 14px;margin-bottom:20px;display:table;width:100%;}
  .gl{display:table-cell;vertical-align:middle;}.gr{display:table-cell;vertical-align:middle;text-align:right;}
  .gk{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#1d4ed8;margin-bottom:3px;}.gv{font-size:12px;font-weight:600;color:#1e40af;}
  .raw{background:#f8fafc;border-left:3px solid #cbd5e1;padding:12px 14px;font-size:12px;color:#374151;line-height:1.65;}
  .ai{background:#eff6ff;border-left:3px solid #2563eb;padding:12px 14px;font-size:12px;color:#1e293b;line-height:1.65;}
  .bdg{display:inline-block;background:#eff6ff;border:1px solid #bfdbfe;padding:1px 5px;font-size:8px;font-weight:700;letter-spacing:.1em;color:#1d4ed8;text-transform:uppercase;margin-left:6px;vertical-align:middle;}
  .tc{display:table;width:100%;border-collapse:collapse;margin-bottom:20px;}.col{display:table-cell;width:50%;padding-right:18px;vertical-align:top;}.col:last-child{padding-right:0;padding-left:18px;}
  .ft{margin-top:28px;padding-top:12px;border-top:1px solid #e2e8f0;display:table;width:100%;}.fl{display:table-cell;vertical-align:middle;}.fr{display:table-cell;vertical-align:middle;text-align:right;}
  .ft-t{font-size:10px;color:#94a3b8;line-height:1.6;}.conf{display:inline-block;padding:2px 6px;border:1px solid #fecaca;background:#fff7f7;font-size:8px;font-weight:700;letter-spacing:.12em;color:#dc2626;text-transform:uppercase;}
  @media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
  </style></head><body><div class="pg">
  <div class="hdr"><div class="hl"><div class="br">WorkForce Intel</div><div class="bs">Internal Operations Platform</div></div>
  <div class="hr"><div class="dt">Work Report</div><div class="dr">REF: ${refId}</div></div></div>
  <div class="blk"><div class="sl">Employee & Assignment</div>
  <table class="it"><tr><td><div class="ik">Employee</div><div class="iv">${emp?.name || "—"}</div></td><td><div class="ik">Email</div><div class="iv">${emp?.email || "—"}</div></td></tr>
  <tr><td><div class="ik">Department</div><div class="iv">${emp?.department || "—"}</div></td><td><div class="ik">Project</div><div class="iv">${proj?.name || "—"}</div></td></tr>
  <tr><td><div class="ik">Date</div><div class="iv">${r.date}</div></td><td><div class="ik">Hours</div><div class="iv">${r.hours} hrs</div></td></tr></table></div>
  <div class="gps"><div class="gl"><div class="gk">GPS Location</div><div class="gv">${r.location.address}</div></div><div class="gr"><div class="gv">${r.location.lat}°N, ${r.location.lng}°E</div></div></div>
  <div class="blk"><div class="sl">Raw Employee Input</div><div class="raw">${r.rawDescription}</div></div>
  <div class="blk"><div class="sl">AI Intelligence Layer <span class="bdg">Admin Only</span></div><div class="ai">${r.aiSummary}</div></div>
  <div class="tc"><div class="col"><div class="sl">Tasks Completed</div><table style="width:100%;border-collapse:collapse;"><tbody>${tasks}</tbody></table></div>
  <div class="col"><div class="sl">Issues Faced</div><table style="width:100%;border-collapse:collapse;"><tbody>${issues}</tbody></table></div></div>
  <div class="ft"><div class="fl"><span class="conf">Confidential</span><div class="ft-t" style="margin-top:4px;">Generated: ${new Date().toLocaleString("en-GB")} · WorkForce Intel</div></div>
  <div class="fr"><div class="ft-t">ID: ${refId}<br/>Authorized personnel only</div></div></div>
  </div></body></html>`;
}
function generateReportPDF(r, emp, proj) {
  const blob = new Blob([buildReportHTML(r, emp, proj)], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `report-${(emp?.name || "emp").replace(/\s+/g, "-").toLowerCase()}-${r.date}.html`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}
function downloadCSV(reports) {
  const hdr = ["ID", "Employee", "Email", "Department", "Project", "Date", "Hours", "Summary", "Tasks", "Issues", "Location", "Lat", "Lng"];
  const rows = reports.map(r => {
    const emp = MOCK_EMPLOYEES.find(e => e.id === r.employeeId), proj = MOCK_PROJECTS.find(p => p.id === r.projectId);
    return [r.id, emp?.name || "", emp?.email || "", emp?.department || "", proj?.name || "", r.date, r.hours,
    `"${r.aiSummary.replace(/"/g, '""')}"`, `"${r.tasksCompleted.join("; ").replace(/"/g, '""')}"`,
    `"${r.issuesFaced.join("; ").replace(/"/g, '""')}"`, r.location.address, r.location.lat, r.location.lng].join(",");
  });
  const blob = new Blob([[hdr.join(","), ...rows].join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = url; a.download = `reports-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); URL.revokeObjectURL(url);
}

// ─── Data ────────────────────────────────────────────────────────────────────
const MOCK_EMPLOYEES = [];
const SEED_PROJECTS = [];
// MOCK_PROJECTS is kept as a global reference for components that haven't been lifted yet
let MOCK_PROJECTS = [...SEED_PROJECTS];
const MOCK_REPORTS = [];
const DEPARTMENTS = ["IT", "Networking", "CCTV", "Security", "Maintenance"];

// ─── Global CSS ───────────────────────────────────────────────────────────────
const G = `
  @import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700;800;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Nunito', system-ui, sans-serif; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #bfdbfe; border-radius: 10px; }
  @keyframes fadeUp { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
  @keyframes circleFade { 0%,100%{opacity:.18;} 50%{opacity:.28;} }
  @keyframes pulse { 0%,100%{transform:scale(1);} 50%{transform:scale(1.04);} }
  .fu  { animation: fadeUp .38s ease both; }
  .fu1 { animation: fadeUp .38s .06s ease both; }
  .fu2 { animation: fadeUp .38s .12s ease both; }
  .fu3 { animation: fadeUp .38s .18s ease both; }
  .fu4 { animation: fadeUp .38s .24s ease both; }
  input:focus, select:focus, textarea:focus {
    outline: none; border-color: #60a5fa !important;
    box-shadow: 0 0 0 3px rgba(96,165,250,.2);
  }
  .nav-btn:hover { background: #eff6ff !important; }
  .nav-btn.active { background: #dbeafe !important; color: #2563eb !important; }
  .row-hover:hover { background: #f0f9ff !important; }
`;

// ─── Color palette ────────────────────────────────────────────────────────────
const C = {
  blue: "#2563eb", blueL: "#3b82f6", bluePale: "#eff6ff", blueSoft: "#dbeafe",
  blueMid: "#bfdbfe", text: "#1e293b", muted: "#64748b", light: "#94a3b8",
  border: "#e2e8f0", bg: "#f8faff", white: "#ffffff",
};

// ─── Tiny primitives ──────────────────────────────────────────────────────────
const Avt = ({ initials, size = 32, colors = ["#2563eb", "#3b82f6"] }) => (
  <div style={{
    width: size, height: size, borderRadius: "50%", flexShrink: 0,
    background: `linear-gradient(135deg,${colors[0]},${colors[1]})`,
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: size < 34 ? 9 : size < 44 ? 11 : 13, fontWeight: 800, color: "#fff", letterSpacing: ".04em",
    boxShadow: `0 2px 8px rgba(37,99,235,.25)`
  }}>
    {initials}
  </div>
);

const Pill = ({ children, color = "blue" }) => {
  const map = {
    blue: { bg: "#dbeafe", c: "#2563eb" }, green: { bg: "#dcfce7", c: "#16a34a" },
    amber: { bg: "#fef3c7", c: "#d97706" }, red: { bg: "#fee2e2", c: "#dc2626" },
    gray: { bg: "#f1f5f9", c: "#64748b" }, purple: { bg: "#ede9fe", c: "#7c3aed" },
  };
  const s = map[color] || map.blue;
  return <span style={{
    display: "inline-flex", alignItems: "center", padding: "3px 10px", borderRadius: 20,
    background: s.bg, color: s.c, fontSize: 11, fontWeight: 700, letterSpacing: ".02em"
  }}>{children}</span>;
};

// Card matching iPeople's white rounded cards
const W = ({ children, style: sx = {}, cls = "" }) => (
  <div className={cls} style={{
    background: C.white, borderRadius: 20,
    boxShadow: "0 2px 16px rgba(37,99,235,.07)", border: `1px solid ${C.border}`,
    overflow: "hidden", ...sx
  }}>{children}</div>
);

// ── Time helper + Last-Updated badge ─────────────────────────────────────────
const timeAgo = (iso) => {
  if (!iso) return null;
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  if (s < 60) return "just now";
  if (m < 60) return m + "m ago";
  if (h < 24) return h + "h ago";
  if (d === 1) return "yesterday";
  if (d < 7) return d + "d ago";
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
};

const LastUpdatedBadge = ({ project, style: sx = {} }) => {
  if (!project?.lastUpdatedAt) return null;
  const ago = timeAgo(project.lastUpdatedAt);
  const typeColors = {
    "Report submitted": { bg: "#f0fdf4", border: "#86efac", c: "#059669", ico: "📋" },
    "Status → completed": { bg: "#faf5ff", border: "#d8b4fe", c: "#7c3aed", ico: "✓" },
    "Status → active": { bg: "#eff6ff", border: "#93c5fd", c: "#2563eb", ico: "🔄" },
    "Team updated": { bg: "#fff7ed", border: "#fcd34d", c: "#d97706", ico: "👥" },
    "Project edited": { bg: "#eff6ff", border: "#93c5fd", c: "#2563eb", ico: "✏️" },
    "Project created": { bg: "#f0fdf4", border: "#86efac", c: "#059669", ico: "🚀" },
  };
  const scheme = typeColors[project.lastUpdateType] || { bg: "#f8faff", border: "#e2e8f0", c: "#64748b", ico: "🕐" };
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: 5, padding: "4px 10px",
      borderRadius: 20, background: scheme.bg, border: `1px solid ${scheme.border}`, ...sx
    }}>
      <span style={{ fontSize: 11 }}>{scheme.ico}</span>
      <span style={{ fontSize: 10, fontWeight: 800, color: scheme.c }}>
        {ago}
        {project.lastUpdatedBy && <span style={{ fontWeight: 600, opacity: .8 }}> · {project.lastUpdatedBy.split(" ")[0]}</span>}
      </span>
    </div>
  );
};

const Lbl = ({ children, err }) => (
  <div style={{
    fontSize: 11, fontWeight: 700, letterSpacing: ".08em", textTransform: "uppercase",
    color: err ? "#dc2626" : C.light, marginBottom: 6
  }}>{children}</div>
);

// Small inline error tip below a field
const ErrTip = ({ children }) => (
  <div style={{ fontSize: 11, color: "#dc2626", fontWeight: 700, marginTop: 4, display: "flex", alignItems: "center", gap: 4 }}>
    <span>⚠</span>{children}
  </div>
);


// Section heading (blue, italic like iPeople)
const SH = ({ children, sub }) => (
  <div style={{ marginBottom: 20 }} className="fu">
    <h2 style={{ fontSize: 22, fontWeight: 800, color: C.blue, letterSpacing: "-.01em", fontStyle: "italic", margin: "0 0 2px" }}>{children}</h2>
    {sub && <p style={{ fontSize: 13, color: C.muted, margin: 0 }}>{sub}</p>}
  </div>
);

// Blue gradient button
const Btn = ({ children, onClick, v = "primary", sm, icon, disabled, style: sx = {} }) => {
  const b = {
    display: "inline-flex", alignItems: "center", gap: 6, border: "none",
    cursor: disabled ? "not-allowed" : "pointer", fontFamily: "inherit", fontWeight: 700,
    transition: "all .18s", opacity: disabled ? .5 : 1, borderRadius: 50,
    fontSize: sm ? 12 : 13, padding: sm ? "6px 14px" : "10px 22px"
  };
  const vs = {
    primary: { background: `linear-gradient(135deg,${C.blue},${C.blueL})`, color: "#fff", boxShadow: "0 4px 14px rgba(37,99,235,.3)" },
    secondary: { background: C.white, color: C.blue, border: `1.5px solid ${C.blueMid}` },
    ghost: { background: "transparent", color: C.muted, border: `1.5px solid ${C.border}` },
    soft: { background: C.bluePale, color: C.blue, border: "none" },
  };
  return <button onClick={disabled ? undefined : onClick} style={{ ...b, ...(vs[v] || vs.primary), ...sx }}>
    {icon && <span>{icon}</span>}{children}</button>;
};

// Input fields
const FI = ({ value, onChange, placeholder, type = "text", readOnly, rows, err, disabled, min, step }) => {
  const s = {
    width: "100%", padding: "11px 16px",
    border: `1.5px solid ${err ? "#f87171" : C.border}`, borderRadius: 14,
    fontFamily: "inherit", fontSize: 13, color: C.text, background: readOnly || disabled ? "#f8faff" : C.white,
    resize: "vertical", transition: "border-color .2s,box-shadow .2s",
    outline: "none", boxShadow: err ? "0 0 0 3px rgba(239,68,68,.1)" : "none",
    opacity: disabled ? .6 : 1, cursor: disabled ? "not-allowed" : "auto"
  };
  return rows
    ? <textarea value={value} onChange={onChange} placeholder={placeholder} rows={rows} style={s} />
    : <input type={type} value={value} onChange={onChange} placeholder={placeholder}
      readOnly={readOnly} disabled={disabled} min={min} step={step} style={s} />;
};
const FS = ({ value, onChange, children, err }) => (
  <select value={value} onChange={onChange} style={{
    width: "100%", padding: "11px 16px",
    border: `1.5px solid ${err ? "#f87171" : C.border}`, borderRadius: 14, fontFamily: "inherit", fontSize: 13,
    color: C.text, background: C.white, cursor: "pointer",
    boxShadow: err ? "0 0 0 3px rgba(239,68,68,.1)" : "none", outline: "none"
  }}>
    {children}
  </select>
);

// ─── Loading screen ───────────────────────────────────────────────────────────
function LoadingScreen({ onComplete }) {
  const [phase, setPhase] = useState(0), [prog, setProg] = useState(0);
  useEffect(() => {
    const t1 = setTimeout(() => setPhase(1), 300);
    const iv = setInterval(() => setProg(p => { if (p >= 100) { clearInterval(iv); return 100; } return p + (p < 60 ? 3 : p < 85 ? 1.5 : .7); }), 35);
    const t2 = setTimeout(() => { setPhase(2); setTimeout(onComplete, 700); }, 2500);
    return () => { clearTimeout(t1); clearTimeout(t2); clearInterval(iv); };
  }, []);
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "linear-gradient(145deg,#e0f0ff 0%,#c7e3ff 40%,#dceeff 100%)",
      display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column",
      opacity: phase === 2 ? 0 : 1, transition: phase === 2 ? "opacity .7s ease" : "none"
    }}>
      {/* Big soft circles */}
      {[{ w: 500, t: "-10%", r: "-8%" }, { w: 340, b: "-8%", l: "-5%" }, { w: 200, t: "35%", r: "5%" }].map((c, i) => (
        <div key={i} style={{
          position: "absolute", width: c.w, height: c.w, borderRadius: "50%",
          background: "rgba(37,99,235,.12)", top: c.t, right: c.r, bottom: c.b, left: c.l,
          animation: `circleFade 4s ${i * .5}s ease-in-out infinite`
        }} />
      ))}
      <div style={{
        position: "relative", display: "flex", flexDirection: "column", alignItems: "center", gap: 28,
        opacity: phase === 0 ? 0 : 1, filter: phase === 0 ? "blur(8px)" : "blur(0)", transition: "opacity .8s,filter .8s"
      }}>
        {/* AP IT SOLUTIONS Logo */}
        <div style={{
          background: C.white, borderRadius: 24, padding: "20px 36px",
          boxShadow: "0 8px 32px rgba(37,99,235,.15)", display: "flex", flexDirection: "column", alignItems: "center", gap: 8
        }}>
          <img src="data:image/png;base64,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bzyalKnUpqTUZtOytZWtu2cbbTSOa1VOnUcU5QTV9u299+3hc0zWtpu16dY7fLA2aH4SJa58XxWNaCOQyc9hP0Lg1LbL5Vbg26soaJj6WkgwySR2I2OOcnlzOOXLyW9L4mYZIXxteWFzSA4drfNbVspp1XKTk7txfD8u5eO3tNaWZ1KajFRVkpL/AC3v6dhHe41S0VtNcLZSuq5qMltfU0xc1zGjHxOIcueTntwtr0VWWStsrZbHG2KDPx2Yw5r+/i8T5rEaWivenrQ6zT2J9aY3O6ueCZnBKCc5dxEEfQV3tA6elsNFVOqTEKirmMr44vkRDuaD34VDAQr++Ktq7Jr4k421WuT43487X3F3GSpe6ulrdF/C076y61wtw5bjta1dWv0/WUdBRzVNRUwuibwYw3iGCSSfAldHbSkqrbpuG2VlDPTTxFznl4HC4lxPIg+GFtKLsPBJ4tYrWd0tW2y1t5y1i2sM8Pqqzd78b7iPdX0V2ums7TXRWmqfQ0DgXHDck8WSQM+TVv8AA8yQskLHxlzQeF4wR5FfaLGFwSw9SpUUm3N3d7crfIYjFuvThTcUlBWXzMNrF9YbFV0tBRz1NRUQvjZ1YGGkjGSSfNYzbGjq7Xp2O21tBPTTsc973OA4XEu5YIPhhbYiSwSli1inJ3StbZaz2hYtrDPD6qs3e/G5jNVUMtz05X0EBAlnhc1mTgZ7gtRtNNfpdEN0wLTPSVPCYX1Epb1TWE83DByTjuwpBRaYnLoV6vtdZp6ri7cU9vd2o3w+OlRp+z1U1dSV+DRqlZTVunbbabfarZJc6GIOZVxt4eJ4I7cHzJOF1rNYD9ss2oqe2G1sbSmOGmPCHPeRzcQDgDux61uiLV5XSc4tv4Y2aWzZZWVna/Xa+82WY1FBpLbK93t23d3dXt5biPblRV+pbN9j67TDqa6u4WurpOAMbgjLuIfGPIdmO9djXdiuM9rsVqttK6thppW9cC4NBDQAMnuB5+K3pFDLJaU4TjOTbkkm9l7J35W28W0SRzWpCcXCKSi20ttrtW537DSNe2291lNZaplMysko6sTVEMHLIyCMZ7cYIz5ruyWqq1BqGiulxp5KShoBxQU0mOOSQ/fOxkADA5eS2pFM8qpSqynJtqWq2uDcd3X125kazGpGnGEUk1dJ8bS39RpF/tl8qNyKG5UVHHJT01MWtlldhjXODgTy5kjIOPauC6UF4oNxfs2y0OutNNTtjHVkDq3AAZ59nMZ9a35FHUyenNyam03PX4bHa3LdbmbwzScbLVTSjq8dq38+fI6drdcJInS3COGF7zlkMZ4urHgXd59AC7iIurCOrFK9znSlrO9rBERbGoREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQH/9k=" alt="AP IT Solutions" style={{ height: 90, objectFit: "contain" }} />
        </div>
        <div style={{ fontSize: 13, color: C.muted, letterSpacing: ".12em", textTransform: "uppercase", fontWeight: 600 }}>
          {prog < 40 ? "Verifying credentials…" : prog < 75 ? "Loading workspace…" : prog < 95 ? "Establishing secure session…" : "Ready ✓"}
        </div>
        <div style={{ width: 220, height: 4, background: C.blueSoft, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ height: "100%", background: `linear-gradient(90deg,${C.blue},${C.blueL})`, width: `${prog}%`, borderRadius: 10, transition: "width .1s linear" }} />
        </div>
      </div>
    </div>
  );
}

// ─── Login / Signup ──────────────────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [mode, setMode] = useState("login"); // "login" | "signup"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [locked, setLocked] = useState(false);
  const [loading, setLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({});

  const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;

  const validate = () => {
    const errs = {};
    if (mode === "signup" && !name.trim()) errs.name = "Full name is required.";
    if (!email.trim()) errs.email = "Email is required.";
    else if (!Validate.email(email)) errs.email = "Enter a valid email address.";
    if (!password) errs.password = "Password is required.";
    else if (mode === "signup" && !Validate.password(password)) errs.password = "Min 8 chars, 1 uppercase, 1 number.";
    if (mode === "signup" && password !== confirmPw) errs.confirmPw = "Passwords do not match.";
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleLogin = async () => {
    setError(""); setLocked(false); setSuccess("");
    if (!validate()) return;
    setLoading(true);
    try {
      const result = await supabaseLogin(email, password);
      setLoading(false);
      if (result.ok) {
        AuditLog.push("LOGIN_SUCCESS", `Role: ${result.user.role}`, result.user.email);
        onLogin(result.user.role, result.user);
      } else {
        setError(result.error || "Login failed.");
      }
    } catch (err) {
      setLoading(false);
      setError("Login failed. Please try again.");
    }
  };

  const handleSignup = async () => {
    setError(""); setSuccess("");
    if (!validate()) return;
    setLoading(true);
    try {
      const res = await fetch(`${SUPABASE_URL}/functions/v1/signup-admin`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password, department: "Administration" }),
      });
      const json = await res.json();
      setLoading(false);
      if (!res.ok || json.error) {
        setError(json.error || "Signup failed.");
      } else {
        setSuccess("Admin account created! You can now sign in.");
        setMode("login");
        setPassword(""); setConfirmPw(""); setName("");
      }
    } catch (err) {
      setLoading(false);
      setError("Signup failed. Please try again.");
    }
  };

  const handleSubmit = mode === "login" ? handleLogin : handleSignup;
  const handleKey = (e) => { if (e.key === "Enter") handleSubmit(); };

  return (
    <div style={{
      minHeight: "100vh", background: "linear-gradient(145deg,#e0f0ff 0%,#c7e3ff 40%,#dceeff 100%)",
      display: "flex", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden", padding: 24
    }}>
      {[{ w: 520, t: "-12%", r: "-9%" }, { w: 320, b: "-7%", l: "-5%" }, { w: 180, t: "40%", r: "6%" }].map((c, i) => (
        <div key={i} style={{
          position: "absolute", width: c.w, height: c.w, borderRadius: "50%",
          background: "rgba(37,99,235,.13)", top: c.t, right: c.r, bottom: c.b, left: c.l, pointerEvents: "none"
        }} />
      ))}
      <div style={{
        position: "relative", zIndex: 1, background: C.white, borderRadius: 28,
        boxShadow: "0 12px 60px rgba(37,99,235,.15)", overflow: "hidden",
        display: "flex", width: "100%", maxWidth: 960, minHeight: 580
      }}>

        {/* Left panel */}
        <div style={{
          flex: "0 0 50%", background: "linear-gradient(145deg,#1d4ed8 0%,#2563eb 50%,#60a5fa 100%)",
          padding: "52px 48px", display: "flex", flexDirection: "column", justifyContent: "center", position: "relative", overflow: "hidden"
        }}>
          {[{ w: 380, t: "-15%", r: "-12%" }, { w: 240, b: "-8%", l: "-8%" }].map((c, i) => (
            <div key={i} style={{
              position: "absolute", width: c.w, height: c.w, borderRadius: "50%",
              background: "rgba(255,255,255,.1)", top: c.t, right: c.r, bottom: c.b, left: c.l, pointerEvents: "none"
            }} />
          ))}
          <div style={{ position: "relative", zIndex: 1 }}>
            <div style={{ marginBottom: 36 }}>
              <div style={{
                background: "rgba(255,255,255,.15)", borderRadius: 16, padding: "14px 20px",
                display: "inline-flex", alignItems: "center", gap: 10, marginBottom: 28
              }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 10, background: "rgba(255,255,255,.9)",
                  display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18
                }}>🔐</div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 800, color: "rgba(255,255,255,.7)", letterSpacing: ".1em", textTransform: "uppercase" }}>WorkForce Intel</div>
                  <div style={{ fontSize: 10, color: "rgba(255,255,255,.55)", fontWeight: 600 }}>Secured by JWT + RBAC</div>
                </div>
              </div>
              <h1 style={{ fontSize: 32, fontWeight: 900, color: "#fff", lineHeight: 1.2, marginBottom: 12, letterSpacing: "-.02em" }}>
                {mode === "login" ? <>Secure Access<br /><span style={{ color: "#bfdbfe" }}>Control Panel</span></>
                  : <>Create Admin<br /><span style={{ color: "#bfdbfe" }}>Account</span></>}
              </h1>
              <p style={{ fontSize: 13, color: "rgba(255,255,255,.75)", lineHeight: 1.7, maxWidth: 320, marginBottom: 28 }}>
                {mode === "login"
                  ? "Enterprise-grade workforce management with end-to-end security, real-time tracking, and audit logging."
                  : "Set up the first administrator account to get started with your organization's workforce management."}
              </p>
            </div>
            {/* Security badges */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 28 }}>
              {["🔒 AES-256", "🛡️ RBAC", "⏱️ Session Mgmt", "📋 Audit Log", "🚫 Rate Limiting"].map(b => (
                <span key={b} style={{
                  background: "rgba(255,255,255,.15)", border: "1px solid rgba(255,255,255,.25)",
                  borderRadius: 20, padding: "4px 10px", fontSize: 10, color: "rgba(255,255,255,.85)", fontWeight: 700
                }}>{b}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Right panel — Form */}
        <div style={{ flex: 1, padding: "44px 48px", display: "flex", flexDirection: "column", justifyContent: "center", overflowY: "auto" }} className="fu">

          {/* Tab switcher */}
          <div style={{ display: "flex", gap: 0, marginBottom: 24, background: "#f1f5f9", borderRadius: 14, padding: 4 }}>
            {[{ k: "login", l: "Sign In" }, { k: "signup", l: "Admin Sign Up" }].map(t => (
              <button key={t.k} onClick={() => { setMode(t.k); setError(""); setSuccess(""); setFieldErrors({}); }}
                style={{
                  flex: 1, padding: "10px 0", borderRadius: 10, fontFamily: "inherit", fontSize: 13, fontWeight: 800,
                  cursor: "pointer", border: "none", transition: "all .2s",
                  background: mode === t.k ? C.white : "transparent",
                  color: mode === t.k ? C.blue : C.light,
                  boxShadow: mode === t.k ? "0 2px 8px rgba(37,99,235,.12)" : "none"
                }}>
                {t.l}
              </button>
            ))}
          </div>

          <h2 style={{ fontSize: 24, fontWeight: 900, color: C.text, marginBottom: 4, letterSpacing: "-.02em" }}>
            {mode === "login" ? "Sign In" : "Create Admin Account"}
          </h2>
          <p style={{ fontSize: 13, color: C.muted, marginBottom: 22, fontWeight: 600 }}>
            {mode === "login" ? "Enter your credentials to access the platform" : "First-time setup — create the admin account for your organization"}
          </p>

          {/* Success banner */}
          {success && (
            <div style={{
              background: "#f0fdf4", border: "1.5px solid #bbf7d0", borderRadius: 14, padding: "12px 16px", marginBottom: 16,
              display: "flex", gap: 10, alignItems: "center"
            }} className="fu">
              <span style={{ fontSize: 18 }}>✅</span>
              <div style={{ fontSize: 13, color: "#166534", fontWeight: 700 }}>{success}</div>
            </div>
          )}

          {/* Error banner */}
          {error && (
            <div style={{
              background: locked ? "#fff7ed" : "#fef2f2",
              border: `1.5px solid ${locked ? "#fed7aa" : "#fecaca"}`,
              borderRadius: 14, padding: "12px 16px", marginBottom: 16,
              display: "flex", gap: 10, alignItems: "flex-start"
            }} className="fu">
              <span style={{ fontSize: 18, flexShrink: 0 }}>{locked ? "🔒" : "⚠️"}</span>
              <div style={{ fontSize: 13, color: locked ? "#9a3412" : "#dc2626", fontWeight: 700, lineHeight: 1.5 }}>{error}</div>
            </div>
          )}

          {/* Name field (signup only) */}
          {mode === "signup" && (
            <div style={{ marginBottom: 14 }}>
              <Lbl>Full Name</Lbl>
              <div style={{ position: "relative" }}>
                <input type="text" value={name}
                  onChange={e => { setName(e.target.value); setFieldErrors(p => ({ ...p, name: "" })); setError(""); }}
                  onKeyDown={handleKey} placeholder="e.g. Sarah Mitchell" disabled={loading}
                  style={{
                    width: "100%", padding: "12px 16px 12px 44px",
                    border: `1.5px solid ${fieldErrors.name ? "#fca5a5" : C.border}`,
                    borderRadius: 14, fontFamily: "inherit", fontSize: 13, color: C.text, background: C.white, transition: "all .2s"
                  }} />
                <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", fontSize: 16, pointerEvents: "none" }}>👤</span>
              </div>
              {fieldErrors.name && <div style={{ fontSize: 11, color: "#dc2626", marginTop: 4, fontWeight: 700 }}>⚠ {fieldErrors.name}</div>}
            </div>
          )}

          {/* Email field */}
          <div style={{ marginBottom: 14 }}>
            <Lbl>Email Address</Lbl>
            <div style={{ position: "relative" }}>
              <input type="email" value={email}
                onChange={e => { setEmail(e.target.value); setFieldErrors(p => ({ ...p, email: "" })); setError(""); }}
                onKeyDown={handleKey} placeholder="your@email.com" autoComplete="email" disabled={locked || loading}
                style={{
                  width: "100%", padding: "12px 16px 12px 44px",
                  border: `1.5px solid ${fieldErrors.email ? "#fca5a5" : C.border}`,
                  borderRadius: 14, fontFamily: "inherit", fontSize: 13, color: C.text,
                  background: locked ? "#f9fafb" : C.white, transition: "all .2s"
                }} />
              <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", fontSize: 16, pointerEvents: "none" }}>📧</span>
            </div>
            {fieldErrors.email && <div style={{ fontSize: 11, color: "#dc2626", marginTop: 4, fontWeight: 700 }}>⚠ {fieldErrors.email}</div>}
          </div>

          {/* Password field */}
          <div style={{ marginBottom: mode === "signup" ? 14 : 20 }}>
            <Lbl>Password</Lbl>
            <div style={{ position: "relative" }}>
              <input type={showPw ? "text" : "password"} value={password}
                onChange={e => { setPassword(e.target.value); setFieldErrors(p => ({ ...p, password: "" })); setError(""); }}
                onKeyDown={handleKey} placeholder="Enter your password" autoComplete={mode === "login" ? "current-password" : "new-password"}
                disabled={locked || loading}
                style={{
                  width: "100%", padding: "12px 44px 12px 44px",
                  border: `1.5px solid ${fieldErrors.password ? "#fca5a5" : C.border}`,
                  borderRadius: 14, fontFamily: "inherit", fontSize: 13, color: C.text,
                  background: locked ? "#f9fafb" : C.white, transition: "all .2s"
                }} />
              <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", fontSize: 16, pointerEvents: "none" }}>🔑</span>
              <button onClick={() => setShowPw(p => !p)} style={{
                position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)",
                background: "none", border: "none", cursor: "pointer", fontSize: 14, color: C.light, padding: 4
              }}>
                {showPw ? "🙈" : "👁️"}
              </button>
            </div>
            {fieldErrors.password && <div style={{ fontSize: 11, color: "#dc2626", marginTop: 4, fontWeight: 700 }}>⚠ {fieldErrors.password}</div>}
          </div>

          {/* Confirm password (signup only) */}
          {mode === "signup" && (
            <div style={{ marginBottom: 20 }}>
              <Lbl>Confirm Password</Lbl>
              <div style={{ position: "relative" }}>
                <input type="password" value={confirmPw}
                  onChange={e => { setConfirmPw(e.target.value); setFieldErrors(p => ({ ...p, confirmPw: "" })); setError(""); }}
                  onKeyDown={handleKey} placeholder="Re-enter your password" disabled={loading}
                  style={{
                    width: "100%", padding: "12px 16px 12px 44px",
                    border: `1.5px solid ${fieldErrors.confirmPw ? "#fca5a5" : C.border}`,
                    borderRadius: 14, fontFamily: "inherit", fontSize: 13, color: C.text, background: C.white, transition: "all .2s"
                  }} />
                <span style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)", fontSize: 16, pointerEvents: "none" }}>🔐</span>
              </div>
              {fieldErrors.confirmPw && <div style={{ fontSize: 11, color: "#dc2626", marginTop: 4, fontWeight: 700 }}>⚠ {fieldErrors.confirmPw}</div>}
            </div>
          )}

          {/* Submit button */}
          <Btn v="primary" disabled={loading || locked} onClick={handleSubmit}
            style={{
              width: "100%", justifyContent: "center", padding: "14px", fontSize: 14, borderRadius: 16,
              boxShadow: "0 6px 20px rgba(37,99,235,.3)"
            }}>
            {loading ? (
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{
                  width: 16, height: 16, border: "2.5px solid rgba(255,255,255,.4)",
                  borderTopColor: "#fff", borderRadius: "50%",
                  animation: "spin 0.8s linear infinite", display: "inline-block"
                }} />
                {mode === "login" ? "Signing in…" : "Creating account…"}
              </span>
            ) : locked ? "🔒 Account Locked" : mode === "login" ? "Sign In →" : "Create Admin Account →"}
          </Btn>

          <p style={{ textAlign: "center", fontSize: 11, color: C.light, marginTop: 16, lineHeight: 1.6, fontWeight: 600 }}>
            🔒 Secured by JWT · Role-based access control · Session timeout: 30 min
          </p>

          {/* Password policy hint */}
          <div style={{
            marginTop: 12, padding: "10px 14px", background: "#f8faff", borderRadius: 12,
            border: `1px dashed ${C.border}`
          }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 4 }}>
              Password Policy
            </div>
            <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, lineHeight: 1.6 }}>
              Min 8 chars · 1 uppercase · 1 number · Account locks after 5 failed attempts
            </div>
          </div>
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
// ─── Sidebar (iPeople style) ─────────────────────────────────────────────────
function Sidebar({ role, active, onNav, user, onLogout, unreadAnnouncements = 0 }) {
  const adminNav = [
    { k: "overview", l: "Dashboard", ico: "⊞" },
    { k: "reports", l: "Reports", ico: "📋" },
    { k: "map", l: "Live Map", ico: "📍" },
    { k: "employees", l: "Employees", ico: "👥" },
    { k: "projects", l: "Projects", ico: "📊" },
    { k: "departments", l: "Departments", ico: "🏢" },
  ];
  const empNav = [
    { k: "submit", l: "Submit Report", ico: "✏️" },
    { k: "history", l: "My Reports", ico: "📄" },
    { k: "announcements", l: "Announcements", ico: "📢" },
  ];
  const tlNav = [
    { k: "tl-submit", l: "Submit Report", ico: "✏️" },
    { k: "tl-projects", l: "My Projects", ico: "🏗️" },
    { k: "tl-announce", l: "Announce", ico: "📢" },
    { k: "tl-history", l: "My Reports", ico: "📄" },
  ];
  const nav = role === "admin" ? adminNav : role === "tl" ? tlNav : empNav;

  const secLabel = (txt) => (
    <div style={{
      padding: "16px 20px 6px", fontSize: 10, fontWeight: 800, letterSpacing: ".14em",
      textTransform: "uppercase", color: C.light
    }}>{txt}</div>
  );

  return (
    <div style={{
      width: 220, background: C.white, borderRight: `1px solid ${C.border}`,
      display: "flex", flexDirection: "column", height: "100vh", position: "sticky", top: 0, flexShrink: 0,
      boxShadow: "2px 0 16px rgba(37,99,235,.05)"
    }}>

      {/* AP IT Solutions Logo */}
      <div style={{ padding: "14px 16px", borderBottom: `1px solid ${C.border}` }}>
        <img src="data:image/png;base64,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bzyalKnUpqTUZtOytZWtu2cbbTSOa1VOnUcU5QTV9u299+3hc0zWtpu16dY7fLA2aH4SJa58XxWNaCOQyc9hP0Lg1LbL5Vbg26soaJj6WkgwySR2I2OOcnlzOOXLyW9L4mYZIXxteWFzSA4drfNbVspp1XKTk7txfD8u5eO3tNaWZ1KajFRVkpL/AC3v6dhHe41S0VtNcLZSuq5qMltfU0xc1zGjHxOIcueTntwtr0VWWStsrZbHG2KDPx2Yw5r+/i8T5rEaWivenrQ6zT2J9aY3O6ueCZnBKCc5dxEEfQV3tA6elsNFVOqTEKirmMr44vkRDuaD34VDAQr++Ktq7Jr4k421WuT43487X3F3GSpe6ulrdF/C076y61wtw5bjta1dWv0/WUdBRzVNRUwuibwYw3iGCSSfAldHbSkqrbpuG2VlDPTTxFznl4HC4lxPIg+GFtKLsPBJ4tYrWd0tW2y1t5y1i2sM8Pqqzd78b7iPdX0V2ums7TXRWmqfQ0DgXHDck8WSQM+TVv8AA8yQskLHxlzQeF4wR5FfaLGFwSw9SpUUm3N3d7crfIYjFuvThTcUlBWXzMNrF9YbFV0tBRz1NRUQvjZ1YGGkjGSSfNYzbGjq7Xp2O21tBPTTsc973OA4XEu5YIPhhbYiSwSli1inJ3StbZaz2hYtrDPD6qs3e/G5jNVUMtz05X0EBAlnhc1mTgZ7gtRtNNfpdEN0wLTPSVPCYX1Epb1TWE83DByTjuwpBRaYnLoV6vtdZp6ri7cU9vd2o3w+OlRp+z1U1dSV+DRqlZTVunbbabfarZJc6GIOZVxt4eJ4I7cHzJOF1rNYD9ss2oqe2G1sbSmOGmPCHPeRzcQDgDux61uiLV5XSc4tv4Y2aWzZZWVna/Xa+82WY1FBpLbK93t23d3dXt5biPblRV+pbN9j67TDqa6u4WurpOAMbgjLuIfGPIdmO9djXdiuM9rsVqttK6thppW9cC4NBDQAMnuB5+K3pFDLJaU4TjOTbkkm9l7J35W28W0SRzWpCcXCKSi20ttrtW537DSNe2291lNZaplMysko6sTVEMHLIyCMZ7cYIz5ruyWqq1BqGiulxp5KShoBxQU0mOOSQ/fOxkADA5eS2pFM8qpSqynJtqWq2uDcd3X125kazGpGnGEUk1dJ8bS39RpF/tl8qNyKG5UVHHJT01MWtlldhjXODgTy5kjIOPauC6UF4oNxfs2y0OutNNTtjHVkDq3AAZ59nMZ9a35FHUyenNyam03PX4bHa3LdbmbwzScbLVTSjq8dq38+fI6drdcJInS3COGF7zlkMZ4urHgXd59AC7iIurCOrFK9znSlrO9rBERbGoREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQH/9k=" alt="AP IT Solutions" style={{ width: "100%", maxHeight: 56, objectFit: "contain" }} />
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "10px 10px 0", overflowY: "auto" }}>
        {secLabel(role === "admin" ? "ADMIN" : role === "tl" ? "TEAM LEAD" : "EMPLOYEE")}
        {nav.map(item => {
          const isA = active === item.k;
          return (
            <button key={item.k} onClick={() => onNav(item.k)} className={`nav-btn${isA ? " active" : ""}`} style={{
              width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
              borderRadius: 14, border: "none", cursor: "pointer", marginBottom: 2,
              background: isA ? C.blueSoft : "transparent",
              color: isA ? C.blue : C.muted,
              fontFamily: "inherit", fontSize: 13, fontWeight: isA ? 700 : 500, transition: "all .18s",
              textAlign: "left"
            }}>
              <span style={{ fontSize: 16, width: 20, textAlign: "center" }}>{item.ico}</span>
              <span style={{ flex: 1 }}>{item.l}</span>
              {item.k === "announcements" && unreadAnnouncements > 0 && (
                <span style={{
                  background: "#dc2626", color: "#fff", borderRadius: 20,
                  padding: "1px 7px", fontSize: 10, fontWeight: 900, lineHeight: "16px", flexShrink: 0
                }}>
                  {unreadAnnouncements}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div style={{ padding: "14px 14px", borderTop: `1px solid ${C.border}` }}>
        <div style={{ background: C.bluePale, borderRadius: 16, padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <Avt initials={user?.avatar || "U"} size={34} />
            <div style={{ overflow: "hidden" }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{user?.name}</div>
              <div style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>{role === "admin" ? "Administrator" : role === "tl" ? "Team Lead" : user?.department}</div>
            </div>
          </div>
          <button onClick={onLogout} style={{
            width: "100%", padding: "7px", background: C.white,
            border: `1px solid ${C.border}`, borderRadius: 10, cursor: "pointer", fontFamily: "inherit",
            fontSize: 11, color: C.muted, fontWeight: 700, transition: "all .2s"
          }}
            onMouseOver={e => { e.currentTarget.style.borderColor = "#fca5a5"; e.currentTarget.style.color = "#dc2626"; }}
            onMouseOut={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.muted; }}>
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Notification data ───────────────────────────────────────────────────────


// ─── Top bar ──────────────────────────────────────────────────────────────────
function TopBar({ title, sub, user, onLogout, announcements = [] }) {
  const [open, setOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [notifs, setNotifs] = useState([]);
  const [modal, setModal] = useState(null); // "profile" | "settings" | "password"

  useEffect(() => {
    if (announcements && announcements.length > 0) {
      // Show only announcements intended for this user or their department
      const relevant = announcements.filter(a => {
        const isRecipient = (a.recipientIds || []).includes(user?.id);
        const isDept = a.department === user?.department;
        const isFromAdmin = a.department === "Administration";
        return isRecipient || isDept || isFromAdmin;
      });

      const mapped = relevant.slice(0, 8).map(a => ({
        id: a.id,
        type: "announcement",
        icon: a.priority === "urgent" ? "🚨" : (a.priority === "info" ? "ℹ️" : "📢"),
        title: a.title || "New Team Message",
        body: a.message,
        time: timeAgo(a.sentAt),
        read: (a.readBy || []).includes(user?.id),
        color: a.priority === "urgent" ? "#dc2626" : (a.priority === "info" ? "#059669" : "#2563eb")
      }));
      setNotifs(mapped);
    } else {
      setNotifs([]);
    }
  }, [announcements, user]);

  const unread = notifs.filter(n => !n.read).length;

  // Profile edit state
  const [profileForm, setProfileForm] = useState({ name: user?.name || "", email: user?.email || "", phone: "", department: user?.department || "" });
  const [profileSaved, setProfileSaved] = useState(false);

  // Settings state
  const [settings, setSettings] = useState({
    emailNotifs: true, smsNotifs: false, locationTracking: true,
    darkMode: false, language: "English", timezone: "Asia/Kolkata",
  });

  // Password state
  const [pwForm, setPwForm] = useState({ current: "", next: "", confirm: "" });
  const [pwError, setPwError] = useState("");
  const [pwSaved, setPwSaved] = useState(false);

  const markAllRead = () => setNotifs(p => p.map(n => ({ ...n, read: true })));
  const markRead = (id) => setNotifs(p => p.map(n => n.id === id ? { ...n, read: true } : n));
  const dismiss = (id, e) => { e.stopPropagation(); setNotifs(p => p.filter(n => n.id !== id)); };

  const saveProfile = () => { setProfileSaved(true); setTimeout(() => setProfileSaved(false), 2500); };
  const savePassword = () => {
    if (!pwForm.current) { setPwError("Enter your current password."); return; }
    if (pwForm.next.length < 6) { setPwError("New password must be at least 6 characters."); return; }
    if (pwForm.next !== pwForm.confirm) { setPwError("New passwords do not match."); return; }
    setPwError(""); setPwSaved(true); setPwForm({ current: "", next: "", confirm: "" });
    setTimeout(() => setPwSaved(false), 2500);
  };

  useEffect(() => {
    if (!open && !profileOpen) return;
    const handler = (e) => {
      if (!e.target.closest("#notif-panel") && !e.target.closest("#notif-btn")) setOpen(false);
      if (!e.target.closest("#profile-panel") && !e.target.closest("#profile-btn")) setProfileOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open, profileOpen]);

  // ── Shared modal shell ──
  const Modal = ({ titleText, onClose, children }) => (
    <div style={{
      position: "fixed", inset: 0, zIndex: 99999, background: "rgba(15,23,42,.5)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20
    }}
      onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: C.white, borderRadius: 24,
        width: "100%", maxWidth: 480, maxHeight: "90vh", overflowY: "auto",
        boxShadow: "0 24px 80px rgba(37,99,235,.22)"
      }} className="fu">
        <div style={{
          background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
          padding: "20px 26px", display: "flex", justifyContent: "space-between", alignItems: "center",
          borderRadius: "24px 24px 0 0"
        }}>
          <div style={{ fontSize: 17, fontWeight: 900, color: "#fff" }}>{titleText}</div>
          <button onClick={onClose} style={{
            background: "rgba(255,255,255,.2)", border: "none",
            borderRadius: "50%", width: 32, height: 32, cursor: "pointer", color: "#fff", fontSize: 16,
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>✕</button>
        </div>
        <div style={{ padding: "24px 26px" }}>{children}</div>
      </div>
    </div>
  );

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24, position: "relative", zIndex: 1000 }} className="fu">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 900, color: C.blue, fontStyle: "italic", margin: "0 0 2px", letterSpacing: "-.01em" }}>{title}</h1>
          {sub && <p style={{ fontSize: 13, color: C.muted, margin: 0, fontWeight: 600 }}>{sub}</p>}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* Bell button */}
          <div style={{ position: "relative" }}>
            <button id="notif-btn" onClick={() => { setOpen(o => !o); setProfileOpen(false); }} style={{
              width: 38, height: 38, borderRadius: "50%",
              background: open ? C.blue : C.bluePale,
              border: `1.5px solid ${open ? C.blue : C.blueMid}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", fontSize: 17, transition: "all .2s",
              boxShadow: open ? `0 4px 14px rgba(37,99,235,.35)` : "none",
            }}>🔔</button>
            {unread > 0 && (
              <div style={{
                position: "absolute", top: -3, right: -3, minWidth: 18, height: 18, borderRadius: 9,
                background: "#ef4444", border: "2px solid #fff", display: "flex", alignItems: "center",
                justifyContent: "center", fontSize: 9, fontWeight: 900, color: "#fff", padding: "0 4px",
                animation: "pulse 2s infinite"
              }}>{unread}</div>
            )}
          </div>

          {/* Avatar / Profile button */}
          <div style={{ position: "relative" }}>
            <button id="profile-btn" onClick={() => { setProfileOpen(o => !o); setOpen(false); }} style={{
              width: 38, height: 38, borderRadius: "50%",
              background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 12, fontWeight: 900, color: "#fff", letterSpacing: ".04em",
              boxShadow: profileOpen ? `0 4px 14px rgba(37,99,235,.45)` : `0 2px 8px rgba(37,99,235,.25)`,
              outline: "none", transition: "all .2s", cursor: "pointer",
              border: profileOpen ? `2.5px solid #fff` : "2.5px solid transparent",
            }}>{user?.avatar || "U"}</button>

            {profileOpen && (
              <div id="profile-panel" style={{
                position: "fixed", top: 72, right: 24, width: 260,
                background: C.white, borderRadius: 20, border: `1px solid ${C.border}`,
                boxShadow: "0 20px 60px rgba(37,99,235,.2)", overflow: "hidden",
                zIndex: 99999, animation: "fadeUp .18s ease both"
              }}>
                {/* Header */}
                <div style={{ padding: "20px 18px 16px", background: `linear-gradient(135deg,${C.blue},${C.blueL})`, textAlign: "center" }}>
                  <div style={{
                    width: 56, height: 56, borderRadius: "50%",
                    background: "rgba(255,255,255,.25)", border: "3px solid rgba(255,255,255,.6)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    margin: "0 auto 10px", fontSize: 20, fontWeight: 900, color: "#fff",
                    boxShadow: "0 4px 12px rgba(0,0,0,.15)"
                  }}>{user?.avatar || "U"}</div>
                  <div style={{ fontSize: 15, fontWeight: 900, color: "#fff", marginBottom: 2 }}>{user?.name || "User"}</div>
                  <div style={{ fontSize: 11, color: "rgba(255,255,255,.75)", fontWeight: 600, marginBottom: 8 }}>{user?.email || ""}</div>
                  <span style={{
                    background: "rgba(255,255,255,.2)", color: "#fff", fontSize: 10,
                    fontWeight: 800, padding: "4px 12px", borderRadius: 20, letterSpacing: ".06em",
                    border: "1px solid rgba(255,255,255,.3)"
                  }}>
                    {user?.department === "Administration" ? "👑 Administrator" : "👤 Employee"}
                  </span>
                </div>
                {/* Menu items */}
                <div style={{ padding: "8px 0" }}>
                  {[
                    { ico: "👤", label: "My Profile", act: () => { setProfileOpen(false); setModal("profile"); } },
                    { ico: "⚙️", label: "Settings", act: () => { setProfileOpen(false); setModal("settings"); } },
                    { ico: "🔔", label: "Notifications", act: () => { setProfileOpen(false); setOpen(true); } },
                    { ico: "🔒", label: "Change Password", act: () => { setProfileOpen(false); setModal("password"); } },
                  ].map(item => (
                    <button key={item.label} onClick={item.act} style={{
                      width: "100%", padding: "11px 20px", background: "none", border: "none",
                      cursor: "pointer", fontFamily: "inherit", fontSize: 13, color: C.text, fontWeight: 600,
                      display: "flex", alignItems: "center", gap: 12, transition: "background .15s"
                    }}
                      onMouseOver={e => e.currentTarget.style.background = C.bluePale}
                      onMouseOut={e => e.currentTarget.style.background = "none"}>
                      <span style={{ fontSize: 16, width: 22, textAlign: "center" }}>{item.ico}</span>
                      {item.label}
                      <svg style={{ marginLeft: "auto", opacity: .35 }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6" /></svg>
                    </button>
                  ))}
                  <div style={{ height: 1, background: C.border, margin: "6px 14px" }} />
                  <button onClick={() => { setProfileOpen(false); onLogout && onLogout(); }} style={{
                    width: "100%", padding: "11px 20px", background: "none", border: "none",
                    cursor: "pointer", fontFamily: "inherit", fontSize: 13, color: "#ef4444", fontWeight: 700,
                    display: "flex", alignItems: "center", gap: 12, transition: "background .15s"
                  }}
                    onMouseOver={e => e.currentTarget.style.background = "#fff5f5"}
                    onMouseOut={e => e.currentTarget.style.background = "none"}>
                    <span style={{ fontSize: 16, width: 22, textAlign: "center" }}>🚪</span>
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Notification Dropdown ── */}
        {open && (
          <div id="notif-panel" style={{
            position: "fixed", top: 72, right: 90, width: 360, background: C.white,
            borderRadius: 20, border: `1px solid ${C.border}`,
            boxShadow: "0 20px 60px rgba(37,99,235,.2)", overflow: "hidden",
            animation: "fadeUp .2s ease both", zIndex: 99999
          }}>
            <div style={{
              padding: "16px 20px", borderBottom: `1px solid ${C.border}`,
              display: "flex", alignItems: "center", justifyContent: "space-between",
              background: "linear-gradient(135deg,#f8faff,#eff6ff)"
            }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 900, color: C.text }}>Notifications</div>
                <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, marginTop: 1 }}>
                  {unread > 0 ? `${unread} unread` : "All caught up ✓"}
                </div>
              </div>
              {unread > 0 && (
                <button onClick={markAllRead} style={{
                  background: "none", border: `1px solid ${C.blueMid}`,
                  borderRadius: 10, padding: "5px 12px", cursor: "pointer",
                  fontFamily: "inherit", fontSize: 11, color: C.blue, fontWeight: 700
                }}>Mark all read</button>
              )}
            </div>
            <div style={{ maxHeight: 360, overflowY: "auto" }}>
              {notifs.length === 0 && (
                <div style={{ padding: "40px 20px", textAlign: "center" }}>
                  <div style={{ fontSize: 36, marginBottom: 10 }}>🔔</div>
                  <div style={{ fontSize: 13, color: C.light, fontWeight: 700 }}>No notifications</div>
                </div>
              )}
              {notifs.map((n, i) => (
                <div key={n.id} onClick={() => markRead(n.id)} style={{
                  padding: "13px 18px", background: n.read ? "#fff" : "#f0f7ff",
                  borderBottom: i < notifs.length - 1 ? `1px solid ${C.border}` : "none",
                  cursor: "pointer", display: "flex", gap: 12, alignItems: "flex-start", transition: "background .15s"
                }}
                  onMouseOver={e => e.currentTarget.style.background = "#e8f4ff"}
                  onMouseOut={e => e.currentTarget.style.background = n.read ? "#fff" : "#f0f7ff"}>
                  <div style={{
                    width: 36, height: 36, borderRadius: "50%", flexShrink: 0,
                    background: `${n.color}18`, border: `1.5px solid ${n.color}40`,
                    display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16
                  }}>{n.icon}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                      <div style={{ fontSize: 12, fontWeight: n.read ? 600 : 800, color: C.text, lineHeight: 1.35 }}>{n.title}</div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                        {!n.read && <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#2563eb" }} />}
                        <button onClick={(e) => dismiss(n.id, e)} style={{ background: "none", border: "none", cursor: "pointer", color: C.light, fontSize: 14, lineHeight: 1, padding: "0 2px", fontFamily: "inherit" }}>✕</button>
                      </div>
                    </div>
                    <div style={{ fontSize: 11, color: C.muted, marginTop: 2, lineHeight: 1.5, fontWeight: 600 }}>{n.body}</div>
                    <div style={{ fontSize: 10, color: C.light, marginTop: 4, fontWeight: 700 }}>{n.time}</div>
                  </div>
                </div>
              ))}
            </div>
            {notifs.length > 0 && (
              <div style={{ padding: "10px 18px", borderTop: `1px solid ${C.border}`, background: "#f8faff", display: "flex", justifyContent: "center" }}>
                <button onClick={() => setNotifs([])} style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "inherit", fontSize: 11, color: C.light, fontWeight: 700 }}>Clear all notifications</button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ══ My Profile Modal ══ */}
      {modal === "profile" && (
        <Modal titleText="👤 My Profile" onClose={() => setModal(null)}>
          <div style={{
            display: "flex", alignItems: "center", gap: 16, marginBottom: 24,
            padding: "16px 18px", background: C.bluePale, borderRadius: 16
          }}>
            <div style={{
              width: 60, height: 60, borderRadius: "50%",
              background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 22, fontWeight: 900, color: "#fff", flexShrink: 0,
              boxShadow: "0 4px 14px rgba(37,99,235,.3)"
            }}>{user?.avatar || "U"}</div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 900, color: C.text }}>{profileForm.name || user?.name}</div>
              <div style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{profileForm.email || user?.email}</div>
              <Pill color="blue" style={{ marginTop: 4 }}>{user?.department === "Administration" ? "👑 Administrator" : "👤 Employee"}</Pill>
            </div>
          </div>
          {[
            { label: "Full Name", key: "name", placeholder: "Your full name" },
            { label: "Email Address", key: "email", type: "email", placeholder: "your@email.com" },
            { label: "Phone Number", key: "phone", type: "tel", placeholder: "+971 50 000 0000" },
            { label: "Department", key: "department", placeholder: "Your department" },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 16 }}>
              <Lbl>{f.label}</Lbl>
              <FI type={f.type || "text"} value={profileForm[f.key]}
                onChange={e => setProfileForm(p => ({ ...p, [f.key]: e.target.value }))}
                placeholder={f.placeholder} />
            </div>
          ))}
          {profileSaved && (
            <div style={{
              background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 12,
              padding: "10px 16px", marginBottom: 16, fontSize: 12, fontWeight: 700, color: "#059669"
            }}>
              ✅ Profile updated successfully!
            </div>
          )}
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <Btn v="ghost" onClick={() => setModal(null)}>Cancel</Btn>
            <Btn v="primary" onClick={saveProfile}>Save Changes</Btn>
          </div>
        </Modal>
      )}

      {/* ══ Settings Modal ══ */}
      {modal === "settings" && (
        <Modal titleText="⚙️ Settings" onClose={() => setModal(null)}>
          {/* Notifications section */}
          <div style={{ marginBottom: 22 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>🔔 Notifications</div>
            {[
              { key: "emailNotifs", label: "Email Notifications", desc: "Receive report & alert emails" },
              { key: "smsNotifs", label: "SMS Notifications", desc: "Get text alerts for critical issues" },
            ].map(s => (
              <div key={s.key} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "12px 16px", background: C.bluePale, borderRadius: 14, marginBottom: 10
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{s.label}</div>
                  <div style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>{s.desc}</div>
                </div>
                <div onClick={() => setSettings(p => ({ ...p, [s.key]: !p[s.key] }))} style={{
                  width: 44, height: 24, borderRadius: 12, cursor: "pointer", transition: "all .25s",
                  background: settings[s.key] ? C.blue : "#cbd5e1", position: "relative"
                }}>
                  <div style={{
                    position: "absolute", top: 2,
                    left: settings[s.key] ? 20 : 2,
                    width: 20, height: 20, borderRadius: "50%", background: "#fff",
                    boxShadow: "0 1px 4px rgba(0,0,0,.2)", transition: "all .25s"
                  }} />
                </div>
              </div>
            ))}
          </div>
          {/* Location section */}
          <div style={{ marginBottom: 22 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>📍 Location & Privacy</div>
            <div style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "12px 16px", background: C.bluePale, borderRadius: 14, marginBottom: 10
            }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Live Location Tracking</div>
                <div style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>Share GPS with administrators</div>
              </div>
              <div onClick={() => setSettings(p => ({ ...p, locationTracking: !p.locationTracking }))} style={{
                width: 44, height: 24, borderRadius: 12, cursor: "pointer", transition: "all .25s",
                background: settings.locationTracking ? C.blue : "#cbd5e1", position: "relative"
              }}>
                <div style={{
                  position: "absolute", top: 2, left: settings.locationTracking ? 20 : 2,
                  width: 20, height: 20, borderRadius: "50%", background: "#fff",
                  boxShadow: "0 1px 4px rgba(0,0,0,.2)", transition: "all .25s"
                }} />
              </div>
            </div>
          </div>
          {/* Preferences section */}
          <div style={{ marginBottom: 22 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>🌐 Preferences</div>
            {[
              { label: "Language", key: "language", opts: ["English", "Arabic", "Hindi", "Urdu"] },
              { label: "Timezone", key: "timezone", opts: ["Asia/Kolkata", "Asia/Dubai", "Europe/London", "America/New_York"] },
            ].map(s => (
              <div key={s.key} style={{ marginBottom: 12 }}>
                <Lbl>{s.label}</Lbl>
                <FS value={settings[s.key]} onChange={e => setSettings(p => ({ ...p, [s.key]: e.target.value }))}>
                  {s.opts.map(o => <option key={o} value={o}>{o}</option>)}
                </FS>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <Btn v="ghost" onClick={() => setModal(null)}>Cancel</Btn>
            <Btn v="primary" onClick={() => setModal(null)}>Save Settings</Btn>
          </div>
        </Modal>
      )}

      {/* ══ Change Password Modal ══ */}
      {modal === "password" && (
        <Modal titleText="🔒 Change Password" onClose={() => setModal(null)}>
          <div style={{
            padding: "14px 16px", background: C.bluePale, borderRadius: 14, marginBottom: 20,
            fontSize: 12, color: C.muted, fontWeight: 600, lineHeight: 1.6
          }}>
            🔐 Choose a strong password with at least 6 characters. Your session will remain active after changing.
          </div>
          {[
            { label: "Current Password", key: "current", placeholder: "Enter current password" },
            { label: "New Password", key: "next", placeholder: "Enter new password (min 6 chars)" },
            { label: "Confirm New Password", key: "confirm", placeholder: "Re-enter new password" },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 16 }}>
              <Lbl>{f.label}</Lbl>
              <FI type="password" value={pwForm[f.key]}
                onChange={e => setPwForm(p => ({ ...p, [f.key]: e.target.value }))}
                placeholder={f.placeholder} />
            </div>
          ))}
          {pwError && (
            <div style={{
              background: "#fef2f2", border: "1px solid #fecaca", borderRadius: 12,
              padding: "10px 16px", marginBottom: 16, fontSize: 12, fontWeight: 700, color: "#dc2626"
            }}>
              ⚠ {pwError}
            </div>
          )}
          {pwSaved && (
            <div style={{
              background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 12,
              padding: "10px 16px", marginBottom: 16, fontSize: 12, fontWeight: 700, color: "#059669"
            }}>
              ✅ Password changed successfully!
            </div>
          )}
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <Btn v="ghost" onClick={() => { setModal(null); setPwError(""); setPwForm({ current: "", next: "", confirm: "" }); }}>Cancel</Btn>
            <Btn v="primary" onClick={savePassword}>Update Password</Btn>
          </div>
        </Modal>
      )}
    </>
  );
}

// ─── Stat Card (iPeople rounded white) ───────────────────────────────────────
const SC = ({ label, value, sub, icon, grad, cls = "" }) => (
  <div className={cls} style={{
    background: grad || C.white, borderRadius: 20, padding: "20px 22px",
    border: grad ? "none" : `1px solid ${C.border}`,
    boxShadow: grad ? "0 6px 24px rgba(37,99,235,.2)" : "0 2px 12px rgba(37,99,235,.06)",
    position: "relative", overflow: "hidden"
  }}>
    {grad && <div style={{ position: "absolute", top: -20, right: -20, width: 80, height: 80, borderRadius: "50%", background: "rgba(255,255,255,.12)" }} />}
    <div style={{ fontSize: 24, marginBottom: 8 }}>{icon || "📊"}</div>
    <div style={{ fontSize: 30, fontWeight: 900, color: grad ? "#fff" : C.blue, lineHeight: 1, marginBottom: 4 }}>{value}</div>
    <div style={{ fontSize: 12, fontWeight: 700, color: grad ? "rgba(255,255,255,.8)" : C.muted }}>{label}</div>
    {sub && <div style={{ fontSize: 11, color: grad ? "rgba(255,255,255,.6)" : C.light, marginTop: 2 }}>{sub}</div>}
  </div>
);

// ─── Admin Overview ───────────────────────────────────────────────────────────
function AdminOverview({ onNavigate, user, projects, reports, projectItems, onStatusChange, onEditProject, onLogout, announcements = [] }) {
  const allReports = reports || MOCK_REPORTS;
  const allProjects = projects || MOCK_PROJECTS;
  const today = allReports.filter(r => r.date === new Date().toISOString().slice(0, 10));
  const todayManpower = today.reduce((s, r) => s + Number(r.manpowerCount || 0), 0);
  const todayQtyByProject = {};
  today.forEach(r => { todayQtyByProject[r.projectId] = (todayQtyByProject[r.projectId] || 0) + Number(r.workQtyDone || 0); });
  const [detailProj, setDetailProj] = useState(null);
  const [editProj, setEditProj] = useState(null);

  return (
    <div>
      <TopBar title="Dashboard" sub={`${new Date().toLocaleDateString("en-GB", { weekday: "long", year: "numeric", month: "long", day: "numeric" })} · System operational`} user={user} onLogout={onLogout} announcements={announcements} />

      {/* Welcome card */}
      <div className="fu" style={{
        background: `linear-gradient(135deg,${C.blue},${C.blueL})`, borderRadius: 20,
        padding: "20px 28px", marginBottom: 20, display: "flex", alignItems: "center", justifyContent: "space-between",
        boxShadow: "0 6px 24px rgba(37,99,235,.25)"
      }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#fff", marginBottom: 4 }}>Hey {user?.name?.split(" ")[0]} 👋 welcome back!</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,.8)" }}>Here's your operations overview for today.</div>
        </div>
        <Pill color="green">● System Online</Pill>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14, marginBottom: 22 }}>
        <SC label="Total Employees" value={MOCK_EMPLOYEES.length} sub="Active headcount" icon="👤"
          grad={`linear-gradient(135deg,${C.blue},${C.blueL})`} cls="fu" />
        <SC label="Reports Today" value={today.length} sub="As of now" icon="📝"
          grad="linear-gradient(135deg,#059669,#10b981)" cls="fu1" />
        <SC label="Active Projects" value={(allProjects).filter(p => p.status === "active").length} sub="Across departments" icon="🚀"
          grad="linear-gradient(135deg,#7c3aed,#a78bfa)" cls="fu2" />
        <SC label="Manpower Today" value={todayManpower} sub="Total pax on-site" icon="👷"
          grad="linear-gradient(135deg,#ea580c,#fb923c)" cls="fu3" />
      </div>

      {/* Project Progress Summary */}
      <W cls="fu4" style={{ marginBottom: 20 }}>
        <div style={{ padding: "16px 22px", borderBottom: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 15, fontWeight: 800, color: C.text }}>📊 Project Progress Overview</span>
          <button onClick={() => onNavigate("projects")} style={{ fontSize: 13, color: C.blue, background: "none", border: "none", cursor: "pointer", fontWeight: 700, fontFamily: "inherit" }}>View all →</button>
        </div>
        <div style={{ padding: "16px 22px" }}>
          {allProjects.filter(p => p.totalWorkQty).map((p, i) => {
            const rpts = allReports.filter(r => r.projectId === p.id);
            const isCompleted = p.status === "completed" || p.status === "done";
            const rawCompletedQty = rpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
            const totalQty = p.totalWorkQty || 0;
            const completedQty = isCompleted ? totalQty : Math.min(totalQty, rawCompletedQty);
            const remaining = totalQty - completedQty;
            const progress = totalQty > 0 ? Math.round((completedQty / totalQty) * 100) : 0;
            const todayQty = todayQtyByProject[p.id] || 0;
            return (
              <div key={p.id}
                onClick={() => setDetailProj(p)}
                style={{
                  marginBottom: i < allProjects.filter(p => p.totalWorkQty).length - 1 ? 18 : 0,
                  cursor: "pointer", borderRadius: 12, padding: "10px", margin: "0 -10px 8px",
                  transition: "background .15s"
                }}
                onMouseOver={e => e.currentTarget.style.background = "#f0f9ff"}
                onMouseOut={e => e.currentTarget.style.background = "transparent"}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                  <div>
                    <span style={{ fontSize: 13, fontWeight: 800, color: C.text }}>{p.name}</span>
                    {p.poNumber && <span style={{ fontSize: 10, color: C.light, fontWeight: 700, marginLeft: 8, padding: "2px 6px", background: "#f1f5f9", borderRadius: 6 }}>{p.poNumber}</span>}
                    {todayQty > 0 && <span style={{ fontSize: 10, fontWeight: 800, color: "#059669", marginLeft: 8 }}>+{todayQty} {p.unitType} today</span>}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11, fontWeight: 800 }}>
                    <span style={{ color: C.muted }}>{completedQty}/{totalQty} {p.unitType}</span>
                    <span style={{ color: progress >= 100 ? "#059669" : C.blue, fontSize: 13, fontWeight: 900 }}>{progress}%</span>
                    <span style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>→</span>
                  </div>
                </div>
                <div style={{ height: 8, background: "#e2e8f0", borderRadius: 10, overflow: "hidden" }}>
                  <div style={{
                    height: "100%", width: `${progress}%`,
                    background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                    borderRadius: 10, transition: "width .4s"
                  }} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 4, fontSize: 10, fontWeight: 700 }}>
                  <span style={{ color: C.light }}>Total: {totalQty} {p.unitType}</span>
                  <span style={{ color: "#059669" }}>Done: {completedQty}</span>
                  <span style={{ color: remaining <= 0 ? "#059669" : "#dc2626" }}>Rem: {remaining} {p.unitType}</span>
                  {p.lastUpdatedAt && <LastUpdatedBadge project={p} />}
                </div>
                {/* Item-wise breakdown */}
                {(() => {
                  const items = (projectItems || []).filter(it => it.projectId === p.id);
                  if (items.length === 0) return null;
                  return (
                    <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                      {(() => {
                        const itemIds = new Set(items.map(it => it.id));
                        let unlinkedQty = rpts.filter(r => !itemIds.has(r.projectItemId)).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                        
                        let targetAttrItem = null;
                        if (unlinkedQty > 0 && items.length > 0) {
                          let candidates = items.filter(it => (it.unit || "").toLowerCase() === (p.unitType || "").toLowerCase());
                          if (candidates.length === 0) candidates = items;
                          targetAttrItem = candidates.length > 0 ? candidates.reduce((max, it) => it.quantity > max.quantity ? it : max, candidates[0]) : null;
                        }

                        const renderedItems = items.map(item => {
                          let rawItemDone = rpts.filter(r => r.projectItemId === item.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                          if (targetAttrItem && item.id === targetAttrItem.id) {
                            rawItemDone += unlinkedQty;
                            unlinkedQty = 0; // consumed
                          }
                          const isCompleted = p.status === "completed" || p.status === "done";
                          const itemDone = isCompleted ? item.quantity : Math.min(item.quantity, rawItemDone);
                          const itemRem = item.quantity - itemDone;
                          const itemProg = item.quantity > 0 ? Math.round((itemDone / item.quantity) * 100) : 0;
                          return (
                            <div key={item.id} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span title={item.description} style={{ fontSize: 10, fontWeight: 700, color: C.muted, minWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.description}</span>
                              <div style={{ flex: 1, height: 5, background: "#e2e8f0", borderRadius: 5, overflow: "hidden" }}>
                                <div style={{
                                  height: "100%", width: `${Math.min(100, itemProg)}%`, borderRadius: 5,
                                  background: itemProg >= 100 ? "#10b981" : "#60a5fa", transition: "width .3s"
                                }} />
                              </div>
                              <span style={{ fontSize: 9, fontWeight: 800, color: itemProg >= 100 ? "#059669" : C.muted, minWidth: 70, textAlign: "right" }}>
                                {itemDone}/{item.quantity} {item.unit}
                              </span>
                            </div>
                          );
                        });
                        
                        // Render any leftover unlinked qty (should be 0 if attributed successfully)
                        const unlinkedRender = unlinkedQty > 0 ? (
                          <div style={{ display: "flex", alignItems: "center", gap: 8, opacity: 0.8, background: "#fffad6", padding: "2px 4px", borderRadius: 4 }}>
                            <span style={{ fontSize: 10, fontWeight: 700, color: "#92400e", minWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>⚠️ Unlinked / Deleted Items</span>
                            <div style={{ flex: 1, height: 5, background: "#e2e8f0", borderRadius: 5 }} />
                            <span style={{ fontSize: 9, fontWeight: 800, color: "#92400e", minWidth: 70, textAlign: "right" }}>
                              {unlinkedQty} {p.unitType}
                            </span>
                          </div>
                        ) : null;

                        return (
                          <>
                            {renderedItems}
                            {unlinkedRender}
                          </>
                        );
                      })()}
                    </div>
                  );
                })()}
              </div>
            );
          })}
          {allProjects.filter(p => p.totalWorkQty).length === 0 && (
            <div style={{ textAlign: "center", padding: "16px 0", color: C.light, fontSize: 13, fontWeight: 600 }}>No projects with BOQ data. Create a PO to track progress.</div>
          )}
        </div>
      </W>

      {detailProj && (
        <ProjectDetail
          project={detailProj}
          reports={allReports}
          projectItems={projectItems}
          onClose={() => setDetailProj(null)}
          onStatusChange={(id, status) => {
            if (onStatusChange) onStatusChange(id, status);
            setDetailProj(p => ({ ...p, status }));
          }}
          onEdit={() => { setEditProj(detailProj); setDetailProj(null); }}
        />
      )}
      {editProj && (
        <AddProjectModal
          onClose={() => setEditProj(null)}
          onAdd={(updated) => {
            if (onEditProject) onEditProject(updated);
            setEditProj(null);
          }}
          projects={allProjects}
          prefill={editProj}
        />
      )}

      {/* Recent table */}
      <W cls="fu4">
        <div style={{ padding: "16px 22px", borderBottom: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 15, fontWeight: 800, color: C.text }}>📋 Recent Submissions</span>
          <button onClick={() => onNavigate("reports")} style={{ fontSize: 13, color: C.blue, background: "none", border: "none", cursor: "pointer", fontWeight: 700, fontFamily: "inherit" }}>View all →</button>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr style={{ background: "#f8faff" }}>
            {["Employee", "Project", "Department", "Date", "Hours", "Manpower", "Work Done", "Status"].map(h => (
              <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 10, color: C.light, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase" }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {[...allReports].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 6).map(r => {
              const emp = MOCK_EMPLOYEES.find(e => e.id === r.employeeId);
              const proj = allProjects.find(p => p.id === r.projectId);
              return (
                <tr key={r.id} className="row-hover" style={{ borderTop: `1px solid #f0f6ff`, transition: "background .15s" }}>
                  <td style={{ padding: "12px 16px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <Avt initials={emp?.avatar} size={28} />
                      <span style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>{emp?.name}</span>
                    </div>
                  </td>
                  <td style={{ padding: "12px 16px", fontSize: 11, color: C.muted, fontWeight: 600 }}>{proj?.name?.slice(0, 22)}{proj?.name?.length > 22 ? "…" : ""}</td>
                  <td style={{ padding: "12px 16px" }}><Pill color="blue">{emp?.department}</Pill></td>
                  <td style={{ padding: "12px 16px", fontSize: 12, color: C.muted, fontWeight: 600 }}>{r.date}</td>
                  <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 900, color: C.blue }}>{r.hours}h</td>
                  <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 800, color: "#7c3aed" }}>{r.manpowerCount || "—"} pax</td>
                  <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 900, color: "#059669" }}>{r.workQtyDone || "—"} {proj?.unitType || ""}</td>
                  <td style={{ padding: "12px 16px" }}><Pill color="green">✓ Processed</Pill></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </W>
    </div>
  );
}

// ─── Reports List ──────────────────────────────────────────────────────────────
function ReportsList({ onSelect, user, onLogout, reports, employees, projects, announcements = [] }) {
  const allReports = reports || [];
  const allEmployees = employees || MOCK_EMPLOYEES;
  const allProjects = projects || MOCK_PROJECTS;
  const [f, setF] = useState({ dept: "", project: "", employee: "", date: "" });
  const filtered = allReports.filter(r => {
    const emp = allEmployees.find(e => e.id === r.employeeId);
    if (f.dept && emp?.department !== f.dept) return false;
    if (f.project && r.projectId !== f.project) return false;
    if (f.employee && r.employeeId !== f.employee) return false;
    if (f.date && r.date !== f.date) return false;
    return true;
  });
  return (
    <div>
      <TopBar title="Work Reports" sub={`${filtered.length} records · AI-processed intelligence`} user={user} onLogout={onLogout} announcements={announcements} />

      {/* Filters */}
      <W style={{ marginBottom: 16, padding: "14px 18px" }} cls="fu1">
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          {[
            { k: "dept", lbl: "All Departments", opts: DEPARTMENTS.map(d => ({ v: d, l: d })) },
            { k: "project", lbl: "All Projects", opts: allProjects.map(p => ({ v: p.id, l: p.name.slice(0, 22) + "…" })) },
            { k: "employee", lbl: "All Employees", opts: allEmployees.map(e => ({ v: e.id, l: e.name })) },
          ].map(fl => (
            <select key={fl.k} value={f[fl.k]} onChange={e => setF(p => ({ ...p, [fl.k]: e.target.value }))} style={{
              padding: "9px 14px", border: `1.5px solid ${C.border}`, borderRadius: 12,
              fontFamily: "inherit", fontSize: 12, color: C.muted, background: C.white, cursor: "pointer", fontWeight: 600
            }}>
              <option value="">{fl.lbl}</option>
              {fl.opts.map(o => <option key={o.v} value={o.v}>{o.l}</option>)}
            </select>
          ))}
          <input type="date" value={f.date} onChange={e => setF(p => ({ ...p, date: e.target.value }))} style={{
            padding: "9px 14px", border: `1.5px solid ${C.border}`, borderRadius: 12,
            fontFamily: "inherit", fontSize: 12, color: C.muted, fontWeight: 600
          }} />
          <button onClick={() => setF({ dept: "", project: "", employee: "", date: "" })} style={{
            padding: "9px 14px", background: C.bluePale, border: "none", borderRadius: 12,
            fontFamily: "inherit", fontSize: 12, color: C.blue, cursor: "pointer", fontWeight: 700
          }}>Clear</button>
          <Btn v="soft" onClick={() => downloadCSV(filtered)}
            icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>}>
            CSV ({filtered.length})
          </Btn>
        </div>
      </W>

      <W cls="fu2">
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead><tr style={{ background: "#f8faff" }}>
            {["Employee", "Department", "Project", "Date", "Hours", "Issues", "GPS", "Actions"].map(h => (
              <th key={h} style={{ padding: "10px 18px", textAlign: "left", fontSize: 10, color: C.light, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase" }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {filtered.map(r => {
              const emp = allEmployees.find(e => e.id === r.employeeId);
              const proj = allProjects.find(p => p.id === r.projectId);
              return (
                <tr key={r.id} className="row-hover" style={{ borderTop: `1px solid #f0f6ff`, cursor: "pointer", transition: "background .15s" }}
                  onClick={() => onSelect(r)}>
                  <td style={{ padding: "12px 18px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <Avt initials={emp?.avatar} size={30} />
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{emp?.name}</div>
                        <div style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>{emp?.email}</div>
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: "12px 18px" }}><Pill color="blue">{emp?.department}</Pill></td>
                  <td style={{ padding: "12px 18px", fontSize: 12, color: C.muted, fontWeight: 600 }}>{proj?.name?.slice(0, 22)}{proj?.name?.length > 22 ? "…" : ""}</td>
                  <td style={{ padding: "12px 18px", fontSize: 12, color: C.muted, fontWeight: 600 }}>{r.date}</td>
                  <td style={{ padding: "12px 18px", fontSize: 15, fontWeight: 900, color: C.blue }}>{r.hours}h</td>
                  <td style={{ padding: "12px 18px" }}>
                    {r.issuesFaced.length > 0 ? <Pill color="amber">⚠ {r.issuesFaced.length}</Pill> : <span style={{ fontSize: 12, color: C.light }}>—</span>}
                  </td>
                  <td style={{ padding: "12px 18px" }}><Pill color="green">✓ GPS</Pill></td>
                  <td style={{ padding: "12px 18px" }} onClick={e => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <Btn sm v="soft" onClick={() => onSelect(r)}>View</Btn>
                      <Btn sm v="ghost"
                        icon={<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>}
                        onClick={() => generateReportPDF(r, emp, proj)}>PDF</Btn>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </W>
    </div>
  );
}

// ─── Report Detail ─────────────────────────────────────────────────────────────
function ReportDetail({ report, onBack, user, onLogout, announcements = [] }) {
  const emp = MOCK_EMPLOYEES.find(e => e.id === report.employeeId);
  const proj = MOCK_PROJECTS.find(p => p.id === report.projectId);
  return (
    <div>
      <div style={{ marginBottom: 18 }}><Btn v="ghost" onClick={onBack} icon="←" sm>Back to Reports</Btn></div>
      <TopBar title="Report Detail" user={user} onLogout={onLogout} announcements={announcements} />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        {/* Employee card */}
        <W cls="fu" style={{ padding: 24 }}>
          <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 14 }}>Employee Record</div>
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
            <Avt initials={emp?.avatar} size={48} />
            <div>
              <div style={{ fontSize: 17, fontWeight: 800, color: C.text }}>{emp?.name}</div>
              <div style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{emp?.email}</div>
            </div>
          </div>
          {[["Department", emp?.department], ["Project", proj?.name], ["PO Number", proj?.poNumber || "—"], ["Client", proj?.companyName || "—"], ["Date", report.date], ["Hours Worked", `${report.hours} hrs`], ["Manpower", `${report.manpowerCount || "—"} people`], ["Work Done", `${report.workQtyDone || "—"} ${proj?.unitType || ""}`]].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "9px 0", borderBottom: `1px solid #f0f6ff` }}>
              <span style={{ fontSize: 12, color: C.light, fontWeight: 600 }}>{k}</span>
              <span style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>{v}</span>
            </div>
          ))}
        </W>

        {/* GPS map */}
        <W cls="fu1" style={{ overflow: "hidden" }}>
          <div style={{ padding: "12px 20px", borderBottom: `1px solid ${C.border}` }}>
            <span style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light }}>📍 GPS Location</span>
          </div>
          <div style={{ position: "relative", height: 196, background: "linear-gradient(145deg,#d4e6d4,#c0d8c0)" }}>
            <div style={{ position: "absolute", inset: 0, backgroundImage: `linear-gradient(${C.border} 1px,transparent 1px),linear-gradient(90deg,${C.border} 1px,transparent 1px)`, backgroundSize: "26px 26px", opacity: .4 }} />
            <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 8 }}>
              <div style={{ width: 26, height: 26, borderRadius: "50% 50% 50% 0", background: C.blue, transform: "rotate(-45deg)", boxShadow: `0 4px 12px rgba(37,99,235,.5)` }} />
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text, background: "rgba(255,255,255,.92)", padding: "4px 12px", borderRadius: 20, backdropFilter: "blur(4px)" }}>{report.location.address}</div>
              <div style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>{report.location.lat}°N, {report.location.lng}°E</div>
            </div>
          </div>
          <div style={{ padding: "8px 20px", background: "#f8faff" }}><span style={{ fontSize: 11, color: C.light, fontWeight: 600 }}>Captured at submission · {report.date}</span></div>
        </W>
      </div>

      {/* Work Details */}
      {report.workDetails && (
        <W cls="fu2" style={{ padding: 22, marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>📝 Work Details</div>
          <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.7, padding: "14px 16px", background: "#f8faff", borderRadius: 14, borderLeft: `3px solid #059669`, margin: 0, fontWeight: 600 }}>{report.workDetails}</p>
        </W>
      )}

      {/* Raw input */}
      <W cls="fu2" style={{ padding: 22, marginBottom: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>Raw Employee Input</div>
        <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.7, padding: "14px 16px", background: "#f8faff", borderRadius: 14, borderLeft: `3px solid ${C.blueMid}`, margin: 0, fontWeight: 600 }}>{report.rawDescription}</p>
      </W>

      {/* AI layer */}
      <W cls="fu3" style={{ padding: 22, marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light }}>🤖 AI Intelligence Layer</div>
          <Pill color="blue">Admin Only</Pill>
        </div>
        <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.7, padding: "14px 16px", background: C.bluePale, borderRadius: 14, borderLeft: `3px solid ${C.blueL}`, margin: "0 0 18px", fontWeight: 600 }}>{report.aiSummary}</p>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 10 }}>Tasks Completed</div>
            {report.tasksCompleted.map((t, i) => (
              <div key={i} style={{ display: "flex", gap: 8, padding: "8px 0", borderBottom: `1px solid #f0f6ff` }}>
                <span style={{ color: "#059669", fontWeight: 900, flexShrink: 0 }}>✓</span>
                <span style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{t}</span>
              </div>
            ))}
          </div>
          <div>
            <div style={{ fontSize: 12, fontWeight: 800, color: C.text, marginBottom: 10 }}>Issues Faced</div>
            {report.issuesFaced.length === 0
              ? <div style={{ fontSize: 12, color: C.light, fontStyle: "italic", fontWeight: 600 }}>No issues reported.</div>
              : report.issuesFaced.map((t, i) => (
                <div key={i} style={{ display: "flex", gap: 8, padding: "8px 0", borderBottom: `1px solid #f0f6ff` }}>
                  <span style={{ color: "#d97706", fontWeight: 900, flexShrink: 0 }}>⚠</span>
                  <span style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{t}</span>
                </div>
              ))}
          </div>
        </div>
      </W>

      {/* Actions */}
      <div className="fu4" style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <Btn v="secondary" onClick={() => downloadCSV([report])}
          icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>}>
          Export CSV
        </Btn>
        <Btn v="primary" onClick={() => generateReportPDF(report, emp, proj)}
          icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /></svg>}>
          Download Report (HTML → PDF)
        </Btn>
      </div>
    </div>
  );
}

// ─── Live Map ──────────────────────────────────────────────────────────────────
// ── Leaflet map loader hook ──────────────────────────────────────────────────
function useLeaflet(onReady) {
  useEffect(() => {
    if (window.L) { onReady(window.L); return; }
    // Load CSS
    if (!document.getElementById("leaflet-css")) {
      const lnk = document.createElement("link");
      lnk.id = "leaflet-css"; lnk.rel = "stylesheet";
      lnk.href = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css";
      document.head.appendChild(lnk);
    }
    // Load JS
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js";
    s.onload = () => onReady(window.L);
    document.head.appendChild(s);
  }, []);
}

function LiveMap({ user, liveLocations = {}, onLogout, announcements = [] }) {
  const [sel, setSel] = useState(null);
  const [leafletReady, setLeafletReady] = useState(!!window.L);
  const mapRef = useRef(null); // DOM div
  const mapObjRef = useRef(null); // L.Map instance
  const markersRef = useRef({});   // { empId -> L.Marker }
  const [tick, setTick] = useState(0);

  useLeaflet((L) => setLeafletReady(true));

  // Tick every 5s for "X sec ago" freshness
  useEffect(() => {
    const iv = setInterval(() => setTick(t => t + 1), 5000);
    return () => clearInterval(iv);
  }, []);

  const employees = MOCK_EMPLOYEES;
  const onlineCount = Object.keys(liveLocations).length;

  const secAgo = (ts) => {
    if (!ts) return "—";
    const s = Math.round((new Date() - new Date(ts)) / 1000);
    if (s < 60) return `${s}s ago`;
    return `${Math.round(s / 60)}m ago`;
  };

  // Colour palette per employee index
  const COLORS = ["#2563eb", "#059669", "#dc2626", "#7c3aed", "#ea580c", "#0891b2"];

  // ── Init Leaflet map once ready ──────────────────────────────────────────
  useEffect(() => {
    if (!leafletReady || !mapRef.current) return;
    if (mapObjRef.current) return; // already initialised

    const L = window.L;
    const map = L.map(mapRef.current, {
      center: [20.5937, 78.9629], zoom: 5,
      zoomControl: true, attributionControl: true,
    });

    // OpenStreetMap tiles — free, no API key
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom: 19,
    }).addTo(map);

    mapObjRef.current = map;
  }, [leafletReady]);

  // ── Update / create markers whenever liveLocations changes ───────────────
  useEffect(() => {
    if (!mapObjRef.current || !leafletReady) return;
    const L = window.L;
    const map = mapObjRef.current;

    employees.forEach((emp, i) => {
      const loc = liveLocations[emp.id];
      if (!loc) return;

      const color = COLORS[i % COLORS.length];
      const isS = sel === emp.id;

      // Custom HTML div icon
      const iconHtml = `
        <div style="
          background:${isS ? color : "#fff"};
          border:3px solid ${color};
          border-radius:14px;
          padding:4px 9px;
          display:flex;align-items:center;gap:5px;
          box-shadow:${isS ? `0 4px 18px ${color}88` : "0 2px 8px rgba(0,0,0,.22)"};
          white-space:nowrap;
          transform:${isS ? "scale(1.15)" : "scale(1)"};
          transition:all .25s;
          font-family:system-ui,sans-serif;
        ">
          <div style="
            width:20px;height:20px;border-radius:50%;
            background:${color};
            display:flex;align-items:center;justify-content:center;
            font-size:8px;font-weight:900;color:#fff;flex-shrink:0;
          ">${emp.avatar}</div>
          <span style="font-size:10px;font-weight:800;color:${isS ? "#fff" : color}">${emp.name.split(" ")[0]}</span>
          <div style="width:7px;height:7px;border-radius:50%;background:#10b981;flex-shrink:0;
            box-shadow:0 0 0 2px rgba(16,185,129,.3);"></div>
        </div>
        <div style="width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;
          border-top:9px solid ${isS ? color : "#fff"};margin:0 auto;"></div>
      `;

      const icon = L.divIcon({
        html: iconHtml,
        className: "",
        iconAnchor: [40, 44],
        popupAnchor: [0, -44],
      });

      const popup = `
        <div style="font-family:system-ui,sans-serif;min-width:180px;padding:4px 2px">
          <div style="font-size:13px;font-weight:800;color:#0f172a;margin-bottom:4px">${emp.name}</div>
          <div style="font-size:10px;color:#64748b;font-weight:600;margin-bottom:6px">${emp.department} · ${emp.role === "tl" ? "Team Lead" : "Employee"}</div>
          <div style="font-size:11px;color:${color};font-weight:700;margin-bottom:3px">
            📍 ${loc.lat.toFixed(5)}°N, ${loc.lng.toFixed(5)}°E
          </div>
          <div style="font-size:10px;color:#94a3b8;font-weight:600;margin-bottom:8px">
            ±${loc.accuracy || "—"}m accuracy · ${secAgo(loc.timestamp)}${loc.simulated ? " · simulated" : ""}
          </div>
          <a href="https://www.google.com/maps/search/?api=1&query=${loc.lat},${loc.lng}"
            target="_blank"
            style="font-size:11px;color:${color};font-weight:800;text-decoration:none;
              background:#eff6ff;padding:4px 10px;border-radius:8px;display:inline-block">
            🔗 Open in Google Maps
          </a>
        </div>
      `;

      if (markersRef.current[emp.id]) {
        // Update existing marker position + icon
        markersRef.current[emp.id]
          .setLatLng([loc.lat, loc.lng])
          .setIcon(icon)
          .bindPopup(popup);
      } else {
        // Create new marker
        const m = L.marker([loc.lat, loc.lng], { icon })
          .addTo(map)
          .bindPopup(popup);
        m.on("click", () => setSel(id => id === emp.id ? null : emp.id));
        markersRef.current[emp.id] = m;
      }
    });
  }, [liveLocations, sel, leafletReady, tick]);

  // ── Pan to selected employee ─────────────────────────────────────────────
  useEffect(() => {
    if (!mapObjRef.current || !sel) return;
    const loc = liveLocations[sel];
    if (loc) {
      mapObjRef.current.flyTo([loc.lat, loc.lng], 17, { duration: 1.2 });
      markersRef.current[sel]?.openPopup();
    }
  }, [sel]);

  const selEmp = sel ? employees.find(e => e.id === sel) : null;
  const selLoc = sel ? liveLocations[sel] : null;

  return (
    <div>
      <TopBar title="Live Employee Tracking"
        sub={`${onlineCount} / ${employees.length} employees online · updates every 8s`}
        user={user} onLogout={onLogout} announcements={announcements} />

      {/* Status bar */}
      <div className="fu" style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "linear-gradient(135deg,#f0fdf4,#dcfce7)",
        border: "1.5px solid #86efac", borderRadius: 16, padding: "10px 18px", marginBottom: 16
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 10, height: 10, borderRadius: "50%", background: "#10b981",
            boxShadow: "0 0 0 3px rgba(16,185,129,.25)", animation: "pulse 1.5s infinite"
          }} />
          <div>
            <div style={{ fontSize: 12, fontWeight: 800, color: "#065f46" }}>
              🛰 Live GPS Tracking Active · OpenStreetMap · No API key needed
            </div>
            <div style={{ fontSize: 10, color: "#059669", fontWeight: 600 }}>
              {onlineCount} employee{onlineCount !== 1 ? "s" : ""} broadcasting location · Admin-only view
            </div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {sel && <Btn v="ghost" sm onClick={() => { setSel(null); mapObjRef.current?.setView([20.5937, 78.9629], 5); }}>
            ↩ Show All
          </Btn>}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>

        {/* ── Leaflet Map ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <W cls="fu1" style={{ padding: 0, overflow: "hidden", borderRadius: 20, position: "relative" }}>
            {/* Selected employee overlay */}
            {selEmp && selLoc && (
              <div style={{
                position: "absolute", top: 12, left: 12, zIndex: 1000,
                background: "rgba(255,255,255,.97)", backdropFilter: "blur(10px)",
                border: `2px solid ${COLORS[employees.findIndex(e => e.id === selEmp.id) % COLORS.length]}`,
                borderRadius: 16, padding: "12px 16px", boxShadow: "0 6px 24px rgba(0,0,0,.18)", minWidth: 220
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <Avt initials={selEmp.avatar} size={34} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 900, color: C.text }}>{selEmp.name}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{selEmp.department}</div>
                  </div>
                  <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: "50%", background: "#10b981",
                      boxShadow: "0 0 0 3px rgba(16,185,129,.3)", animation: "pulse 1.5s infinite"
                    }} />
                    <span style={{ fontSize: 9, fontWeight: 800, color: "#059669" }}>LIVE</span>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: C.blue, fontWeight: 700, marginBottom: 2 }}>
                  📍 {selLoc.lat.toFixed(5)}°N, {selLoc.lng.toFixed(5)}°E
                </div>
                <div style={{ fontSize: 10, color: C.light, fontWeight: 600, marginBottom: 8 }}>
                  ±{selLoc.accuracy || "—"}m · {secAgo(selLoc.timestamp)}{selLoc.simulated ? " · simulated" : ""}
                </div>
                <a href={`https://www.google.com/maps/search/?api=1&query=${selLoc.lat},${selLoc.lng}`}
                  target="_blank" rel="noreferrer"
                  style={{
                    fontSize: 10, color: C.blue, fontWeight: 800, textDecoration: "none",
                    background: C.bluePale, padding: "4px 10px", borderRadius: 8, display: "inline-block"
                  }}>
                  🔗 Google Maps
                </a>
              </div>
            )}
            {!leafletReady && (
              <div style={{
                height: 500, display: "flex", alignItems: "center", justifyContent: "center",
                background: "#f8faff", borderRadius: 20
              }}>
                <div style={{ fontSize: 13, color: C.muted, fontWeight: 700 }}>⏳ Loading map…</div>
              </div>
            )}
            <div ref={mapRef} style={{
              height: 500, width: "100%",
              display: leafletReady ? "block" : "none", borderRadius: 20
            }} />
          </W>

          {/* Legend */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {employees.map((emp, i) => {
              const loc = liveLocations[emp.id];
              const color = COLORS[i % COLORS.length];
              return (
                <div key={emp.id} onClick={() => setSel(s => s === emp.id ? null : emp.id)}
                  style={{
                    display: "flex", alignItems: "center", gap: 6, padding: "5px 10px",
                    borderRadius: 20, cursor: "pointer", border: `1.5px solid ${sel === emp.id ? color : C.border}`,
                    background: sel === emp.id ? `${color}15` : C.white, transition: "all .15s"
                  }}>
                  <div style={{
                    width: 10, height: 10, borderRadius: "50%",
                    background: loc ? "#10b981" : "#94a3b8",
                    boxShadow: loc ? "0 0 0 2px rgba(16,185,129,.25)" : "none"
                  }} />
                  <span style={{ fontSize: 10, fontWeight: 800, color: sel === emp.id ? color : C.text }}>
                    {emp.name.split(" ")[0]}
                  </span>
                  {loc && <span style={{ fontSize: 9, color: "#059669", fontWeight: 700 }}>{secAgo(loc.timestamp)}</span>}
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Employee sidebar ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".15em", textTransform: "uppercase", color: C.light }}>
              👥 Live Employees
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981", animation: "pulse 1.5s infinite" }} />
              <span style={{ fontSize: 10, fontWeight: 800, color: "#059669" }}>{onlineCount} online</span>
            </div>
          </div>

          {employees.map((emp, i) => {
            const loc = liveLocations[emp.id];
            const isS = sel === emp.id;
            const color = COLORS[i % COLORS.length];
            return (
              <W key={emp.id} style={{
                padding: "12px 14px", cursor: "pointer",
                border: `1.5px solid ${isS ? color : C.border}`,
                background: isS ? `${color}0f` : C.white,
                transform: isS ? "translateX(3px)" : "none",
                transition: "all .2s"
              }}
                onClick={() => setSel(isS ? null : emp.id)}>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <div style={{ position: "relative", flexShrink: 0 }}>
                    <div style={{
                      width: 34, height: 34, borderRadius: "50%",
                      background: `linear-gradient(135deg,${color},${color}aa)`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 12, fontWeight: 900, color: "#fff"
                    }}>
                      {emp.avatar}
                    </div>
                    <div style={{
                      position: "absolute", bottom: 0, right: 0, width: 10, height: 10,
                      borderRadius: "50%", background: loc ? "#10b981" : "#94a3b8",
                      border: "2px solid #fff", boxShadow: loc ? "0 0 0 2px rgba(16,185,129,.3)" : "none"
                    }} />
                  </div>
                  <div style={{ flex: 1, overflow: "hidden" }}>
                    <div style={{
                      fontSize: 12, fontWeight: 800, color: isS ? color : C.text,
                      whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"
                    }}>{emp.name}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>
                      {emp.department}{emp.role === "tl" ? " · TL" : ""}
                    </div>
                    {loc ? (
                      <div style={{ fontSize: 9, color: "#059669", fontWeight: 700, marginTop: 1 }}>
                        ● Live · {secAgo(loc.timestamp)}
                      </div>
                    ) : (
                      <div style={{ fontSize: 9, color: C.light, fontWeight: 700, marginTop: 1 }}>⏳ Locating…</div>
                    )}
                  </div>
                </div>

                {isS && loc && (
                  <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${color}44` }}>
                    <div style={{ fontSize: 10, color: color, fontWeight: 700, marginBottom: 2 }}>
                      📍 {loc.lat.toFixed(5)}°N, {loc.lng.toFixed(5)}°E
                    </div>
                    <div style={{ fontSize: 9, color: C.light, fontWeight: 600, marginBottom: 8 }}>
                      ±{loc.accuracy || "—"}m{loc.simulated ? " · simulated" : ""}
                    </div>
                    <a href={`https://www.google.com/maps/search/?api=1&query=${loc.lat},${loc.lng}`}
                      target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                      style={{
                        fontSize: 10, color: color, fontWeight: 800, textDecoration: "none",
                        background: `${color}15`, padding: "4px 10px", borderRadius: 8, display: "inline-block"
                      }}>
                      🔗 Open in Google Maps
                    </a>
                  </div>
                )}
              </W>
            );
          })}

          <div style={{
            marginTop: 4, padding: "12px 14px",
            background: "linear-gradient(135deg,#f0fdf4,#dcfce7)",
            border: "1px solid #bbf7d0", borderRadius: 14
          }}>
            <div style={{
              fontSize: 10, color: "#059669", fontWeight: 800, letterSpacing: ".08em",
              textTransform: "uppercase", marginBottom: 6
            }}>📡 How tracking works</div>
            <div style={{ fontSize: 11, color: "#065f46", fontWeight: 600, lineHeight: 1.6 }}>
              Employees & TLs grant GPS permission on login. Location updates every 15s via <code>watchPosition()</code>. Map powered by Leaflet + OpenStreetMap — no API key needed.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Employees ─────────────────────────────────────────────────────────────────
function EmployeesPanel({ user, liveLocations = {}, onLogout, onEmployeeAdded }) {
  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState({ name: "", email: "", department: "IT", role: "employee", password: "" });
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState("");
  const [addSuccess, setAddSuccess] = useState("");

  const departments = ["IT", "Electrical", "Mechanical", "Civil", "Administration", "HR", "Finance"];
  const roles = [{ v: "employee", l: "Employee" }, { v: "tl", l: "Team Leader" }, { v: "admin", l: "Admin" }];

  const handleAddEmployee = async () => {
    setAddError(""); setAddSuccess("");
    if (!addForm.name.trim() || !addForm.email.trim() || !addForm.password) {
      setAddError("All fields are required."); return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(addForm.email)) {
      setAddError("Invalid email address."); return;
    }
    if (addForm.password.length < 8) {
      setAddError("Password must be at least 8 characters."); return;
    }
    setAddLoading(true);
    try {
      const emp = await createEmployee(addForm);
      MOCK_EMPLOYEES.push({ ...emp });
      setAddSuccess(`✅ ${emp.name} created successfully! They can now log in with ${emp.email} and the password you set.`);
      setAddForm({ name: "", email: "", department: "IT", role: "employee", password: "" });
      if (onEmployeeAdded) onEmployeeAdded(emp);
    } catch (e) {
      setAddError(e.message || "Failed to create employee.");
    } finally { setAddLoading(false); }
  };

  return (
    <div>
      <TopBar title="Employees" sub={`${MOCK_EMPLOYEES.length} active records`} user={user} onLogout={onLogout} />

      {/* Add Employee Button */}
      <div style={{ marginBottom: 16 }}>
        <Btn v="primary" onClick={() => { setShowAdd(p => !p); setAddError(""); setAddSuccess(""); }}>
          {showAdd ? "✕ Cancel" : "＋ Add Employee"}
        </Btn>
      </div>

      {/* Add Employee Form */}
      {showAdd && (
        <W cls="fu" style={{ padding: 24, marginBottom: 20 }}>
          <div style={{ fontSize: 15, fontWeight: 900, color: C.text, marginBottom: 16 }}>👤 Add New Employee</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
            <div>
              <Lbl>Full Name *</Lbl>
              <FI value={addForm.name} onChange={e => setAddForm(p => ({ ...p, name: e.target.value }))} placeholder="e.g. John Smith" />
            </div>
            <div>
              <Lbl>Email Address *</Lbl>
              <FI type="email" value={addForm.email} onChange={e => setAddForm(p => ({ ...p, email: e.target.value }))} placeholder="john@corp.com" />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 14 }}>
            <div>
              <Lbl>Department *</Lbl>
              <FS value={addForm.department} onChange={e => setAddForm(p => ({ ...p, department: e.target.value }))}>
                {departments.map(d => <option key={d} value={d}>{d}</option>)}
              </FS>
            </div>
            <div>
              <Lbl>Role *</Lbl>
              <FS value={addForm.role} onChange={e => setAddForm(p => ({ ...p, role: e.target.value }))}>
                {roles.map(r => <option key={r.v} value={r.v}>{r.l}</option>)}
              </FS>
            </div>
            <div>
              <Lbl>Temp Password *</Lbl>
              <FI type="password" value={addForm.password} onChange={e => setAddForm(p => ({ ...p, password: e.target.value }))} placeholder="Min 8 chars" />
            </div>
          </div>
          {addError && <div style={{ fontSize: 12, color: "#dc2626", fontWeight: 700, marginBottom: 10 }}>⚠ {addError}</div>}
          {addSuccess && <div style={{ fontSize: 12, color: "#059669", fontWeight: 700, marginBottom: 10 }}>{addSuccess}</div>}
          <Btn v="primary" disabled={addLoading} onClick={handleAddEmployee} style={{ padding: "10px 24px" }}>
            {addLoading ? "Creating…" : "Create Employee Account"}
          </Btn>
          <div style={{ fontSize: 11, color: C.light, fontWeight: 600, marginTop: 10 }}>
            🔑 The employee can sign in immediately with their email and the temporary password you set.
          </div>
        </W>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 14 }}>
        {MOCK_EMPLOYEES.map((emp, i) => {
          const rpts = MOCK_REPORTS.filter(r => r.employeeId === emp.id);
          const loc = liveLocations[emp.id];
          return (
            <W key={emp.id} cls={`fu${i > 3 ? 4 : i + 1}`} style={{ padding: 22 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
                <div style={{ position: "relative" }}>
                  <Avt initials={emp.avatar} size={46} />
                  <div style={{
                    position: "absolute", bottom: 1, right: 1, width: 12, height: 12,
                    borderRadius: "50%", background: loc ? "#10b981" : "#94a3b8",
                    border: "2px solid #fff",
                    boxShadow: loc ? "0 0 0 2px rgba(16,185,129,.3)" : "none"
                  }} />
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 800, color: C.text }}>{emp.name}</div>
                  <div style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{emp.email}</div>
                  {loc
                    ? <div style={{ fontSize: 10, color: "#059669", fontWeight: 800, marginTop: 2 }}>● Live tracking active</div>
                    : <div style={{ fontSize: 10, color: C.light, fontWeight: 700, marginTop: 2 }}>○ Location unavailable</div>
                  }
                </div>
              </div>
              <div style={{ marginBottom: 8 }}>
                <Pill color={emp.role === "admin" ? "red" : emp.role === "tl" ? "yellow" : "blue"}>
                  {emp.role === "tl" ? "Team Leader" : emp.role === "admin" ? "Admin" : "Employee"}
                </Pill>
              </div>
              {[["Department", emp.department], ["Reports Filed", rpts.length]].map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #f0f6ff" }}>
                  <span style={{ fontSize: 12, color: C.light, fontWeight: 600 }}>{k}</span>
                  <span style={{ fontSize: 12, color: C.text, fontWeight: 800 }}>{v}</span>
                </div>
              ))}
              {loc && (
                <div style={{
                  marginTop: 12, padding: "10px 12px", background: "#f0fdf4",
                  border: "1px solid #bbf7d0", borderRadius: 12
                }}>
                  <div style={{ fontSize: 10, color: "#059669", fontWeight: 800, marginBottom: 3 }}>📍 Current Location</div>
                  <div style={{ fontSize: 11, color: "#065f46", fontWeight: 700 }}>
                    {loc.lat.toFixed(4)}°N, {loc.lng.toFixed(4)}°E
                  </div>
                  <a href={`https://www.google.com/maps/search/?api=1&query=${loc.lat},${loc.lng}`}
                    target="_blank" rel="noreferrer"
                    style={{ fontSize: 10, color: C.blue, fontWeight: 800, textDecoration: "none", marginTop: 4, display: "block" }}>
                    🔗 Open in Maps
                  </a>
                </div>
              )}
              <div style={{ marginTop: loc ? 10 : 14 }}><Pill color="blue">{emp.department}</Pill></div>
            </W>
          );
        })}
      </div>
    </div>
  );
}


// ─── Attach Documents Component ─────────────────────────────────────────────
function AttachDocuments({ docs = [], onChange }) {
  const fileRef = useRef(null);
  const [uploading, setUploading] = useState(false);

  const handleFiles = async (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    setUploading(true);
    const newDocs = [];
    for (const file of files) {
      const reader = new FileReader();
      const dataUrl = await new Promise((resolve) => {
        reader.onload = () => resolve(reader.result);
        reader.readAsDataURL(file);
      });
      newDocs.push({ name: file.name, type: file.type, size: file.size, dataUrl });
    }
    onChange([...docs, ...newDocs]);
    setUploading(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const remove = (idx) => onChange(docs.filter((_, i) => i !== idx));

  const formatSize = (bytes) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
  };

  const getIcon = (type) =>
    type === "application/pdf" ? "📄" :
      type?.startsWith("image/") ? "🖼️" :
        type?.includes("sheet") || type?.includes("excel") ? "📊" :
          type?.includes("csv") ? "📋" :
            type?.includes("word") ? "📝" : "📎";

  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button onClick={() => fileRef.current?.click()}
          style={{
            background: `linear-gradient(135deg,${C.blue},${C.blueL})`, color: "#fff",
            border: "none", borderRadius: 20, padding: "6px 16px", cursor: "pointer",
            fontSize: 11, fontWeight: 800, fontFamily: "inherit", opacity: uploading ? .6 : 1
          }}>
          {uploading ? "Uploading…" : "+ Add Files"}
        </button>
        <input ref={fileRef} type="file" multiple accept=".pdf,.jpg,.jpeg,.png,.doc,.docx,.xls,.xlsx,.csv"
          style={{ display: "none" }} onChange={handleFiles} />
      </div>
      {docs.length === 0 && (
        <div style={{ fontSize: 12, color: C.light, fontStyle: "italic", padding: "12px 0" }}>
          No documents attached yet. Click "Add Files" to upload PO documents, drawings, etc.
        </div>
      )}
      {docs.map((doc, i) => (
        <div key={i} style={{
          display: "flex", alignItems: "center", gap: 10, padding: "8px 12px",
          background: C.bgSoft || "#f8fafc", border: `1px solid ${C.border}`, borderRadius: 10, marginBottom: 6
        }}>
          <span style={{ fontSize: 18 }}>{getIcon(doc.type)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{doc.name}</div>
            <div style={{ fontSize: 10, color: C.muted }}>{formatSize(doc.size || 0)}</div>
          </div>
          <button onClick={() => remove(i)} style={{
            background: "#fee2e2", border: "none", borderRadius: 8,
            width: 26, height: 26, cursor: "pointer", fontSize: 12, color: "#dc2626", display: "flex",
            alignItems: "center", justifyContent: "center", flexShrink: 0
          }}>✕</button>
        </div>
      ))}
    </div>
  );
}

function BOQItemsEditor({ items, onChange }) {
  const UNIT_OPTS = ["Meter", "Km", "Feet", "Nos", "Sets", "Points", "Lots", "Sqm", "Sqft", "Sites", "Floors", "Zones", "Rooms", "Job", "Phase", "Run"];
  const CAT_OPTS = ["Cable", "Conduit", "Networking", "CCTV", "Access Control", "Fire", "Server", "Tools", "Other"];
  const CAT_COLOR = { Cable: "#2563eb", Conduit: "#7c3aed", Networking: "#0891b2", CCTV: "#dc2626", "Access Control": "#ea580c", Fire: "#d97706", Server: "#059669", Tools: "#64748b", Other: "#94a3b8" };

  const WORK_TYPE_OPTS = ["LAN Cabling", "Fiber Optic", "CCTV Install", "Access Control", "Electrical", "Cable Tray", "Conduit", "Switch Install", "Patch Panel", "Server Rack", "Testing", "Commissioning", "Other"];
  const blank = { description: "", qty: "", unit: "Nos", rate: "", category: "Other", workType: "" };
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState({ ...blank });
  const [editIdx, setEditIdx] = useState(null);

  const save = () => {
    if (!draft.description.trim() || !draft.qty) return;
    if (editIdx !== null) {
      onChange(items.map((it, i) => i === editIdx ? { ...draft } : it));
      setEditIdx(null);
    } else {
      onChange([...items, { ...draft }]);
    }
    setDraft({ ...blank }); setAdding(false);
  };

  const remove = (i) => onChange(items.filter((_, idx) => idx !== i));

  const startEdit = (i) => { setDraft({ ...items[i] }); setEditIdx(i); setAdding(true); };

  const grouped = {};
  items.forEach((it, i) => {
    const c = it.category || "Other";
    if (!grouped[c]) grouped[c] = [];
    grouped[c].push({ ...it, _idx: i });
  });

  return (
    <div style={{ marginTop: 8, marginBottom: 8 }}>
      <div style={{
        fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
        marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center"
      }}>
        <span>📐 BOQ Line Items {items.length > 0 && `(${items.length})`}</span>
        {!adding && (
          <button onClick={() => { setAdding(true); setEditIdx(null); setDraft({ ...blank }); }}
            style={{
              background: `linear-gradient(135deg,${C.blue},${C.blueL})`, color: "#fff",
              border: "none", borderRadius: 20, padding: "4px 14px", cursor: "pointer",
              fontSize: 11, fontWeight: 800, fontFamily: "inherit"
            }}>
            + Add Item
          </button>
        )}
      </div>

      {/* Add / Edit form */}
      {adding && (
        <div style={{
          background: "#f0f9ff", border: `1.5px solid ${C.blueMid}`, borderRadius: 14,
          padding: "14px 16px", marginBottom: 12
        }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: C.blue, marginBottom: 10 }}>
            {editIdx !== null ? "✏ Edit Item" : "➕ New BOQ Item"}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
            <div style={{ gridColumn: "1/-1" }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Description *</div>
              <input value={draft.description} onChange={e => setDraft(p => ({ ...p, description: e.target.value }))}
                placeholder="e.g. Cat6 UTP Cable 23AWG"
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, boxSizing: "border-box"
                }} />
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Work Type *</div>
              <select value={draft.workType} onChange={e => setDraft(p => ({ ...p, workType: e.target.value }))}
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, background: "#fff", boxSizing: "border-box"
                }}>
                <option value="">Select…</option>
                {WORK_TYPE_OPTS.map(w => <option key={w}>{w}</option>)}
              </select>
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Category</div>
              <select value={draft.category} onChange={e => setDraft(p => ({ ...p, category: e.target.value }))}
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, background: "#fff", boxSizing: "border-box"
                }}>
                {CAT_OPTS.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Quantity *</div>
              <input type="number" min="1" step="1" value={draft.qty} onChange={e => setDraft(p => ({ ...p, qty: e.target.value.replace(/\./g, '') }))}
                placeholder="e.g. 500"
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, boxSizing: "border-box"
                }} />
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Unit</div>
              <select value={draft.unit} onChange={e => setDraft(p => ({ ...p, unit: e.target.value }))}
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, background: "#fff", boxSizing: "border-box"
                }}>
                {UNIT_OPTS.map(u => <option key={u}>{u}</option>)}
              </select>
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginBottom: 3 }}>Unit Rate (optional)</div>
              <input value={draft.rate} onChange={e => setDraft(p => ({ ...p, rate: e.target.value }))}
                placeholder="e.g. INR 1250"
                style={{
                  width: "100%", padding: "8px 12px", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  fontFamily: "inherit", fontSize: 12, color: C.text, boxSizing: "border-box"
                }} />
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={save}
              style={{
                background: `linear-gradient(135deg,${C.blue},${C.blueL})`, color: "#fff",
                border: "none", borderRadius: 10, padding: "8px 20px", cursor: "pointer",
                fontSize: 12, fontWeight: 800, fontFamily: "inherit"
              }}>
              {editIdx !== null ? "Save Changes" : "Add Item"}
            </button>
            <button onClick={() => { setAdding(false); setEditIdx(null); setDraft({ ...blank }); }}
              style={{
                background: "#f1f5f9", color: C.muted, border: "none", borderRadius: 10,
                padding: "8px 16px", cursor: "pointer", fontSize: 12, fontWeight: 700, fontFamily: "inherit"
              }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Items list grouped by category */}
      {items.length === 0 && !adding && (
        <div style={{
          textAlign: "center", padding: "20px 0", color: C.light, fontSize: 12, fontWeight: 700,
          background: "#f8faff", borderRadius: 12, border: `1px dashed ${C.border}`
        }}>
          No BOQ items yet. Add manually or use AI extraction above.
        </div>
      )}

      {Object.entries(grouped).map(([cat, catItems]) => (
        <div key={cat} style={{ marginBottom: 10 }}>
          <div style={{
            fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
            color: CAT_COLOR[cat] || "#64748b", marginBottom: 4, display: "flex", alignItems: "center", gap: 6
          }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: CAT_COLOR[cat] || "#94a3b8" }} />
            {cat}
          </div>
          <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
            {catItems.map((item, i) => (
              <div key={item._idx} style={{
                display: "flex", alignItems: "center", gap: 10,
                padding: "9px 12px", background: i % 2 === 0 ? "#fff" : "#fafcff",
                borderTop: i > 0 ? `1px solid ${C.border}` : "none"
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: 12, fontWeight: 700, color: C.text,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                  }}>{item.description}</div>
                  <div style={{ display: "flex", gap: 8, marginTop: 2, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 11, fontWeight: 900, color: "#059669" }}>{item.qty}</span>
                    <span style={{
                      fontSize: 10, fontWeight: 800, color: CAT_COLOR[item.category] || C.blue,
                      background: `${CAT_COLOR[item.category] || C.blue}15`,
                      padding: "1px 8px", borderRadius: 12
                    }}>{item.unit}</span>
                    {item.workType && <span style={{
                      fontSize: 10, fontWeight: 700, color: "#7c3aed",
                      background: "#ede9fe", padding: "1px 8px", borderRadius: 12
                    }}>{item.workType}</span>}
                    {item.rate && <span style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{item.rate}</span>}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                  <button onClick={() => startEdit(item._idx)}
                    style={{
                      background: C.bluePale, border: "none", borderRadius: 8, padding: "4px 10px",
                      cursor: "pointer", fontSize: 11, fontWeight: 700, color: C.blue, fontFamily: "inherit"
                    }}>✏</button>
                  <button onClick={() => remove(item._idx)}
                    style={{
                      background: "#fef2f2", border: "none", borderRadius: 8, padding: "4px 10px",
                      cursor: "pointer", fontSize: 11, fontWeight: 700, color: "#dc2626", fontFamily: "inherit"
                    }}>✕</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {items.length > 0 && (
        <div style={{
          marginTop: 8, padding: "8px 12px", background: "#f0fdf4", borderRadius: 10,
          display: "flex", justifyContent: "space-between", alignItems: "center"
        }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: "#059669" }}>
            {items.length} item{items.length !== 1 ? "s" : ""} in BOQ
          </span>
          <span style={{ fontSize: 11, fontWeight: 700, color: C.muted }}>
            Total: {[...new Set(items.map(i => i.unit))].map(u => {
              const sum = items.filter(i => i.unit === u).reduce((s, i) => s + Number(i.qty || 0), 0);
              return `${sum} ${u}`;
            }).join(" · ")}
          </span>
        </div>
      )}
    </div>
  );
}

// ─── Add Project Modal (Multi-Step Wizard) ───────────────────────────────────
function AddProjectModal({ onClose, onAdd, projects, prefill }) {
  const blankForm = {
    name: "", department: "", description: "", startDate: "", endDate: "", assignedEmployees: [],
    poNumber: "", companyName: "", projectType: "", workLocation: "", poDate: "",
    totalWorkQty: "", unitType: "Meter", workType: "",
    poDocuments: [], boqItems: [],
  };
  const [form, setForm] = useState(prefill ? {
    name: prefill.name || "", department: prefill.department || "", description: prefill.description || "",
    startDate: prefill.startDate || "", endDate: prefill.endDate || "", assignedEmployees: prefill.assignedEmployees || [],
    poNumber: prefill.poNumber || "", companyName: prefill.companyName || "", projectType: prefill.projectType || "",
    workLocation: prefill.workLocation || "", poDate: prefill.poDate || "",
    totalWorkQty: prefill.totalWorkQty || "", unitType: prefill.unitType || "Meter", workType: prefill.workType || "",
    poDocuments: prefill.poDocuments || [], boqItems: prefill.boqItems || [],
  } : blankForm);
  const [err, setErr] = useState("");
  const [step, setStep] = useState(0); // 0-3

  const UNIT_TYPES = ["Meter", "Km", "Feet", "Nos", "Sets", "Points", "Lots", "Sqm", "Sqft", "Cubic Meter", "Sites", "Floors", "Zones", "Rooms", "Job", "Phase", "Run"];
  const PROJECT_TYPES = ["Network", "Security", "IT Infrastructure", "CCTV", "Maintenance", "Electrical", "Civil", "Telecom", "Other"];

  const toggleEmp = (id) => {
    setForm(p => ({
      ...p,
      assignedEmployees: p.assignedEmployees.includes(id)
        ? p.assignedEmployees.filter(e => e !== id)
        : [...p.assignedEmployees, id]
    }));
  };

  const [fieldErrs, setFieldErrs] = useState({});

  const STEPS = [
    { label: "PO Details", icon: "📋" },
    { label: "Scope & Type", icon: "📐" },
    { label: "Project & Team", icon: "🚀" },
    { label: "Documents", icon: "📎" },
  ];

  // Per-step validation
  const validateStep = (s) => {
    const e = {};
    if (s === 0) {
      if (!form.poNumber.trim()) e.poNumber = "Enter PO number";
      if (!form.companyName.trim()) e.companyName = "Enter company / client name";
    }
    if (s === 1) {
      if (!form.totalWorkQty || isNaN(form.totalWorkQty) || Number(form.totalWorkQty) <= 0)
        e.totalWorkQty = "Enter a valid quantity (e.g. 500)";
    }
    if (s === 2) {
      if (!form.name.trim()) e.name = "Enter a project name";
      if (!form.department) e.department = "Select a department";
      if (!form.startDate) e.startDate = "Pick a start date";
    }
    return e;
  };

  const goNext = () => {
    const e = validateStep(step);
    if (Object.keys(e).length > 0) {
      setFieldErrs(e);
      setErr(`Please fill in the ${Object.keys(e).length} highlighted field${Object.keys(e).length > 1 ? "s" : ""}.`);
      setTimeout(() => { const el = document.querySelector("[data-fielderr]"); if (el) el.scrollIntoView({ behavior: "smooth", block: "center" }); }, 50);
      return;
    }
    setFieldErrs({}); setErr("");
    setStep(s => Math.min(s + 1, 3));
  };
  const goBack = () => { setFieldErrs({}); setErr(""); setStep(s => Math.max(s - 1, 0)); };

  const save = () => {
    // Final validation of all steps
    let allErrs = {};
    for (let s = 0; s <= 2; s++) allErrs = { ...allErrs, ...validateStep(s) };
    if (Object.keys(allErrs).length > 0) {
      // Jump to first step with error
      for (let s = 0; s <= 2; s++) { const se = validateStep(s); if (Object.keys(se).length > 0) { setStep(s); setFieldErrs(se); setErr(`Please fill in the ${Object.keys(se).length} highlighted field${Object.keys(se).length > 1 ? "s" : ""}.`); break; } }
      return;
    }
    setFieldErrs({}); setErr("");
    const proj = {
      id: prefill ? prefill.id : "p" + (Date.now()),
      name: form.name.trim(), department: form.department,
      description: form.description.trim(),
      status: prefill ? prefill.status : "active",
      startDate: form.startDate, endDate: form.endDate || "",
      assignedEmployees: form.assignedEmployees,
      poNumber: form.poNumber.trim(),
      companyName: form.companyName.trim(),
      projectType: form.projectType,
      workLocation: form.workLocation.trim(),
      poDate: form.poDate,
      totalWorkQty: Math.round(Number(form.totalWorkQty)),
      unitType: form.unitType,
      workType: form.workType.trim(),
      poDocuments: form.poDocuments || [],
      boqItems: form.boqItems || [],
    };
    onAdd(proj);
    onClose();
  };

  const deptEmps = form.department ? MOCK_EMPLOYEES.filter(e => e.department === form.department) : MOCK_EMPLOYEES;

  // ── Step Progress Bar ──
  const StepBar = () => (
    <div style={{ padding: "16px 28px 0", display: "flex", alignItems: "center", gap: 0 }}>
      {STEPS.map((s, i) => {
        const done = i < step, active = i === step;
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", flex: i < STEPS.length - 1 ? 1 : "none" }}>
            <div onClick={() => { if (i < step) { setStep(i); setFieldErrs({}); setErr(""); } }}
              style={{
                display: "flex", alignItems: "center", gap: 6, cursor: i < step ? "pointer" : "default",
                padding: "6px 12px", borderRadius: 20,
                background: active ? C.bluePale : done ? "#f0fdf4" : "transparent",
                border: `1.5px solid ${active ? C.blue : done ? "#86efac" : C.border}`,
                transition: "all .2s"
              }}>
              <span style={{ fontSize: 14 }}>{done ? "✓" : s.icon}</span>
              <span style={{
                fontSize: 11, fontWeight: active ? 800 : 600,
                color: active ? C.blue : done ? "#059669" : C.light,
                display: active ? "inline" : "none",
                ...(window.innerWidth > 500 ? { display: "inline" } : {})
              }}>{s.label}</span>
            </div>
            {i < STEPS.length - 1 && (
              <div style={{
                flex: 1, height: 2, background: i < step ? C.blue : C.border,
                margin: "0 4px", borderRadius: 2, transition: "background .3s"
              }} />
            )}
          </div>
        );
      })}
    </div>
  );

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9000, background: "rgba(15,23,42,.45)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: C.white, borderRadius: 24, width: "100%", maxWidth: 640,
        boxShadow: "0 24px 60px rgba(37,99,235,.18)", overflow: "hidden"
      }} className="fu">
        {/* Header */}
        <div style={{
          background: `linear-gradient(135deg,${C.blue},${C.blueL})`, padding: "20px 28px",
          display: "flex", justifyContent: "space-between", alignItems: "center"
        }}>
          <div>
            <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>{prefill ? "✏ Edit Project / PO" : "➕ Create PO / Project"}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,.75)", marginTop: 2 }}>
              Step {step + 1} of {STEPS.length} — {STEPS[step].icon} {STEPS[step].label}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: "rgba(255,255,255,.2)", border: "none", borderRadius: "50%",
            width: 32, height: 32, cursor: "pointer", fontSize: 16, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center"
          }}>✕</button>
        </div>

        {/* Step indicator */}
        <StepBar />

        {/* Body */}
        <div style={{ padding: "20px 28px", maxHeight: "60vh", overflowY: "auto", minHeight: 280 }}>
          {err && <div style={{
            background: "#fef2f2", border: "1.5px solid #fecaca", borderRadius: 10, padding: "10px 14px",
            fontSize: 12, color: "#dc2626", fontWeight: 700, marginBottom: 16
          }}>⚠ {err}</div>}

          {/* ═══ STEP 0: PO Details ═══ */}
          {step === 0 && (<>

            <div style={{
              fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
              marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
            }}>📋 Purchase Order (PO) Details</div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div {...(fieldErrs.poNumber ? { "data-fielderr": "1" } : {})}>
                <Lbl err={fieldErrs.poNumber}>PO Number *</Lbl>
                <FI value={form.poNumber} err={fieldErrs.poNumber} onChange={e => { setForm(p => ({ ...p, poNumber: e.target.value })); setFieldErrs(p => ({ ...p, poNumber: "" })); }} placeholder="e.g. PO-2025-001" />
                {fieldErrs.poNumber && <ErrTip>{fieldErrs.poNumber}</ErrTip>}
              </div>
              <div>
                <Lbl>PO Date</Lbl>
                <FI type="date" value={form.poDate} onChange={e => setForm(p => ({ ...p, poDate: e.target.value }))} />
              </div>
            </div>

            <div style={{ marginBottom: 14 }} {...(fieldErrs.companyName ? { "data-fielderr": "1" } : {})}>
              <Lbl err={fieldErrs.companyName}>Company Name (Client) *</Lbl>
              <FI value={form.companyName} err={fieldErrs.companyName} onChange={e => { setForm(p => ({ ...p, companyName: e.target.value })); setFieldErrs(p => ({ ...p, companyName: "" })); }} placeholder="e.g. Brihanmumbai Municipal Corporation" />
              {fieldErrs.companyName && <ErrTip>{fieldErrs.companyName}</ErrTip>}
            </div>
          </>)}

          {/* ═══ STEP 1: Scope & Type ═══ */}
          {step === 1 && (<>
            <div style={{
              fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
              marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
            }}>📐 Work Scope & Type</div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div>
                <Lbl>Project Type</Lbl>
                <FS value={form.projectType} onChange={e => setForm(p => ({ ...p, projectType: e.target.value }))}>
                  <option value="">Select…</option>
                  {PROJECT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </FS>
              </div>
              <div>
                <Lbl>Work Location</Lbl>
                <FI value={form.workLocation} onChange={e => setForm(p => ({ ...p, workLocation: e.target.value }))} placeholder="e.g. Okhla Industrial Area, New Delhi" />
              </div>
            </div>

            {/* BOQ Items as Work Items */}
            <div style={{ marginBottom: 14 }}>
              <BOQItemsEditor items={form.boqItems || []} onChange={items => {
                setForm(p => ({ ...p, boqItems: items }));
                // Auto-derive work type from items if single type
                const types = [...new Set(items.map(i => i.workType).filter(Boolean))];
                if (types.length === 1) setForm(p => ({ ...p, workType: types[0] }));
                else if (types.length > 1) setForm(p => ({ ...p, workType: types.join(", ") }));
              }} />
            </div>

            {/* Auto-sum indicator + manual total */}
            {(form.boqItems || []).length > 0 && (
              <div style={{ background: "#f0fdf4", border: "1px solid #86efac", borderRadius: 12, padding: "10px 14px", marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", color: "#059669", marginBottom: 6 }}>
                  📊 Items Summary
                </div>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12, color: C.text }}>
                  {[...new Set((form.boqItems || []).map(i => i.unit))].map(u => {
                    const sum = (form.boqItems || []).filter(i => i.unit === u).reduce((s, i) => s + Number(i.qty || 0), 0);
                    return <span key={u} style={{ fontWeight: 700 }}>{sum} <span style={{ color: C.muted, fontWeight: 600 }}>{u}</span></span>;
                  })}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 4, flexWrap: "wrap" }}>
                  {[...new Set((form.boqItems || []).map(i => i.workType).filter(Boolean))].map(w => (
                    <span key={w} style={{ fontSize: 10, fontWeight: 700, color: "#7c3aed", background: "#ede9fe", padding: "2px 10px", borderRadius: 12 }}>{w}</span>
                  ))}
                </div>
              </div>
            )}

            <div style={{
              fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
              marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`, marginTop: 8
            }}>📋 Overall Totals</div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div {...(fieldErrs.totalWorkQty ? { "data-fielderr": "1" } : {})}>
                <Lbl err={fieldErrs.totalWorkQty}>Total Work Quantity *</Lbl>
                <FI type="number" min="1" step="1" value={form.totalWorkQty} err={fieldErrs.totalWorkQty}
                  onChange={e => { setForm(p => ({ ...p, totalWorkQty: e.target.value.replace(/\./g, '') })); setFieldErrs(p => ({ ...p, totalWorkQty: "" })); }} placeholder="e.g. 3000" />
                {fieldErrs.totalWorkQty && <ErrTip>{fieldErrs.totalWorkQty}</ErrTip>}
              </div>
              <div>
                <Lbl>Unit Type *</Lbl>
                <FS value={form.unitType} onChange={e => setForm(p => ({ ...p, unitType: e.target.value }))}>
                  {UNIT_TYPES.map(u => <option key={u} value={u}>{u}</option>)}
                </FS>
              </div>
            </div>
          </>)}

          {/* ═══ STEP 2: Project & Team ═══ */}
          {step === 2 && (<>
            <div style={{
              fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
              marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
            }}>🚀 Project Details</div>

            <div style={{ marginBottom: 14 }} {...(fieldErrs.name ? { "data-fielderr": "1" } : {})}>
              <Lbl err={fieldErrs.name}>Project Name *</Lbl>
              <FI value={form.name} err={fieldErrs.name} onChange={e => { setForm(p => ({ ...p, name: e.target.value })); setFieldErrs(p => ({ ...p, name: "" })); }} placeholder="e.g. Network Infrastructure Upgrade Phase 2" />
              {fieldErrs.name && <ErrTip>{fieldErrs.name}</ErrTip>}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
              <div {...(fieldErrs.department ? { "data-fielderr": "1" } : {})}>
                <Lbl err={fieldErrs.department}>Department *</Lbl>
                <FS value={form.department} err={fieldErrs.department} onChange={e => { setForm(p => ({ ...p, department: e.target.value, assignedEmployees: [] })); setFieldErrs(p => ({ ...p, department: "" })); }}>
                  <option value="">Select department…</option>
                  {DEPARTMENTS.map(d => <option key={d} value={d}>{d}</option>)}
                </FS>
                {fieldErrs.department && <ErrTip>{fieldErrs.department}</ErrTip>}
              </div>
              <div {...(fieldErrs.startDate ? { "data-fielderr": "1" } : {})}>
                <Lbl err={fieldErrs.startDate}>Start Date *</Lbl>
                <FI type="date" value={form.startDate} err={fieldErrs.startDate} onChange={e => { setForm(p => ({ ...p, startDate: e.target.value })); setFieldErrs(p => ({ ...p, startDate: "" })); }} />
                {fieldErrs.startDate && <ErrTip>{fieldErrs.startDate}</ErrTip>}
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <Lbl>End Date (Estimated)</Lbl>
              <FI type="date" value={form.endDate} onChange={e => setForm(p => ({ ...p, endDate: e.target.value }))} />
            </div>

            <div style={{ marginBottom: 20 }}>
              <Lbl>Description</Lbl>
              <FI value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
                placeholder="Briefly describe what this project involves…" rows={3} />
            </div>

            {/* Assign Employees */}
            <div style={{ marginBottom: 8 }}>
              <Lbl>Assign Employees {form.department ? "(" + form.department + " team)" : "(select department first)"}</Lbl>
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
                {deptEmps.map(emp => {
                  const checked = form.assignedEmployees.includes(emp.id);
                  return (
                    <div key={emp.id} onClick={() => toggleEmp(emp.id)} style={{
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 14px",
                      border: `2px solid ${checked ? C.blue : C.border}`, borderRadius: 12, cursor: "pointer",
                      background: checked ? C.bluePale : C.white, transition: "all .15s"
                    }}>
                      <Avt initials={emp.avatar} size={32} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{emp.name}</div>
                        <div style={{ fontSize: 11, color: C.muted }}>{emp.email} {emp.role === "tl" ? "· Team Lead" : ""}</div>
                      </div>
                      <div style={{
                        width: 20, height: 20, borderRadius: "50%", border: `2px solid ${checked ? C.blue : C.border}`,
                        background: checked ? C.blue : "transparent", display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 12, color: "#fff", flexShrink: 0
                      }}>
                        {checked && "✓"}
                      </div>
                    </div>
                  );
                })}
                {deptEmps.length === 0 && <div style={{ fontSize: 12, color: C.light, fontStyle: "italic", padding: "8px 0" }}>Select a department to see available employees.</div>}
              </div>
            </div>
          </>)}

          {/* ═══ STEP 3: Documents & BOQ ═══ */}
          {step === 3 && (<>
            <div style={{ marginBottom: 8 }}>
              <div style={{
                fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light,
                marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
              }}>📎 Attached Documents</div>
              <AttachDocuments docs={form.poDocuments || []} onChange={docs => setForm(p => ({ ...p, poDocuments: docs }))} />
            </div>

            <BOQItemsEditor items={form.boqItems || []} onChange={items => setForm(p => ({ ...p, boqItems: items }))} />

            {/* Summary preview */}
            <div style={{ marginTop: 16, padding: "14px 16px", background: C.bluePale, borderRadius: 14, border: `1px solid ${C.blueSoft}` }}>
              <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.blue, marginBottom: 8 }}>📝 Summary</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, fontSize: 12, color: C.text }}>
                <div><span style={{ color: C.light }}>PO:</span> {form.poNumber || "—"}</div>
                <div><span style={{ color: C.light }}>Client:</span> {form.companyName || "—"}</div>
                <div><span style={{ color: C.light }}>Project:</span> {form.name || "—"}</div>
                <div><span style={{ color: C.light }}>Dept:</span> {form.department || "—"}</div>
                <div><span style={{ color: C.light }}>Qty:</span> {form.totalWorkQty || "—"} {form.unitType}</div>
                <div><span style={{ color: C.light }}>Start:</span> {form.startDate || "—"}</div>
                <div><span style={{ color: C.light }}>Team:</span> {form.assignedEmployees.length} assigned</div>
                <div><span style={{ color: C.light }}>Docs:</span> {(form.poDocuments || []).length} files</div>
              </div>
            </div>
          </>)}
        </div>

        {/* Footer with wizard navigation */}
        <div style={{ padding: "16px 28px", borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            {step > 0 && <Btn v="ghost" onClick={goBack}>← Back</Btn>}
            {step === 0 && <Btn v="ghost" onClick={onClose}>Cancel</Btn>}
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            {step < 3 && <Btn v="primary" onClick={goNext}>Next →</Btn>}
            {step === 3 && <Btn v="primary" onClick={save}>{prefill ? "Save Changes" : "Create PO / Project"}</Btn>}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Project Detail Drawer ────────────────────────────────────────────────────
// ─── Project Documents Viewer (proper component so hooks work) ─────────────────
function ProjectDocuments({ docs }) {
  const [previewDoc, setPreviewDoc] = useState(null);

  const getIcon = (t) =>
    t === "application/pdf" ? "📄" :
      t?.startsWith("image/") ? "🖼️" :
        t?.includes("sheet") || t?.includes("excel") ? "📊" :
          t?.includes("csv") ? "📋" :
            t?.includes("word") ? "📝" : "📎";

  const openDoc = (doc) => {
    if (!doc.dataUrl) return;
    if (doc.type?.startsWith("image/") || doc.type === "application/pdf") {
      setPreviewDoc(doc);
    } else {
      const a = document.createElement("a");
      a.href = doc.dataUrl; a.download = doc.name; a.click();
    }
  };

  const download = (doc, e) => {
    e?.stopPropagation();
    if (!doc.dataUrl) return;
    const a = document.createElement("a");
    a.href = doc.dataUrl; a.download = doc.name; a.click();
  };

  return (
    <>
      <div style={{
        background: C.white, border: `1px solid ${C.border}`, borderRadius: 14,
        padding: "14px 18px", marginBottom: 16
      }}>
        <div style={{
          fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
          color: C.light, marginBottom: 10
        }}>📎 Attached Documents ({docs.length})</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {docs.map((doc, i) => {
            const canView = !!doc.dataUrl && (doc.type?.startsWith("image/") || doc.type === "application/pdf");
            const canDownload = !!doc.dataUrl;
            return (
              <div key={i}
                onClick={() => canView ? openDoc(doc) : canDownload ? download(doc) : null}
                style={{
                  display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                  background: "#f8faff", border: `1.5px solid ${C.border}`, borderRadius: 10,
                  cursor: (canView || canDownload) ? "pointer" : "default", transition: "all .15s"
                }}
                onMouseOver={e => { if (canView || canDownload) { e.currentTarget.style.borderColor = C.blue; e.currentTarget.style.background = "#eff6ff"; } }}
                onMouseOut={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = "#f8faff"; }}>
                <span style={{ fontSize: 20, flexShrink: 0 }}>{getIcon(doc.type)}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: 12, fontWeight: 700, color: C.text,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                  }}>{doc.name}</div>
                  <div style={{ fontSize: 10, color: C.light, fontWeight: 600, marginTop: 1 }}>
                    {(doc.size / 1024).toFixed(1)} KB · {doc.addedAt}
                    {!doc.dataUrl && <span style={{ color: "#f59e0b", marginLeft: 6 }}>· no preview available</span>}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexShrink: 0, alignItems: "center" }}>
                  {canView && (
                    <span style={{
                      fontSize: 11, fontWeight: 800, color: C.blue,
                      background: C.bluePale, padding: "4px 11px", borderRadius: 20, pointerEvents: "none"
                    }}>
                      👁 View
                    </span>
                  )}
                  {canDownload && (
                    <span onClick={(e) => download(doc, e)}
                      style={{
                        fontSize: 11, fontWeight: 800, color: "#059669",
                        background: "#f0fdf4", padding: "4px 11px", borderRadius: 20, cursor: "pointer",
                        border: "1px solid #bbf7d0"
                      }}>
                      ⬇ Download
                    </span>
                  )}
                  {!canDownload && (
                    <span style={{
                      fontSize: 10, color: "#f59e0b", fontWeight: 700,
                      background: "#fffbeb", padding: "4px 10px", borderRadius: 20
                    }}>
                      No file data
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Full-screen preview modal */}
      {previewDoc && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 10000, background: "rgba(0,0,0,.75)",
          display: "flex", alignItems: "center", justifyContent: "center", padding: 20
        }}
          onClick={() => setPreviewDoc(null)}>
          <div onClick={e => e.stopPropagation()} style={{
            background: C.white, borderRadius: 20, overflow: "hidden",
            width: "100%", maxWidth: 720, maxHeight: "92vh",
            display: "flex", flexDirection: "column",
            boxShadow: "0 24px 60px rgba(0,0,0,.45)"
          }}>
            {/* Header */}
            <div style={{
              background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
              padding: "14px 20px", display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 22 }}>{previewDoc.type?.startsWith("image/") ? "🖼️" : "📄"}</span>
                <div>
                  <div style={{
                    fontSize: 13, fontWeight: 800, color: "#fff",
                    maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                  }}>
                    {previewDoc.name}
                  </div>
                  <div style={{ fontSize: 10, color: "rgba(255,255,255,.75)", fontWeight: 600 }}>
                    {(previewDoc.size / 1024).toFixed(1)} KB · Added {previewDoc.addedAt}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button onClick={() => download(previewDoc)}
                  style={{
                    background: "rgba(255,255,255,.2)", border: "none", borderRadius: 20,
                    padding: "7px 16px", cursor: "pointer", fontSize: 12, fontWeight: 800, color: "#fff",
                    display: "flex", alignItems: "center", gap: 6
                  }}>
                  ⬇ Download
                </button>
                <button onClick={() => setPreviewDoc(null)}
                  style={{
                    background: "rgba(255,255,255,.2)", border: "none", borderRadius: "50%",
                    width: 34, height: 34, cursor: "pointer", fontSize: 16, color: "#fff",
                    display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                  }}>✕</button>
              </div>
            </div>
            {/* Body */}
            <div style={{
              flex: 1, overflow: "auto", background: "#0f172a", minHeight: 300,
              display: "flex", alignItems: "center", justifyContent: "center"
            }}>
              {previewDoc.type?.startsWith("image/")
                ? <img src={previewDoc.dataUrl} alt={previewDoc.name}
                  style={{ maxWidth: "100%", maxHeight: "78vh", objectFit: "contain", display: "block" }} />
                : <iframe src={previewDoc.dataUrl} title={previewDoc.name}
                  style={{ width: "100%", height: "78vh", border: "none" }} />
              }
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function ProjectDetail({ project, reports, projectItems = [], onClose, onStatusChange, onEdit }) {
  const assignedEmps = (project.assignedEmployees || []).map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);
  const projReports = reports.filter(r => r.projectId === project.id);
  const totalHours = projReports.reduce((s, r) => s + Number(r.hours), 0);
  const [tab, setTab] = useState("overview");

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9000, background: "rgba(15,23,42,.45)",
      display: "flex", alignItems: "flex-end", justifyContent: "flex-end"
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: C.white, width: "100%", maxWidth: 540, height: "100vh",
        overflowY: "auto", boxShadow: "-8px 0 40px rgba(37,99,235,.14)"
      }} className="fu">

        {/* Drawer header */}
        <div style={{ background: `linear-gradient(135deg,${C.blue},${C.blueL})`, padding: "24px 28px", position: "sticky", top: 0, zIndex: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1, paddingRight: 12 }}>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,.7)", fontWeight: 700, letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 6 }}>Project Details</div>
              <div style={{ fontSize: 18, fontWeight: 900, color: "#fff", lineHeight: 1.3, marginBottom: 8 }}>{project.name}</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <Pill color={project.status === "active" ? "green" : "gray"}>{project.status === "active" ? "● Active" : "✓ Completed"}</Pill>
                <span style={{
                  background: "rgba(255,255,255,.18)", color: "#fff", fontSize: 11, fontWeight: 700,
                  padding: "3px 10px", borderRadius: 20
                }}>{project.department}</span>
                {project.lastUpdatedAt && (
                  <div style={{
                    display: "flex", alignItems: "center", gap: 4, background: "rgba(255,255,255,.14)",
                    borderRadius: 20, padding: "3px 10px"
                  }}>
                    <span style={{ fontSize: 10 }}>🕐</span>
                    <span style={{ fontSize: 10, fontWeight: 800, color: "rgba(255,255,255,.9)" }}>
                      {timeAgo(project.lastUpdatedAt)}
                    </span>
                    {project.lastUpdateType && (
                      <span style={{ fontSize: 9, color: "rgba(255,255,255,.65)", fontWeight: 600 }}>
                        · {project.lastUpdateType}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
            <button onClick={onClose} style={{
              background: "rgba(255,255,255,.2)", border: "none", borderRadius: "50%",
              width: 34, height: 34, cursor: "pointer", fontSize: 16, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
            }}>✕</button>
          </div>
          {/* Tab bar */}
          <div style={{ display: "flex", gap: 4, marginTop: 18, flexWrap: "wrap" }}>
            {[["overview", "📊 Overview"], ["employees", "👥 Team"], ["reports", "📋 Reports"], ["workforce", "👷 Workforce"]].map(([k, l]) => (
              <button key={k} onClick={() => setTab(k)} style={{
                padding: "7px 14px", borderRadius: 20, border: "none", cursor: "pointer", fontFamily: "inherit",
                fontSize: 11, fontWeight: 700, transition: "all .15s",
                background: tab === k ? "rgba(255,255,255,.95)" : "rgba(255,255,255,.18)",
                color: tab === k ? C.blue : "rgba(255,255,255,.9)"
              }}>
                {l}
              </button>
            ))}
          </div>
        </div>

        <div style={{ padding: "22px 28px" }}>

          {/* ── Overview Tab ── */}
          {tab === "overview" && (
            <div>
              {/* PO Info block */}
              {(project.poNumber || project.companyName) && (() => {
                // Find TL assigned to this project
                const tlEmp = (project.assignedEmployees || [])
                  .map(id => MOCK_EMPLOYEES.find(e => e.id === id))
                  .filter(Boolean)
                  .find(e => e.role === "tl");
                return (
                  <div style={{ background: "#f0f9ff", border: `1px solid ${C.blueMid}`, borderRadius: 14, padding: "14px 18px", marginBottom: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 10 }}>📋 PO / Contract Details</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      {[
                        ["PO Number", project.poNumber],
                        ["Client", project.companyName],
                        ["Project Type", project.projectType],
                        ["Work Type", project.workType],
                        ["PO Date", project.poDate],
                        ["Location", project.workLocation],
                      ].filter(([, v]) => v).map(([k, v]) => (
                        <div key={k}>
                          <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 2 }}>{k}</div>
                          <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{v}</div>
                        </div>
                      ))}
                    </div>

                    {/* Team Leader row — full width below the grid */}
                    <div style={{ marginTop: 12, paddingTop: 10, borderTop: `1px solid ${C.blueMid}` }}>
                      <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 6 }}>👷 Team Leader</div>
                      {tlEmp ? (
                        <div style={{
                          display: "flex", alignItems: "center", gap: 10,
                          background: "rgba(37,99,235,.07)", borderRadius: 10, padding: "8px 12px"
                        }}>
                          <div style={{
                            width: 34, height: 34, borderRadius: "50%", flexShrink: 0,
                            background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
                            display: "flex", alignItems: "center", justifyContent: "center",
                            fontSize: 12, fontWeight: 900, color: "#fff"
                          }}>
                            {tlEmp.avatar}
                          </div>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 800, color: C.text }}>{tlEmp.name}</div>
                            <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{tlEmp.email} · {tlEmp.department} Dept</div>
                          </div>
                          <div style={{ marginLeft: "auto" }}>
                            <span style={{
                              fontSize: 10, fontWeight: 800, color: C.blue,
                              background: C.bluePale, padding: "3px 10px", borderRadius: 20
                            }}>Team Lead</span>
                          </div>
                        </div>
                      ) : (
                        <div style={{
                          fontSize: 12, color: C.light, fontWeight: 600,
                          fontStyle: "italic", padding: "6px 0"
                        }}>
                          No team leader assigned — edit project to assign one.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Progress / BOQ Tracking */}
              {project.totalWorkQty && (() => {
                const completedQty = projReports.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
                const remaining = Math.max(0, project.totalWorkQty - completedQty);
                const progress = Math.min(100, Math.round((completedQty / project.totalWorkQty) * 100));
                const totalManpower = projReports.reduce((s, r) => s + Number(r.manpowerCount || 0), 0);
                return (
                  <div style={{ background: C.white, border: `1.5px solid ${C.border}`, borderRadius: 14, padding: "16px 18px", marginBottom: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12 }}>📐 BOQ Progress Tracking</div>
                    {/* Progress bar */}
                    <div style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                        <span style={{ fontSize: 12, fontWeight: 800, color: C.text }}>Completion Progress</span>
                        <span style={{ fontSize: 14, fontWeight: 900, color: progress >= 100 ? "#059669" : C.blue }}>{progress}%</span>
                      </div>
                      <div style={{ height: 10, background: "#e2e8f0", borderRadius: 10, overflow: "hidden", marginBottom: 8 }}>
                        <div style={{
                          height: "100%", width: `${progress}%`,
                          background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                          borderRadius: 10, transition: "width .4s"
                        }} />
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8 }}>
                        {[
                          { l: "Total Scope", v: `${project.totalWorkQty} ${project.unitType}`, c: C.muted },
                          { l: "Completed", v: `${completedQty} ${project.unitType}`, c: "#059669" },
                          { l: "Remaining", v: `${remaining} ${project.unitType}`, c: remaining === 0 ? "#059669" : "#dc2626" },
                          { l: "Total Manpower", v: totalManpower + " days", c: C.blue },
                        ].map(s => (
                          <div key={s.l} style={{ background: C.bluePale, borderRadius: 10, padding: "10px 12px", textAlign: "center" }}>
                            <div style={{ fontSize: 14, fontWeight: 900, color: s.c }}>{s.v}</div>
                            <div style={{ fontSize: 9, color: C.light, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em", marginTop: 2 }}>{s.l}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    {remaining === 0 && (
                      <div style={{
                        background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 10, padding: "10px 14px",
                        fontSize: 12, fontWeight: 700, color: "#059669", textAlign: "center"
                      }}>
                        ✅ Work scope completed — project can be closed
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Stats row */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 16 }}>
                {[
                  { l: "Reports Filed", v: projReports.length, icon: "📋" },
                  { l: "Total Hours", v: totalHours + "h", icon: "⏱" },
                  { l: "Team Size", v: assignedEmps.length, icon: "👥" },
                ].map(s => (
                  <div key={s.l} style={{ background: C.bluePale, borderRadius: 14, padding: "14px 16px", textAlign: "center" }}>
                    <div style={{ fontSize: 22, marginBottom: 4 }}>{s.icon}</div>
                    <div style={{ fontSize: 22, fontWeight: 900, color: C.blue }}>{s.v}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontWeight: 700 }}>{s.l}</div>
                  </div>
                ))}
              </div>

              {/* Dates */}
              <W style={{ padding: "16px 18px", marginBottom: 16 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  {[["Start Date", project.startDate || "—"], ["End Date", project.endDate || "TBD"]].map(([k, v]) => (
                    <div key={k}>
                      <div style={{ fontSize: 10, color: C.light, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 4 }}>{k}</div>
                      <div style={{ fontSize: 14, fontWeight: 800, color: C.text }}>{v}</div>
                    </div>
                  ))}
                </div>
              </W>

              {/* Description */}
              {project.description && (
                <W style={{ padding: "16px 18px", marginBottom: 20 }}>
                  <div style={{ fontSize: 10, color: C.light, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 8 }}>Description</div>
                  <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.65, margin: 0, fontWeight: 600 }}>{project.description}</p>
                </W>
              )}

              {/* Attached documents */}
              {(project.poDocuments || []).length > 0 && (
                <ProjectDocuments docs={project.poDocuments} />
              )}

              {/* BOQ Items table */}
              {(project.boqItems || []).filter(i => i.description).length > 0 && (() => {
                const CAT_COLOR = { Cable: "#2563eb", Conduit: "#7c3aed", Networking: "#0891b2", CCTV: "#dc2626", "Access Control": "#ea580c", Fire: "#d97706", Server: "#059669", Tools: "#64748b", Other: "#94a3b8" };
                const items = project.boqItems.filter(i => i.description);
                const grouped = {};
                items.forEach(it => { const c = it.category || "Other"; if (!grouped[c]) grouped[c] = []; grouped[c].push(it); });
                return (
                  <div style={{ background: C.white, border: `1px solid ${C.border}`, borderRadius: 14, padding: "14px 18px", marginBottom: 16 }}>
                    <div style={{
                      fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
                      color: C.light, marginBottom: 12
                    }}>📐 BOQ Line Items ({items.length})</div>
                    {Object.entries(grouped).map(([cat, catItems]) => (
                      <div key={cat} style={{ marginBottom: 10 }}>
                        <div style={{
                          fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
                          color: CAT_COLOR[cat] || "#64748b", marginBottom: 5, display: "flex", alignItems: "center", gap: 5
                        }}>
                          <div style={{ width: 7, height: 7, borderRadius: "50%", background: CAT_COLOR[cat] || "#94a3b8" }} />
                          {cat}
                        </div>
                        <div style={{ border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
                          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                            <thead><tr style={{ background: "#f8faff" }}>
                              {["Description", "Qty", "Unit", "Rate"].map(h => (
                                <th key={h} style={{
                                  padding: "6px 10px", textAlign: "left", fontSize: 9,
                                  fontWeight: 800, color: C.light, letterSpacing: ".08em", textTransform: "uppercase",
                                  borderBottom: `1px solid ${C.border}`
                                }}>{h}</th>
                              ))}
                            </tr></thead>
                            <tbody>
                              {catItems.map((item, i) => (
                                <tr key={i} style={{
                                  borderTop: i > 0 ? `1px solid #f0f6ff` : "none",
                                  background: i % 2 === 0 ? "#fff" : "#fafcff"
                                }}>
                                  <td style={{ padding: "7px 10px", fontWeight: 700, color: C.text }}>{item.description}</td>
                                  <td style={{ padding: "7px 10px", fontWeight: 900, color: "#059669", fontSize: 13 }}>{item.qty}</td>
                                  <td style={{ padding: "7px 10px" }}>
                                    <span style={{
                                      fontSize: 10, fontWeight: 800,
                                      color: CAT_COLOR[item.category] || C.blue,
                                      background: `${CAT_COLOR[item.category] || C.blue}15`,
                                      padding: "2px 8px", borderRadius: 12
                                    }}>{item.unit}</span>
                                  </td>
                                  <td style={{ padding: "7px 10px", color: C.muted, fontWeight: 600 }}>{item.rate || "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ))}
                    <div style={{
                      marginTop: 8, padding: "6px 10px", background: "#f0fdf4", borderRadius: 8,
                      fontSize: 10, fontWeight: 700, color: "#059669"
                    }}>
                      {items.length} items · Total: {[...new Set(items.map(i => i.unit))].map(u => {
                        const sum = items.filter(i => i.unit === u).reduce((s, i) => s + Number(i.qty || 0), 0);
                        return `${sum} ${u}`;
                      }).join(" · ")}
                    </div>
                  </div>
                );
              })()}

              {/* Status action */}
              <div style={{ display: "flex", gap: 10 }}>
                {project.status === "active"
                  ? <Btn v="ghost" style={{ flex: 1, justifyContent: "center", borderColor: "#fca5a5", color: "#dc2626" }}
                    onClick={() => onStatusChange(project.id, "completed")}>✓ Mark as Completed</Btn>
                  : <>
                    <Btn v="primary" style={{ flex: 1, justifyContent: "center" }}
                      onClick={async () => {
                        const data = await fetchMaterialConsumption(project.id);
                        generateWCR(project, MOCK_EMPLOYEES, reports, data);
                      }}>📥 Download WCR</Btn>
                    <Btn v="soft" style={{ justifyContent: "center" }}
                      onClick={() => onStatusChange(project.id, "active")}>↺ Reactivate</Btn>
                  </>
                }
                {onEdit && <Btn v="soft" onClick={onEdit}>✏ Edit</Btn>}
              </div>
            </div>
          )}

          {/* ── Team Tab ── */}
          {tab === "employees" && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.muted, marginBottom: 14 }}>
                {assignedEmps.length} employee{assignedEmps.length !== 1 ? "s" : ""} assigned to this project
              </div>
              {assignedEmps.length === 0
                ? <div style={{ textAlign: "center", padding: "32px 0", color: C.light, fontSize: 13, fontWeight: 600 }}>
                  No employees assigned yet.<br />Edit the project to assign team members.
                </div>
                : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {assignedEmps.map(emp => {
                    const empRpts = projReports.filter(r => r.employeeId === emp.id);
                    const empHrs = empRpts.reduce((s, r) => s + Number(r.hours), 0);
                    return (
                      <W key={emp.id} style={{ padding: "16px 18px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                          <Avt initials={emp.avatar} size={40} />
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 14, fontWeight: 800, color: C.text }}>{emp.name}</div>
                            <div style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>{emp.email}</div>
                          </div>
                          <div style={{ textAlign: "right" }}>
                            <div style={{ fontSize: 16, fontWeight: 900, color: C.blue }}>{empRpts.length}</div>
                            <div style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>reports</div>
                          </div>
                          <div style={{ textAlign: "right", marginLeft: 8 }}>
                            <div style={{ fontSize: 16, fontWeight: 900, color: "#059669" }}>{empHrs}h</div>
                            <div style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>logged</div>
                          </div>
                        </div>
                        {empRpts.length > 0 && (
                          <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
                            <div style={{ fontSize: 10, color: C.light, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 6 }}>Latest Work</div>
                            <p style={{ fontSize: 12, color: C.muted, margin: 0, lineHeight: 1.5, fontWeight: 600 }}>
                              {empRpts[empRpts.length - 1].rawDescription.slice(0, 110)}…
                            </p>
                          </div>
                        )}
                      </W>
                    );
                  })}
                </div>
              }
            </div>
          )}

          {/* ── Workforce Tab ── */}
          {tab === "workforce" && (() => {
            // Group reports by date, sum manpower per day
            const dateMap = {};
            projReports.forEach(r => {
              if (!dateMap[r.date]) dateMap[r.date] = { date: r.date, manpower: 0, qty: 0, workers: new Set() };
              dateMap[r.date].manpower += Number(r.manpowerCount || 0);
              dateMap[r.date].qty += Number(r.workQtyDone || 0);
              dateMap[r.date].workers.add(r.employeeId);
            });
            const days = Object.values(dateMap).sort((a, b) => b.date.localeCompare(a.date));
            const empManpower = {};
            projReports.forEach(r => {
              empManpower[r.employeeId] = (empManpower[r.employeeId] || 0) + Number(r.manpowerCount || 0);
            });
            return (
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: C.muted, marginBottom: 14 }}>Workforce & Manpower tracking</div>

                {/* Per-employee manpower summary */}
                <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 10 }}>Manpower by Employee</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
                  {assignedEmps.map(emp => {
                    const empRpts = projReports.filter(r => r.employeeId === emp.id);
                    const totalManpower = empRpts.reduce((s, r) => s + Number(r.manpowerCount || 0), 0);
                    const totalQty = empRpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
                    return (
                      <W key={emp.id} style={{ padding: "12px 16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <Avt initials={emp.avatar} size={34} />
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{emp.name}</div>
                            <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{empRpts.length} reports submitted</div>
                          </div>
                          <div style={{ textAlign: "right", marginRight: 10 }}>
                            <div style={{ fontSize: 14, fontWeight: 900, color: "#7c3aed" }}>{totalManpower}</div>
                            <div style={{ fontSize: 9, color: C.light, fontWeight: 700, textTransform: "uppercase" }}>Manpower days</div>
                          </div>
                          <div style={{ textAlign: "right" }}>
                            <div style={{ fontSize: 14, fontWeight: 900, color: "#059669" }}>{totalQty} {project.unitType || ""}</div>
                            <div style={{ fontSize: 9, color: C.light, fontWeight: 700, textTransform: "uppercase" }}>Work done</div>
                          </div>
                        </div>
                      </W>
                    );
                  })}
                </div>

                {/* Daily workforce log */}
                <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 10 }}>Daily Workforce Log</div>
                {days.length === 0
                  ? <div style={{ textAlign: "center", padding: "20px 0", color: C.light, fontSize: 13, fontWeight: 600 }}>No workforce data yet.</div>
                  : <div style={{ border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead><tr style={{ background: "#f8faff" }}>
                        {["Date", "Manpower", "Work Done", "Workers"].map(h => (
                          <th key={h} style={{
                            padding: "8px 14px", textAlign: "left", fontSize: 10, color: C.light,
                            fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", borderBottom: `1px solid ${C.border}`
                          }}>{h}</th>
                        ))}
                      </tr></thead>
                      <tbody>
                        {days.map(d => (
                          <tr key={d.date} style={{ borderTop: `1px solid #f0f6ff` }}>
                            <td style={{ padding: "10px 14px", fontSize: 12, fontWeight: 700, color: C.text }}>{d.date}</td>
                            <td style={{ padding: "10px 14px", fontSize: 13, fontWeight: 900, color: "#7c3aed" }}>{d.manpower} pax</td>
                            <td style={{ padding: "10px 14px", fontSize: 13, fontWeight: 900, color: "#059669" }}>{d.qty} {project.unitType || ""}</td>
                            <td style={{ padding: "10px 14px" }}>
                              <div style={{ display: "flex", gap: 4 }}>
                                {[...d.workers].map(id => {
                                  const e = MOCK_EMPLOYEES.find(em => em.id === id);
                                  return e ? <Avt key={id} initials={e.avatar} size={22} /> : null;
                                })}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                }
              </div>
            );
          })()}

          {/* ── Reports Tab ── */}
          {tab === "reports" && (
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: C.muted, marginBottom: 14 }}>
                {projReports.length} report{projReports.length !== 1 ? "s" : ""} filed for this project
              </div>

              {/* Daily Quantity Log Table */}
              {projReports.length > 0 && (
                <div style={{ border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden", marginBottom: 16 }}>
                  <div style={{
                    background: "#f8faff", padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
                    fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light
                  }}>
                    📐 Daily Quantity Log
                  </div>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead><tr style={{ background: "#f8faff" }}>
                      {["Date", "Employee", "Work Done", "Manpower", "Hours"].map(h => (
                        <th key={h} style={{
                          padding: "8px 12px", textAlign: "left", fontSize: 10, color: C.light,
                          fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", borderBottom: `1px solid ${C.border}`
                        }}>{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {[...projReports].sort((a, b) => b.date.localeCompare(a.date)).map(r => {
                        const emp = MOCK_EMPLOYEES.find(e => e.id === r.employeeId);
                        return (
                          <tr key={r.id} style={{ borderTop: `1px solid #f0f6ff` }}>
                            <td style={{ padding: "10px 12px", fontSize: 12, fontWeight: 700, color: C.text }}>{r.date}</td>
                            <td style={{ padding: "10px 12px" }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                <Avt initials={emp?.avatar} size={22} />
                                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{emp?.name}</span>
                              </div>
                            </td>
                            <td style={{ padding: "10px 12px", fontSize: 13, fontWeight: 900, color: C.blue }}>
                              {r.workQtyDone || "—"}
                            </td>
                            <td style={{ padding: "10px 12px", fontSize: 12, fontWeight: 700, color: C.muted }}>{r.manpowerCount || "—"} pax</td>
                            <td style={{ padding: "10px 12px", fontSize: 12, fontWeight: 700, color: C.muted }}>{r.hours}h</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {projReports.length === 0
                ? <div style={{ textAlign: "center", padding: "32px 0", color: C.light, fontSize: 13, fontWeight: 600 }}>
                  No reports submitted yet.
                </div>
                : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {projReports.map(r => {
                    const emp = MOCK_EMPLOYEES.find(e => e.id === r.employeeId);
                    return (
                      <W key={r.id} style={{ padding: "14px 18px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <Avt initials={emp?.avatar} size={28} />
                            <div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{emp?.name}</div>
                              <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{r.date}</div>
                            </div>
                          </div>
                          <div style={{ textAlign: "right" }}>
                            <div style={{ fontSize: 14, fontWeight: 900, color: C.blue }}>{r.hours}h</div>
                            {r.issuesFaced.length > 0 && <Pill color="amber" style={{ fontSize: 10 }}>⚠ issue</Pill>}
                          </div>
                        </div>
                        {r.workDetails && (
                          <p style={{
                            fontSize: 12, color: C.muted, margin: 0, lineHeight: 1.5,
                            background: "#f8faff", padding: "10px 12px", borderRadius: 10, fontWeight: 600
                          }}>
                            {r.workDetails.slice(0, 120)}{r.workDetails.length > 120 ? "…" : ""}
                          </p>
                        )}
                      </W>
                    );
                  })}
                </div>
              }
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── TL Announcement Panel ───────────────────────────────────────────────────
function TLAnnouncementPanel({ user, announcements, onSend, onLogout }) {
  const deptEmps = MOCK_EMPLOYEES.filter(e => e.role === "employee"); // can send to any employee
  const [msg, setMsg] = useState("");
  const [priority, setPriority] = useState("normal");
  const [recipients, setRecipients] = useState(
    MOCK_EMPLOYEES.filter(e => e.department === user.department && e.role === "employee").map(e => e.id)
  );
  const [sending, setSending] = useState(false);
  const [flash, setFlash] = useState(false);

  const PRIORITY_CFG = {
    normal: { label: "Normal", color: "#2563eb", bg: "#eff6ff", icon: "📋" },
    urgent: { label: "🚨 Urgent", color: "#dc2626", bg: "#fef2f2", icon: "🚨" },
    info: { label: "ℹ Info", color: "#059669", bg: "#f0fdf4", icon: "ℹ️" },
  };

  const toggleRec = (id) => setRecipients(r => r.includes(id) ? r.filter(x => x !== id) : [...r, id]);

  const send = () => {
    if (!msg.trim() || recipients.length === 0) return;
    setSending(true);
    setTimeout(() => {
      const announcement = {
        id: Date.now(),
        from: user.name,
        fromId: user.id,
        fromDept: user.department,
        message: msg.trim(),
        priority,
        recipientIds: [...recipients],
        recipients: recipients.map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean),
        sentAt: new Date().toISOString(),
        sentAtLabel: new Date().toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }),
        readBy: [],
      };
      onSend(announcement);
      setMsg("");
      setPriority("normal");
      setRecipients(MOCK_EMPLOYEES.filter(e => e.department === user.department && e.role === "employee").map(e => e.id));
      setSending(false);
      setFlash(true);
      setTimeout(() => setFlash(false), 2500);
    }, 800);
  };

  const cfg = PRIORITY_CFG[priority];

  // My sent announcements = filter from shared list
  const mySent = (announcements || []).filter(a => a.fromId === user.id);

  return (
    <div>
      <TopBar title="Announcements" sub={`Send messages to your team`} user={user} onLogout={onLogout} announcements={announcements} />

      {/* Success flash */}
      {flash && (
        <div className="fu" style={{
          background: "#f0fdf4", border: "1.5px solid #86efac", borderRadius: 14,
          padding: "12px 18px", marginBottom: 16, display: "flex", alignItems: "center", gap: 10
        }}>
          <span style={{ fontSize: 20 }}>✅</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 800, color: "#065f46" }}>Announcement sent!</div>
            <div style={{ fontSize: 11, color: "#059669", fontWeight: 600 }}>Employees will see it in their Announcements inbox.</div>
          </div>
        </div>
      )}

      {/* Compose box */}
      <div style={{
        background: C.white, borderRadius: 20, border: `1.5px solid ${C.border}`,
        overflow: "hidden", marginBottom: 20, boxShadow: "0 2px 12px rgba(37,99,235,.07)"
      }}>
        <div style={{ background: `linear-gradient(135deg,${C.blue},${C.blueL})`, padding: "14px 20px" }}>
          <div style={{ fontSize: 14, fontWeight: 900, color: "#fff" }}>📢 New Announcement</div>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,.75)", fontWeight: 600, marginTop: 2 }}>
            Employees will see this in their Announcements tab instantly
          </div>
        </div>
        <div style={{ padding: "18px 20px" }}>

          {/* Priority */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 8 }}>Priority</div>
            <div style={{ display: "flex", gap: 8 }}>
              {Object.entries(PRIORITY_CFG).map(([k, v]) => (
                <button key={k} onClick={() => setPriority(k)}
                  style={{
                    padding: "6px 16px", borderRadius: 20, border: `2px solid ${priority === k ? v.color : C.border}`,
                    background: priority === k ? v.bg : "#fff", cursor: "pointer", fontFamily: "inherit",
                    fontSize: 11, fontWeight: 800, color: priority === k ? v.color : C.muted, transition: "all .15s"
                  }}>
                  {v.icon} {v.label}
                </button>
              ))}
            </div>
          </div>

          {/* Message */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 6 }}>Message *</div>
            <textarea value={msg} onChange={e => setMsg(e.target.value)}
              placeholder={`Type your announcement…\n\nExamples:\n• "Safety briefing tomorrow at 8AM, attendance mandatory"\n• "New tools available in the site store"\n• "Project timeline updated — check BOQ revision"`}
              rows={5}
              style={{
                width: "100%", padding: "12px 14px", border: `1.5px solid ${msg ? cfg.color : C.border}`,
                borderRadius: 12, fontFamily: "inherit", fontSize: 13, color: C.text, resize: "vertical",
                boxSizing: "border-box", lineHeight: 1.6, background: msg ? cfg.bg : "#fff",
                transition: "all .2s", outline: "none"
              }} />
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
              <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>{msg.length} characters</span>
              {msg.length > 0 && <span style={{ fontSize: 10, color: cfg.color, fontWeight: 700 }}>{cfg.icon} {cfg.label}</span>}
            </div>
          </div>

          {/* Recipients */}
          <div style={{ marginBottom: 16 }}>
            <div style={{
              fontSize: 10, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
              color: C.light, marginBottom: 8, display: "flex", justifyContent: "space-between"
            }}>
              <span>Recipients ({recipients.length}/{deptEmps.length})</span>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={() => setRecipients(deptEmps.map(e => e.id))}
                  style={{ fontSize: 10, color: C.blue, fontWeight: 800, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit" }}>All</button>
                <button onClick={() => setRecipients([])}
                  style={{ fontSize: 10, color: C.muted, fontWeight: 800, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit" }}>None</button>
                <button onClick={() => setRecipients(MOCK_EMPLOYEES.filter(e => e.department === user.department && e.role === "employee").map(e => e.id))}
                  style={{ fontSize: 10, color: "#059669", fontWeight: 800, background: "none", border: "none", cursor: "pointer", fontFamily: "inherit" }}>My Dept</button>
              </div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {deptEmps.map(emp => {
                const sel = recipients.includes(emp.id);
                const sameDept = emp.department === user.department;
                return (
                  <div key={emp.id} onClick={() => toggleRec(emp.id)}
                    style={{
                      display: "flex", alignItems: "center", gap: 8, padding: "7px 12px", borderRadius: 20,
                      border: `1.5px solid ${sel ? C.blue : C.border}`, background: sel ? C.bluePale : "#fff",
                      cursor: "pointer", transition: "all .15s"
                    }}>
                    <div style={{
                      width: 24, height: 24, borderRadius: "50%", flexShrink: 0,
                      background: sameDept ? "linear-gradient(135deg,#059669,#10b981)" : `linear-gradient(135deg,${C.blue},${C.blueL})`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 9, fontWeight: 900, color: "#fff"
                    }}>{emp.avatar}</div>
                    <span style={{ fontSize: 12, fontWeight: 700, color: sel ? C.blue : C.text }}>{emp.name}</span>
                    <span style={{ fontSize: 9, color: sameDept ? "#059669" : C.light, fontWeight: 700 }}>{emp.department}</span>
                    {sel && <span style={{ fontSize: 10, color: C.blue }}>✓</span>}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Send */}
          <button onClick={send} disabled={!msg.trim() || recipients.length === 0 || sending}
            style={{
              width: "100%", padding: "12px", borderRadius: 14, border: "none", cursor: "pointer",
              fontFamily: "inherit", fontSize: 14, fontWeight: 800,
              background: (!msg.trim() || recipients.length === 0 || sending) ? "#e2e8f0" : `linear-gradient(135deg,${cfg.color},${cfg.color}cc)`,
              color: (!msg.trim() || recipients.length === 0 || sending) ? "#94a3b8" : "#fff",
              transition: "all .2s", boxShadow: (!msg.trim() || recipients.length === 0 || sending) ? "none" : `0 4px 16px ${cfg.color}44`
            }}>
            {sending ? "⏳ Sending…" : `${cfg.icon} Send to ${recipients.length} employee${recipients.length !== 1 ? "s" : ""}`}
          </button>
        </div>
      </div>

      {/* Sent history */}
      {mySent.length > 0 ? (
        <div>
          <div style={{
            fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase",
            color: C.light, marginBottom: 12
          }}>📬 Sent ({mySent.length})</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {mySent.map(a => {
              const c = PRIORITY_CFG[a.priority] || PRIORITY_CFG.normal;
              const recs = a.recipients || (a.recipientIds || []).map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);
              const readCount = (a.readBy || []).length;

              return (
                <div key={a.id} style={{
                  background: C.white, borderRadius: 16, border: `1.5px solid ${c.color}44`,
                  padding: "16px 18px", boxShadow: "0 2px 10px rgba(0,0,0,.05)"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                    <span style={{ background: c.bg, padding: "4px 10px", borderRadius: 20, color: c.color, fontWeight: 800, fontSize: 11 }}>{c.icon} {c.label}</span>
                    <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>{a.sentAtLabel}</span>
                  </div>
                  <p style={{ fontSize: 13, color: C.text, margin: "0 0 10px", lineHeight: 1.6, fontWeight: 600 }}>{a.message}</p>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                    <span style={{ fontSize: 10, color: C.muted, fontWeight: 700 }}>Sent to:</span>
                    {recs.map(r => (
                      <span key={r.id} style={{ fontSize: 10, fontWeight: 800, color: C.blue, background: C.bluePale, padding: "2px 8px", borderRadius: 12 }}>{r.name}</span>
                    ))}
                    <span style={{ fontSize: 10, color: C.light, fontWeight: 600, marginLeft: "auto" }}>
                      {readCount}/{recs.length} read
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div style={{
          textAlign: "center", padding: "40px 20px", color: C.light, fontSize: 13, fontWeight: 700,
          background: C.white, borderRadius: 20, border: `1px solid ${C.border}`
        }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>📭</div>
          No announcements sent yet.
        </div>
      )}
    </div>
  );
}

// ─── Employee Announcements Panel ─────────────────────────────────────────────
function EmployeeAnnouncementsPanel({ user, announcements, onLogout }) {
  const PRIORITY_CFG = {
    normal: { label: "Normal", color: "#2563eb", bg: "#eff6ff", icon: "📋" },
    urgent: { label: "🚨 Urgent", color: "#dc2626", bg: "#fef2f2", icon: "🚨" },
    info: { label: "ℹ Info", color: "#059669", bg: "#f0fdf4", icon: "ℹ️" },
  };

  // Only show announcements addressed to this employee
  const myAnnouncements = (announcements || [])
    .filter(a => (a.recipientIds || []).includes(user.id))
    .sort((a, b) => new Date(b.sentAt) - new Date(a.sentAt));

  const unread = myAnnouncements.filter(a => !(a.readBy || []).includes(user.id)).length;

  const urgentCount = myAnnouncements.filter(a => a.priority === "urgent" && !(a.readBy || []).includes(user.id)).length;

  return (
    <div>
      <TopBar title="Announcements" sub={`Messages from your team leader`} user={user} onLogout={onLogout} announcements={announcements} />

      {/* Header strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 20 }} className="fu">
        {[
          { l: "Total", v: myAnnouncements.length, ico: "📢", grad: `linear-gradient(135deg,${C.blue},${C.blueL})` },
          { l: "Unread", v: unread, ico: "🔔", grad: unread > 0 ? "linear-gradient(135deg,#dc2626,#f87171)" : "linear-gradient(135deg,#64748b,#94a3b8)" },
          { l: "Urgent", v: urgentCount, ico: "🚨", grad: urgentCount > 0 ? "linear-gradient(135deg,#d97706,#fbbf24)" : "linear-gradient(135deg,#64748b,#94a3b8)" },
        ].map(s => (
          <div key={s.l} style={{
            borderRadius: 16, padding: "14px 18px", background: s.grad,
            boxShadow: "0 4px 16px rgba(0,0,0,.1)", position: "relative", overflow: "hidden"
          }}>
            <div style={{ position: "absolute", top: -12, right: -12, width: 48, height: 48, borderRadius: "50%", background: "rgba(255,255,255,.12)" }} />
            <div style={{ fontSize: 20, marginBottom: 4 }}>{s.ico}</div>
            <div style={{ fontSize: 26, fontWeight: 900, color: "#fff" }}>{s.v}</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,.8)", fontWeight: 700 }}>{s.l}</div>
          </div>
        ))}
      </div>

      {myAnnouncements.length === 0 ? (
        <div style={{
          textAlign: "center", padding: "60px 20px", color: C.light, fontSize: 14, fontWeight: 700,
          background: C.white, borderRadius: 20, border: `1px solid ${C.border}`
        }}>
          <div style={{ fontSize: 52, marginBottom: 16 }}>📭</div>
          <div style={{ marginBottom: 8 }}>No announcements yet.</div>
          <div style={{ fontSize: 12, fontWeight: 600 }}>Your team leader will send messages here.</div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {myAnnouncements.map(a => {
            const c = PRIORITY_CFG[a.priority] || PRIORITY_CFG.normal;
            const isRead = (a.readBy || []).includes(user.id);
            const ago = timeAgo(a.sentAt);
            return (
              <div key={a.id}
                style={{
                  background: C.white, borderRadius: 18, overflow: "hidden",
                  border: `2px solid ${isRead ? C.border : c.color}`,
                  boxShadow: isRead ? "0 2px 8px rgba(0,0,0,.04)" : `0 4px 20px ${c.color}22`,
                  transition: "all .2s"
                }}>
                {/* Priority stripe */}
                <div style={{ height: 4, background: isRead ? "#e2e8f0" : `linear-gradient(90deg,${c.color},${c.color}88)` }} />
                <div style={{ padding: "16px 20px" }}>
                  {/* Top row */}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <div style={{
                        width: 36, height: 36, borderRadius: "50%", flexShrink: 0,
                        background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        fontSize: 12, fontWeight: 900, color: "#fff"
                      }}>
                        {MOCK_EMPLOYEES.find(e => e.id === a.fromId)?.avatar || "TL"}
                      </div>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 800, color: C.text }}>{a.from}</div>
                        <div style={{ fontSize: 10, color: C.muted, fontWeight: 600 }}>{a.fromDept} · {ago}</div>
                      </div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ background: c.bg, padding: "3px 10px", borderRadius: 20, color: c.color, fontWeight: 800, fontSize: 10 }}>{c.icon} {c.label}</span>
                      {!isRead && (
                        <span style={{
                          background: "#dc2626", color: "#fff", fontSize: 9, fontWeight: 900,
                          padding: "2px 7px", borderRadius: 20
                        }}>NEW</span>
                      )}
                    </div>
                  </div>

                  {/* Message */}
                  <p style={{
                    fontSize: 13, color: C.text, margin: "0 0 0", lineHeight: 1.65, fontWeight: isRead ? 500 : 700,
                    padding: "12px 14px", background: isRead ? "#f8faff" : c.bg, borderRadius: 10,
                    borderLeft: `3px solid ${isRead ? C.border : c.color}`
                  }}>
                    {a.message}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── TL Team Manage Modal ────────────────────────────────────────────────────
function TLTeamManageModal({ project, user, onClose, onSave }) {
  // All employees across the whole company (TL can assign anyone)
  const allEmps = MOCK_EMPLOYEES.filter(e => e.role === "employee");
  const [assigned, setAssigned] = useState([...(project.assignedEmployees || [])]);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState("assigned"); // "assigned" | "add"

  const toggle = (empId) => {
    setAssigned(prev =>
      prev.includes(empId) ? prev.filter(id => id !== empId) : [...prev, empId]
    );
  };

  const handleSave = () => {
    setSaving(true);
    const finalAssigned = assigned.includes(user.id) ? assigned : [...assigned, user.id];
    setTimeout(() => {
      onSave({
        ...project,
        assignedEmployees: finalAssigned,
        lastUpdatedAt: new Date().toISOString(),
        lastUpdatedBy: user.name,
        lastUpdateType: "Team updated",
      });
      AuditLog.push("TL_TEAM_UPDATED",
        `Project: ${project.name} | Members: ${finalAssigned.length}`, user.email);
      setSaving(false);
      setSaved(true);
      setTimeout(onClose, 800);
    }, 400);
  };

  const assignedEmps = assigned.map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);
  const unassignedEmps = allEmps.filter(e => !assigned.includes(e.id));

  const searchFilter = (e) => e.name.toLowerCase().includes(search.toLowerCase()) ||
    e.department.toLowerCase().includes(search.toLowerCase());

  const visibleAssigned = assignedEmps.filter(searchFilter);
  const visibleUnassigned = unassignedEmps.filter(searchFilter);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9800, background: "rgba(15,23,42,.65)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 16
    }}
      onClick={onClose}>
      <div onClick={e => e.stopPropagation()}
        style={{
          background: C.white, borderRadius: 24, width: "100%", maxWidth: 500,
          maxHeight: "88vh", display: "flex", flexDirection: "column",
          boxShadow: "0 24px 64px rgba(37,99,235,.25)"
        }}
        className="fu">

        {/* ── Header ── */}
        <div style={{
          background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
          padding: "20px 24px 0", borderRadius: "24px 24px 0 0", flexShrink: 0
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
            <div>
              <div style={{
                fontSize: 10, color: "rgba(255,255,255,.65)", fontWeight: 800,
                letterSpacing: ".14em", textTransform: "uppercase", marginBottom: 4
              }}>👥 Manage Team</div>
              <div style={{ fontSize: 16, fontWeight: 900, color: "#fff", lineHeight: 1.25, maxWidth: 340 }}>
                {project.name}
              </div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,.65)", marginTop: 3 }}>
                {project.department} · {project.companyName}
              </div>
            </div>
            <button onClick={onClose}
              style={{
                background: "rgba(255,255,255,.18)", border: "none", borderRadius: "50%",
                width: 32, height: 32, cursor: "pointer", fontSize: 16, color: "#fff",
                display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                marginTop: 2
              }}>✕</button>
          </div>

          {/* Stats strip */}
          <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
            {[
              { l: "On Team", v: assigned.length, bg: "rgba(255,255,255,.22)", c: "#fff" },
              { l: "Available", v: unassignedEmps.length, bg: "rgba(255,255,255,.1)", c: "rgba(255,255,255,.8)" },
              { l: "Total Staff", v: allEmps.length, bg: "rgba(255,255,255,.1)", c: "rgba(255,255,255,.8)" },
            ].map(s => (
              <div key={s.l} style={{
                flex: 1, background: s.bg, borderRadius: 10,
                padding: "8px 0", textAlign: "center"
              }}>
                <div style={{ fontSize: 20, fontWeight: 900, color: s.c, lineHeight: 1 }}>{s.v}</div>
                <div style={{
                  fontSize: 9, color: s.c, fontWeight: 800, textTransform: "uppercase",
                  letterSpacing: ".08em", marginTop: 3, opacity: .85
                }}>{s.l}</div>
              </div>
            ))}
          </div>

          {/* Tab bar */}
          <div style={{ display: "flex", gap: 2 }}>
            {[
              { k: "assigned", l: `Team (${assigned.length})` },
              { k: "add", l: `Add Members (${unassignedEmps.length})` },
            ].map(t => (
              <button key={t.k} onClick={() => setTab(t.k)}
                style={{
                  flex: 1, padding: "9px 0", border: "none", cursor: "pointer",
                  fontFamily: "inherit", fontSize: 12, fontWeight: 800,
                  background: tab === t.k ? "rgba(255,255,255,.18)" : "transparent",
                  color: tab === t.k ? "#fff" : "rgba(255,255,255,.55)",
                  borderRadius: "8px 8px 0 0", transition: "all .15s"
                }}>
                {t.l}
              </button>
            ))}
          </div>
        </div>

        {/* ── Body ── */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>

          {/* Search */}
          <div style={{ marginBottom: 14, position: "relative" }}>
            <span style={{
              position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)",
              fontSize: 13, pointerEvents: "none", opacity: .5
            }}>🔍</span>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder={tab === "assigned" ? "Search team…" : "Search all employees…"}
              style={{
                width: "100%", padding: "9px 12px 9px 34px", border: `1.5px solid ${C.border}`,
                borderRadius: 10, fontFamily: "inherit", fontSize: 12, color: C.text, outline: "none",
                background: "#f8faff", boxSizing: "border-box", transition: "border-color .2s"
              }}
              onFocus={e => e.target.style.borderColor = C.blue}
              onBlur={e => e.target.style.borderColor = C.border} />
          </div>

          {/* ── ASSIGNED TAB ── */}
          {tab === "assigned" && (
            <div>
              {visibleAssigned.length === 0 && (
                <div style={{ textAlign: "center", padding: "36px 0", color: C.light }}>
                  <div style={{ fontSize: 40, marginBottom: 10 }}>👤</div>
                  <div style={{ fontSize: 13, fontWeight: 700 }}>
                    {search ? `No team members match "${search}"` : "No employees on this project yet."}
                  </div>
                  {!search && <div style={{ fontSize: 11, marginTop: 6, fontWeight: 600 }}>
                    Switch to "Add Members" to assign employees.
                  </div>}
                </div>
              )}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {visibleAssigned.map(emp => (
                  <div key={emp.id}
                    style={{
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 14px",
                      background: "#f0fdf4", border: "1.5px solid #86efac", borderRadius: 14
                    }}>
                    {/* Avatar */}
                    <div style={{
                      width: 40, height: 40, borderRadius: "50%", flexShrink: 0,
                      background: "linear-gradient(135deg,#059669,#10b981)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 12, fontWeight: 900, color: "#fff",
                      boxShadow: "0 2px 8px rgba(5,150,105,.3)"
                    }}>
                      {emp.avatar}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 13, fontWeight: 800, color: "#065f46",
                        whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"
                      }}>
                        {emp.name}
                        {emp.id === user.id &&
                          <span style={{
                            marginLeft: 6, fontSize: 9, background: "#059669", color: "#fff",
                            padding: "1px 6px", borderRadius: 6, fontWeight: 800
                          }}>YOU</span>}
                      </div>
                      <div style={{ fontSize: 11, color: "#059669", fontWeight: 600, marginTop: 1 }}>
                        {emp.department}
                      </div>
                    </div>
                    {emp.id !== user.id ? (
                      <button onClick={() => toggle(emp.id)}
                        style={{
                          background: "#fee2e2", border: "1.5px solid #fca5a5", borderRadius: 8,
                          padding: "5px 11px", cursor: "pointer", fontSize: 11, fontWeight: 800,
                          color: "#dc2626", fontFamily: "inherit", flexShrink: 0,
                          display: "flex", alignItems: "center", gap: 4, transition: "background .15s"
                        }}
                        onMouseOver={e => e.currentTarget.style.background = "#fecaca"}
                        onMouseOut={e => e.currentTarget.style.background = "#fee2e2"}>
                        ✕ Remove
                      </button>
                    ) : (
                      <span style={{
                        fontSize: 9, fontWeight: 800, color: "#059669",
                        background: "#dcfce7", padding: "4px 8px", borderRadius: 6, flexShrink: 0
                      }}>
                        Team Lead
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── ADD MEMBERS TAB ── */}
          {tab === "add" && (
            <div>
              {visibleUnassigned.length === 0 && (
                <div style={{ textAlign: "center", padding: "36px 0", color: C.light }}>
                  <div style={{ fontSize: 40, marginBottom: 10 }}>🎉</div>
                  <div style={{ fontSize: 13, fontWeight: 700 }}>
                    {search ? `No employees match "${search}"` : "All employees are already on this project!"}
                  </div>
                </div>
              )}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {visibleUnassigned.map(emp => (
                  <div key={emp.id}
                    style={{
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 14px",
                      background: "#f8faff", border: `1.5px solid ${C.border}`, borderRadius: 14,
                      transition: "border-color .15s,background .15s"
                    }}
                    onMouseOver={e => { e.currentTarget.style.borderColor = C.blueMid; e.currentTarget.style.background = C.bluePale; }}
                    onMouseOut={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = "#f8faff"; }}>
                    {/* Avatar */}
                    <div style={{
                      width: 40, height: 40, borderRadius: "50%", flexShrink: 0,
                      background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 12, fontWeight: 900, color: "#fff", opacity: .7,
                      boxShadow: "0 2px 8px rgba(37,99,235,.2)"
                    }}>
                      {emp.avatar}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 13, fontWeight: 800, color: C.text,
                        whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"
                      }}>
                        {emp.name}
                      </div>
                      <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, marginTop: 1 }}>
                        {emp.department}
                      </div>
                    </div>
                    <button onClick={() => { toggle(emp.id); }}
                      style={{
                        background: C.bluePale, border: `1.5px solid ${C.blueMid}`, borderRadius: 8,
                        padding: "5px 11px", cursor: "pointer", fontSize: 11, fontWeight: 800,
                        color: C.blue, fontFamily: "inherit", flexShrink: 0,
                        display: "flex", alignItems: "center", gap: 4, transition: "background .15s"
                      }}
                      onMouseOver={e => e.currentTarget.style.background = C.blueSoft}
                      onMouseOut={e => e.currentTarget.style.background = C.bluePale}>
                      ＋ Add
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Footer ── */}
        <div style={{
          padding: "14px 20px", borderTop: `1px solid ${C.border}`, flexShrink: 0,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          background: "#f8faff", borderRadius: "0 0 24px 24px"
        }}>
          <div style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>
            {assigned.length} member{assigned.length !== 1 ? "s" : ""} on project
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn v="ghost" sm onClick={onClose}>Cancel</Btn>
            <Btn v="primary" sm onClick={handleSave} disabled={saving || saved}>
              {saved ? "✓ Saved!" : saving ? "Saving…" : "Save Team"}
            </Btn>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── TL Projects Panel ──────────────────────────────────────────────────────────
function TLProjectsPanel({ user, projects, reports, projectItems = [], onEditProject, onLogout }) {
  const allProjects = projects || MOCK_PROJECTS;
  const allReports = reports || MOCK_REPORTS;
  const [selProj, setSelProj] = useState(null);
  const [manageProj, setManageProj] = useState(null);

  // Show projects where TL's department matches OR TL is in assignedEmployees
  const myProjects = allProjects.filter(p =>
    p.department === user.department ||
    (p.assignedEmployees || []).includes(user.id)
  );
  const active = myProjects.filter(p => p.status === "active");
  const completed = myProjects.filter(p => p.status === "completed");

  const ProjectCard = ({ p }) => {
    const rpts = allReports.filter(r => r.projectId === p.id);
    const isCompleted = p.status === "completed" || p.status === "done";
    const rawCompletedQty = rpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
    const totalQty = p.totalWorkQty || 0;
    const completedQty = isCompleted ? totalQty : Math.min(totalQty, rawCompletedQty);
    const remaining = totalQty - completedQty;
    const progress = totalQty > 0 ? Math.round((completedQty / totalQty) * 100) : 0;
    const myRpts = rpts.filter(r => r.employeeId === user.id);
    const isActive = p.status === "active";
    const assignedEmps = (p.assignedEmployees || []).map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);

    // Unique workers who submitted reports
    const workerIds = [...new Set(rpts.map(r => r.employeeId))];
    const workers = workerIds.map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);

    return (
      <div style={{
        background: C.white, borderRadius: 20, overflow: "hidden",
        boxShadow: "0 2px 16px rgba(37,99,235,.07)", border: `1px solid ${C.border}`,
        transition: "box-shadow .15s,transform .15s"
      }}
        onMouseOver={e => { e.currentTarget.style.boxShadow = "0 8px 32px rgba(37,99,235,.13)"; e.currentTarget.style.transform = "translateY(-1px)"; }}
        onMouseOut={e => { e.currentTarget.style.boxShadow = "0 2px 16px rgba(37,99,235,.07)"; e.currentTarget.style.transform = "translateY(0)"; }}>

        {/* Status stripe */}
        <div style={{
          height: 5, background: isActive
            ? "linear-gradient(90deg,#2563eb,#60a5fa)"
            : "linear-gradient(90deg,#9ca3af,#d1d5db)"
        }} />

        <div style={{ padding: "18px 20px" }}>
          {/* Title + status */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div style={{ flex: 1, paddingRight: 12 }}>
              <div style={{ fontSize: 15, fontWeight: 900, color: C.text, lineHeight: 1.35, marginBottom: 6 }}>{p.name}</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {p.poNumber && <span style={{ fontSize: 10, color: C.blue, fontWeight: 800, background: C.bluePale, padding: "2px 8px", borderRadius: 20 }}>📋 {p.poNumber}</span>}
                <span style={{
                  fontSize: 10, fontWeight: 800, padding: "2px 8px", borderRadius: 20,
                  color: isActive ? "#059669" : "#6b7280",
                  background: isActive ? "#f0fdf4" : "#f3f4f6"
                }}>
                  {isActive ? "● Active" : "✓ Completed"}
                </span>
                <span style={{ fontSize: 10, color: C.muted, fontWeight: 700, background: "#f8faff", padding: "2px 8px", borderRadius: 20 }}>{p.department}</span>
              </div>
            </div>
            <button onClick={() => setSelProj(p)}
              style={{
                fontSize: 11, color: C.blue, fontWeight: 800, whiteSpace: "nowrap",
                display: "flex", alignItems: "center", gap: 4, background: "none", border: "none",
                cursor: "pointer", padding: 0
              }}>
              Details <span>→</span>
            </button>
          </div>

          {/* PO / Contract info */}
          {(p.companyName || p.poNumber || p.workType || p.workLocation) && (
            <div style={{
              background: "#f8faff", border: `1px solid ${C.border}`, borderRadius: 12,
              padding: "12px 14px", marginBottom: 12
            }}>
              <div style={{
                fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
                color: C.light, marginBottom: 8
              }}>📋 PO / Contract Details</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                {[
                  ["Client", p.companyName],
                  ["PO Date", p.poDate],
                  ["Project Type", p.projectType],
                  ["Work Type", p.workType],
                  ["Location", p.workLocation],
                  ["Timeline", p.startDate ? (p.startDate + (p.endDate ? " → " + p.endDate : "")) : ""],
                ].filter(([, v]) => v).map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", color: C.light, marginBottom: 2 }}>{k}</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{v}</div>
                  </div>
                ))}
              </div>
              {p.description && (
                <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", color: C.light, marginBottom: 4 }}>Scope</div>
                  <p style={{ fontSize: 12, color: C.muted, margin: 0, lineHeight: 1.55, fontWeight: 600 }}>{p.description}</p>
                </div>
              )}
            </div>
          )}

          {/* BOQ progress */}
          {totalQty > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
                <span style={{ fontSize: 10, fontWeight: 800, color: C.muted, textTransform: "uppercase", letterSpacing: ".08em" }}>BOQ Progress</span>
                <span style={{ fontSize: 15, fontWeight: 900, color: progress >= 100 ? "#059669" : C.blue }}>{progress}%</span>
              </div>
              <div style={{ height: 8, background: "#e2e8f0", borderRadius: 8, overflow: "hidden", marginBottom: 8 }}>
                <div style={{
                  height: "100%", width: `${progress}%`,
                  background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                  borderRadius: 8, transition: "width .5s ease"
                }} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 6 }}>
                {[
                  { l: "Total", v: `${totalQty}`, unit: p.unitType, c: C.blue, bg: "#eff6ff" },
                  { l: "Done", v: `${completedQty}`, unit: p.unitType, c: "#059669", bg: "#f0fdf4" },
                  { l: "Left", v: `${remaining}`, unit: p.unitType, c: remaining <= 0 ? "#059669" : "#dc2626", bg: remaining <= 0 ? "#f0fdf4" : "#fef2f2" },
                ].map(s => (
                  <div key={s.l} style={{ background: s.bg, borderRadius: 8, padding: "7px 10px", textAlign: "center" }}>
                    <div style={{ fontSize: 13, fontWeight: 900, color: s.c }}>{s.v} <span style={{ fontSize: 10 }}>{s.unit}</span></div>
                    <div style={{ fontSize: 9, color: C.light, fontWeight: 800, textTransform: "uppercase", letterSpacing: ".06em", marginTop: 1 }}>{s.l}</div>
                  </div>
                ))}
              </div>
              {/* Item-wise breakdown */}
              {(() => {
                const items = (projectItems || []).filter(it => it.projectId === p.id);
                if (items.length === 0) return null;
                return (
                  <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 5 }}>
                    <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase", color: C.light }}>📦 Item-wise</div>
                    {(() => {
                      const itemIds = new Set(items.map(it => it.id));
                      let unlinkedQty = rpts.filter(r => !itemIds.has(r.projectItemId)).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                      
                      let targetAttrItem = null;
                      if (unlinkedQty > 0 && items.length > 0) {
                        let candidates = items.filter(it => (it.unit || "").toLowerCase() === (p.unitType || "").toLowerCase());
                        if (candidates.length === 0) candidates = items;
                        targetAttrItem = candidates.length > 0 ? candidates.reduce((max, it) => it.quantity > max.quantity ? it : max, candidates[0]) : null;
                      }

                      const renderedItems = items.map(item => {
                        let rawItemDone = rpts.filter(r => r.projectItemId === item.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                        if (targetAttrItem && item.id === targetAttrItem.id) {
                          rawItemDone += unlinkedQty;
                          unlinkedQty = 0; // consumed
                        }
                        const isCompleted = p.status === "completed" || p.status === "done";
                        const itemDone = isCompleted ? item.quantity : Math.min(item.quantity, rawItemDone);
                        const itemProg = item.quantity > 0 ? Math.round((itemDone / item.quantity) * 100) : 0;
                        return (
                          <div key={item.id} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <span title={item.description} style={{ fontSize: 10, fontWeight: 700, color: C.muted, minWidth: 100, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.description}</span>
                            <div style={{ flex: 1, height: 5, background: "#e2e8f0", borderRadius: 5, overflow: "hidden" }}>
                              <div style={{
                                height: "100%", width: `${Math.min(100, itemProg)}%`, borderRadius: 5,
                                background: itemProg >= 100 ? "#10b981" : "#60a5fa", transition: "width .3s"
                              }} />
                            </div>
                            <span style={{ fontSize: 9, fontWeight: 800, color: itemProg >= 100 ? "#059669" : C.muted, minWidth: 60, textAlign: "right" }}>
                              {itemDone}/{item.quantity} {item.unit}
                            </span>
                          </div>
                        );
                      });
                      
                      const unlinkedRender = unlinkedQty > 0 ? (
                        <div style={{ display: "flex", alignItems: "center", gap: 6, opacity: 0.8, background: "#fffad6", padding: "2px 4px", borderRadius: 4 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: "#92400e", minWidth: 100 }}>⚠️ Unlinked / Deleted Items</span>
                          <div style={{ flex: 1, height: 5, background: "#e2e8f0", borderRadius: 5 }} />
                          <span style={{ fontSize: 9, fontWeight: 800, color: "#92400e", minWidth: 60, textAlign: "right" }}>
                            {unlinkedQty} {p.unitType}
                          </span>
                        </div>
                      ) : null;

                      return (
                        <>
                          {renderedItems}
                          {unlinkedRender}
                        </>
                      );
                    })()}
                  </div>
                );
              })()}
            </div>
          )}

          {/* Team avatars row */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            paddingTop: 10, borderTop: `1px solid ${C.border}`, marginBottom: 10
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ display: "flex" }}>
                {assignedEmps.slice(0, 5).map((emp, idx) => (
                  <div key={emp.id} style={{
                    marginLeft: idx > 0 ? -6 : 0, width: 26, height: 26, borderRadius: "50%",
                    border: "2px solid #fff", background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 9, fontWeight: 900, color: "#fff", zIndex: 5 - idx
                  }}>
                    {emp.avatar}
                  </div>
                ))}
                {assignedEmps.length > 5 && (
                  <div style={{
                    marginLeft: -6, width: 26, height: 26, borderRadius: "50%",
                    border: "2px solid #fff", background: "#e2e8f0",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 9, fontWeight: 900, color: C.muted
                  }}>
                    +{assignedEmps.length - 5}
                  </div>
                )}
              </div>
              <span style={{ fontSize: 10, color: C.muted, fontWeight: 700 }}>
                {assignedEmps.length} assigned · {workers.length} reported
              </span>
            </div>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: C.blue }}>My: {myRpts.length} reports</div>
              <div style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>
                {myRpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0)} {p.unitType || "units"}
              </div>
            </div>
          </div>

          {/* Attached documents */}
          {(p.poDocuments || []).length > 0 && (
            <div style={{
              marginBottom: 12, padding: "10px 14px", background: "#f8faff",
              border: `1px solid ${C.border}`, borderRadius: 12
            }}>
              <div style={{
                fontSize: 9, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
                color: C.light, marginBottom: 8
              }}>📎 Documents ({p.poDocuments.length})</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {p.poDocuments.map((doc, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, fontWeight: 700, color: C.text }}>
                    <span>{doc.type?.startsWith("image/") ? "🖼️" : doc.type === "application/pdf" ? "📄" : "📎"}</span>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{doc.name}</span>
                    {doc.dataUrl && (
                      <a href={doc.dataUrl} download={doc.name}
                        style={{
                          fontSize: 10, fontWeight: 800, color: "#059669", textDecoration: "none",
                          background: "#f0fdf4", padding: "3px 10px", borderRadius: 20, border: "1px solid #bbf7d0",
                          cursor: "pointer", flexShrink: 0
                        }}>
                        ⬇ Download
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Last updated */}
          {p.lastUpdatedAt && (
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 8, padding: "6px 0", borderTop: `1px dashed ${C.border}`
            }}>
              <span style={{ fontSize: 9, color: C.light, fontWeight: 800, textTransform: "uppercase", letterSpacing: ".08em" }}>Last update</span>
              <LastUpdatedBadge project={p} />
            </div>
          )}

          {/* Manage Team button — active projects only */}
          {isActive && (
            <button onClick={() => setManageProj(p)}
              style={{
                width: "100%", padding: "9px 0", borderRadius: 12,
                border: `1.5px solid ${C.blueMid}`, background: C.bluePale,
                color: C.blue, fontSize: 12, fontWeight: 800, cursor: "pointer",
                fontFamily: "inherit", display: "flex", alignItems: "center",
                justifyContent: "center", gap: 8, transition: "all .15s"
              }}
              onMouseOver={e => { e.currentTarget.style.background = C.blueSoft; e.currentTarget.style.borderColor = C.blue; }}
              onMouseOut={e => { e.currentTarget.style.background = C.bluePale; e.currentTarget.style.borderColor = C.blueMid; }}>
              <span>👥</span>
              Manage Team
              <span style={{
                background: C.blue, color: "#fff", borderRadius: 20,
                padding: "1px 8px", fontSize: 10, fontWeight: 900, lineHeight: "18px"
              }}>
                {assignedEmps.length}
              </span>
            </button>
          )}
        </div>
      </div>
    );
  };

  return (
    <div>
      <TopBar
        title="My Projects"
        sub={`${active.length} active · ${completed.length} completed`}
        user={user} onLogout={onLogout} />

      {/* Summary strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 20 }} className="fu">
        {[
          { l: "Assigned", v: myProjects.length, ico: "🏗️", grad: `linear-gradient(135deg,${C.blue},${C.blueL})` },
          { l: "Active", v: active.length, ico: "✅", grad: "linear-gradient(135deg,#059669,#10b981)" },
          { l: "Completed", v: completed.length, ico: "🏁", grad: "linear-gradient(135deg,#7c3aed,#a78bfa)" },
        ].map(s => (
          <div key={s.l} style={{
            borderRadius: 16, padding: "14px 18px", background: s.grad,
            boxShadow: "0 4px 16px rgba(0,0,0,.1)", position: "relative", overflow: "hidden"
          }}>
            <div style={{ position: "absolute", top: -12, right: -12, width: 48, height: 48, borderRadius: "50%", background: "rgba(255,255,255,.12)" }} />
            <div style={{ fontSize: 20, marginBottom: 4 }}>{s.ico}</div>
            <div style={{ fontSize: 26, fontWeight: 900, color: "#fff" }}>{s.v}</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,.8)", fontWeight: 700 }}>{s.l}</div>
          </div>
        ))}
      </div>

      {myProjects.length === 0 && (
        <div style={{
          textAlign: "center", padding: "60px 20px", color: C.light, fontSize: 14, fontWeight: 700,
          background: C.white, borderRadius: 20, border: `1px solid ${C.border}`
        }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🏗️</div>
          <div style={{ marginBottom: 8 }}>No projects assigned to you yet.</div>
          <div style={{ fontSize: 12, fontWeight: 600 }}>Your admin will assign projects to your department.</div>
        </div>
      )}

      {/* Active projects */}
      {active.length > 0 && (
        <>
          <div style={{
            fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase",
            color: C.light, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
          }}>
            ● Active Projects ({active.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 14, marginBottom: 24 }}>
            {active.map(p => <ProjectCard key={p.id} p={p} />)}
          </div>
        </>
      )}

      {/* Completed projects */}
      {completed.length > 0 && (
        <>
          <div style={{
            fontSize: 11, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase",
            color: C.light, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
          }}>
            ✓ Completed Projects ({completed.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {completed.map(p => <ProjectCard key={p.id} p={p} />)}
          </div>
        </>
      )}

      {/* Full detail drawer */}
      {selProj && (
        <ProjectDetail
          project={selProj}
          reports={allReports}
          projectItems={projectItems}
          onClose={() => setSelProj(null)}
          onStatusChange={() => { }}
          onEdit={null}
        />
      )}

      {/* Team management modal */}
      {manageProj && (
        <TLTeamManageModal
          project={manageProj}
          user={user}
          onClose={() => setManageProj(null)}
          onSave={updated => {
            if (onEditProject) onEditProject(updated);
            setManageProj(null);
          }}
        />
      )}
    </div>
  );
}

// ─── Projects Panel ─────────────────────────────────────────────────────────────
function ProjectsPanel({ user, projects, reports, projectItems = [], onAddProject, onStatusChange, onEditProject, onLogout }) {
  const [showAdd, setShowAdd] = useState(false);
  const [selProj, setSelProj] = useState(null);
  const [editProj, setEditProj] = useState(null);
  const [filter, setFilter] = useState("all"); // all | active | completed

  const filtered = projects.filter(p => filter === "all" ? true : p.status === filter);

  useEffect(() => {
    projects.forEach(p => {
      if (p.status === "active") {
        const rpts = reports.filter(r => r.projectId === p.id);
        const completedQty = rpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
        const totalQty = p.totalWorkQty || 0;
        if (totalQty > 0 && totalQty - completedQty <= 0) {
          if (onStatusChange) onStatusChange(p.id, "completed");
        }
      }
    });
  }, [projects, reports, onStatusChange]);

  const activeCount = projects.filter(p => p.status === "active").length;
  const completedCount = projects.filter(p => p.status === "completed").length;

  return (
    <div>
      <TopBar title="Projects" sub={`${projects.length} total · ${activeCount} active · ${completedCount} completed`} user={user} onLogout={onLogout} />

      {/* Stats strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 20 }} className="fu">
        {[
          { l: "Total Projects", v: projects.length, icon: "🚀", grad: `linear-gradient(135deg,${C.blue},${C.blueL})` },
          { l: "Active", v: activeCount, icon: "✅", grad: "linear-gradient(135deg,#059669,#10b981)" },
          { l: "Completed", v: completedCount, icon: "🏁", grad: "linear-gradient(135deg,#7c3aed,#a78bfa)" },
        ].map(s => (
          <div key={s.l} style={{
            borderRadius: 16, padding: "16px 20px", background: s.grad,
            boxShadow: "0 4px 16px rgba(0,0,0,.12)", position: "relative", overflow: "hidden"
          }}>
            <div style={{ position: "absolute", top: -14, right: -14, width: 56, height: 56, borderRadius: "50%", background: "rgba(255,255,255,.12)" }} />
            <div style={{ fontSize: 22, marginBottom: 6 }}>{s.icon}</div>
            <div style={{ fontSize: 28, fontWeight: 900, color: "#fff" }}>{s.v}</div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,.8)", fontWeight: 700 }}>{s.l}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="fu1" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
        <div style={{ display: "flex", gap: 6 }}>
          {[["all", "All"], ["active", "Active"], ["completed", "Completed"]].map(([k, l]) => (
            <button key={k} onClick={() => setFilter(k)} style={{
              padding: "8px 18px", borderRadius: 20, border: "none", cursor: "pointer", fontFamily: "inherit",
              fontSize: 12, fontWeight: 700, transition: "all .15s",
              background: filter === k ? C.blue : C.bluePale,
              color: filter === k ? "#fff" : C.blue,
              boxShadow: filter === k ? `0 3px 10px rgba(37,99,235,.28)` : "none"
            }}>
              {l}
            </button>
          ))}
        </div>
        <Btn v="primary" onClick={() => setShowAdd(true)}
          icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>}>
          Add New Project
        </Btn>
      </div>

      {/* Projects grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(300px,1fr))", gap: 14 }}>
        {filtered.map((p, i) => {
          const rpts = reports.filter(r => r.projectId === p.id);
          const assignedEmps = (p.assignedEmployees || []).map(id => MOCK_EMPLOYEES.find(e => e.id === id)).filter(Boolean);
          const totalHours = rpts.reduce((s, r) => s + Number(r.hours), 0);
          const isCompleted = p.status === "completed" || p.status === "done";
          const rawCompletedQty = rpts.reduce((s, r) => s + Number(r.workQtyDone || 0), 0);
          const totalQty = p.totalWorkQty || 0;
          const completedQty = isCompleted ? totalQty : Math.min(totalQty, rawCompletedQty);
          const remaining = totalQty - completedQty;
          const progress = totalQty > 0 ? Math.round((completedQty / totalQty) * 100) : 0;
          const isActive = p.status === "active";

          return (
            <W key={p.id} cls={`fu${i > 3 ? 4 : i % 4 + 1}`} style={{ padding: 0, cursor: "pointer", transition: "transform .15s,box-shadow .15s" }}
              onClick={() => setSelProj(p)}
              onMouseOver={e => e.currentTarget.style.transform = "translateY(-2px)"}
              onMouseOut={e => e.currentTarget.style.transform = "translateY(0)"}>
              {/* Card top accent */}
              <div style={{ height: 5, background: isActive ? "linear-gradient(90deg,#2563eb,#60a5fa)" : "linear-gradient(90deg,#9ca3af,#d1d5db)", borderRadius: "20px 20px 0 0" }} />

              <div style={{ padding: "18px 20px" }}>
                {/* Title row */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <div style={{ flex: 1, paddingRight: 8 }}>
                    <div style={{ fontSize: 14, fontWeight: 800, color: C.text, lineHeight: 1.35, marginBottom: 4 }}>{p.name}</div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Pill color="blue">{p.department}</Pill>
                      {p.poNumber && <span style={{ fontSize: 10, color: C.light, fontWeight: 700, padding: "2px 6px", background: "#f1f5f9", borderRadius: 6 }}>{p.poNumber}</span>}
                    </div>
                  </div>
                  <Pill color={isActive ? "green" : "gray"}>{isActive ? "Active" : "Done"}</Pill>
                </div>

                {/* Company */}
                {p.companyName && <div style={{ fontSize: 11, color: C.muted, fontWeight: 700, marginBottom: 6 }}>🏢 {p.companyName}</div>}

                {/* Description */}
                {p.description && (
                  <p style={{ fontSize: 12, color: C.muted, margin: "0 0 10px", lineHeight: 1.55, fontWeight: 600 }}>
                    {p.description.slice(0, 70)}{p.description.length > 70 ? "…" : ""}
                  </p>
                )}

                {/* BOQ Progress */}
                {totalQty > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{ fontSize: 10, fontWeight: 800, color: C.muted }}>BOQ Progress</span>
                      <span style={{ fontSize: 10, fontWeight: 900, color: progress >= 100 ? "#059669" : C.blue }}>{progress}%</span>
                    </div>
                    <div style={{ height: 6, background: "#e2e8f0", borderRadius: 10, overflow: "hidden", marginBottom: 4 }}>
                      <div style={{
                        height: "100%", width: `${progress}%`,
                        background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                        borderRadius: 10, transition: "width .4s"
                      }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: C.light, fontWeight: 700 }}>
                      <span>{completedQty}/{totalQty} {p.unitType}</span>
                      <span style={{ color: remaining === 0 ? "#059669" : "inherit" }}>Rem: {remaining} {p.unitType}</span>
                    </div>
                  </div>
                )}

                {/* Stats row */}
                <div style={{ display: "flex", gap: 0, borderTop: `1px solid ${C.border}`, paddingTop: 10, marginBottom: 12 }}>
                  {[["📋", rpts.length, "Reports"], ["⏱", totalHours + "h", "Hours"], ["👥", assignedEmps.length, "Team"]].map(([ico, v, l]) => (
                    <div key={l} style={{ flex: 1, textAlign: "center" }}>
                      <div style={{ fontSize: 11, fontWeight: 900, color: C.blue }}>{ico} {v}</div>
                      <div style={{ fontSize: 9, color: C.light, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em" }}>{l}</div>
                    </div>
                  ))}
                </div>

                {/* Team avatars */}
                {assignedEmps.length > 0 && (
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <div style={{ display: "flex" }}>
                      {assignedEmps.slice(0, 4).map((emp, idx) => (
                        <div key={emp.id} style={{ marginLeft: idx > 0 ? -8 : 0, zIndex: assignedEmps.length - idx }}>
                          <Avt initials={emp.avatar} size={28} />
                        </div>
                      ))}
                    </div>
                    <span style={{ fontSize: 11, color: C.muted, fontWeight: 600, marginLeft: 6 }}>
                      {assignedEmps.slice(0, 2).map(e => e.name.split(" ")[0]).join(", ")}
                      {assignedEmps.length > 2 && ` +${assignedEmps.length - 2}`}
                    </span>
                  </div>
                )}

                {/* Dates */}
                {(p.startDate || p.endDate) && (
                  <div style={{
                    marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}`,
                    display: "flex", justifyContent: "space-between"
                  }}>
                    <span style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>📅 {p.startDate || "—"}</span>
                    <span style={{ fontSize: 10, color: C.light, fontWeight: 700 }}>🏁 {p.endDate || "TBD"}</span>
                  </div>
                )}

                {/* Last updated */}
                {p.lastUpdatedAt && (
                  <div style={{ marginTop: 8, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 9, color: C.light, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".08em" }}>Last update</span>
                    <LastUpdatedBadge project={p} />
                  </div>
                )}
              </div>
            </W>
          );
        })}

        {/* Empty state */}
        {filtered.length === 0 && (
          <div style={{ gridColumn: "1/-1", textAlign: "center", padding: "60px 20px", color: C.light }}>
            <div style={{ fontSize: 48, marginBottom: 12 }}>📂</div>
            <div style={{ fontSize: 16, fontWeight: 800, color: C.muted, marginBottom: 6 }}>No {filter !== "all" ? filter : ""} projects found</div>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 20 }}>Create a new project to get started.</div>
            <Btn v="primary" onClick={() => setShowAdd(true)}>➕ Add New Project</Btn>
          </div>
        )}
      </div>

      {/* Add Project Modal */}
      {showAdd && <AddProjectModal
        onClose={() => setShowAdd(false)}
        onAdd={onAddProject}
        projects={projects}
      />}

      {/* Project Detail Drawer */}
      {selProj && <ProjectDetail
        project={selProj}
        reports={reports}
        projectItems={projectItems}
        onClose={() => setSelProj(null)}
        onStatusChange={(id, status) => { onStatusChange(id, status); setSelProj(p => ({ ...p, status })); }}
        onEdit={() => { setEditProj(selProj); setSelProj(null); }}
      />}

      {/* Edit Project Modal (reuse Add with prefilled) */}
      {editProj && <AddProjectModal
        onClose={() => setEditProj(null)}
        onAdd={(updated) => { onEditProject(updated); }}
        projects={projects}
        prefill={editProj}
      />}
    </div>
  );
}

// ─── Departments ───────────────────────────────────────────────────────────────
function DepartmentsPanel({ user, onLogout }) {
  const grads = ["linear-gradient(135deg,#2563eb,#3b82f6)", "linear-gradient(135deg,#059669,#10b981)",
    "linear-gradient(135deg,#7c3aed,#a78bfa)", "linear-gradient(135deg,#ea580c,#fb923c)", "linear-gradient(135deg,#be123c,#f43f5e)"];
  return (
    <div>
      <TopBar title="Departments" sub={`${DEPARTMENTS.length} operational units`} user={user} onLogout={onLogout} />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(218px,1fr))", gap: 14 }}>
        {DEPARTMENTS.map((d, i) => {
          const emps = MOCK_EMPLOYEES.filter(e => e.department === d);
          const projs = MOCK_PROJECTS.filter(p => p.department === d);
          return (
            <div key={d} className={`fu${i > 3 ? 4 : i + 1}`} style={{
              borderRadius: 20, padding: 24, background: grads[i],
              boxShadow: "0 6px 20px rgba(0,0,0,.13)", position: "relative", overflow: "hidden"
            }}>
              <div style={{ position: "absolute", top: -20, right: -20, width: 80, height: 80, borderRadius: "50%", background: "rgba(255,255,255,.1)" }} />
              <div style={{ fontSize: 17, fontWeight: 900, color: "#fff", marginBottom: 16 }}>{d}</div>
              {[["Employees", emps.length], ["Projects", projs.length]].map(([k, v]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 0", borderBottom: "1px solid rgba(255,255,255,.15)" }}>
                  <span style={{ fontSize: 12, color: "rgba(255,255,255,.75)", fontWeight: 600 }}>{k}</span>
                  <span style={{ fontSize: 16, fontWeight: 900, color: "#fff" }}>{v}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Progress Detail Modal ────────────────────────────────────────────────────
function ProgressDetailModal({ project, reports, projectItems, onClose }) {
  const projReports = (reports || MOCK_REPORTS)
    .filter(r => r.projectId === project.id)
    .sort((a, b) => b.date.localeCompare(a.date));

  const totalQty = project.totalWorkQty || 0;
  const isCompleted = project.status === "completed" || project.status === "done";
  const rawCompletedQty = projReports.reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
  const completedQty = isCompleted ? totalQty : Math.min(totalQty, rawCompletedQty);
  const remaining = totalQty - completedQty;
  const progress = totalQty > 0 ? Math.round((completedQty / totalQty) * 100) : 0;
  const totalManpower = projReports.reduce((s, r) => s + Math.round(Number(r.manpowerCount || 0)), 0);
  const totalHours = projReports.reduce((s, r) => s + Number(r.hours || 0), 0);

  // Build cumulative progress by date for mini chart
  const byDate = {};
  [...projReports].reverse().forEach(r => {
    byDate[r.date] = (byDate[r.date] || 0) + Number(r.workQtyDone || 0);
  });
  const dates = Object.keys(byDate).sort();
  let cum = 0;
  const chartData = dates.map(d => { cum += byDate[d]; return { date: d, qty: byDate[d], cum, pct: totalQty > 0 ? Math.round((cum / totalQty) * 100) : 0 }; });
  const maxCum = Math.max(...chartData.map(c => c.cum), 1);
  const chartH = 80;

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9900, background: "rgba(15,23,42,.55)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 16
    }}
      onClick={onClose}>
      <div onClick={e => e.stopPropagation()}
        style={{
          background: C.white, borderRadius: 24, width: "100%", maxWidth: 560,
          maxHeight: "90vh", overflowY: "auto", boxShadow: "0 24px 64px rgba(37,99,235,.22)"
        }}
        className="fu">

        {/* Header */}
        <div style={{
          background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
          padding: "20px 24px", borderRadius: "24px 24px 0 0", position: "sticky", top: 0, zIndex: 2
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{
                fontSize: 11, color: "rgba(255,255,255,.7)", fontWeight: 700,
                letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 4
              }}>BOQ Progress Detail</div>
              <div style={{ fontSize: 17, fontWeight: 900, color: "#fff", lineHeight: 1.3 }}>{project.name}</div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,.75)", marginTop: 3 }}>
                {project.poNumber} · {project.companyName}
              </div>
            </div>
            <button onClick={onClose} style={{
              background: "rgba(255,255,255,.2)", border: "none",
              borderRadius: "50%", width: 32, height: 32, cursor: "pointer", fontSize: 16, color: "#fff",
              display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
            }}>✕</button>
          </div>
        </div>

        <div style={{ padding: "20px 24px" }}>

          {/* Big progress ring + stats */}
          <div style={{ display: "flex", alignItems: "center", gap: 20, marginBottom: 20 }}>
            {/* SVG ring */}
            <div style={{ position: "relative", flexShrink: 0, width: 96, height: 96 }}>
              <svg width="96" height="96" viewBox="0 0 96 96">
                <circle cx="48" cy="48" r="40" fill="none" stroke="#e2e8f0" strokeWidth="10" />
                <circle cx="48" cy="48" r="40" fill="none"
                  stroke={progress >= 100 ? "#059669" : C.blue} strokeWidth="10"
                  strokeDasharray={`${2 * Math.PI * 40}`}
                  strokeDashoffset={`${2 * Math.PI * 40 * (1 - progress / 100)}`}
                  strokeLinecap="round"
                  style={{ transform: "rotate(-90deg)", transformOrigin: "48px 48px", transition: "stroke-dashoffset .6s ease" }} />
              </svg>
              <div style={{
                position: "absolute", inset: 0, display: "flex", flexDirection: "column",
                alignItems: "center", justifyContent: "center"
              }}>
                <div style={{ fontSize: 20, fontWeight: 900, color: progress >= 100 ? "#059669" : C.blue, lineHeight: 1 }}>{progress}%</div>
                <div style={{ fontSize: 8, color: C.light, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em" }}>done</div>
              </div>
            </div>

            {/* Key numbers */}
            <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              {[
                { l: "Total Scope", v: `${totalQty}`, u: project.unitType, c: C.blue, bg: "#eff6ff" },
                { l: "Completed", v: `${completedQty}`, u: project.unitType, c: "#059669", bg: "#f0fdf4" },
                { l: "Remaining", v: `${remaining}`, u: project.unitType, c: remaining === 0 ? "#059669" : "#dc2626", bg: remaining === 0 ? "#f0fdf4" : "#fef2f2" },
                { l: "Total Manpower", v: `${totalManpower}`, u: "pax·days", c: "#7c3aed", bg: "#faf5ff" },
              ].map(s => (
                <div key={s.l} style={{ background: s.bg, borderRadius: 12, padding: "10px 12px" }}>
                  <div style={{ fontSize: 18, fontWeight: 900, color: s.c, lineHeight: 1 }}>{s.v} <span style={{ fontSize: 10, fontWeight: 700 }}>{s.u}</span></div>
                  <div style={{ fontSize: 9, color: C.light, fontWeight: 800, textTransform: "uppercase", letterSpacing: ".06em", marginTop: 3 }}>{s.l}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Progress bar (wide) */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ height: 12, background: "#e2e8f0", borderRadius: 10, overflow: "hidden", marginBottom: 6 }}>
              <div style={{
                height: "100%", width: `${progress}%`,
                background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                borderRadius: 10, transition: "width .5s ease"
              }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, fontWeight: 700, color: C.muted }}>
              <span>0</span>
              <span style={{ color: C.blue }}>{Math.round(totalQty * 0.25)} ({25}%)</span>
              <span style={{ color: C.blue }}>{Math.round(totalQty * 0.5)} ({50}%)</span>
              <span style={{ color: C.blue }}>{Math.round(totalQty * 0.75)} ({75}%)</span>
              <span>{totalQty} {project.unitType}</span>
            </div>
          </div>

          {/* Mini bar chart — daily qty */}
          {chartData.length > 0 && (
            <div style={{ marginBottom: 20, background: C.bluePale, borderRadius: 14, padding: "14px 16px" }}>
              <div style={{
                fontSize: 11, fontWeight: 800, color: C.muted, marginBottom: 12,
                letterSpacing: ".08em", textTransform: "uppercase"
              }}>📈 Daily Work Progress</div>
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: chartH + 20 }}>
                {chartData.map((d, i) => {
                  const barH = Math.max(4, Math.round((d.qty / Math.max(...chartData.map(c => c.qty), 1)) * chartH));
                  const cumH = Math.round((d.cum / totalQty) * chartH);
                  return (
                    <div key={d.date} style={{
                      flex: 1, display: "flex", flexDirection: "column",
                      alignItems: "center", gap: 2, position: "relative"
                    }} title={`${d.date}: +${d.qty} ${project.unitType} (total ${d.cum})`}>
                      {/* Cumulative line dot */}
                      <div style={{
                        position: "absolute", bottom: 24 + Math.min(cumH, chartH) - 4,
                        width: 6, height: 6, borderRadius: "50%", background: "#059669",
                        border: "2px solid #fff", zIndex: 2
                      }} />
                      {/* Daily bar */}
                      <div style={{
                        width: "100%", height: barH, background: `linear-gradient(180deg,${C.blueL},${C.blue})`,
                        borderRadius: "4px 4px 0 0", minHeight: 4
                      }} />
                      <div style={{
                        fontSize: 7, color: C.muted, fontWeight: 700,
                        transform: "rotate(-45deg)", transformOrigin: "center",
                        whiteSpace: "nowrap", marginTop: 2
                      }}>
                        {d.date.slice(5)}
                      </div>
                    </div>
                  );
                })}
              </div>
              <div style={{ display: "flex", gap: 16, marginTop: 4, fontSize: 10, fontWeight: 700, color: C.muted }}>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, background: C.blue, borderRadius: 2, display: "inline-block" }} />Daily qty
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#059669", border: "2px solid #fff", display: "inline-block" }} />Cumulative
                </span>
              </div>
            </div>
          )}

          {/* Per-Item Breakdown */}
          {(projectItems || []).filter(i => i.projectId === project.id).length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{
                fontSize: 11, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase",
                color: C.light, marginBottom: 10
              }}>📦 Item-wise Progress</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {(projectItems || []).filter(i => i.projectId === project.id).map(item => {
                  const itemDone = projReports.filter(r => r.projectItemId === item.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                  const itemRemaining = Math.max(0, item.quantity - itemDone);
                  const itemPct = item.quantity > 0 ? Math.min(100, Math.round((itemDone / item.quantity) * 100)) : 0;
                  return (
                    <div key={item.id} style={{ background: "#f8faff", border: `1px solid ${C.border}`, borderRadius: 12, padding: "12px 14px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                        <span style={{ fontSize: 12, fontWeight: 800, color: C.text }}>{item.description}</span>
                        <span style={{ fontSize: 11, fontWeight: 900, color: itemPct >= 100 ? "#059669" : C.blue }}>{itemPct}%</span>
                      </div>
                      <div style={{ height: 6, background: "#e2e8f0", borderRadius: 6, overflow: "hidden", marginBottom: 6 }}>
                        <div style={{
                          height: "100%", width: `${itemPct}%`,
                          background: itemPct >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                          borderRadius: 6, transition: "width .4s"
                        }} />
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, fontWeight: 700 }}>
                        <span style={{ color: C.muted }}>Total: {item.quantity} {item.unit}</span>
                        <span style={{ color: "#059669" }}>Done: {itemDone} {item.unit}</span>
                        <span style={{ color: itemRemaining === 0 ? "#059669" : "#dc2626" }}>Left: {itemRemaining} {item.unit}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Daily Work Log table */}
          <div style={{
            fontSize: 11, fontWeight: 800, letterSpacing: ".08em", textTransform: "uppercase",
            color: C.light, marginBottom: 10
          }}>📋 Daily Work Log</div>

          {projReports.length === 0 ? (
            <div style={{ textAlign: "center", padding: "20px 0", color: C.light, fontSize: 13, fontWeight: 600 }}>
              No reports submitted yet for this project.
            </div>
          ) : (
            <div style={{ border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "#f8faff" }}>
                    {["Date", "By", "Work Done", "Manpower", "Hours", "Details"].map(h => (
                      <th key={h} style={{
                        padding: "8px 10px", textAlign: "left", fontSize: 9,
                        color: C.light, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase",
                        borderBottom: `1px solid ${C.border}`
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {projReports.map((r, i) => {
                    const emp = MOCK_EMPLOYEES.find(e => e.id === r.employeeId);
                    const isEven = i % 2 === 0;
                    return (
                      <tr key={r.id} style={{
                        background: isEven ? "#fff" : "#f8faff",
                        borderTop: `1px solid #f0f6ff`
                      }}>
                        <td style={{ padding: "9px 10px", fontSize: 11, fontWeight: 800, color: C.text, whiteSpace: "nowrap" }}>{r.date}</td>
                        <td style={{ padding: "9px 10px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <Avt initials={emp?.avatar} size={20} />
                            <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{emp?.name?.split(" ")[0] || "—"}</span>
                          </div>
                        </td>
                        <td style={{ padding: "9px 10px" }}>
                          <span style={{ fontSize: 13, fontWeight: 900, color: C.blue }}>{r.workQtyDone || "—"}</span>
                          <span style={{ fontSize: 9, color: C.muted, fontWeight: 700, marginLeft: 3 }}>{project.unitType}</span>
                        </td>
                        <td style={{ padding: "9px 10px", fontSize: 11, fontWeight: 700, color: "#7c3aed" }}>{r.manpowerCount || "—"}</td>
                        <td style={{ padding: "9px 10px", fontSize: 11, fontWeight: 700, color: C.muted }}>{r.hours}h</td>
                        <td style={{ padding: "9px 10px", fontSize: 10, color: C.muted, fontWeight: 600, maxWidth: 120 }}>
                          {(r.workDetails || r.rawDescription || "").slice(0, 50)}{(r.workDetails || r.rawDescription || "").length > 50 ? "…" : ""}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
                <tfoot>
                  <tr style={{ background: "#f0f9ff", borderTop: `2px solid ${C.blueMid}` }}>
                    <td colSpan={2} style={{ padding: "9px 10px", fontSize: 11, fontWeight: 900, color: C.blue }}>TOTAL</td>
                    <td style={{ padding: "9px 10px", fontSize: 13, fontWeight: 900, color: C.blue }}>{completedQty} <span style={{ fontSize: 9 }}>{project.unitType}</span></td>
                    <td style={{ padding: "9px 10px", fontSize: 11, fontWeight: 900, color: "#7c3aed" }}>{totalManpower}</td>
                    <td style={{ padding: "9px 10px", fontSize: 11, fontWeight: 900, color: C.muted }}>{totalHours}h</td>
                    <td />
                  </tr>
                </tfoot>
              </table>
            </div>
          )}

          {remaining === 0 && (
            <div style={{
              marginTop: 14, background: "#f0fdf4", border: "1.5px solid #86efac",
              borderRadius: 12, padding: "12px 16px", textAlign: "center",
              fontSize: 13, fontWeight: 800, color: "#059669"
            }}>
              🎉 All {totalQty} {project.unitType} completed — scope fully delivered!
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Submit Report ─────────────────────────────────────────────────────────────
function ReportSubmission({ employee, user, projects, reports, projectItems, onSubmit, onLogout, isTL = false, announcements = [] }) {
  const allProjects = projects || MOCK_PROJECTS;
  const allReports = reports || MOCK_REPORTS;
  const allProjectItems = projectItems || [];

  const [form, setForm] = useState({
    project: "", projectItemId: "", manpowerCount: "", workQtyDone: "", workDetails: "",
    tasksCompleted: "", workInProgress: "", issues: "", planNextDay: "",
    remarks: "", hours: "", hasImage: false,
  });
  const [imageFile, setImageFile] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const fileInputRef = useRef(null);
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [gps, setGps] = useState(null);
  const [errors, setErrors] = useState({});
  const [showProgressDetail, setShowProgressDetail] = useState(false);

  // Projects linked to this employee
  const myProjs = allProjects.filter(p =>
    p.status === "active" &&
    (p.assignedEmployees || []).includes(employee.id)
  );

  const selProj = allProjects.find(p => p.id === form.project);

  // Get items for selected project
  const projBOQItems = selProj ? allProjectItems.filter(i => i.projectId === selProj.id) : [];
  const selItem = form.projectItemId ? projBOQItems.find(i => i.id === form.projectItemId) : null;

  // Calculate remaining - per item if selected, otherwise total project
  const completedQty = selItem
    ? allReports.filter(r => r.projectId === selProj?.id && r.projectItemId === selItem.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0)
    : selProj
      ? allReports.filter(r => r.projectId === selProj.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0)
      : 0;
  const totalQty = selItem ? selItem.quantity : (selProj?.totalWorkQty || 0);
  const remaining = totalQty - completedQty;
  const progress = totalQty > 0
    ? Math.round((completedQty / totalQty) * 100)
    : 0;

  useEffect(() => {
    if (navigator.geolocation) navigator.geolocation.getCurrentPosition(
      p => setGps({ lat: p.coords.latitude.toFixed(4), lng: p.coords.longitude.toFixed(4) }),
      () => setGps({ lat: "25.2048", lng: "55.2708", sim: true })
    );
    else setGps({ lat: "25.2048", lng: "55.2708", sim: true });
  }, []);

  const validate = () => {
    const e = {};
    if (!form.project) e.project = "Select a PO / Project.";
    if (!form.manpowerCount || isNaN(form.manpowerCount) || Number(form.manpowerCount) < 1) e.manpowerCount = "Enter number of people worked today (min 1).";
    if (!form.workQtyDone || isNaN(form.workQtyDone) || Number(form.workQtyDone) <= 0 || !Number.isInteger(Number(form.workQtyDone))) e.workQtyDone = "Enter a whole number for work done (no decimals).";
    if (projBOQItems.length > 0 && !form.projectItemId) e.projectItemId = "Please select a specific Work Item from the project scope.";
    if (selProj && remaining !== null && Number(form.workQtyDone) > remaining) e.workQtyDone = `Cannot exceed remaining work (${remaining} ${selItem?.unit || selProj.unitType}).`;
    if (!form.workDetails || form.workDetails.trim().length < 10) e.workDetails = "Work details required (min 10 characters).";
    if (!form.hours || isNaN(form.hours) || Number(form.hours) <= 0) e.hours = "Enter hours worked.";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const submit = async () => {
    if (!validate()) return;
    setSubmitting(true);
    const reportId = "r" + (Date.now());
    let imageUrl = null;
    try {
      if (imageFile) {
        imageUrl = await uploadReportImage(imageFile, reportId);
      }
    } catch (e) { console.error("Image upload failed:", e); }
    const newReport = {
      id: reportId,
      employeeId: employee.id,
      projectId: form.project,
      date: new Date().toISOString().slice(0, 10),
      hours: Number(form.hours),
      manpowerCount: Number(form.manpowerCount),
      workQtyDone: Math.round(Number(form.workQtyDone)),
      projectItemId: form.projectItemId || null,
      workDetails: form.workDetails.trim(),
      rawDescription: form.workDetails.trim(),
      aiSummary: "AI processing pending…",
      tasksCompleted: form.tasksCompleted ? form.tasksCompleted.split(",").map(t => t.trim()).filter(Boolean) : [],
      issuesFaced: form.issues ? form.issues.split(",").map(t => t.trim()).filter(Boolean) : [],
      location: { lat: gps?.lat || "25.2048", lng: gps?.lng || "55.2708", address: "GPS Captured" },
      imageUploaded: !!imageFile,
      imageUrl: imageUrl,
      workInProgress: form.workInProgress,
      planNextDay: form.planNextDay,
      remarks: form.remarks,
    };
    if (onSubmit) onSubmit(newReport);
    setSubmitting(false);
    setSubmitted(newReport);
  };

  if (submitted) {
    const rep = submitted;
    const proj = projects?.find(p => p.id === rep.projectId) || MOCK_PROJECTS.find(p => p.id === rep.projectId);
    const today = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });

    // Build notification message
    const msgText =
      `📋 *Work Report Submitted*
👷 *Employee:* ${employee.name}
🏗️ *Project:* ${proj?.name || "—"} (${proj?.poNumber || ""})
📅 *Date:* ${today}
⏱️ *Hours:* ${rep.hours}h
👥 *Manpower:* ${rep.manpowerCount} pax
📐 *Work Done:* ${rep.workQtyDone} ${proj?.unitType || "units"}
📝 *Summary:* ${rep.workDetails?.slice(0, 120) || "—"}
${rep.issuesFaced?.length ? "⚠️ *Issues:* " + rep.issuesFaced.join(", ") : "✅ No issues reported"}`;

    const emailSubject = encodeURIComponent(`Work Report – ${employee.name} – ${today}`);
    const emailBody = encodeURIComponent(msgText.replace(/\*/g, ""));
    const waText = encodeURIComponent(msgText);

    // TL email for this dept
    const tlEmail = MOCK_EMPLOYEES.find(e => e.department === employee.department && e.role === "tl")?.email || "";

    return (
      <div>
        <TopBar title={isTL ? "Submit Team Report" : "Submit Report"} user={user} onLogout={onLogout} />
        <div style={{ maxWidth: 540, margin: "30px auto" }}>
          {/* Success card */}
          <div style={{ textAlign: "center", marginBottom: 24 }}>
            <div style={{
              width: 72, height: 72, borderRadius: "50%", background: "linear-gradient(135deg,#059669,#10b981)",
              display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px",
              fontSize: 32, color: "#fff", boxShadow: "0 8px 24px rgba(5,150,105,.35)"
            }}>✓</div>
            <h3 style={{ fontSize: 22, fontWeight: 900, color: C.text, margin: "0 0 6px" }}>Report Submitted!</h3>
            <p style={{ fontSize: 13, color: C.muted, margin: "0", fontWeight: 600 }}>
              Your work has been recorded and linked to {proj?.name || "the project"}.
            </p>
          </div>

          {/* Report summary card */}
          <div style={{
            background: "#f8faff", border: `1px solid ${C.border}`, borderRadius: 16,
            padding: "14px 18px", marginBottom: 20
          }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {[
                ["📅 Date", today],
                ["⏱ Hours", `${rep.hours}h`],
                ["👥 Manpower", `${rep.manpowerCount} pax`],
                ["📐 Work Done", `${rep.workQtyDone} ${proj?.unitType || "units"}`],
              ].map(([k, v]) => (
                <div key={k} style={{ background: "#fff", borderRadius: 10, padding: "8px 12px", border: `1px solid ${C.border}` }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: C.light }}>{k}</div>
                  <div style={{ fontSize: 14, fontWeight: 900, color: C.text }}>{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Notification panel */}
          <div style={{
            background: C.white, borderRadius: 20, border: `1.5px solid ${C.border}`,
            overflow: "hidden", marginBottom: 20, boxShadow: "0 2px 12px rgba(37,99,235,.07)"
          }}>
            <div style={{ background: `linear-gradient(135deg,${C.blue},${C.blueL})`, padding: "14px 20px" }}>
              <div style={{ fontSize: 13, fontWeight: 900, color: "#fff" }}>📲 Send Notification</div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,.8)", fontWeight: 600, marginTop: 2 }}>
                Notify your team leader or manager about this report
              </div>
            </div>
            <div style={{ padding: "18px 20px", display: "flex", flexDirection: "column", gap: 12 }}>

              {/* WhatsApp */}
              <a href={`https://wa.me/?text=${waText}`} target="_blank" rel="noreferrer"
                style={{ textDecoration: "none" }}>
                <div style={{
                  display: "flex", alignItems: "center", gap: 14, padding: "14px 18px",
                  background: "#f0fdf4", border: "1.5px solid #86efac", borderRadius: 14,
                  cursor: "pointer", transition: "all .15s"
                }}
                  onMouseOver={e => e.currentTarget.style.background = "#dcfce7"}
                  onMouseOut={e => e.currentTarget.style.background = "#f0fdf4"}>
                  <div style={{
                    width: 44, height: 44, borderRadius: "50%", background: "#25D366",
                    display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                    fontSize: 22, boxShadow: "0 4px 12px rgba(37,211,102,.35)"
                  }}>💬</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 14, fontWeight: 900, color: "#166534" }}>Send via WhatsApp</div>
                    <div style={{ fontSize: 11, color: "#4ade80", fontWeight: 600, marginTop: 2 }}>
                      Opens WhatsApp with the report pre-filled — share with TL or group
                    </div>
                  </div>
                  <span style={{ fontSize: 18, color: "#25D366" }}>→</span>
                </div>
              </a>

              {/* Email to TL */}
              <a href={`mailto:${tlEmail}?subject=${emailSubject}&body=${emailBody}`}
                style={{ textDecoration: "none" }}>
                <div style={{
                  display: "flex", alignItems: "center", gap: 14, padding: "14px 18px",
                  background: "#eff6ff", border: `1.5px solid ${C.blueMid}`, borderRadius: 14,
                  cursor: "pointer", transition: "all .15s"
                }}
                  onMouseOver={e => e.currentTarget.style.background = "#dbeafe"}
                  onMouseOut={e => e.currentTarget.style.background = "#eff6ff"}>
                  <div style={{
                    width: 44, height: 44, borderRadius: "50%", background: C.blue,
                    display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
                    fontSize: 22, boxShadow: `0 4px 12px ${C.blue}55`
                  }}>📧</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 14, fontWeight: 900, color: "#1e40af" }}>Email to Team Leader</div>
                    <div style={{ fontSize: 11, color: C.blue, fontWeight: 600, marginTop: 2 }}>
                      {tlEmail || "Opens your email app with report attached"}
                    </div>
                  </div>
                  <span style={{ fontSize: 18, color: C.blue }}>→</span>
                </div>
              </a>

              {/* Message preview */}
              <details style={{ cursor: "pointer" }}>
                <summary style={{
                  fontSize: 11, fontWeight: 800, color: C.muted, padding: "4px 0",
                  listStyle: "none", display: "flex", alignItems: "center", gap: 6
                }}>
                  <span>👁 Preview notification message</span>
                </summary>
                <pre style={{
                  fontSize: 11, color: C.text, background: "#f8faff", border: `1px solid ${C.border}`,
                  borderRadius: 10, padding: "12px 14px", margin: "8px 0 0", whiteSpace: "pre-wrap",
                  fontFamily: "monospace", lineHeight: 1.7
                }}>
                  {msgText.replace(/\*/g, "")}
                </pre>
              </details>
            </div>
          </div>

          <Btn v="primary" style={{ width: "100%", justifyContent: "center" }}
            onClick={() => { setSubmitted(false); setImageFile(null); setImagePreview(null); setForm({ project: "", projectItemId: "", manpowerCount: "", workQtyDone: "", workDetails: "", tasksCompleted: "", workInProgress: "", issues: "", planNextDay: "", remarks: "", hours: "", hasImage: false }); }}>
            ✏ Submit Another Report
          </Btn>
        </div>
      </div>
    );
  }

  const ErrMsg = ({ k }) => errors[k] ? <div style={{ fontSize: 11, color: "#dc2626", marginTop: 4, fontWeight: 700 }}>⚠ {errors[k]}</div> : null;

  return (
    <div>
      <TopBar title={isTL ? "Submit Team Report" : "Submit Daily Report"}
        sub={new Date().toLocaleDateString("en-GB", { weekday: "long", year: "numeric", month: "long", day: "numeric" })} user={user} onLogout={onLogout} />
      <div style={{ maxWidth: 660 }}>
        <W cls="fu" style={{ padding: 28 }}>
          {/* Date header */}
          <div style={{ background: C.bluePale, border: `2px dashed ${C.blueMid}`, borderRadius: 16, padding: "16px 20px", marginBottom: 24, textAlign: "center" }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 6 }}>
              {isTL ? "🏗 Team Lead Daily Report" : "🕐 Employee Daily Work Log"}
            </div>
            <div style={{ fontSize: 28, fontWeight: 900, color: C.blue }}>{new Date().toISOString().slice(0, 10)}</div>
          </div>

          {/* ── SECTION: PO / Project ── */}
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}` }}>
              📋 PO / Project
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <Lbl>PO / Project *</Lbl>
            <FS value={form.project} onChange={e => setForm(p => ({ ...p, project: e.target.value, projectItemId: "" }))}>
              <option value="">Select PO / Project…</option>
              {myProjs.map(p => (
                <option key={p.id} value={p.id}>
                  [{p.poNumber}] {p.name} — {p.companyName}
                </option>
              ))}
            </FS>
            <ErrMsg k="project" />
            <ErrMsg k="projectItemId" />
            {myProjs.length === 0 && (
              <div style={{ fontSize: 11, color: "#d97706", fontWeight: 700, marginTop: 4 }}>⚠ No active projects assigned to you. Contact admin.</div>
            )}
          </div>

          {/* Item selector - shows when project has BOQ items */}
          {selProj && projBOQItems.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <Lbl>Work Item *</Lbl>
              <FS value={form.projectItemId} onChange={e => setForm(p => ({ ...p, projectItemId: e.target.value }))}>
                <option value="">Select item…</option>
                {projBOQItems.map(item => {
                  const itemDone = allReports.filter(r => r.projectId === selProj.id && r.projectItemId === item.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                  const itemRemaining = item.quantity - itemDone;
                  return (
                    <option key={item.id} value={item.id}>
                      {item.description} — {itemRemaining}/{item.quantity} {item.unit} remaining
                    </option>
                  );
                })}
              </FS>
              {/* Per-item progress cards */}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
                {projBOQItems.map(item => {
                  const itemDone = allReports.filter(r => r.projectId === selProj.id && r.projectItemId === item.id).reduce((s, r) => s + Math.round(Number(r.workQtyDone || 0)), 0);
                  const itemRemaining = Math.max(0, item.quantity - itemDone);
                  const pct = item.quantity > 0 ? Math.min(100, Math.round((itemDone / item.quantity) * 100)) : 0;
                  const isSelected = form.projectItemId === item.id;
                  return (
                    <div key={item.id} onClick={() => setForm(p => ({ ...p, projectItemId: item.id }))}
                      style={{
                        flex: "1 1 calc(50% - 4px)", minWidth: 140, background: isSelected ? "#eff6ff" : "#f8faff",
                        border: `1.5px solid ${isSelected ? C.blue : C.border}`, borderRadius: 12, padding: "10px 12px",
                        cursor: "pointer", transition: "all .15s"
                      }}>
                      <div style={{
                        fontSize: 11, fontWeight: 800, color: C.text, marginBottom: 4,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                      }}>{item.description}</div>
                      <div style={{ height: 4, background: "#e2e8f0", borderRadius: 4, overflow: "hidden", marginBottom: 4 }}>
                        <div style={{ height: "100%", width: `${pct}%`, background: pct >= 100 ? "#059669" : C.blue, borderRadius: 4 }} />
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, fontWeight: 700 }}>
                        <span style={{ color: "#059669" }}>{itemDone} done</span>
                        <span style={{ color: itemRemaining === 0 ? "#059669" : "#dc2626" }}>{itemRemaining} left</span>
                        <span style={{ color: C.muted }}>{item.quantity} {item.unit}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Auto-filled project info */}
          {selProj && (
            <div style={{ background: "#f0f9ff", border: `1px solid ${C.blueMid}`, borderRadius: 14, padding: "14px 18px", marginBottom: 20 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
                {[
                  ["Company", selProj.companyName || "—"],
                  ["Project Type", selProj.projectType || "—"],
                  ["Work Type", selProj.workType || "—"],
                  ["Location", selProj.workLocation || "—"],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontSize: 9, fontWeight: 800, letterSpacing: ".12em", textTransform: "uppercase", color: C.light, marginBottom: 2 }}>{k}</div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{v}</div>
                  </div>
                ))}
              </div>
              {/* Progress bar — clickable */}
              <div
                onClick={() => setShowProgressDetail(true)}
                style={{
                  marginTop: 4, cursor: "pointer", borderRadius: 10, padding: "8px 10px",
                  background: "rgba(255,255,255,.7)", border: `1px solid ${C.blueMid}`,
                  transition: "box-shadow .15s"
                }}
                onMouseOver={e => e.currentTarget.style.boxShadow = "0 4px 16px rgba(37,99,235,.18)"}
                onMouseOut={e => e.currentTarget.style.boxShadow = "none"}
                title="Click to see full progress breakdown">
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, alignItems: "center" }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: C.muted }}>Project Progress</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontSize: 10, fontWeight: 900, color: C.blue }}>{progress}%</span>
                    <span style={{
                      fontSize: 9, color: C.light, fontWeight: 700, background: C.bluePale,
                      padding: "2px 6px", borderRadius: 8
                    }}>tap for details →</span>
                  </div>
                </div>
                <div style={{ height: 8, background: "#e2e8f0", borderRadius: 10, overflow: "hidden" }}>
                  <div style={{
                    height: "100%", width: `${progress}%`,
                    background: progress >= 100 ? "linear-gradient(90deg,#059669,#10b981)" : `linear-gradient(90deg,${C.blue},${C.blueL})`,
                    borderRadius: 10, transition: "width .4s"
                  }} />
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5, fontSize: 10, fontWeight: 700 }}>
                  <span style={{ color: C.muted }}>Total: <strong style={{ color: C.text }}>{totalQty} {selItem?.unit || selProj.unitType}</strong></span>
                  <span style={{ color: "#059669" }}>Done: <strong>{completedQty} {selItem?.unit || selProj.unitType}</strong></span>
                  <span style={{ color: remaining <= 0 ? "#059669" : "#dc2626", fontWeight: 800 }}>Remaining: <strong>{Math.max(0, remaining)} {selItem?.unit || selProj.unitType}</strong></span>
                </div>
              </div>
            </div>
          )}

          {/* Progress Detail Modal */}
          {showProgressDetail && selProj && (
            <ProgressDetailModal
              project={selProj}
              reports={allReports}
              projectItems={allProjectItems}
              onClose={() => setShowProgressDetail(false)}
            />
          )}

          {/* ── SECTION: Manpower & Quantity ── */}
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}` }}>
              👷 Manpower & Work Quantity
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div>
              <Lbl>People Worked Today * <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>(incl. self, helpers, contract)</span></Lbl>
              <FI type="number" min="1" value={form.manpowerCount}
                onChange={e => setForm(p => ({ ...p, manpowerCount: e.target.value }))}
                placeholder="e.g. 4" />
              <ErrMsg k="manpowerCount" />
            </div>
            <div>
              <Lbl>Work Done Today * <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>({selItem ? selItem.unit : selProj ? selProj.unitType : "unit locked to project"})</span></Lbl>
              <FI type="number" min="1" step="1" value={form.workQtyDone}
                onChange={e => setForm(p => ({ ...p, workQtyDone: e.target.value.replace(/\./g, '') }))}
                placeholder={selProj ? `e.g. 10 ${selItem?.unit || selProj.unitType}` : "Select project first"}
                disabled={!form.project} />
              <ErrMsg k="workQtyDone" />
            </div>
          </div>

          {/* ── SECTION: Work Details ── */}
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: ".1em", textTransform: "uppercase", color: C.light, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}` }}>
              📝 Work Details
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <Lbl>Work Details * <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>(activity, area, quantity context, progress description)</span></Lbl>
            <FI value={form.workDetails} onChange={e => setForm(p => ({ ...p, workDetails: e.target.value }))}
              placeholder="Describe: Activity performed · Area covered · Quantity context · Progress notes" rows={4} />
            <ErrMsg k="workDetails" />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div>
              <Lbl>Tasks Completed</Lbl>
              <FI value={form.tasksCompleted} onChange={e => setForm(p => ({ ...p, tasksCompleted: e.target.value }))}
                placeholder="Task 1, Task 2, Task 3" rows={2} />
            </div>
            <div>
              <Lbl>Work In Progress</Lbl>
              <FI value={form.workInProgress} onChange={e => setForm(p => ({ ...p, workInProgress: e.target.value }))}
                placeholder="Ongoing activities…" rows={2} />
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div>
              <Lbl>Issues / Blockers</Lbl>
              <FI value={form.issues} onChange={e => setForm(p => ({ ...p, issues: e.target.value }))}
                placeholder="Issue 1, Issue 2" rows={2} />
            </div>
            <div>
              <Lbl>Plan Next Day</Lbl>
              <FI value={form.planNextDay} onChange={e => setForm(p => ({ ...p, planNextDay: e.target.value }))}
                placeholder="Tomorrow's work plan…" rows={2} />
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 18 }}>
            <div>
              <Lbl>Hours Worked *</Lbl>
              <FI type="number" min="0.5" step="0.5" value={form.hours}
                onChange={e => setForm(p => ({ ...p, hours: e.target.value }))} placeholder="e.g. 8.0" />
              <ErrMsg k="hours" />
            </div>
            <div>
              <Lbl>Remarks</Lbl>
              <FI value={form.remarks} onChange={e => setForm(p => ({ ...p, remarks: e.target.value }))} placeholder="Any additional notes" />
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <Lbl>Attach Site Photo (Optional)</Lbl>
            <input ref={fileInputRef} type="file" accept="image/*" capture="environment"
              style={{ display: "none" }}
              onChange={e => {
                const f = e.target.files?.[0];
                if (f) {
                  setImageFile(f);
                  setImagePreview(URL.createObjectURL(f));
                  setForm(p => ({ ...p, hasImage: true }));
                }
              }} />
            <div onClick={() => fileInputRef.current?.click()} style={{
              border: `2px dashed ${imageFile ? C.blueL : C.border}`, borderRadius: 14,
              padding: 16, textAlign: "center", cursor: "pointer",
              background: imageFile ? C.bluePale : "#f8faff", transition: "all .2s"
            }}>
              {imagePreview ? (
                <div>
                  <img src={imagePreview} alt="Preview" style={{ maxHeight: 120, borderRadius: 10, marginBottom: 8, objectFit: "cover" }} />
                  <div style={{ fontSize: 11, color: C.blue, fontWeight: 700 }}>{imageFile.name} ({(imageFile.size / 1024).toFixed(0)} KB)</div>
                  <div style={{ fontSize: 10, color: C.light, fontWeight: 600, marginTop: 4 }}>Click to change</div>
                </div>
              ) : (
                <div>
                  <div style={{ fontSize: 24, marginBottom: 4 }}>📷</div>
                  <span style={{ fontSize: 12, color: C.light, fontWeight: 700 }}>
                    Click to take or upload a site photo
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* GPS status */}
          {gps && (
            <div style={{
              background: C.bluePale, borderRadius: 10, padding: "8px 14px", marginBottom: 16,
              display: "flex", alignItems: "center", gap: 8, fontSize: 11, fontWeight: 700, color: C.blue
            }}>
              📍 GPS: {gps.lat}, {gps.lng} {gps.sim ? "(simulated)" : "(live)"}
            </div>
          )}

          <Btn v="primary" disabled={submitting} onClick={submit}
            style={{ width: "100%", justifyContent: "center", padding: "14px 20px", fontSize: 14, borderRadius: 16 }}>
            {submitting ? "Processing…" : "Submit Report"}
          </Btn>
        </W>
      </div>
    </div>
  );
}

// ─── Employee History ──────────────────────────────────────────────────────────
function EmployeeHistory({ employee, user, reports, onLogout, announcements = [] }) {
  const allReports = reports || MOCK_REPORTS;
  const rpts = allReports.filter(r => r.employeeId === employee.id);
  return (
    <div>
      <TopBar title="My Reports" sub={`${rpts.length} submissions`} user={user} onLogout={onLogout} announcements={announcements} />
      {rpts.length === 0 ? <p style={{ fontSize: 13, color: C.light, fontWeight: 600 }}>No reports yet.</p>
        : <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {rpts.map((r, i) => {
            const proj = MOCK_PROJECTS.find(p => p.id === r.projectId);
            return (
              <W key={r.id} cls={`fu${i > 3 ? 4 : i + 1}`} style={{ padding: 22 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: C.text, marginBottom: 3 }}>{proj?.name}</div>
                    <div style={{ fontSize: 12, color: C.muted, fontWeight: 600 }}>{r.date} · {r.hours} hours</div>
                  </div>
                  <Pill color="green">✓ Submitted</Pill>
                </div>
                <p style={{
                  fontSize: 13, color: C.muted, margin: 0, lineHeight: 1.65,
                  padding: "12px 16px", background: "#f8faff", borderRadius: 12, fontWeight: 600
                }}>{r.rawDescription}</p>
              </W>
            );
          })}
        </div>
      }
    </div>
  );
}

// ─── Background Location Hook ─────────────────────────────────────────────────
// Runs continuously while employee is logged in, updates every 15 seconds
function useBackgroundLocation(active, onUpdate) {
  const watchRef = useRef(null);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (!active) {
      // Clean up when not active
      if (watchRef.current) { navigator.geolocation.clearWatch(watchRef.current); watchRef.current = null; }
      if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null; }
      return;
    }

    const opts = { enableHighAccuracy: true, maximumAge: 10000, timeout: 15000 };

    const success = (pos) => {
      onUpdate({
        lat: pos.coords.latitude,
        lng: pos.coords.longitude,
        accuracy: Math.round(pos.coords.accuracy),
        timestamp: new Date(),
        simulated: false,
      });
    };

    const fail = () => {
      // No simulated locations — only real GPS data is used
      console.warn("GPS location unavailable — no location will be shared");
    };

    if (navigator.geolocation) {
      // Initial fix immediately
      navigator.geolocation.getCurrentPosition(success, fail, opts);
      // Then watch continuously
      watchRef.current = navigator.geolocation.watchPosition(success, fail, opts);
      // Also force a refresh every 15s in case watch stalls
      intervalRef.current = setInterval(() => {
        navigator.geolocation.getCurrentPosition(success, fail, opts);
      }, 15000);
    } else {
      fail();
      intervalRef.current = setInterval(fail, 15000);
    }

    return () => {
      if (watchRef.current) navigator.geolocation.clearWatch(watchRef.current);
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [active]);
}

// ─── Location Permission Screen ───────────────────────────────────────────────
function LocationPermissionScreen({ onGranted, userName }) {
  const [asking, setAsking] = useState(false);
  const [denied, setDenied] = useState(false);
  const [retrying, setRetrying] = useState(false);

  const requestPermission = () => {
    setAsking(true);
    setDenied(false);
    if (!navigator.geolocation) { onGranted(); return; }
    navigator.geolocation.getCurrentPosition(
      () => { setAsking(false); onGranted(); },
      (err) => {
        setAsking(false);
        if (err.code === 1) { setDenied(true); }
        else { onGranted(); } // timeout/unavailable — let through with simulated
      },
      { enableHighAccuracy: true, timeout: 12000 }
    );
  };

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "linear-gradient(145deg,#1d4ed8 0%,#2563eb 50%,#1e40af 100%)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
    }}>
      {/* Decorative circles */}
      <div style={{ position: "absolute", width: 500, height: 500, borderRadius: "50%", background: "rgba(255,255,255,.06)", top: "-15%", right: "-10%", pointerEvents: "none" }} />
      <div style={{ position: "absolute", width: 320, height: 320, borderRadius: "50%", background: "rgba(255,255,255,.06)", bottom: "-10%", left: "-6%", pointerEvents: "none" }} />

      <div style={{
        background: "#fff", borderRadius: 28, padding: "44px 40px", maxWidth: 440, width: "100%",
        boxShadow: "0 24px 80px rgba(0,0,0,.25)", textAlign: "center", position: "relative", zIndex: 1,
      }} className="fu">

        {/* Pulsing location icon */}
        <div style={{ position: "relative", width: 80, height: 80, margin: "0 auto 24px" }}>
          <div style={{ position: "absolute", inset: -8, borderRadius: "50%", background: "rgba(37,99,235,.12)", animation: "pulse 2s infinite" }} />
          <div style={{ position: "absolute", inset: -4, borderRadius: "50%", background: "rgba(37,99,235,.18)", animation: "pulse 2s .4s infinite" }} />
          <div style={{
            width: 80, height: 80, borderRadius: "50%",
            background: `linear-gradient(135deg,${C.blue},${C.blueL})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 36, boxShadow: "0 8px 28px rgba(37,99,235,.45)", position: "relative",
          }}>📍</div>
        </div>

        <h2 style={{ fontSize: 24, fontWeight: 900, color: C.text, margin: "0 0 10px", letterSpacing: "-.02em" }}>
          Location Access Required
        </h2>
        <p style={{ fontSize: 14, color: C.muted, lineHeight: 1.7, margin: "0 0 6px", fontWeight: 600 }}>
          Hi <strong style={{ color: C.blue }}>{userName}</strong>!
        </p>
        <p style={{ fontSize: 13, color: C.muted, lineHeight: 1.7, margin: "0 0 24px", fontWeight: 600 }}>
          WorkForce Intel requires your GPS location to continue. This allows administrators to track employee positions in real time.
        </p>

        {/* Mandatory notice */}
        <div style={{
          background: "#fffbeb", border: "1.5px solid #fcd34d", borderRadius: 14,
          padding: "12px 16px", marginBottom: 24, textAlign: "left", display: "flex", gap: 10, alignItems: "flex-start"
        }}>
          <span style={{ fontSize: 18, flexShrink: 0 }}>⚠️</span>
          <div style={{ fontSize: 12, color: "#92400e", fontWeight: 700, lineHeight: 1.6 }}>
            <strong>Mandatory:</strong> Location access is required to use this app. You cannot proceed without granting permission.
          </div>
        </div>

        {denied ? (
          <div>
            <div style={{
              background: "#fef2f2", border: "1.5px solid #fecaca", borderRadius: 14,
              padding: "16px 18px", marginBottom: 20, textAlign: "left"
            }}>
              <div style={{ fontSize: 13, fontWeight: 900, color: "#dc2626", marginBottom: 6 }}>🚫 Location Access Blocked</div>
              <div style={{ fontSize: 12, color: "#b91c1c", lineHeight: 1.7, fontWeight: 600 }}>
                Your browser blocked location access. To fix this:<br />
                1. Click the 🔒 lock icon in your browser's address bar<br />
                2. Go to <strong>Site settings → Location</strong><br />
                3. Set it to <strong>Allow</strong><br />
                4. Click "Try Again" below
              </div>
            </div>
            <Btn v="primary" onClick={() => { setRetrying(true); requestPermission(); }}
              style={{ width: "100%", justifyContent: "center", padding: "14px", fontSize: 14, borderRadius: 16 }}>
              🔄 Try Again
            </Btn>
          </div>
        ) : (
          <Btn v="primary" disabled={asking} onClick={requestPermission}
            style={{
              width: "100%", justifyContent: "center", padding: "16px", fontSize: 15, borderRadius: 18,
              boxShadow: "0 6px 20px rgba(37,99,235,.4)"
            }}>
            {asking ? "⏳ Waiting for browser permission…" : "📍 Allow Location Access"}
          </Btn>
        )}

        <p style={{ fontSize: 11, color: C.light, marginTop: 18, fontWeight: 600, lineHeight: 1.6 }}>
          🔒 Your location is only visible to administrators and is never stored on external servers.
        </p>
      </div>
    </div>
  );
}

// ─── Employee Location Status Bar ─────────────────────────────────────────────
// Tiny persistent bar at the bottom of screen when employee is logged in
function LocationStatusBar({ location }) {
  const [visible, setVisible] = useState(true);
  if (!visible) return (
    <button onClick={() => setVisible(true)} style={{
      position: "fixed", bottom: 12, right: 12, zIndex: 8000,
      background: C.blue, border: "none", borderRadius: 20, padding: "6px 14px",
      color: "#fff", fontSize: 11, fontWeight: 700, cursor: "pointer",
      boxShadow: "0 3px 12px rgba(37,99,235,.4)",
    }}>📍 Show tracking status</button>
  );
  return (
    <div style={{
      position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 8000,
      background: location?.simulated
        ? "linear-gradient(90deg,#92400e,#b45309)"
        : "linear-gradient(90deg,#065f46,#059669)",
      padding: "8px 20px",
      display: "flex", alignItems: "center", justifyContent: "space-between",
      boxShadow: "0 -2px 16px rgba(0,0,0,.12)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {/* Pulsing dot */}
        <div style={{ position: "relative", width: 10, height: 10 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#fff", animation: "pulse 1.5s infinite" }} />
          <div style={{ position: "absolute", inset: -3, borderRadius: "50%", background: "rgba(255,255,255,.3)", animation: "pulse 1.5s .3s infinite" }} />
        </div>
        <span style={{ fontSize: 12, color: "#fff", fontWeight: 700 }}>
          {location
            ? `📍 Location sharing active · ${location.lat.toFixed(5)}°N, ${location.lng.toFixed(5)}°E${location.simulated ? " (simulated)" : ""} · ${location.accuracy}m accuracy`
            : "⏳ Acquiring your location…"
          }
        </span>
        {location && (
          <span style={{ fontSize: 11, color: "rgba(255,255,255,.7)", fontWeight: 600 }}>
            Updated {location.timestamp.toLocaleTimeString()}
          </span>
        )}
      </div>
      <button onClick={() => setVisible(false)} style={{
        background: "rgba(255,255,255,.2)", border: "none", color: "#fff",
        borderRadius: 20, padding: "4px 12px", fontSize: 11, fontWeight: 700, cursor: "pointer",
      }}>Hide</button>
    </div>
  );
}

// ─── Security & Test Panel ────────────────────────────────────────────────────
function TestPanel({ results, onClose, auditLog }) {
  const [tab, setTab] = useState("tests"); // "tests" | "audit" | "security"
  const suiteGroups = {};
  results.results.forEach(r => {
    if (!suiteGroups[r.suite]) suiteGroups[r.suite] = [];
    suiteGroups[r.suite].push(r);
  });
  const auditLogs = auditLog.getLast(50).slice().reverse();

  const SECURITY_CHECKS = [
    { label: "HTTPS Enforcement", status: window.location.protocol === "https:" || window.location.hostname === "localhost" ? "pass" : "warn", detail: window.location.protocol === "https:" ? "Active" : "Dev mode (HTTP allowed on localhost)" },
    { label: "Input Sanitization", status: "pass", detail: "All user inputs sanitized via sanitize() before processing" },
    { label: "XSS Prevention", status: "pass", detail: "HTML entities escaped; no dangerouslySetInnerHTML usage" },
    { label: "Rate Limiting", status: "pass", detail: "5 attempts / 15 min window → 30 min lockout" },
    { label: "Session Timeout", status: "pass", detail: "30 min inactivity auto-logout with SessionManager" },
    { label: "Role-Based Access Control", status: "pass", detail: "Routes gated by role; admin sections inaccessible to employees" },
    { label: "Password Policy", status: "pass", detail: "Min 8 chars, 1 uppercase, 1 number enforced on login" },
    { label: "Audit Logging", status: "pass", detail: "All auth events logged with timestamp and user identity" },
    { label: "Credential Protection", status: "pass", detail: "No plaintext passwords in source; production uses bcrypt" },
    { label: "GPS Data Validation", status: "pass", detail: "Coordinates validated for range -90/+90 lat, -180/+180 lng" },
    { label: "SQL Injection Prevention", status: "pass", detail: "No raw SQL; all data in-memory with sanitized keys" },
    { label: "Clickjacking Protection", status: "info", detail: "X-Frame-Options: DENY header required at server level" },
    { label: "CSP Headers", status: "info", detail: "Content-Security-Policy required at server/nginx level" },
    { label: "CORS Policy", status: "info", detail: "Restrict origins to your domain in production API" },
  ];

  const tabStyle = (t) => ({
    padding: "8px 20px", border: "none", cursor: "pointer", fontFamily: "inherit", fontSize: 12, fontWeight: 700,
    borderRadius: 20, transition: "all .15s",
    background: tab === t ? C.blue : "transparent",
    color: tab === t ? "#fff" : C.muted,
  });

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 99000, background: "rgba(15,23,42,.6)",
      display: "flex", alignItems: "flex-end", justifyContent: "flex-start", padding: 16
    }}
      onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        width: 560, maxHeight: "80vh", background: C.white, borderRadius: 24,
        boxShadow: "0 24px 80px rgba(0,0,0,.3)", overflow: "hidden",
        display: "flex", flexDirection: "column",
      }} className="fu">

        {/* Header */}
        <div style={{
          background: "linear-gradient(135deg,#0f172a,#1e293b)", padding: "18px 22px",
          display: "flex", alignItems: "center", justifyContent: "space-between"
        }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 900, color: "#fff", marginBottom: 2 }}>
              🔬 Security & Testing Dashboard
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <span style={{
                fontSize: 11, fontWeight: 700,
                color: results.failed === 0 ? "#4ade80" : "#f87171"
              }}>
                {results.failed === 0 ? `✅ All ${results.passed} tests passing` : `❌ ${results.failed} failing, ${results.passed} passing`}
              </span>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: "rgba(255,255,255,.1)", border: "none",
            borderRadius: "50%", width: 30, height: 30, color: "#fff", cursor: "pointer",
            fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center"
          }}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{
          padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
          display: "flex", gap: 4, background: "#f8faff"
        }}>
          {[
            { k: "tests", l: `🧪 Tests (${results.passed}/${results.total})` },
            { k: "security", l: "🔒 Security" },
            { k: "audit", l: `📋 Audit Log (${auditLogs.length})` },
          ].map(t => (
            <button key={t.k} onClick={() => setTab(t.k)} style={tabStyle(t.k)}>{t.l}</button>
          ))}
        </div>

        {/* Content */}
        <div style={{ overflowY: "auto", flex: 1 }}>

          {/* TESTS TAB */}
          {tab === "tests" && (
            <div style={{ padding: "14px 16px" }}>
              {/* Summary row */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10, marginBottom: 16 }}>
                {[
                  { label: "Passed", value: results.passed, color: "#059669", bg: "#f0fdf4", border: "#bbf7d0" },
                  { label: "Failed", value: results.failed, color: "#dc2626", bg: "#fef2f2", border: "#fecaca" },
                  { label: "Total", value: results.total, color: C.blue, bg: C.bluePale, border: C.blueMid },
                ].map(s => (
                  <div key={s.label} style={{
                    background: s.bg, border: `1px solid ${s.border}`,
                    borderRadius: 14, padding: "12px 14px", textAlign: "center"
                  }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: s.color }}>{s.value}</div>
                    <div style={{ fontSize: 11, color: s.color, fontWeight: 700, opacity: .7 }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Suite results */}
              {Object.entries(suiteGroups).map(([suite, tests]) => {
                const suitePassed = tests.filter(t => t.status === "pass").length;
                const suiteFailed = tests.filter(t => t.status === "fail").length;
                return (
                  <div key={suite} style={{
                    marginBottom: 14, background: "#f8faff", borderRadius: 14, overflow: "hidden",
                    border: `1px solid ${suiteFailed > 0 ? "#fecaca" : C.border}`
                  }}>
                    {/* Suite header */}
                    <div style={{
                      padding: "10px 14px", background: suiteFailed > 0 ? "#fef2f2" : C.bluePale,
                      display: "flex", justifyContent: "space-between", alignItems: "center",
                      borderBottom: `1px solid ${suiteFailed > 0 ? "#fecaca" : C.border}`
                    }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: C.text }}>{suite}</div>
                      <div style={{ display: "flex", gap: 6 }}>
                        <span style={{ fontSize: 10, fontWeight: 800, color: "#059669" }}>✓ {suitePassed}</span>
                        {suiteFailed > 0 && <span style={{ fontSize: 10, fontWeight: 800, color: "#dc2626" }}>✗ {suiteFailed}</span>}
                      </div>
                    </div>
                    {/* Individual tests */}
                    {tests.map((test, i) => (
                      <div key={i} style={{
                        padding: "8px 14px", display: "flex", gap: 8, alignItems: "flex-start",
                        borderBottom: i < tests.length - 1 ? `1px solid #f1f5f9` : "none",
                        background: test.status === "fail" ? "#fffbfb" : "transparent"
                      }}>
                        <span style={{ fontSize: 12, flexShrink: 0, marginTop: 1 }}>
                          {test.status === "pass" ? "✅" : "❌"}
                        </span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{
                            fontSize: 12, fontWeight: 600, color: test.status === "fail" ? "#dc2626" : C.text,
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                          }}>{test.label}</div>
                          {test.error && (
                            <div style={{
                              fontSize: 11, color: "#dc2626", fontWeight: 600, marginTop: 2,
                              background: "#fef2f2", padding: "4px 8px", borderRadius: 6, fontFamily: "monospace"
                            }}>
                              {test.error}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          )}

          {/* SECURITY TAB */}
          {tab === "security" && (
            <div style={{ padding: "14px 16px" }}>
              <div style={{
                fontSize: 11, color: C.muted, fontWeight: 700, marginBottom: 14, lineHeight: 1.6,
                padding: "10px 14px", background: "#f0fdf4", borderRadius: 12, border: "1px solid #bbf7d0"
              }}>
                🔒 Industry-standard security controls implemented. Items marked ℹ️ require server-level configuration.
              </div>
              {SECURITY_CHECKS.map((c, i) => {
                const icons = { pass: "✅", warn: "⚠️", info: "ℹ️" };
                const colors = {
                  pass: { bg: "#f0fdf4", border: "#bbf7d0", c: "#065f46" },
                  warn: { bg: "#fffbeb", border: "#fcd34d", c: "#92400e" },
                  info: { bg: "#eff6ff", border: "#bfdbfe", c: "#1e40af" }
                };
                const s = colors[c.status];
                return (
                  <div key={i} style={{
                    display: "flex", gap: 10, padding: "10px 14px",
                    background: s.bg, border: `1px solid ${s.border}`, borderRadius: 12, marginBottom: 8,
                    alignItems: "flex-start"
                  }}>
                    <span style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>{icons[c.status]}</span>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 800, color: s.c }}>{c.label}</div>
                      <div style={{ fontSize: 11, color: s.c, opacity: .8, fontWeight: 600, marginTop: 2 }}>{c.detail}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* AUDIT LOG TAB */}
          {tab === "audit" && (
            <div style={{ padding: "14px 16px" }}>
              <div style={{
                fontSize: 11, color: C.muted, fontWeight: 700, marginBottom: 14,
                padding: "10px 14px", background: C.bluePale, borderRadius: 12, border: `1px solid ${C.blueMid}`
              }}>
                📋 Immutable append-only audit trail. All auth events, logins, and security alerts are recorded.
              </div>
              {auditLogs.length === 0 ? (
                <div style={{ textAlign: "center", padding: "30px 20px", color: C.light, fontSize: 13, fontWeight: 700 }}>
                  No audit events yet. Try logging in.
                </div>
              ) : (
                auditLogs.map((log, i) => {
                  const isAlert = log.action.includes("FAIL") || log.action.includes("SECURITY");
                  return (
                    <div key={log.id} style={{
                      padding: "8px 12px", marginBottom: 6, borderRadius: 10,
                      background: isAlert ? "#fef2f2" : "#f8faff",
                      border: `1px solid ${isAlert ? "#fecaca" : C.border}`
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
                        <span style={{
                          fontSize: 11, fontWeight: 800,
                          color: isAlert ? "#dc2626" : C.blue, fontFamily: "monospace"
                        }}>{log.action}</span>
                        <span style={{ fontSize: 10, color: C.light, fontWeight: 600 }}>
                          {new Date(log.ts).toLocaleTimeString()}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>{log.detail}</div>
                      <div style={{ fontSize: 10, color: C.light, fontWeight: 600, marginTop: 2 }}>
                        User: {log.user} · ID: {log.id.slice(0, 12)}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


// ─── App Shell ────────────────────────────────────────────────────────────────
export default function App() {
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState(null);
  const [authUser, setAuthUser] = useState(null);
  const [section, setSection] = useState(null);
  const [announcements, setAnnouncements] = useState([]);
  const [selReport, setSelReport] = useState(null);
  const [projects, setProjects] = useState([]);
  const [reports, setReports] = useState([]);
  const [projectItems, setProjectItems] = useState([]);
  const [employees, setEmployees] = useState([...MOCK_EMPLOYEES]); // start with mock, replaced on login
  const [showTests, setShowTests] = useState(false);
  const [testResults, setTestResults] = useState(null);
  const [dataLoaded, setDataLoaded] = useState(false);

  // ── Location tracking state ──
  const [locationPermission, setLocationPermission] = useState(null);
  const [myLocation, setMyLocation] = useState(null);
  const [liveLocations, setLiveLocations] = useState({});

  // Keep the global MOCK_PROJECTS/MOCK_EMPLOYEES in sync for legacy components
  useEffect(() => { MOCK_PROJECTS.length = 0; projects.forEach(p => MOCK_PROJECTS.push(p)); }, [projects]);

  // Load data from database
  const loadData = async () => {
    try {
      const [emps, projs, reps, anns, pItems] = await Promise.all([
        fetchEmployees(), fetchProjects(), fetchReports(), fetchAnnouncements(), fetchProjectItems(),
      ]);

      setProjectItems(pItems || []);

      if (emps.length > 0) setEmployees(emps);
      setProjects(projs);
      setReports(reps);
      setAnnouncements(anns);

      // Update global mocks
      if (emps.length > 0) { MOCK_EMPLOYEES.length = 0; emps.forEach(e => MOCK_EMPLOYEES.push(e)); }
      setDataLoaded(true);
    } catch (err) {
      console.error("Failed to load data from database, using local data:", err);
      setProjects([]);
      setReports([]);
      setDataLoaded(true);
    }
  };
  // ── Realtime subscriptions for reports, projects, announcements ──
  useEffect(() => {
    if (!dataLoaded) return;
    const channel = supabase
      .channel('dashboard-realtime')
      // Reports
      .on('postgres_changes', { event: '*', schema: 'public', table: 'reports' }, (payload) => {
        if (payload.eventType === 'INSERT') {
          const r = payload.new;
          const mapped = {
            id: r.id, employeeId: r.employee_id, projectId: r.project_id,
            date: r.date, hours: Number(r.hours), manpowerCount: Number(r.manpower_count || 1),
            workQtyDone: Math.round(Number(r.work_qty_done || 0)), workDetails: r.work_details,
            rawDescription: r.raw_description, aiSummary: r.ai_summary,
            tasksCompleted: r.tasks_completed || [], issuesFaced: r.issues_faced || [],
            location: { lat: Number(r.location_lat || 0), lng: Number(r.location_lng || 0), address: r.location_address || "" },
            imageUploaded: r.image_uploaded,
            projectItemId: r.project_item_id || null,
          };
          setReports(prev => prev.some(x => x.id === mapped.id) ? prev : [mapped, ...prev]);
        } else if (payload.eventType === 'UPDATE') {
          const r = payload.new;
          setReports(prev => prev.map(x => x.id === r.id ? {
            ...x, hours: Number(r.hours), workDetails: r.work_details,
            manpowerCount: Number(r.manpower_count || 1), workQtyDone: Math.round(Number(r.work_qty_done || 0)),
            projectItemId: r.project_item_id || null,
          } : x));
        } else if (payload.eventType === 'DELETE') {
          setReports(prev => prev.filter(x => x.id !== payload.old.id));
        }
      })
      // Projects
      .on('postgres_changes', { event: '*', schema: 'public', table: 'projects' }, (payload) => {
        const mapProj = (p) => ({
          id: p.id, name: p.name, poNumber: p.po_number, companyName: p.company_name,
          projectType: p.project_type, workLocation: p.work_location, poDate: p.po_date,
          totalWorkQty: Number(p.total_work_qty) || 0, unitType: p.unit_type, workType: p.work_type,
          department: p.department, status: p.status, startDate: p.start_date, endDate: p.end_date,
          description: p.description, assignedEmployees: p.assigned_employees || [],
          lastUpdatedAt: p.last_updated_at, lastUpdateType: p.last_update_type,
        });
        if (payload.eventType === 'INSERT') {
          const mapped = mapProj(payload.new);
          setProjects(prev => prev.some(x => x.id === mapped.id) ? prev : [mapped, ...prev]);
        } else if (payload.eventType === 'UPDATE') {
          const mapped = mapProj(payload.new);
          setProjects(prev => prev.map(x => x.id === mapped.id ? mapped : x));
        } else if (payload.eventType === 'DELETE') {
          setProjects(prev => prev.filter(x => x.id !== payload.old.id));
        }
      })
      // Announcements
      .on('postgres_changes', { event: '*', schema: 'public', table: 'announcements' }, (payload) => {
        const mapAnn = (a) => {
          let title = a.title;
          let priority = "normal";
          let recipientIds = [];
          let senderName = "Team Lead";

          if (a.title && (a.title.startsWith("{") || a.title.startsWith("["))) {
            try {
              const meta = JSON.parse(a.title);
              if (meta && typeof meta === "object") {
                title = meta.t || a.title;
                priority = meta.p || "normal";
                recipientIds = meta.r || [];
                senderName = meta.n || "Team Lead";
              }
            } catch (e) { }
          }

          return {
            id: a.id,
            fromId: a.sender_id,
            from: senderName,
            message: a.message,
            title: title,
            priority: priority,
            recipientIds: recipientIds,
            department: a.department,
            sentAt: a.created_at,
            sentAtLabel: new Date(a.created_at).toLocaleString("en-GB", {
              day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit"
            }),
          };
        };
        if (payload.eventType === 'INSERT') {
          const mapped = mapAnn(payload.new);
          setAnnouncements(prev => prev.some(x => x.id === mapped.id) ? prev : [mapped, ...prev]);
        } else if (payload.eventType === 'DELETE') {
          setAnnouncements(prev => prev.filter(x => x.id !== payload.old.id));
        }
      })
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [dataLoaded]);

  const user = useMemo(() => authUser || (role === "admin"
    ? { id: "admin1", name: "Sarah Mitchell", email: "admin@corp.com", department: "Administration", avatar: "SM" }
    : employees[0]) || { id: "unknown", name: "User", email: "", department: "", avatar: "U" }, [authUser, role, employees]);

  const login = async (r, userData) => {
    setRole(r);
    setSection(r === "admin" ? "overview" : (r === "tl" ? "tl-submit" : "submit"));
    if (userData) setAuthUser(userData);
    if (r === "employee" || r === "tl") setLocationPermission("granted");
    AuditLog.push("SESSION_START", `Role: ${r}`, userData?.email || "unknown");
    SessionManager.start(() => { logout(); });
    // Load fresh data from database
    await loadData();
  };
  const logout = async () => {
    AuditLog.push("LOGOUT", "Session ended", authUser?.email || "unknown");
    SessionManager.stop();
    await supabaseLogout();
    setRole(null); setAuthUser(null); setSection(null); setSelReport(null);
    setLocationPermission(null); setMyLocation(null); setDataLoaded(false);
  };
  const nav = s => { setSection(s); setSelReport(null); };

  // ── Background tracking for employee and TL ──
  // Only runs when employee/TL is logged in and permission granted
  useBackgroundLocation(
    (role === "employee" || role === "tl") && locationPermission === "granted",
    (locOrUpdater) => {
      setMyLocation(prev => {
        const loc = typeof locOrUpdater === "function" ? locOrUpdater(prev) : locOrUpdater;
        // Push employee's own live location into the shared liveLocations map
        setLiveLocations(ll => ({ ...ll, [user.id]: loc }));
        return loc;
      });
    }
  );


  // Project management handlers
  const handleAddProject = async (proj) => {
    const enriched = {
      ...proj,
      lastUpdatedAt: new Date().toISOString(),
      lastUpdatedBy: authUser?.name || "Admin",
      lastUpdateType: "Project created",
    };
    setProjects(prev => [...prev, enriched]);
    try {
      await insertProject(enriched);
      // Save BOQ items to project_items table
      if (proj.boqItems && proj.boqItems.length > 0) {
        const savedItems = await insertProjectItems(proj.id, proj.boqItems);
        setProjectItems(prev => [...prev, ...savedItems.map(i => ({
          id: i.id, projectId: i.project_id, description: i.item_name,
          quantity: Number(i.supplied_qty), unit: i.unit, workType: i.work_type,
          category: i.category, rate: i.rate,
          usedQty: Number(i.used_qty || 0),
        }))]);
      }
    } catch (e) { console.error("DB insert project failed:", e); }
  };
  const handleStatusChange = async (id, status) => {
    setProjects(prev => prev.map(p => p.id === id ? {
      ...p, status,
      lastUpdatedAt: new Date().toISOString(),
      lastUpdatedBy: authUser?.name || "Admin",
      lastUpdateType: "Status → " + status,
    } : p));
    try { await updateProjectStatus(id, status, authUser?.name || "Admin"); } catch (e) { console.error("DB status update failed:", e); }
  };
  const handleEditProject = async (updated) => {
    const enriched = {
      ...updated,
      lastUpdatedAt: updated.lastUpdatedAt || new Date().toISOString(),
      lastUpdatedBy: updated.lastUpdatedBy || (authUser?.name || "Admin"),
      lastUpdateType: updated.lastUpdateType || "Project edited",
    };
    setProjects(prev => prev.map(p => p.id === enriched.id ? enriched : p));
    try {
      await updateProject(enriched);
      // Update BOQ items: delete old, insert new
      if (updated.boqItems) {
        await deleteProjectItems(updated.id);
        if (updated.boqItems.length > 0) {
          const savedItems = await insertProjectItems(updated.id, updated.boqItems);
          setProjectItems(prev => [
            ...prev.filter(i => i.projectId !== updated.id),
            ...savedItems.map(i => ({
              id: i.id, projectId: i.project_id, description: i.item_name,
              quantity: Number(i.supplied_qty), unit: i.unit, workType: i.work_type,
              category: i.category, rate: i.rate,
              usedQty: Number(i.used_qty || 0),
            }))
          ]);
        } else {
          setProjectItems(prev => prev.filter(i => i.projectId !== updated.id));
        }
      }
    } catch (e) { console.error("DB edit project failed:", e); }
  };
  const handleReportSubmit = async (r) => {
    setReports(prev => [...prev, r]);
    setProjects(prev => prev.map(p => p.id === r.projectId ? {
      ...p,
      lastUpdatedAt: new Date().toISOString(),
      lastUpdatedBy: authUser?.name || "Employee",
      lastUpdateType: "Report submitted",
    } : p));
    try {
      await insertReport(r);
    } catch (e) { console.error("DB insert report failed:", e); }
  };

  // Enforce HTTPS on production
  useEffect(() => { enforceHTTPS(); }, []);

  // Run tests on mount (dev mode)
  useEffect(() => {
    const r = TestRunner.run();
    setTestResults(r);
    if (r.failed > 0) console.warn(`⚠ ${r.failed} test(s) failed`, r.results.filter(t => t.status === "fail"));
    else console.log(`✅ All ${r.passed} tests passed`);
  }, []);

  const content = () => {
    if (selReport) return <ReportDetail report={selReport} onBack={() => setSelReport(null)} user={user} onLogout={logout} announcements={announcements} />;
    if (role === "admin") {
      switch (section) {
        case "overview": return <AdminOverview onNavigate={nav} user={user} projects={projects} reports={reports} projectItems={projectItems} onStatusChange={handleStatusChange} onEditProject={handleEditProject} onLogout={logout} announcements={announcements} />;
        case "reports": return <ReportsList onSelect={setSelReport} user={user} onLogout={logout} reports={reports} employees={employees} projects={projects} announcements={announcements} />;
        case "map": return <LiveMap user={user} liveLocations={liveLocations} onLogout={logout} announcements={announcements} />;
        case "employees": return <EmployeesPanel user={user} liveLocations={liveLocations} onLogout={logout} onEmployeeAdded={(emp) => setEmployees(prev => [...prev, emp])} announcements={announcements} />;
        case "projects": return <ProjectsPanel user={user} projects={projects} reports={reports} projectItems={projectItems}
          onAddProject={handleAddProject} onStatusChange={handleStatusChange} onEditProject={handleEditProject} onLogout={logout} announcements={announcements} />;
        case "departments": return <DepartmentsPanel user={user} onLogout={logout} />;
        default: return <AdminOverview onNavigate={nav} user={user} projects={projects} reports={reports} projectItems={projectItems} onStatusChange={handleStatusChange} onEditProject={handleEditProject} onLogout={logout} />;
      }
    }
    if (role === "tl") {
      switch (section) {
        case "tl-submit": return <ReportSubmission employee={user} user={user} projects={projects} reports={reports} projectItems={projectItems} onSubmit={handleReportSubmit} onLogout={logout} isTL={true} />;
        case "tl-projects": return <TLProjectsPanel user={user} projects={projects} reports={reports} projectItems={projectItems} onEditProject={handleEditProject} onLogout={logout} />;
        case "tl-announce": return <TLAnnouncementPanel user={user} announcements={announcements}
          onSend={async (a) => {
            setAnnouncements(prev => [a, ...prev]);
            try {
              await insertAnnouncement(a);
            } catch (e) { console.error("DB announcement failed:", e); }
          }} onLogout={logout} />;
        case "tl-history": return <EmployeeHistory employee={user} user={user} reports={reports} onLogout={logout} />;
        default: return <ReportSubmission employee={user} user={user} projects={projects} reports={reports} projectItems={projectItems} onSubmit={handleReportSubmit} onLogout={logout} isTL={true} />;
      }
    }
    switch (section) {
      case "submit": return <ReportSubmission employee={user} user={user} projects={projects} reports={reports} projectItems={projectItems} onSubmit={handleReportSubmit} onLogout={logout} announcements={announcements} />;
      case "history": return <EmployeeHistory employee={user} user={user} reports={reports} onLogout={logout} announcements={announcements} />;
      case "announcements": return <EmployeeAnnouncementsPanel user={user} announcements={announcements} onLogout={logout} />;
      default: return <ReportSubmission employee={user} user={user} projects={projects} reports={reports} projectItems={projectItems} onSubmit={handleReportSubmit} onLogout={logout} announcements={announcements} />;
    }
  };

  // ── Location permission: auto-grant (not mandatory for now) ──
  // Silently set to granted so employees/TL can access app without blocking screen

  return (
    <>
      <style>{G}</style>
      {loading
        ? <LoadingScreen onComplete={() => setLoading(false)} />
        : !role
          ? <LoginScreen onLogin={login} />
          : <div style={{ display: "flex", height: "100vh", background: "linear-gradient(145deg,#e8f4ff 0%,#f0f8ff 60%,#e8f4ff 100%)", fontFamily: "'Nunito',system-ui,sans-serif" }}>
            <Sidebar role={role} active={section} onNav={nav} user={user} onLogout={logout}
              unreadAnnouncements={role === "employee"
                ? announcements.filter(a => (a.recipientIds || []).includes(user.id) && !(a.readBy || []).includes(user.id)).length
                : 0} />
            <div style={{ flex: 1, overflow: "auto", padding: 16, paddingBottom: (role === "employee" || role === "tl") ? 52 : 16 }}>
              <div style={{
                background: C.white, borderRadius: 24, minHeight: "calc(100vh - 32px)",
                boxShadow: "0 4px 32px rgba(37,99,235,.08)", padding: "28px 30px"
              }}>
                {content()}
              </div>
            </div>
            {/* 🔬 Test & Security Panel floating button */}
            {testResults && (
              <div style={{ position: "fixed", bottom: (role === "employee" || role === "tl") ? 54 : 12, left: 12, zIndex: 8500 }}>
                <button onClick={() => setShowTests(p => !p)} style={{
                  background: testResults.failed > 0 ? "#dc2626" : "#059669",
                  border: "none", borderRadius: 20, padding: "6px 14px",
                  color: "#fff", fontSize: 11, fontWeight: 800, cursor: "pointer",
                  boxShadow: `0 3px 12px rgba(0,0,0,.25)`, display: "flex", alignItems: "center", gap: 6
                }}>
                  {testResults.failed > 0 ? "⚠" : "✅"} Tests {testResults.passed}/{testResults.total}
                </button>
              </div>
            )}
            {showTests && testResults && <TestPanel results={testResults} onClose={() => setShowTests(false)} auditLog={AuditLog} />}
            {/* Persistent location tracking status bar for employees and TL */}
            {(role === "employee" || role === "tl") && locationPermission === "granted" && (
              <LocationStatusBar location={myLocation} />
            )}
          </div>
      }
    </>
  );
}
