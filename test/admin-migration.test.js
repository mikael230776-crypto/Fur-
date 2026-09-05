import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const sql = readFileSync(new URL("../supabase/migrations/20260905_create_admin_foundation.sql", import.meta.url), "utf8");

test("migration defines products and append-only activity history", () => {
  assert.match(sql, /create table if not exists public\.admin_products/i);
  assert.match(sql, /create table if not exists public\.admin_activity_history/i);
  assert.match(sql, /before update or delete on public\.admin_activity_history/i);
  assert.match(sql, /admin activity history is append-only/i);
});

test("migration enables RLS and denies browser roles", () => {
  assert.match(sql, /alter table public\.admin_products enable row level security/i);
  assert.match(sql, /alter table public\.admin_activity_history enable row level security/i);
  assert.match(sql, /revoke all on public\.admin_products from public, anon, authenticated/i);
  assert.match(sql, /revoke all on public\.admin_activity_history from public, anon, authenticated/i);
});

test("transactional mutation function repeats role checks", () => {
  assert.match(sql, /create or replace function public\.admin_mutate_product/i);
  assert.match(sql, /p_actor_role not in \('editor', 'administrator'\)/i);
  assert.match(sql, /p_actor_role <> 'administrator'/i);
  assert.match(sql, /insert into public\.admin_activity_history/i);
  assert.match(sql, /grant execute on function[\s\S]+to service_role/i);
});
