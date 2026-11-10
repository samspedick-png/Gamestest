-- 60 Second Showdown private leader application
-- Run once in Supabase Dashboard > SQL Editor.
create table if not exists public.leader_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin', 'scorekeeper', 'viewer')),
  created_at timestamptz not null default now()
);

create table if not exists public.season_config (
  id integer primary key check (id = 1),
  carryover jsonb not null,
  point_values jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.weeks (
  week_date date primary key,
  games jsonb not null default '{}'::jsonb,
  students jsonb not null default '{}'::jsonb,
  other jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

insert into public.season_config (id, carryover, point_values)
values (
  1,
  '{"msg":2000,"hsg":2000,"hsb":3500,"msb":1000}'::jsonb,
  '{"round":1000,"student":500,"can":10,"question":50}'::jsonb
)
on conflict (id) do nothing;

create or replace function public.is_authorized_leader()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.leader_roles lr
    where lr.user_id = (select auth.uid())
      and lr.role in ('admin', 'scorekeeper', 'viewer')
  );
$$;

create or replace function public.can_edit_scores()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.leader_roles lr
    where lr.user_id = (select auth.uid())
      and lr.role in ('admin', 'scorekeeper')
  );
$$;

alter table public.leader_roles enable row level security;
alter table public.season_config enable row level security;
alter table public.weeks enable row level security;

-- A leader can only inspect their own role. Assignment is done by an admin using
-- the SQL instructions in README.md, not through a public signup flow.
drop policy if exists "Leaders can read own role" on public.leader_roles;
create policy "Leaders can read own role" on public.leader_roles
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists "Leaders can read season settings" on public.season_config;
create policy "Leaders can read season settings" on public.season_config
  for select to authenticated using (public.is_authorized_leader());
drop policy if exists "Scorekeepers can update season settings" on public.season_config;
create policy "Scorekeepers can update season settings" on public.season_config
  for all to authenticated using (public.can_edit_scores()) with check (public.can_edit_scores());

drop policy if exists "Leaders can read weeks" on public.weeks;
create policy "Leaders can read weeks" on public.weeks
  for select to authenticated using (public.is_authorized_leader());
drop policy if exists "Scorekeepers can create weeks" on public.weeks;
create policy "Scorekeepers can create weeks" on public.weeks
  for insert to authenticated with check (public.can_edit_scores());
drop policy if exists "Scorekeepers can delete weeks" on public.weeks;
create policy "Scorekeepers can delete weeks" on public.weeks
  for delete to authenticated using (public.can_edit_scores());
drop policy if exists "Scorekeepers can update weeks" on public.weeks;
create policy "Scorekeepers can update weeks" on public.weeks
  for update to authenticated using (public.can_edit_scores()) with check (public.can_edit_scores());

create or replace function public.set_week_score(
  p_week_date date,
  p_row text,
  p_team text,
  p_value numeric
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if not public.can_edit_scores() then
    raise exception 'Scorekeeper access required';
  end if;
  if p_row not in ('games', 'students', 'other') then
    raise exception 'Invalid score category';
  end if;
  if p_team not in ('msg', 'hsg', 'hsb', 'msb') then
    raise exception 'Invalid team';
  end if;
  update public.weeks
    set games = case when p_row = 'games' then jsonb_set(games, array[p_team], to_jsonb(p_value), true) else games end,
        students = case when p_row = 'students' then jsonb_set(students, array[p_team], to_jsonb(p_value), true) else students end,
        other = case when p_row = 'other' then jsonb_set(other, array[p_team], to_jsonb(p_value), true) else other end,
        updated_at = now()
    where week_date = p_week_date;
  if not found then
    raise exception 'Week not found';
  end if;
end;
$$;

revoke all on function public.is_authorized_leader() from public, anon;
revoke all on function public.can_edit_scores() from public, anon;
revoke all on function public.set_week_score(date, text, text, numeric) from public, anon;
grant execute on function public.is_authorized_leader() to authenticated;
grant execute on function public.can_edit_scores() to authenticated;
grant execute on function public.set_week_score(date, text, text, numeric) to authenticated;
grant select, insert, update, delete on public.leader_roles to authenticated;
grant select, insert, update, delete on public.season_config to authenticated;
grant select, insert, update, delete on public.weeks to authenticated;

-- Enable database change notifications used for cross-device live sync.
do $$ begin
  alter publication supabase_realtime add table public.weeks;
exception when duplicate_object then null;
when undefined_object then null;
end $$;
do $$ begin
  alter publication supabase_realtime add table public.season_config;
exception when duplicate_object then null;
when undefined_object then null;
end $$;
