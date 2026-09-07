alter table public.letters
add column if not exists revoked_at timestamptz;

alter table public.letters
add column if not exists expires_at timestamptz;

alter table public.letters enable row level security;

-- Remove older policies.
drop policy if exists "Public can create letters"
on public.letters;

drop policy if exists "Public can open sent letters"
on public.letters;

drop policy if exists "Signed in users can create letters"
on public.letters;

drop policy if exists "Senders can read their letters"
on public.letters;

-- Remove the new policies if this migration was previously attempted.
drop policy if exists "Authenticated users create their own letters"
on public.letters;

drop policy if exists "Senders read their own letters"
on public.letters;

drop policy if exists "Senders update their own letters"
on public.letters;

-- Recreate secure policies.
create policy "Authenticated users create their own letters"
on public.letters
for insert
to authenticated
with check (
  auth.uid() = sender_id
  and status = 'sent'
);

create policy "Senders read their own letters"
on public.letters
for select
to authenticated
using (
  auth.uid() = sender_id
);

create policy "Senders update their own letters"
on public.letters
for update
to authenticated
using (
  auth.uid() = sender_id
)
with check (
  auth.uid() = sender_id
);

-- Public recipients fetch one letter through its secret token.
create or replace function public.get_public_letter(
  letter_token uuid
)
returns public.letters
language sql
security definer
set search_path = public
stable
as $$
  select l
  from public.letters l
  where l.public_token = letter_token
    and l.status = 'sent'
    and l.revoked_at is null
    and (
      l.expires_at is null
      or l.expires_at > now()
    )
  limit 1;
$$;

revoke all
on function public.get_public_letter(uuid)
from public;

grant execute
on function public.get_public_letter(uuid)
to anon, authenticated;